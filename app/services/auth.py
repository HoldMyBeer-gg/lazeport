from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request

log = logging.getLogger(__name__)

from app.config import settings
from app.db import get_adapter
from app.db.adapter import StorageAdapter
from app.db import models
from app.services.crypto import decrypt_text, encrypt_text

PBKDF2_ITERATIONS = 210000  # 210,000 iterations is a good balance between security and performance

# Runtime role override for testing only (never set in production).
# Mutated via /api/_test/set-role endpoint when AUTH_DISABLED=1.
# Can also be read from a file at data/.test_role for cross-process signaling.
_test_forced_role: str | None = None

_TEST_ROLE_FILE = "data/.test_role"


def _get_test_role() -> str | None:
    """Return the forced test role. Checks module var first, then file."""
    if _test_forced_role:
        return _test_forced_role
    try:
        with open(_TEST_ROLE_FILE) as f:
            role = f.read().strip()
            return role if role else None
    except FileNotFoundError:
        return None


def _encode_b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _decode_b64(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${_encode_b64(salt)}${_encode_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = _decode_b64(salt_b64)
        expected = _decode_b64(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(dk, expected)
    except (ValueError, IndexError, TypeError) as e:
        log.debug("Password verification failed (malformed hash): %s", type(e).__name__)
        return False
    except Exception as e:
        log.debug("Password verification failed: %s", type(e).__name__)
        return False


def hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """Generate a high-entropy API key with a prefix."""
    return f"lp_{secrets.token_urlsafe(32)}"


def hash_api_key(key: str) -> str:
    """Hash the API key for secure storage."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def authenticate_user(email: str, password: str, adapter: StorageAdapter) -> tuple[models.User, bool]:
    """
    Authenticate user with email and password.
    
    Returns:
        Tuple of (user, requires_2fa)
        - user: Authenticated user object
        - requires_2fa: True if 2FA verification is required, False otherwise
    """
    user = adapter.get_user_by_email(email)
    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is inactive")
    if not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    from app.services import twofa
    requires_2fa = twofa.check_2fa_required(user, adapter)
    
    return user, requires_2fa


def get_storage() -> StorageAdapter:
    return get_adapter()


def is_auth_enabled() -> bool:
    import os
    return os.getenv("AUTH_DISABLED", "0").strip() not in ("1", "true", "yes")


def _get_user_from_session(request: Request, adapter: StorageAdapter) -> Optional[models.User]:
    """Get user from session (fully authenticated only).
    
    Only returns user if they have completed full authentication including 2FA.
    Users with pending_2fa_user_id must complete 2FA before accessing protected endpoints.
    
    Security: Sessions created before 2FA enforcement must have 2fa_verified flag.
    This prevents old sessions from bypassing 2FA after the security fix.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    
    user = adapter.get_user_by_id(str(user_id))
    if not user:
        return None

    # MED-6: Validate session_version — incremented on forced logout events (e.g. 2FA reset)
    # If mismatch, the session was issued before the forced logout; clear it.
    if user.session_version != request.session.get("session_version", 0):
        request.session.clear()
        return None

    # If user has 2FA enabled, session must have 2fa_verified flag
    # This invalidates old sessions created before the bypass fix
    from app.services import twofa
    requires_2fa = twofa.check_2fa_required(user, adapter)
    if requires_2fa and not request.session.get("2fa_verified"):
        # Invalidate this session - user needs to re-authenticate with 2FA
        request.session.clear()
        return None

    # Check session timeout (sliding idle timeout)
    last_activity_str = (
        request.session.get("session_last_activity")
        or request.session.get("session_created_at")  # backward compat with old sessions
    )
    if last_activity_str:
        try:
            last_activity = datetime.fromisoformat(last_activity_str)
            timeout = timedelta(minutes=settings.session_timeout_minutes)
            if datetime.utcnow() - last_activity > timeout:
                request.session.clear()
                return None
        except (ValueError, TypeError):
            # Malformed timestamp, invalidate session
            request.session.clear()
            return None

    # Update sliding window - refresh the session timeout on each authenticated request
    request.session["session_last_activity"] = datetime.utcnow().isoformat()

    return user


def get_pending_or_authenticated_user(
    request: Request,
    adapter: StorageAdapter = Depends(get_storage),
) -> models.User:
    """Get user from session, allowing both fully authenticated and pending 2FA states.
    
    Used ONLY for 2FA enrollment/verification endpoints where users need access
    before completing 2FA (to prevent deadlock with mandatory 2FA policy).
    
    All other endpoints should use get_current_user which requires full authentication.
    """
    if not is_auth_enabled():
        return get_current_user(request, adapter)
    
    # Check for fully authenticated user first
    user_id = request.session.get("user_id")
    if not user_id:
        # Allow pending 2FA users (password authenticated, but 2FA not completed)
        user_id = request.session.get("pending_2fa_user_id")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = adapter.get_user_by_id(str(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


def _get_user_from_api_key(request: Request, adapter: StorageAdapter) -> Optional[models.User]:
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    
    key_hash = hash_api_key(api_key)
    key_record = adapter.get_api_key_by_hash(key_hash)
    if not key_record:
        return None
        
    if key_record.expires_at and key_record.expires_at < datetime.utcnow():
        return None
        
    adapter.update_api_key_last_used(key_record.id)
    return adapter.get_user_by_id(key_record.user_id)


def get_current_user(
    request: Request,
    adapter: StorageAdapter = Depends(get_storage),
) -> models.User:
    if not is_auth_enabled():
        # _get_test_role allows behave/integration tests to simulate non-admin
        # users at runtime via file or API endpoint.
        # Only honoured when auth is disabled (i.e. never in production).
        forced_role = _get_test_role() or "admin"
        forced_email = "test@local" if forced_role == "admin" else f"test-{forced_role}@local"
        if not adapter:
            return models.User(id="00000000-0000-0000-0000-000000000000", email=forced_email, role=forced_role, provider="local", name="Test User")
        user = adapter.get_user_by_email(forced_email)
        if not user:
            user = adapter.upsert_user(
                email=forced_email,
                name="Test User" if forced_role == "admin" else f"Test {forced_role.title()}",
                provider="local",
                role=forced_role,
            )
        if user.role != forced_role:
            user = adapter.set_user_role(user.id, forced_role) or user
        if not user.is_active:
            adapter.set_user_active(user.id, True)
        
        # Ensure test user is in System org for consistent behavior
        system_org_id = adapter.ensure_system_org()
        existing_member = adapter.get_organization_member(system_org_id, user.id)
        if not existing_member:
            # Add test user to System org with appropriate role
            org_role = "org_owner" if forced_role == "admin" else "consultant"
            adapter.create_organization_member(system_org_id, user.id, org_role)
        
        return user
    
    # Try session first, then API key
    user = _get_user_from_session(request, adapter) or _get_user_from_api_key(request, adapter)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_system_admin(
    user: models.User = Depends(get_current_user),
) -> models.User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def ensure_bootstrap_admin(adapter: StorageAdapter) -> str:
    """Ensure local admin exists and return plaintext password for logging."""
    admin_email = "admin@local.domain"
    admin = adapter.get_user_by_email(admin_email)
    if not admin:
        admin = adapter.upsert_user(
            email=admin_email,
            name="admin",
            provider="local",
            role="admin",
        )
    
    # Ensure System organization exists
    system_org = adapter.get_organization_by_slug("system")
    if not system_org:
        system_org = adapter.create_organization(
            name="System",
            slug="system",
            settings="{}"
        )
    
    # Ensure admin is a member of System organization with org_owner role
    membership = adapter.get_organization_member(system_org.id, admin.id)
    if not membership:
        adapter.create_organization_member(
            org_id=system_org.id,
            user_id=admin.id,
            role="org_owner",
            invited_by=None
        )

    secret = adapter.get_bootstrap_secret()
    if not secret:
        from secrets import token_urlsafe

        plaintext = token_urlsafe(16)
        encrypted = encrypt_text(plaintext)
        adapter.set_bootstrap_secret(encrypted)
        if not admin.password_hash:
            adapter.set_user_password_hash(admin.id, hash_password(plaintext))
        return plaintext
    try:
        plaintext = decrypt_text(secret.encrypted_password)
        if not admin.password_hash:
            adapter.set_user_password_hash(admin.id, hash_password(plaintext))
        return plaintext
    except Exception as e:
        # Reset to a new password if decryption fails
        log.exception("Bootstrap secret decryption failed, resetting: %s", e)
        from secrets import token_urlsafe

        plaintext = token_urlsafe(16)
        encrypted = encrypt_text(plaintext)
        adapter.set_bootstrap_secret(encrypted)
        adapter.set_user_password_hash(admin.id, hash_password(plaintext))
        return plaintext


def local_admin_login(username: str, password: str, adapter: StorageAdapter) -> models.User:
    if username.strip().lower() != "admin":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    secret = adapter.get_bootstrap_secret()
    if not secret:
        raise HTTPException(status_code=401, detail="Admin not initialized")
    stored = decrypt_text(secret.encrypted_password)
    if password != stored:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = adapter.get_user_by_email("admin@local.domain")
    if not user:
        user = adapter.upsert_user(email="admin@local.domain", name="admin", provider="local", role="admin")
    return user
