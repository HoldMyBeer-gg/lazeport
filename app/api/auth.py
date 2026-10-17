from __future__ import annotations

import logging
import unicodedata
from datetime import datetime
from fastapi import APIRouter, Depends, Request, Response, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, field_validator

from app.db import get_adapter, models
from app.db.models import SYSTEM_ORG_ID
from app.middleware.csrf import (
    CSRF_COOKIE_NAME,
    generate_csrf_token,
)
from app.db.adapter import StorageAdapter
from app.services.auth import (
    authenticate_user,
    generate_api_key,
    get_current_user,
    get_pending_or_authenticated_user,
    hash_api_key,
    hash_invite_token,
    hash_password,
    local_admin_login,
)
from app.validation import ValidatedString
from app.services.audit import log_auth
from app.services.rate_limit import (
    check_rate_limit,
    record_failed_login,
    clear_login_attempts,
)
from app.services.oidc import (
    get_oidc_auth_url,
    exchange_code_for_userinfo,
    _extract_domain,
)
from app.config import settings
from urllib.parse import urlparse

log = logging.getLogger(__name__)


def _validate_redirect_url(redirect: str | None, base_url: str) -> str | None:
    """
    Validate redirect URL to prevent open redirects.
    Allows: relative paths (/path), same-origin absolute URLs.
    Rejects: external domains, javascript:, data:, //evil.com.
    Returns validated path (e.g. /dashboard) or None if invalid.
    """
    if not redirect or not isinstance(redirect, str):
        return None
    redirect = redirect.strip()
    if not redirect:
        return None
    # Reject dangerous schemes
    lower = redirect.lower()
    if lower.startswith(("javascript:", "data:", "vbscript:")):
        return None
    # Allow relative path (must start with /)
    if redirect.startswith("/") and not redirect.startswith("//"):
        # Basic path validation: no protocol-relative
        return redirect
    # Allow absolute URL only if same origin
    try:
        parsed = urlparse(redirect)
        if parsed.scheme in ("http", "https"):
            base_parsed = urlparse(base_url.rstrip("/"))
            if (
                parsed.netloc == base_parsed.netloc
                and parsed.scheme == base_parsed.scheme
            ):
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                return path
    except ValueError as e:
        log.debug("Invalid redirect URL: %s", e)
    return None
router = APIRouter()


@router.get("/auth/csrf")
def get_csrf_token(request: Request, response: Response):
    """Return CSRF token in body and set HttpOnly cookie. Client reads from body, not cookie."""
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        token = generate_csrf_token()
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            httponly=True,  # XSS cannot steal it; client gets token from response body
            samesite="lax",
            secure=request.url.scheme == "https",
            max_age=86400,
        )
    return {"token": token}


class LocalLoginRequest(BaseModel):
    username: str
    password: str

    @field_validator('username', 'password')
    @classmethod
    def validate_length(cls, v):
        v = str(v).strip()
        if len(v) > 255:
            raise ValueError("Must be 255 characters or less")
        return v


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        # Don't validate email format - accept any string to prevent rate limit bypass
        # Invalid formats will fail authentication and be rate limited properly
        if v is None:
            raise ValueError("email is required")
        v = unicodedata.normalize('NFKC', str(v)).strip().lower()
        if len(v) > 255:
            raise ValueError("Must be 255 characters or less")
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if v is None:
            raise ValueError("password is required")
        v = str(v).strip()
        if len(v) > 255:
            raise ValueError("Must be 255 characters or less")
        return v


class InviteAcceptRequest(BaseModel):
    token: str
    password: str
    name: str | None = None

    @field_validator('token', 'password')
    @classmethod
    def validate_length(cls, v):
        v = str(v).strip()
        if len(v) > 1024:
            raise ValueError("Must be 1024 characters or less")
        return v

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return v
        return ValidatedString.name_validator(v)


@router.post("/auth/login/local")
def login_local(
    request: Request,
    payload: LocalLoginRequest,
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Login with username and password."""
    # Rate limit by IP to prevent brute-force without enabling account DoS attacks
    # Use system-wide defaults to avoid username enumeration via timing/rate limit differences
    ip_address = request.client.host if request.client else "unknown"
    identifier = f"login_ip:{ip_address}"
    
    # Don't look up user before rate limiting to avoid enumeration
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=None)
    
    if not is_allowed:
        seconds_remaining = int((locked_until - datetime.utcnow()).total_seconds())
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Too many failed login attempts. Please try again later.",
                "seconds_remaining": max(0, seconds_remaining)
            }
        )
    
    try:
        user = local_admin_login(payload.username, payload.password, adapter)
        clear_login_attempts(adapter, identifier)
        
        from app.services import twofa
        requires_2fa = twofa.check_2fa_required(user, adapter)
        
        if requires_2fa:
            request.session["pending_2fa_user_id"] = user.id
            return {"requires_2fa": True, "enrolled": user.twofa_enabled}
        else:
            request.session["user_id"] = user.id
            request.session["session_version"] = user.session_version
            request.session["session_created_at"] = datetime.utcnow().isoformat()
            request.session["session_last_activity"] = datetime.utcnow().isoformat()
            org_id = SYSTEM_ORG_ID
            log_auth(adapter, org_id, user.id, "login", request, username=payload.username)
            return {"ok": True, "user": {"email": user.email, "role": user.role, "name": user.name}}
    except HTTPException:
        record_failed_login(adapter, identifier, ip_address)
        raise


@router.post("/auth/login")
def login_user(
    request: Request,
    payload: LoginRequest,
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Login with email and password."""
    email_raw = unicodedata.normalize('NFKC', (payload.email or "")).strip()
    if not email_raw:
        raise HTTPException(status_code=400, detail="email is required")
    # Rate limit by IP to prevent brute-force without enabling account DoS attacks
    # Use system-wide defaults to avoid username enumeration via timing/rate limit differences
    ip_address = request.client.host if request.client else "unknown"
    identifier = f"login_ip:{ip_address}"
    
    # Don't look up user before rate limiting to avoid enumeration
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=None)
    
    if not is_allowed:
        seconds_remaining = int((locked_until - datetime.utcnow()).total_seconds())
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Too many failed login attempts. Please try again later.",
                "seconds_remaining": max(0, seconds_remaining)
            }
        )
    
    try:
        user, requires_2fa = authenticate_user(email_raw.lower(), payload.password, adapter)
        if user.role != "admin":
            orgs = adapter.get_user_organizations(user.id)
            if not orgs:
                raise HTTPException(status_code=403, detail="No organization access")
        
        clear_login_attempts(adapter, identifier)
        
        if requires_2fa:
            request.session["pending_2fa_user_id"] = user.id
            return {"requires_2fa": True, "enrolled": user.twofa_enabled}
        else:
            request.session["user_id"] = user.id
            request.session["session_version"] = user.session_version
            request.session["session_created_at"] = datetime.utcnow().isoformat()
            request.session["session_last_activity"] = datetime.utcnow().isoformat()
            org_id = SYSTEM_ORG_ID
            log_auth(adapter, org_id, user.id, "login", request, username=user.email)
            return {"ok": True, "user": {"email": user.email, "role": user.role, "name": user.name}}
    except HTTPException:
        record_failed_login(adapter, identifier, ip_address)
        raise


@router.post("/auth/logout")
def logout(
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Logout and clear session."""
    # Audit log before clearing session
    org_id = SYSTEM_ORG_ID
    log_auth(adapter, org_id, user.id, "logout", request)

    # Invalidate all existing sessions for this user by incrementing session_version
    adapter.increment_user_session_version(user.id)
    request.session.clear()
    return {"ok": True}


class OidcEmailCheckRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if v is None:
            raise ValueError("email is required")
        v = unicodedata.normalize("NFKC", str(v)).strip().lower()
        if len(v) > 255:
            raise ValueError("Must be 255 characters or less")
        return v


@router.post("/auth/oidc/email-check")
def oidc_email_check(
    payload: OidcEmailCheckRequest,
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Email-first flow: check if domain has OIDC configured.
    Returns org_id, provider_id, provider_label for redirect, or password_only.
    """
    domain = _extract_domain(payload.email)
    if not domain:
        return {"password_only": True}
    org = adapter.get_org_by_domain(domain)
    if not org:
        return {"password_only": True}
    configs = list(adapter.list_org_oidc_configs(org.id))
    if not configs:
        return {"password_only": True}
    cfg = configs[0]
    return {
        "org_id": org.id,
        "provider_id": cfg.provider_id,
        "provider_label": cfg.provider_label or cfg.provider_id,
    }


@router.get("/auth/oidc/login")
async def oidc_login(
    request: Request,
    org_id: str = Query(...),
    provider_id: str = Query(...),
    redirect: str | None = Query(None),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Initiate OIDC flow: redirect to IdP."""
    base_url = settings.public_app_url or str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/auth/oidc/callback"
    try:
        auth_url, state = await get_oidc_auth_url(
            adapter, org_id, provider_id, redirect_uri
        )
    except ValueError as e:
        log.exception("OIDC login failed: %s", e)
        return RedirectResponse(url="/login?error=oidc_failed", status_code=302)
    request.session["oidc_state"] = state
    request.session["oidc_org_id"] = org_id
    request.session["oidc_provider_id"] = provider_id
    # Store post-login redirect if valid
    validated = _validate_redirect_url(redirect, base_url)
    if validated:
        request.session["oidc_redirect"] = validated
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Handle OIDC callback: exchange code, find user, set session."""
    if error:
        log.warning("OIDC callback error: %s", error)
        return RedirectResponse(url="/login?error=oidc_failed", status_code=302)

    if not code or not state:
        return RedirectResponse(url="/login?error=oidc_failed", status_code=302)

    stored_state = request.session.get("oidc_state")
    org_id = request.session.get("oidc_org_id")
    provider_id = request.session.get("oidc_provider_id")

    post_login_redirect = request.session.pop("oidc_redirect", None)
    for key in ("oidc_state", "oidc_org_id", "oidc_provider_id"):
        request.session.pop(key, None)

    if not stored_state or stored_state != state or not org_id or not provider_id:
        log.warning("OIDC callback: invalid or missing state")
        return RedirectResponse(url="/login?error=oidc_failed", status_code=302)

    base_url = settings.public_app_url or str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/auth/oidc/callback"
    callback_url = str(request.url)

    try:
        userinfo = await exchange_code_for_userinfo(
            adapter, org_id, provider_id, redirect_uri, code, state, callback_url
        )
    except Exception as e:
        log.exception("OIDC token exchange failed: %s", e)
        return RedirectResponse(url="/login?error=oidc_failed", status_code=302)

    email = (userinfo.get("email") or userinfo.get("preferred_username") or "").strip().lower()
    if not email:
        log.warning("OIDC userinfo missing email")
        return RedirectResponse(url="/login?error=oidc_failed", status_code=302)

    user = adapter.get_user_by_email(email)
    if not user:
        return RedirectResponse(url="/login?error=no_account", status_code=302)

    orgs = list(adapter.get_user_organizations(user.id))
    if not orgs and user.role != "admin":
        return RedirectResponse(url="/login?error=no_account", status_code=302)

    # Sync profile from IdP (Okta, etc.) so it stays current
    oidc_name = (
        userinfo.get("name")
        or f"{userinfo.get('given_name', '')} {userinfo.get('family_name', '')}".strip()
        or userinfo.get("preferred_username", "")
    )
    if isinstance(oidc_name, str) and oidc_name.strip():
        adapter.set_user_name(user.id, oidc_name.strip())

    oidc_phone = userinfo.get("phone_number") or userinfo.get("phone", "")
    if isinstance(oidc_phone, str) and oidc_phone.strip():
        adapter.update_user_profile(user.id, phone=oidc_phone.strip())

    # Populate contact_email from IdP email when empty (used for reports, etc.)
    if not (user.contact_email or "").strip():
        oidc_email = (userinfo.get("email") or userinfo.get("preferred_username") or "").strip()
        if oidc_email:
            adapter.update_user_profile(user.id, contact_email=oidc_email)

    request.session["user_id"] = user.id
    request.session["session_version"] = user.session_version
    request.session["session_created_at"] = datetime.utcnow().isoformat()
    request.session["session_last_activity"] = datetime.utcnow().isoformat()
    audit_org = orgs[0].id if orgs else SYSTEM_ORG_ID
    log_auth(adapter, audit_org, user.id, "login", request, username=user.email, details={"method": "oidc"})

    # Validate post-login redirect (defense in depth)
    base_url = settings.public_app_url or str(request.base_url).rstrip("/")
    dest = _validate_redirect_url(post_login_redirect, base_url) if post_login_redirect else None
    return RedirectResponse(url=dest or "/dashboard", status_code=302)


@router.get("/api/me")
def me(user=Depends(get_current_user), adapter: StorageAdapter = Depends(get_adapter)):
    """Get current user info including their organization role."""
    response = {
        "email": user.email,
        "role": user.role,  # System-level role (admin, user, etc.)
        "name": user.name,
        "id": user.id,
        "org_role": None,  # Organization-level role
        "org_id": None,
        "twofa_enabled": user.twofa_enabled,
        "twofa_configured_at": user.twofa_configured_at.isoformat() if user.twofa_configured_at else None,
    }
    
    # Get user's organization role if they belong to an org
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
            response["org_id"] = org_id
            
            # Get their role in that organization
            from app.services.rbac import get_user_role_in_org
            org_role = get_user_role_in_org(user.id, org_id, adapter)
            response["org_role"] = org_role
    except Exception as e:
        log.debug("Could not resolve org for /api/me: %s", e)
    
    return response


@router.post("/auth/invite/accept")
def accept_invite(
    payload: InviteAcceptRequest,
    request: Request,
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Accept an organization invite and set a password."""
    # HIGH-15 fix: Add rate limiting to prevent token brute-force
    ip_address = request.client.host if request.client else "unknown"
    identifier = f"invite_accept:{ip_address}"
    
    # Check rate limit (use generic org_id since invite hasn't been validated yet)
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=None)
    
    if not is_allowed:
        seconds_remaining = int((locked_until - datetime.utcnow()).total_seconds())
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Too many invite acceptance attempts. Please try again later.",
                "seconds_remaining": max(0, seconds_remaining)
            }
        )
    
    if not payload.token or len(payload.token.strip()) < 20:
        raise HTTPException(status_code=400, detail="Invalid invite")
    if not payload.password or len(payload.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters")
    token_hash = hash_invite_token(payload.token.strip())
    invite = adapter.get_org_invite_by_hash(token_hash)
    if not invite:
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=400, detail="Invalid invite")
    if invite.used_at:
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=400, detail="Invite already used")
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=400, detail="Invite expired")

    user = None
    if invite.user_id:
        user = adapter.get_user_by_id(invite.user_id)
    if not user:
        user = adapter.get_user_by_email(invite.email)
    if not user:
        user = adapter.upsert_user(email=invite.email, name=payload.name or "", provider="local", role="user")

    if payload.name:
        adapter.set_user_name(user.id, payload.name)
    adapter.set_user_password_hash(user.id, hash_password(payload.password))
    adapter.set_user_active(user.id, True)

    member = adapter.get_organization_member(invite.organization_id, user.id)
    if not member:
        adapter.create_organization_member(
            org_id=invite.organization_id,
            user_id=user.id,
            role=invite.role,
            invited_by=invite.invited_by,
        )
    elif member.role != invite.role:
        adapter.update_organization_member_role(invite.organization_id, user.id, invite.role)
    adapter.mark_org_invite_used(invite.id)
    
    # Clear rate limit attempts on successful acceptance
    clear_login_attempts(adapter, identifier)
    
    return {"status": "accepted"}


class ApiKeyCreateRequest(BaseModel):
    name: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)


@router.get("/api/me/keys")
def list_my_keys(
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List API keys for the current user."""
    keys = adapter.list_api_keys(user.id)
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
        }
        for k in keys
    ]


@router.post("/api/me/keys")
def create_key(
    payload: ApiKeyCreateRequest,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new API key."""
    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    prefix = raw_key[:7]  # lp_ + next 4 chars
    record = adapter.create_api_key(
        user_id=user.id,
        name=payload.name,
        key_hash=key_hash,
        prefix=prefix,
    )
    return {"key": raw_key, "id": record.id, "prefix": prefix}


@router.delete("/api/me/keys/{key_id}")
def delete_key(
    key_id: str,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Revoke an API key."""
    ok = adapter.delete_api_key(user.id, key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


# ===== 2FA Endpoints =====


class TwoFAVerifyRequest(BaseModel):
    code: str = ""
    backup_code: str = ""


class TwoFADisableRequest(BaseModel):
    password: str


class TwoFARegenerateRequest(BaseModel):
    password: str


@router.post("/auth/2fa/enroll")
def enroll_2fa(
    request: Request,
    user: models.User = Depends(get_pending_or_authenticated_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Start 2FA enrollment: generate secret and QR code.
    
    Returns QR code as base64 data URL and the secret for manual entry.
    """
    from app.services import twofa
    
    secret = twofa.generate_secret()
    uri = twofa.get_provisioning_uri(secret, user.email)
    qr_code = twofa.generate_qr_code(uri)
    
    request.session["pending_2fa_secret"] = secret
    
    return {
        "qr_code": qr_code,
        "secret": secret
    }


@router.post("/auth/2fa/verify-enrollment")
def verify_enrollment(
    request: Request,
    payload: TwoFAVerifyRequest,
    user: models.User = Depends(get_pending_or_authenticated_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Verify enrollment code and enable 2FA.
    
    Returns backup codes (shown only once).
    """
    from app.services import twofa
    import json
    
    # MED-3: Add rate limiting to prevent brute-force of 6-digit TOTP codes
    identifier = f"2fa_enroll_{user.id}"
    ip_address = request.client.host if request.client else "unknown"
    org_id = None
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA enroll rate limit: %s", e)
    
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=org_id)
    if not is_allowed:
        minutes_remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many verification attempts. Please try again in {minutes_remaining} minutes."
        )
    
    secret = request.session.get("pending_2fa_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="No enrollment in progress")
    
    if not twofa.verify_token(secret, payload.code):
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=400, detail="Invalid code")
    
    # Clear rate limit on successful verification
    clear_login_attempts(adapter, identifier)
    
    backup_codes = twofa.generate_backup_codes()
    hashed_codes = [twofa.hash_backup_code(code) for code in backup_codes]
    
    encrypted_secret = twofa.encrypt_secret(secret)
    
    adapter.update_user_2fa(
        user.id,
        twofa_secret=encrypted_secret,
        twofa_enabled=True,
        twofa_backup_codes=json.dumps(hashed_codes),
        twofa_configured_at=datetime.utcnow(),
    )
    
    request.session.pop("pending_2fa_secret", None)
    
    # Get user's organization for logging and email
    org_id = SYSTEM_ORG_ID
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA enabled audit: %s", e)
    
    log_auth(adapter, org_id, user.id, "2fa_enabled", request)
    
    # Send email notification
    from app.services.email import send_org_email
    try:
        send_org_email(
            adapter,
            org_id,
            user.email,
            "Two-Factor Authentication Enabled",
            f"Hello {user.name or user.email},\n\n"
            f"Two-factor authentication has been successfully enabled for your account.\n\n"
            f"If you did not make this change, please contact your administrator immediately.\n\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            f"IP: {request.client.host if request.client else 'Unknown'}\n\n"
            f"Best regards,\n"
            f"Lazeport Security Team"
        )
    except Exception as e:
        log.exception("Failed to send 2FA enabled email to %s: %s", user.email, e)
    
    return {
        "success": True,
        "backup_codes": backup_codes
    }


@router.post("/auth/2fa/complete-enrollment")
def complete_enrollment(
    request: Request,
    user: models.User = Depends(get_pending_or_authenticated_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Complete enrollment and force logout (user must login with 2FA).
    """
    org_id = SYSTEM_ORG_ID
    log_auth(adapter, org_id, user.id, "2fa_enrollment_complete", request)
    
    request.session.clear()
    
    return {"success": True}


@router.post("/auth/2fa/verify")
def verify_2fa(
    request: Request,
    payload: TwoFAVerifyRequest,
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Verify 2FA code during login.
    
    Accepts either a TOTP code or a backup code.
    """
    from app.services import twofa
    import json
    
    pending_user_id = request.session.get("pending_2fa_user_id")
    if not pending_user_id:
        raise HTTPException(status_code=400, detail="No login in progress")
    
    user = adapter.get_user_by_id(pending_user_id)
    if not user or not user.twofa_enabled:
        request.session.pop("pending_2fa_user_id", None)
        raise HTTPException(status_code=400, detail="2FA not configured")
    
    # Check rate limit for 2FA verification (by IP to prevent DoS)
    ip_address = request.client.host if request.client else "unknown"
    identifier = f"2fa_verify_ip:{ip_address}"
    org_id = None
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA verify rate limit: %s", e)
    
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=org_id)
    if not is_allowed:
        minutes_remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Please try again in {minutes_remaining} minutes."
        )
    
    # MED-4: Validate inputs before any processing
    if not payload.code and not payload.backup_code:
        raise HTTPException(status_code=400, detail="Code or backup code required")
    
    # MED-5: Handle decryption errors gracefully to avoid information leakage
    try:
        decrypted_secret = twofa.decrypt_secret(user.twofa_secret)
    except Exception as e:
        log.exception("Failed to decrypt 2FA secret for user %s: %s", user.id, e)
        raise HTTPException(status_code=401, detail="Invalid 2FA configuration")
    
    verified = False
    
    if payload.code:
        verified = twofa.verify_token(decrypted_secret, payload.code)
        auth_method = "2fa_code"
    elif payload.backup_code:
        # MED-7: Use row locking to prevent backup code race condition
        from sqlalchemy import text
        with adapter._session() as session:
            # For SQLite, use BEGIN IMMEDIATE for write lock
            if adapter.db_url.startswith("sqlite:"):
                session.exec(text("BEGIN IMMEDIATE"))
            
            # Re-fetch user with lock to ensure atomic read-modify-write
            db_user = session.get(models.User, user.id)
            if not db_user:
                raise HTTPException(status_code=401, detail="User not found")
            
            # Verify backup code with fresh data from locked row
            verified, updated_codes = twofa.verify_backup_code(
                payload.backup_code, db_user.twofa_backup_codes
            )
            if verified:
                db_user.twofa_backup_codes = updated_codes
                session.commit()
            else:
                # Rollback to release lock
                session.rollback()
        auth_method = "2fa_backup"
    
    if not verified:
        # Record failed 2FA attempt
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=401, detail="Invalid code")
    
    # Clear rate limit on successful verification
    clear_login_attempts(adapter, identifier)
    
    request.session.pop("pending_2fa_user_id", None)
    request.session["user_id"] = user.id
    request.session["session_version"] = user.session_version
    request.session["session_created_at"] = datetime.utcnow().isoformat()
    request.session["session_last_activity"] = datetime.utcnow().isoformat()
    request.session["2fa_verified"] = True  # Mark session as 2FA-verified
    
    org_id = SYSTEM_ORG_ID
    log_auth(adapter, org_id, user.id, "login", request, username=user.email, details={"method": auth_method})
    
    return {"success": True, "user": {"email": user.email, "role": user.role, "name": user.name}}


@router.post("/auth/2fa/disable")
def disable_2fa(
    request: Request,
    payload: TwoFADisableRequest,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Disable 2FA (requires password confirmation).
    
    Clears all 2FA data and forces logout.
    """
    from app.services.auth import verify_password
    
    # Check rate limit for sensitive 2FA operations
    identifier = f"2fa_mgmt_{user.id}"
    org_id = None
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA disable rate limit: %s", e)
    
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=org_id)
    if not is_allowed:
        minutes_remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Please try again in {minutes_remaining} minutes."
        )
    
    if not verify_password(payload.password, user.password_hash):
        # Record failed attempt
        ip_address = request.client.host if request.client else None
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Clear rate limit on successful password verification
    clear_login_attempts(adapter, identifier)
    
    # Check session age for sensitive operations (must be logged in within last 15 minutes)
    session_created_str = request.session.get("session_created_at")
    if session_created_str:
        try:
            session_created = datetime.fromisoformat(session_created_str)
            session_age_minutes = (datetime.utcnow() - session_created).total_seconds() / 60
            if session_age_minutes > 15:
                raise HTTPException(
                    status_code=403,
                    detail="Session too old. Please log out and log back in to perform this action."
                )
        except (ValueError, TypeError):
            # If we can't parse the session age, require fresh login
            raise HTTPException(
                status_code=403,
                detail="Invalid session. Please log out and log back in to perform this action."
            )
    else:
        # No session timestamp means old session, require fresh login
        raise HTTPException(
            status_code=403,
            detail="Session age unknown. Please log out and log back in to perform this action."
        )
    
    adapter.disable_user_2fa(user.id)
    
    # Get user's organization for logging and email
    org_id = SYSTEM_ORG_ID
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA disabled audit: %s", e)
    
    log_auth(adapter, org_id, user.id, "2fa_disabled", request)
    
    # Send email notification
    from app.services.email import send_org_email
    try:
        send_org_email(
            adapter,
            org_id,
            user.email,
            "Two-Factor Authentication Disabled",
            f"Hello {user.name or user.email},\n\n"
            f"Two-factor authentication has been disabled for your account.\n\n"
            f"If you did not make this change, please contact your administrator immediately "
            f"and reset your password.\n\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            f"IP: {request.client.host if request.client else 'Unknown'}\n\n"
            f"Best regards,\n"
            f"Lazeport Security Team"
        )
    except Exception as e:
        log.exception("Failed to send 2FA disabled email to %s: %s", user.email, e)
    
    request.session.clear()
    
    return {"success": True}


@router.post("/auth/2fa/regenerate-backup-codes")
def regenerate_backup_codes(
    request: Request,
    payload: TwoFARegenerateRequest,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Regenerate backup codes (requires password confirmation).
    
    Invalidates all existing backup codes.
    """
    from app.services.auth import verify_password
    from app.services import twofa
    import json
    
    # Check rate limit for sensitive 2FA operations
    identifier = f"2fa_mgmt_{user.id}"
    org_id = None
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA regenerate rate limit: %s", e)
    
    is_allowed, locked_until = check_rate_limit(adapter, identifier, org_id=org_id)
    if not is_allowed:
        minutes_remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Please try again in {minutes_remaining} minutes."
        )
    
    if not verify_password(payload.password, user.password_hash):
        # Record failed attempt
        ip_address = request.client.host if request.client else None
        record_failed_login(adapter, identifier, ip_address)
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Clear rate limit on successful password verification
    clear_login_attempts(adapter, identifier)
    
    # Check session age for sensitive operations (must be logged in within last 15 minutes)
    session_created_str = request.session.get("session_created_at")
    if session_created_str:
        try:
            session_created = datetime.fromisoformat(session_created_str)
            session_age_minutes = (datetime.utcnow() - session_created).total_seconds() / 60
            if session_age_minutes > 15:
                raise HTTPException(
                    status_code=403,
                    detail="Session too old. Please log out and log back in to perform this action."
                )
        except (ValueError, TypeError):
            # If we can't parse the session age, require fresh login
            raise HTTPException(
                status_code=403,
                detail="Invalid session. Please log out and log back in to perform this action."
            )
    else:
        # No session timestamp means old session, require fresh login
        raise HTTPException(
            status_code=403,
            detail="Session age unknown. Please log out and log back in to perform this action."
        )
    
    if not user.twofa_enabled:
        raise HTTPException(status_code=400, detail="2FA not enabled")
    
    backup_codes = twofa.generate_backup_codes()
    hashed_codes = [twofa.hash_backup_code(code) for code in backup_codes]
    
    adapter.update_user_2fa(user.id, twofa_backup_codes=json.dumps(hashed_codes))
    
    # Get user's organization for logging and email
    org_id = SYSTEM_ORG_ID
    try:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.debug("Could not resolve org for 2FA backup codes audit: %s", e)
    
    log_auth(adapter, org_id, user.id, "2fa_backup_codes_regenerated", request)
    
    # Send email notification
    from app.services.email import send_org_email
    try:
        send_org_email(
            adapter,
            org_id,
            user.email,
            "Two-Factor Authentication Backup Codes Regenerated",
            f"Hello {user.name or user.email},\n\n"
            f"New backup codes have been generated for your account. "
            f"Your previous backup codes are no longer valid.\n\n"
            f"If you did not make this change, please contact your administrator immediately.\n\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            f"IP: {request.client.host if request.client else 'Unknown'}\n\n"
            f"Best regards,\n"
            f"Lazeport Security Team"
        )
    except Exception as e:
        log.exception("Failed to send backup codes regenerated email to %s: %s", user.email, e)
    
    return {
        "success": True,
        "backup_codes": backup_codes
    }
