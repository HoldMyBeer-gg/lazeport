"""
Two-Factor Authentication (2FA) service using TOTP.

Provides functions for:
- TOTP secret generation and verification
- QR code generation for authenticator apps
- Backup code generation, hashing, and verification
- Policy enforcement
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
from typing import Optional

import pyotp
import qrcode

from app.config import get_settings
from app.db import models
from app.db.adapter import StorageAdapter
from app.services.crypto import decrypt_text, encrypt_text


def generate_secret() -> str:
    """Generate a random TOTP secret (base32 encoded)."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, email: str, issuer_name: str = "Laze Report") -> str:
    """
    Generate an otpauth:// URI for authenticator apps.
    
    Args:
        secret: Base32-encoded TOTP secret
        email: User's email address (shown in authenticator app)
        issuer_name: Application name (shown in authenticator app)
    
    Returns:
        otpauth:// URI string
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer_name)


def generate_qr_code(uri: str) -> str:
    """
    Generate QR code image as base64-encoded data URL.
    
    Args:
        uri: otpauth:// URI
    
    Returns:
        Data URL string: "data:image/png;base64,..."
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    img_base64 = base64.b64encode(buffer.read()).decode("utf-8")
    return f"data:image/png;base64,{img_base64}"


def verify_token(secret: str, token: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP token.
    
    Args:
        secret: Base32-encoded TOTP secret
        token: 6-digit code from authenticator app
        valid_window: Number of 30-second windows to check (1 = ±30s)
    
    Returns:
        True if token is valid, False otherwise
    """
    if not token or not secret:
        return False
    
    token = token.strip().replace(" ", "").replace("-", "")
    
    if not token.isdigit() or len(token) != 6:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=valid_window)


def generate_backup_codes(count: int = 10) -> list[str]:
    """
    Generate single-use backup codes.
    
    Format: XXXX-XXXX (8 characters, hyphenated)
    
    Args:
        count: Number of backup codes to generate
    
    Returns:
        List of backup codes
    """
    codes = []
    for _ in range(count):
        code = secrets.token_hex(4).upper()
        formatted = f"{code[:4]}-{code[4:]}"
        codes.append(formatted)
    return codes


def hash_backup_code(code: str) -> str:
    """
    Hash a backup code using PBKDF2-SHA256.
    
    Uses same hashing as passwords for consistency.
    
    Args:
        code: Backup code (e.g., "ABCD-1234")
    
    Returns:
        Hashed code in format: pbkdf2_sha256$iterations$salt$hash
    """
    from app.services.auth import hash_password
    
    normalized = code.strip().upper().replace("-", "")
    return hash_password(normalized)


def verify_backup_code(code: str, hashed_codes_json: str) -> tuple[bool, str]:
    """
    Verify a backup code and return updated codes list (single-use).
    
    Args:
        code: Backup code to verify
        hashed_codes_json: JSON array of hashed backup codes
    
    Returns:
        Tuple of (is_valid, updated_hashed_codes_json)
        - If valid, the code is removed from the list
        - If invalid, the list is unchanged
    """
    from app.services.auth import verify_password
    
    if not code or not hashed_codes_json:
        return False, hashed_codes_json
    
    normalized = code.strip().upper().replace("-", "")
    
    try:
        hashed_codes = json.loads(hashed_codes_json)
    except (json.JSONDecodeError, TypeError):
        return False, hashed_codes_json
    
    if not isinstance(hashed_codes, list):
        return False, hashed_codes_json
    
    # LOW-7: Iterate all codes before returning to avoid timing side channel
    matched_index = -1
    for i, hashed_code in enumerate(hashed_codes):
        if verify_password(normalized, hashed_code):
            matched_index = i
    if matched_index >= 0:
        updated_codes = hashed_codes[:matched_index] + hashed_codes[matched_index + 1:]
        return True, json.dumps(updated_codes)
    return False, hashed_codes_json


def check_2fa_required(user: models.User, adapter: StorageAdapter) -> bool:
    """
    Determine if 2FA is required for a user based on org policy.
    
    Args:
        user: User object
        adapter: Database adapter
    
    Returns:
        True if 2FA is required, False otherwise
    """
    settings = get_settings()
    
    if settings.disable_2fa:
        return False
    
    if user.twofa_enabled:
        return True
    
    orgs = adapter.get_user_organizations(user.id)
    
    for org in orgs:
        if not org:
            continue
        
        try:
            org_settings = json.loads(org.settings) if org.settings else {}
        except (json.JSONDecodeError, TypeError):
            org_settings = {}
        
        policy = org_settings.get("twofa_policy", "disabled")
        
        if policy == "mandatory":
            return True
    
    return False


def encrypt_secret(secret: str) -> str:
    """Encrypt TOTP secret for storage."""
    return encrypt_text(secret)


def decrypt_secret(encrypted_secret: str) -> str:
    """Decrypt TOTP secret from storage."""
    if not encrypted_secret:
        return ""
    return decrypt_text(encrypted_secret)
