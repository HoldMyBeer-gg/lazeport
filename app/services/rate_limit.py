"""
Rate limiting service for login attempts.

Tracks failed login attempts and enforces configurable rate limits
to protect against brute force attacks.
"""
import json
from datetime import datetime, timedelta
from typing import Optional
from app.db.adapter import StorageAdapter


DEFAULT_MAX_ATTEMPTS = 4
DEFAULT_LOCKOUT_MINUTES = 15


def get_org_rate_limit_settings(adapter: StorageAdapter, org_id: str) -> dict:
    """Get rate limit settings for an organization."""
    org = adapter.get_organization(org_id)
    if not org or not org.settings:
        return {
            "max_attempts": DEFAULT_MAX_ATTEMPTS,
            "lockout_minutes": DEFAULT_LOCKOUT_MINUTES,
        }
    
    try:
        settings = json.loads(org.settings)
        return {
            "max_attempts": settings.get("rate_limit_max_attempts", DEFAULT_MAX_ATTEMPTS),
            "lockout_minutes": settings.get("rate_limit_lockout_minutes", DEFAULT_LOCKOUT_MINUTES),
        }
    except json.JSONDecodeError:
        return {
            "max_attempts": DEFAULT_MAX_ATTEMPTS,
            "lockout_minutes": DEFAULT_LOCKOUT_MINUTES,
        }


def check_rate_limit(adapter: StorageAdapter, identifier: str, org_id: Optional[str] = None) -> tuple[bool, Optional[datetime]]:
    """
    Check if a login attempt is allowed for the given identifier (email or IP).
    
    Returns:
        (is_allowed, locked_until): Tuple of whether login is allowed and when the lockout expires
    """
    # Get rate limit settings
    if org_id:
        settings = get_org_rate_limit_settings(adapter, org_id)
    else:
        # Use system defaults for pre-org-association checks
        settings = {
            "max_attempts": DEFAULT_MAX_ATTEMPTS,
            "lockout_minutes": DEFAULT_LOCKOUT_MINUTES,
        }
    
    max_attempts = settings["max_attempts"]
    lockout_minutes = settings["lockout_minutes"]
    
    # Get recent failed attempts
    cutoff = datetime.utcnow() - timedelta(minutes=lockout_minutes)
    attempts = adapter.get_login_attempts(identifier, since=cutoff)
    
    if len(attempts) >= max_attempts:
        # User is locked out
        oldest_attempt = min(attempts, key=lambda x: x.attempted_at)
        locked_until = oldest_attempt.attempted_at + timedelta(minutes=lockout_minutes)
        return False, locked_until
    
    return True, None


def record_failed_login(adapter: StorageAdapter, identifier: str, ip_address: Optional[str] = None) -> None:
    """Record a failed login attempt."""
    adapter.create_login_attempt(identifier=identifier, ip_address=ip_address, success=False)


def clear_login_attempts(adapter: StorageAdapter, identifier: str) -> None:
    """Clear login attempts for an identifier (called on successful login)."""
    adapter.clear_login_attempts(identifier)
