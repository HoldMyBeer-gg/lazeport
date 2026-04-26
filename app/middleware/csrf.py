"""
CSRF protection using the double-submit cookie pattern. Token goes in an HttpOnly cookie
plus response body on GET /auth/csrf; the client sends it back in X-CSRF-Token for POST/PUT/DELETE/PATCH.

APIs are exempt - Swagger, mobile apps, CLIs etc. need to work without it. CSRF is mainly
a browser thing (evil site making your browser send cookies), and the auth layer already
protects the API. For programmatic access, use API keys.
"""
import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi import HTTPException

CSRF_TOKEN_LENGTH = 32
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

# Methods that require CSRF protection
STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Paths exempt from CSRF. APIs are exempt - CSRF is mainly a browser thing. APIs use proper auth (JWT, API keys) instead. CSRF protection is for browser form submissions with session cookies.
EXEMPT_PATHS = {
    "/auth/login",           # Login endpoint needs to work without existing token
    "/auth/logout",          # Logout should work even with stale/missing token
    "/auth/invite/accept",   # Invite acceptance is public (token-based, no prior session)
    "/auth/2fa/",            # 2FA flow (enrollment, verification) for API clients
    "/api/",                 # All API endpoints (used by Swagger UI, mobile apps, CLI tools)
    "/docs",                 # Swagger UI
    "/redoc",                # ReDoc
    "/openapi.json",         # OpenAPI spec
}


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


def is_exempt(path: str) -> bool:
    """Check if a path is exempt from CSRF protection."""
    return any(path.startswith(exempt) for exempt in EXEMPT_PATHS)


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection using Double Submit Cookie. Tokens are cryptographically random, compared in constant time to prevent timing attacks. SameSite=Lax prevents CSRF from external origins. Secure attribute when HTTPS."""
    
    async def dispatch(self, request: Request, call_next):
        # Skip CSRF check for safe methods and exempt paths
        if request.method not in STATE_CHANGING_METHODS or is_exempt(request.url.path):
            return await call_next(request)
        
        # For state-changing methods, validate CSRF token
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        
        if not cookie_token or not header_token:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                f"CSRF token missing for {request.method} {request.url.path} - "
                f"cookie_present={bool(cookie_token)}, header_present={bool(header_token)}"
            )
            raise HTTPException(
                status_code=403,
                detail="CSRF token missing. Please refresh the page and try again."
            )
        
        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(cookie_token, header_token):
            raise HTTPException(
                status_code=403,
                detail="CSRF token mismatch. Please refresh the page and try again."
            )
        
        # Token is valid, proceed with request
        response = await call_next(request)
        return response
