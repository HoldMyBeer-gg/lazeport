"""Security headers middleware."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Client-side desync mitigation (browser-powered request smuggling): when the server returns
        # 405 Method Not Allowed, the request body may not have been consumed. If the connection
        # is reused, leftover body bytes could be interpreted as the start of the next request.
        # Forcing connection close on 405 prevents reuse so the next request uses a clean connection.
        # See https://portswigger.net/research/browser-powered-desync-attacks
        if getattr(response, "status_code", None) == 405:
            response.headers["Connection"] = "close"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS filter (legacy but still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy
        path = request.url.path

        # Relaxed CSP for OpenAPI documentation pages (they need CDN resources)
        if path in ("/docs", "/redoc", "/openapi.json"):
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",  # ReDoc needs unsafe-eval
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
                "img-src 'self' data: https: blob:",  # Allow all HTTPS images for logos
                "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "worker-src 'self' blob:",  # ReDoc may use web workers
            ]
        else:
            # Standard CSP for application pages (Vue 3 + Vite production build does NOT need unsafe-eval)
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline'",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data: blob:",
                "font-src 'self' data:",
                "connect-src 'self'",
                "frame-ancestors 'none'",  # Equivalent to X-Frame-Options: DENY
                "base-uri 'self'",
                "form-action 'self'",
            ]

            # Only upgrade to HTTPS when already running over HTTPS
            forwarded_proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
            if forwarded_proto == "https":
                csp_directives.append("upgrade-insecure-requests")

        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # Permissions Policy (formerly Feature-Policy)
        # Disable features we don't need
        permissions_directives = [
            "accelerometer=()",
            "ambient-light-sensor=()",
            "autoplay=()",
            "battery=()",
            "camera=()",
            "display-capture=()",
            "document-domain=()",
            "encrypted-media=()",
            "geolocation=()",
            "gyroscope=()",
            "magnetometer=()",
            "microphone=()",
            "midi=()",
            "payment=()",
            "picture-in-picture=()",
            "publickey-credentials-get=()",
            "usb=()",
            "wake-lock=()",
            "xr-spatial-tracking=()",
        ]
        response.headers["Permissions-Policy"] = ", ".join(permissions_directives)

        # Cache control
        if path.startswith("/assets/"):
            # Vite assets use content hashes; safe to cache long, immutable avoids revalidation
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path.startswith("/bg/"):
            # Background images change rarely
            response.headers["Cache-Control"] = "public, max-age=2592000"  # 30 days
        elif "text/html" in response.headers.get("content-type", ""):
            # HTML (index.html, SPA shell): short cache so deploys get picked up promptly
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        elif path.startswith("/api/") and not path.startswith("/api/health"):
            # Don't cache API responses (except public health check)
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # HSTS (only when served over HTTPS)
        # Caddy/reverse proxy sets X-Forwarded-Proto header
        forwarded_proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
        if forwarded_proto == "https":
            # Tell browsers to only connect via HTTPS for 1 year
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        return response
