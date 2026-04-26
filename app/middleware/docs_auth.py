"""Require authentication for /docs, /redoc, and /openapi.json when auth is enabled."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response


DOCS_PATHS = ("/docs", "/redoc", "/openapi.json", "/api/spec")


class DocsAuthMiddleware(BaseHTTPMiddleware):
    """When auth is enabled, require a valid session for docs and OpenAPI spec."""

    async def dispatch(self, request: Request, call_next) -> Response:
        from app.services.auth import is_auth_enabled

        if not is_auth_enabled():
            return await call_next(request)

        path = request.url.path
        if path not in DOCS_PATHS:
            return await call_next(request)

        session = request.scope.get("session") if "session" in request.scope else {}
        user_id = (session or {}).get("user_id")
        if user_id:
            return await call_next(request)

        if path in ("/openapi.json", "/api/spec"):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
            )
        return RedirectResponse(url="/login", status_code=302)
