"""Tests for app.middleware.rate_limit (APIRateLimitMiddleware)."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.rate_limit import APIRateLimitMiddleware


def _make_app(requests_per_minute: int = 5) -> FastAPI:
    """Create a minimal app with rate limit middleware for testing."""
    app = FastAPI()

    @app.get("/api/test")
    def api_test():
        return {"ok": True}

    @app.get("/api/health")
    def api_health():
        return {"status": "ok"}

    @app.get("/other")
    def other():
        return {"path": "other"}

    app.add_middleware(APIRateLimitMiddleware, requests_per_minute=requests_per_minute)
    return app


class _SessionInjectorMiddleware(BaseHTTPMiddleware):
    """In tests, inject scope['session'] so rate limit sees authenticated user."""

    async def dispatch(self, request: Request, call_next):
        request.scope["session"] = {"user_id": "test-user-id"}
        return await call_next(request)


def test_rate_limit_allows_normal_traffic():
    """Normal traffic under limit is allowed."""
    app = _make_app(requests_per_minute=10)
    client = TestClient(app)
    for _ in range(5):
        r = client.get("/api/test")
        assert r.status_code == 200
        assert r.json() == {"ok": True}


def test_rate_limit_blocks_excessive_traffic():
    """Excessive requests return 429."""
    app = _make_app(requests_per_minute=3)
    client = TestClient(app)
    for _ in range(3):
        r = client.get("/api/test")
        assert r.status_code == 200
    r = client.get("/api/test")
    assert r.status_code == 429
    assert "detail" in r.json()
    assert "Too many" in r.json()["detail"] or "requests" in r.json()["detail"].lower()


def test_rate_limit_exempt_paths_not_limited():
    """Exempt paths (/api/health, etc.) are not rate limited."""
    app = _make_app(requests_per_minute=2)
    client = TestClient(app)
    for _ in range(3):
        client.get("/api/test")
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_rate_limit_returns_retry_after_header():
    """429 response includes Retry-After header."""
    app = _make_app(requests_per_minute=2)
    client = TestClient(app)
    for _ in range(3):
        client.get("/api/test")
    r = client.get("/api/test")
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    retry_after = int(r.headers["Retry-After"])
    assert retry_after >= 0


def test_authenticated_users_exempt_from_rate_limit():
    """When scope['session'] has user_id, requests are not rate limited (normal UI use)."""
    app = FastAPI()

    @app.get("/api/test")
    def api_test():
        return {"ok": True}

    # Session injector runs first (innermost), then rate limit sees session and exempts.
    app.add_middleware(APIRateLimitMiddleware, requests_per_minute=2)
    app.add_middleware(_SessionInjectorMiddleware)
    client = TestClient(app)
    # Would hit 429 after 2 requests without session; with session all succeed.
    for _ in range(8):
        r = client.get("/api/test")
        assert r.status_code == 200, "Authenticated user must not be rate limited"
        assert r.json() == {"ok": True}
