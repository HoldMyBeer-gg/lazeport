"""General API rate limiting middleware using a sliding window counter."""
import logging
import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

log = logging.getLogger(__name__)

# Limit applies only to unauthenticated requests. Authenticated users are exempt so normal
# UI usage (clicking links, loading reports/findings) doesn't trigger 429. Login brute force
# is protected by per-identifier lockout in app.services.rate_limit (auth endpoints).
DEFAULT_REQUESTS_PER_MINUTE = 300
WINDOW_SECONDS = 60

_EXEMPT_PREFIXES = (
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/health",
    "/assets/",
    "/bg/",
)


class _SlidingWindow:
    __slots__ = ("timestamps",)

    def __init__(self):
        self.timestamps: list[float] = []

    def hit(self, now: float, window: int) -> int:
        cutoff = now - window
        self.timestamps = [t for t in self.timestamps if t > cutoff]
        self.timestamps.append(now)
        return len(self.timestamps)


class APIRateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter for API endpoints."""

    def __init__(self, app, requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE, enabled: bool = True):
        super().__init__(app)
        self.limit = requests_per_minute
        self.enabled = enabled
        self._buckets: dict[str, _SlidingWindow] = defaultdict(_SlidingWindow)
        self._last_cleanup = time.monotonic()

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _cleanup(self, now: float):
        if now - self._last_cleanup < 120:
            return
        self._last_cleanup = now
        stale = [k for k, v in self._buckets.items() if not v.timestamps or v.timestamps[-1] < now - WINDOW_SECONDS]
        for k in stale:
            del self._buckets[k]

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        path = request.url.path

        if not path.startswith("/api/"):
            return await call_next(request)

        # Authenticated users: no global rate limit (login brute force is handled by auth layer)
        session = request.scope.get("session") or {}
        if session.get("user_id"):
            return await call_next(request)

        for prefix in _EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        now = time.monotonic()
        self._cleanup(now)

        ip = self._client_ip(request)
        count = self._buckets[ip].hit(now, WINDOW_SECONDS)

        if count > self.limit:
            retry_after = WINDOW_SECONDS
            log.warning("Rate limit exceeded for %s (%d/%d rpm)", ip, count, self.limit)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.limit - count))
        return response
