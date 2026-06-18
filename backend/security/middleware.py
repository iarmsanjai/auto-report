"""
security/middleware.py
───────────────────────────────────────────────────────────────────────────────
Two responsibilities:
  1. SecurityHeadersMiddleware — injects OWASP-recommended HTTP security headers
     on every response.
  2. RateLimiter — a lightweight in-process per-IP rate limiter using a sliding
     window token-bucket, implemented without external state dependencies.
     Compatible with FastAPI without decorator-based signature conflicts.

Security controls implemented
──────────────────────────────
• Content-Security-Policy    — restricts JS/CSS/font/image origins
• X-Frame-Options            — prevents clickjacking (SAMEORIGIN)
• X-Content-Type-Options     — blocks MIME sniffing
• Strict-Transport-Security  — enforces HTTPS in browsers (2-year max-age)
• Referrer-Policy            — limits referrer leakage
• Permissions-Policy         — disables camera/mic/geolocation by default
• Cache-Control              — prevents sensitive API responses being cached
• Rate Limiting              — per-IP sliding window (login: 10/min, exports: 30/min)
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger(__name__)


# ── Lightweight In-Process Rate Limiter ───────────────────────────────────────

class _SlidingWindowRateLimiter:
    """
    Thread-safe per-IP sliding window rate limiter.
    Stores request timestamps per (IP, route_key) pair.
    """

    def __init__(self) -> None:
        # { (ip, route_key): [timestamp, ...] }
        self._windows: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, ip: str, route_key: str, limit: int, window_seconds: int) -> bool:
        """
        Returns True if the request is within the rate limit, False otherwise.
        Also prunes stale entries to prevent memory growth.
        """
        key = (ip, route_key)
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            # Prune timestamps outside the sliding window
            timestamps = self._windows[key]
            # Remove old entries
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            if len(timestamps) >= limit:
                return False

            timestamps.append(now)
            return True


# Singleton instance shared across the application
_rate_limiter = _SlidingWindowRateLimiter()


def check_rate_limit(ip: str, route_key: str, limit: int = 60, window_seconds: int = 60) -> bool:
    """
    Public helper used by route handlers to enforce per-IP rate limits.
    Returns True if allowed, False if the limit is exceeded.
    """
    return _rate_limiter.is_allowed(ip, route_key, limit, window_seconds)


def get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For if set."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first (leftmost) IP — the original client
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit_response() -> JSONResponse:
    """Standard 429 response body — generic, no internal detail."""
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please wait and try again."},
        headers={"Retry-After": "60"},
    )


# ── Security Headers Middleware ───────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that appends OWASP security headers to every HTTP
    response. Does NOT alter the response body or status code.
    """

    # CSP policy — tight allow-list for a React SPA + FastAPI backend
    _CSP: str = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "          # React build requires inline
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "                  # blob: needed for PDF preview
        "connect-src 'self'; "
        "frame-ancestors 'none'; "                      # stronger than X-Frame-Options
        "base-uri 'self'; "
        "form-action 'self';"
    )

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # ── Security headers ─────────────────────────────────────────────────
        response.headers["Content-Security-Policy"] = self._CSP
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )

        # Prevent API responses from being cached by proxies / browsers
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        # Remove headers that leak server implementation details
        if "Server" in response.headers:
            del response.headers["Server"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]

        return response
