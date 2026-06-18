"""
VAPT Report Automation System — FastAPI Backend
-----------------------------------------------
Run:
    uvicorn main:app --reload --port 8000

Docs (DEBUG=True only):
    http://localhost:8000/docs

Security controls applied at app level:
  - SecurityHeadersMiddleware: CSP, X-Frame-Options, HSTS, Referrer-Policy, etc.
  - CORSMiddleware: explicit allow-list for origins, methods, and headers (no wildcards)
  - In-process sliding-window rate limiter applied per-route in handlers
  - API docs disabled in production (DEBUG=False)
"""
import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.ai_routes import router as ai_router
from api.auth_routes import auth_router
from api.deps import require_user
from api.routes import public_router, router
from api.report_routes import router as report_router
from auth.utils import _ensure_users_file
from config.settings import settings
from security.middleware import SecurityHeadersMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)

# Create default users.json on startup if it doesn't exist
_ensure_users_file()

# ── FastAPI app — hide docs in production ────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Production-grade VAPT Report Automation API — import CSV/JSON/HTML, manage findings, export HTML reports.",
    # Disable interactive API docs in production (DEBUG=False)
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# ── Security headers middleware ───────────────────────────────────────────────
# Must be added BEFORE CORS middleware so headers are injected on all responses.
app.add_middleware(SecurityHeadersMiddleware)

# ── CORS: explicit methods & headers — NO wildcards ───────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    # Explicit method list — only what the API actually uses
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    # Explicit header list — only necessary headers
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Accept"],
)

# ── Auth routes (no token required) ──────────────────────────────────────────
app.include_router(auth_router, prefix="/api/auth")

# ── AI routes (JWT required) ─────────────────────────────────────────────────
app.include_router(ai_router, prefix="/api/ai", dependencies=[Depends(require_user)])

# ── Public routes (health check — no token required) ─────────────────────────
app.include_router(public_router, prefix="/api")

# ── Protected routes (JWT required for all endpoints) ────────────────────────
app.include_router(
    router,
    prefix="/api",
    dependencies=[Depends(require_user)],
)
app.include_router(
    report_router,
    prefix="/api",
    dependencies=[Depends(require_user)],
)


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "auth": "JWT Bearer — POST /api/auth/login",
    }
