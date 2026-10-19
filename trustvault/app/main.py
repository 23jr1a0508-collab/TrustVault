from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import database
from .api import router


APP_DIR = Path(__file__).resolve().parent
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    if os.getenv("TRUSTVAULT_ENV", "development").lower() == "production":
        raise RuntimeError("SESSION_SECRET must be set before running TrustVault in production.")
    import secrets

    SESSION_SECRET = secrets.token_urlsafe(48)


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize_database()
    yield


app = FastAPI(
    title="TrustVault API",
    description="Secure document sharing with server-enforced permissions and a tamper-evident audit trail.",
    version="1.0.0",
    docs_url="/trustvault-api/docs",
    openapi_url="/trustvault-api/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="trustvault_session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=os.getenv("TRUSTVAULT_ENV", "development").lower() == "production",
)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")
app.include_router(router)


@app.middleware("http")
async def security_headers_and_denied_audit(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not request.url.path.startswith("/trustvault-api/docs"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
    if response.status_code in {401, 403} and request.url.path != "/trustvault-api/auth/login":
        try:
            from .models import User
            from .security import record_audit

            actor_id = request.session.get("user_id")
            db = database.SessionLocal()
            try:
                if isinstance(actor_id, int) and db.get(User, actor_id) is None:
                    actor_id = None
                record_audit(
                    db,
                    actor_id,
                    "denied_access",
                    request.url.path[:180],
                    {"status_code": response.status_code, "method": request.method},
                )
            finally:
                db.close()
        except Exception:
            # The original authorization response must not be replaced by an
            # audit-storage failure; the server logs the failure for operators.
            import logging

            logging.getLogger("trustvault.security").exception("Unable to persist denied-access audit event")
    return response


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(APP_DIR / "templates" / "index.html")


@app.get("/healthz", include_in_schema=False)
def health():
    return JSONResponse({"status": "ok"})
