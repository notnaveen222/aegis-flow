"""Application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import settings
from .database import Base, engine
from .routes import router


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Create tables on startup. Fine for a demo; production uses migrations (Alembic).
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.service_name, version="1.0.0", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Baseline hardening headers. Missing these is seeded flaw #11, caught by ZAP."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health", tags=["ops"])
def health() -> JSONResponse:
    """Liveness probe for docker-compose, Kubernetes, and the CI DAST job."""
    return JSONResponse({"status": "ok", "service": settings.service_name})


app.include_router(router, prefix="/auth", tags=["auth"])
