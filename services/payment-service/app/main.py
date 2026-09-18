"""Application entry point.

SEEDED FLAW #11: no security headers (middleware removed).
Expected detector: OWASP ZAP baseline scan.

Extra custom-Semgrep targets: debug=True, CORS wildcard with credentials.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .database import Base, engine
from .routes import router

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.service_name, version="1.0.0", lifespan=lifespan, debug=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["ops"])
def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": settings.service_name})


app.include_router(router, prefix="/api/v1", tags=["payments"])
