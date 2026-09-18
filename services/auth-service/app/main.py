"""Application entry point.

SEEDED FLAW #11: no security headers.
Expected detector: OWASP ZAP baseline scan (missing X-Content-Type-Options,
X-Frame-Options, CSP, ...). The middleware that set them has been removed.

Extra targets for custom Semgrep rules (not counted in the 12):
  - `debug=True` on the FastAPI app  -> rule `fastapi-debug-enabled`
    Debug mode returns stack traces and local variables to the client.
  - CORS `allow_origins=["*"]` with credentials -> rule `cors-wildcard-origin`
    Any website can make authenticated requests to this API from a victim's browser.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .database import Base, engine
from .routes import router


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


app.include_router(router, prefix="/auth", tags=["auth"])
