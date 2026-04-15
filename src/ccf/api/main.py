"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from ..config import get_settings
from ..logging import configure_logging, get_logger
from .metrics import metrics_endpoint, metrics_middleware
from .routes import (
    controls,
    coverage,
    diff,
    evidence,
    frameworks,
    health,
    mappings,
    oscal,
    poams,
    reports,
    risks,
    search,
    systems,
    ui,
    users,
    worksheets,
)

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    configure_logging()
    log.info("api.startup")
    yield
    log.info("api.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Concord",
        version="0.2.0",
        description=(
            "Concord — compliance controls platform. NIST SP 800-53A Rev 5 "
            "catalog, cross-framework mappings, and compliance operations."
        ),
        lifespan=lifespan,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.middleware("http")(metrics_middleware)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    app.add_route("/metrics", metrics_endpoint)

    app.include_router(health.router)
    app.include_router(controls.router)
    app.include_router(frameworks.router)
    app.include_router(worksheets.router)
    app.include_router(search.router)
    app.include_router(mappings.router)
    app.include_router(coverage.router)
    app.include_router(oscal.router)
    app.include_router(diff.router)
    app.include_router(systems.router)
    app.include_router(evidence.router)
    app.include_router(poams.router)
    app.include_router(risks.router)
    app.include_router(users.router)
    app.include_router(reports.router)
    app.include_router(ui.router)
    return app


app = create_app()
