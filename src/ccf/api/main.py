"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ..config import get_settings
from ..logging import configure_logging, get_logger
from .routes import controls, frameworks, health, reports, search, systems, ui, worksheets

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


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
        version="0.1.0",
        description=(
            "Concord — compliance controls platform. NIST SP 800-53A Rev 5 "
            "catalog, cross-framework mappings, and compliance operations."
        ),
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    app.include_router(health.router)
    app.include_router(controls.router)
    app.include_router(frameworks.router)
    app.include_router(worksheets.router)
    app.include_router(search.router)
    app.include_router(systems.router)
    app.include_router(reports.router)
    app.include_router(ui.router)
    return app


app = create_app()
