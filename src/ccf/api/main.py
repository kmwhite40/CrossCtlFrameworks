"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import RequestResponseEndpoint
from starlette.types import ExceptionHandler

from ..config import enforce_secure_config, get_settings
from ..logging import configure_logging, get_logger
from .audit import audit_middleware
from .auth_deps import auth_gate_middleware
from .metrics import metrics_endpoint, metrics_middleware
from .routes import (
    ai_actions,
    ai_agents,
    ai_settings,
    approvals,
    artifacts,
    assessments,
    assurance,
    audit,
    auth,
    automation,
    catalog,
    conmon,
    connector_settings,
    controls,
    coverage,
    diagrams,
    diff,
    events,
    evidence,
    evidence_repo,
    fedramp20x,
    frameworks,
    grc,
    health,
    identity,
    insights,
    mappings,
    notifications,
    oscal,
    packages,
    packs,
    personnel,
    poams,
    policies,
    portal,
    posture,
    prep,
    queries,
    questionnaires,
    reliability,
    reports,
    risks,
    scans,
    scoring,
    search,
    self_assurance,
    ssp,
    systems,
    tasks,
    ui,
    ui_grc,
    users,
    vendors,
    worksheets,
)

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    log.info("api.startup")
    from ..governance import scheduler  # noqa: PLC0415 — lazy to keep factory import light

    scheduler.start()  # no-op unless CCF_SCHEDULER_ENABLED
    yield
    await scheduler.stop()
    log.info("api.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    # Fail closed on insecure configuration outside dev (IA-01/IA-11).
    for _warning in enforce_secure_config(settings):
        log.warning("config.insecure_default", detail=_warning)
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
    app.add_exception_handler(
        RateLimitExceeded,
        cast(ExceptionHandler, _rate_limit_exceeded_handler),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.middleware("http")(metrics_middleware)
    if settings.audit_enabled and not settings.readonly:
        app.middleware("http")(audit_middleware)
    # Registered last → runs first, so the principal is resolved before audit/routes.
    if settings.auth_enabled:
        app.middleware("http")(auth_gate_middleware)

    if settings.readonly:

        @app.middleware("http")
        async def readonly_guard(request: Request, call_next: RequestResponseEndpoint) -> Response:
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                return JSONResponse(
                    {"detail": "Concord Reader is read-only."},
                    status_code=403,
                )
            return await call_next(request)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    app.add_route("/metrics", metrics_endpoint)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(identity.router)
    app.include_router(assurance.router)
    app.include_router(packages.router)
    app.include_router(packages.delta_router)
    app.include_router(packs.router)
    app.include_router(self_assurance.router)
    app.include_router(portal.router)
    app.include_router(portal.public_router)
    app.include_router(portal.ui_router)
    app.include_router(queries.router)
    app.include_router(queries.ui_router)
    app.include_router(ai_actions.router)
    app.include_router(ai_agents.router)
    app.include_router(ai_settings.router)
    app.include_router(ai_settings.ui_router)
    app.include_router(connector_settings.router)
    app.include_router(controls.router)
    app.include_router(frameworks.router)
    app.include_router(worksheets.router)
    app.include_router(search.router)
    app.include_router(mappings.router)
    app.include_router(coverage.router)
    app.include_router(oscal.router)
    app.include_router(catalog.router)
    app.include_router(diff.router)
    app.include_router(systems.router)
    app.include_router(scoring.router)
    app.include_router(ssp.router)
    app.include_router(assessments.router)
    app.include_router(posture.router)
    app.include_router(audit.router)
    app.include_router(evidence.router)
    app.include_router(evidence_repo.router)
    if settings.prep_enabled:
        # A brand-new feature whose worker makes billable AI calls: register
        # nothing at all when disabled, rather than registering the router and
        # gating inside it, so a disabled deployment gets a plain 404 (route
        # not found, absent from /openapi.json and /docs) instead of a 200
        # that merely confirms the endpoints exist.
        app.include_router(prep.router)
    app.include_router(poams.router)
    app.include_router(risks.router)
    app.include_router(scans.router)
    app.include_router(personnel.router)
    app.include_router(questionnaires.router)
    app.include_router(users.router)
    app.include_router(reports.router)
    # FedRAMP 20x layer (separate from traditional FedRAMP scoring).
    app.include_router(fedramp20x.router)
    app.include_router(reliability.router)
    # Enterprise governance layer.
    app.include_router(automation.router)
    app.include_router(approvals.router)
    app.include_router(conmon.router)
    app.include_router(tasks.router)
    app.include_router(notifications.router)
    app.include_router(events.router)
    app.include_router(policies.router)
    app.include_router(vendors.router)
    app.include_router(artifacts.router)
    app.include_router(diagrams.router)
    app.include_router(insights.router)
    app.include_router(grc.router)
    app.include_router(ui_grc.router)
    app.include_router(ui.router)
    return app


app = create_app()
