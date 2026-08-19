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
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import RequestResponseEndpoint
from starlette.types import ExceptionHandler

from ..config import enforce_secure_config, get_settings, is_dev_env
from ..logging import configure_logging, get_logger
from .audit import audit_middleware
from .auth_deps import auth_gate_middleware
from .csrf import CsrfOriginMiddleware
from .limiter import limiter
from .metrics import metrics_endpoint, metrics_middleware
from .routes import (
    ai_actions,
    ai_agents,
    ai_settings,
    approvals,
    artifacts,
    assessment_engine,
    assessments,
    assurance,
    audit,
    auth,
    automation,
    boundary,
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
    ui_boundary,
    ui_grc,
    users,
    vendors,
    worksheets,
)
from .security_headers import SecurityHeadersMiddleware

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


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
    # ---- Middleware stack -------------------------------------------------
    # Starlette inserts each registration at position 0 and then builds the app
    # with ``reversed(user_middleware)``, so THE LAST ONE ADDED IS OUTERMOST.
    # The block below is therefore written innermost-first, and the intended
    # runtime order (outermost -> innermost) is:
    #
    #   CORS -> SecurityHeaders -> readonly_guard -> metrics -> Csrf
    #        -> auth_gate -> audit -> router
    #
    # Each position is load-bearing:
    #   CORS outermost      - a browser preflight (OPTIONS) carries neither
    #                         cookie nor Authorization by spec. Below the auth
    #                         gate it was answered 401 with no Access-Control-*
    #                         headers, so every preflighted cross-origin request
    #                         failed whenever auth was enabled.
    #   SecurityHeaders next- every guard below it can short-circuit. Beneath
    #                         them, auth-gate 401s, /login redirects and the
    #                         readonly 403 all shipped with no CSP or HSTS.
    #   metrics above auth  - so ccf_http_requests_total counts rejections; you
    #                         cannot alert on an auth-failure spike otherwise.
    #   Csrf above auth     - reject a forged origin before doing auth work.
    #   auth_gate above audit - auth_gate sets request.state.principal, which
    #                         the audit middleware reads.
    #
    # tests/test_middleware_order.py pins this. Change the order there too.
    if settings.audit_enabled and not settings.readonly:
        app.middleware("http")(audit_middleware)
    if settings.auth_enabled:
        app.middleware("http")(auth_gate_middleware)
    if settings.csrf_protection:
        # Defense in depth beneath the session cookie's SameSite=Lax. Trusts the
        # served host implicitly, plus any explicitly configured origin (the
        # CORS allow-list is included so a separately-hosted front end that is
        # already permitted to call the API is not blocked here).
        app.add_middleware(
            CsrfOriginMiddleware,
            trusted_origins=(*settings.csrf_trusted_origins, *settings.api_cors_origins),
        )
    app.middleware("http")(metrics_middleware)

    if settings.readonly:

        @app.middleware("http")
        async def readonly_guard(request: Request, call_next: RequestResponseEndpoint) -> Response:
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                return JSONResponse(
                    {"detail": "Concord Reader is read-only."},
                    status_code=403,
                )
            return await call_next(request)

    app.add_middleware(SecurityHeadersMiddleware, hsts=not is_dev_env(settings))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
    app.include_router(boundary.router)
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
    if settings.assessment_engine_enabled:
        # Same reasoning as prep.router above: register nothing at all when
        # disabled (plain 404, absent from /openapi.json), not a 200 that
        # merely confirms the endpoints exist.
        app.include_router(assessment_engine.router)
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
    app.include_router(ui_boundary.router)
    app.include_router(ui.router)
    return app


app = create_app()
