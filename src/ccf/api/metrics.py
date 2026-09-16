"""Prometheus instrumentation."""

from __future__ import annotations

import time

from fastapi import HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from ..config import get_settings
from .auth_deps import get_principal

HTTP_REQUESTS = Counter(
    "ccf_http_requests_total",
    "HTTP requests",
    ["method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "ccf_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
INGESTION_RUNS = Counter(
    "ccf_ingestion_runs_total",
    "Ingestion runs by outcome",
    ["status"],
)
CONTROLS_TOTAL = Gauge("ccf_controls_total", "Rows in ccf.controls")
MAPPINGS_TOTAL = Gauge("ccf_framework_mappings_total", "Rows in ccf.framework_mappings")

# --- FedRAMP 20x ------------------------------------------------------------
KSI_VALIDATIONS = Counter(
    "ccf_ksi_validations_total",
    "KSI validation results by status",
    ["status"],
)
KSI_VALIDATION_DURATION = Histogram(
    "ccf_fedramp20x_validation_duration_seconds",
    "Duration of a full validate_system run",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
KSI_DRIFT_EVENTS = Counter(
    "ccf_ksi_drift_events_total",
    "KSI regressions (pass -> warn/fail) detected by continuous monitoring",
)
FEDRAMP20X_READINESS = Gauge(
    "ccf_fedramp20x_readiness_pct",
    "Most recent FedRAMP 20x readiness percentage per system",
    ["system_id"],
)


# --- Posture: drift, suppression, retention ---------------------------------
#
# One constraint shapes every label here: **bound the cardinality.** A label per
# resource would put one Prometheus series per user, storage account or device
# -- ten thousand series from a single check on a mid-sized tenant -- and a
# label per check key grows with content nobody controls. So verdict, transition
# kind and connector (small closed vocabularies -- the connector registry has a
# handful of entries, see ``connectors._REGISTRY``) are labelled, ``system_id``
# follows the precedent FEDRAMP20X_READINESS already set, and nothing else is.
# ``POSTURE_METRICS`` exists so a test can enforce that structurally rather
# than relying on a reviewer to remember it.
POSTURE_CHECK_RESULTS = Counter(
    "ccf_posture_check_results_total",
    "Posture check outcomes recorded by a scan, by verdict",
    ["verdict"],
)
POSTURE_DRIFT_TRANSITIONS = Counter(
    "ccf_posture_drift_transitions_total",
    "Per-resource transitions observed between consecutive scans, by kind",
    ["kind"],
)
#: Despite the ``posture_`` prefix (kept for API stability -- renaming would
#: break any dashboard or alert already scraping it), this counts every
#: waiver-suppressed failure ``record_result`` sees, not only posture-scan
#: ones: the scheduler's ``run_due``, the on-demand
#: ``POST /control-tests/{id}/evaluate`` route, and the manual
#: ``POST /control-tests/{id}/run`` form all funnel through the same writer.
WAIVER_SUPPRESSIONS = Counter(
    "ccf_posture_waiver_suppressions_total",
    "Failing control-test results (posture, conmon, or manual) whose alert, "
    "task and POA&M an approved waiver suppressed",
)
POSTURE_DETAIL_PRUNED = Counter(
    "ccf_posture_resource_detail_pruned_total",
    "Per-resource posture rows deleted by retention",
)
POSTURE_FAILING_RESOURCES = Gauge(
    "ccf_posture_failing_resources",
    "Resources failing at the most recent scan, per system and connector",
    ["system_id", "connector"],
)

#: Every posture metric, so the cardinality rule is enforced by a test.
POSTURE_METRICS = (
    POSTURE_CHECK_RESULTS,
    POSTURE_DRIFT_TRANSITIONS,
    WAIVER_SUPPRESSIONS,
    POSTURE_DETAIL_PRUNED,
    POSTURE_FAILING_RESOURCES,
)


async def metrics_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    # Label with the matched *route template* (e.g. "/api/controls/{identifier}"),
    # never the raw URL path. Unmatched requests (404s, scanners, "/api/../x") all
    # collapse to a single "<unmatched>" series to bound Prometheus cardinality.
    route = request.scope.get("route")
    route_path = getattr(route, "path", None) or "<unmatched>"
    HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
    HTTP_LATENCY.labels(request.method, route_path).observe(elapsed)
    return response


async def metrics_endpoint(request: Request) -> Response:
    """Prometheus scrape endpoint, gated to an operator-level role.

    IMPORTANT 5 (PR #16 review): this deployment's per-tenant gauges --
    ``ccf_posture_failing_resources{system_id=...}`` and the pre-existing
    ``ccf_fedramp20x_readiness_pct{system_id=...}`` -- let any caller who can
    read them infer another tenant's posture and system inventory.
    ``auth_gate_middleware`` alone only requires *a* valid principal (any
    role, any tenant); registering this route with ``app.add_route`` bypasses
    the FastAPI-dependency ``require_role`` every other admin-tier route uses,
    since there is no ``Depends`` here to carry it. This closes that gap
    in-process rather than adding a second, parallel gate.

    A Prometheus scraper is not an interactive user, so this does not assume
    a session cookie. Prometheus's own ``scrape_configs`` support presenting a
    bearer token (``authorization: {credentials_file: ...}`` or
    ``bearer_token``), and ``auth_deps._lookup_principal`` already resolves
    one against ``User.api_token_hash`` -- the same machine-caller path SCIM
    and the external portal use. An operator scrapes this endpoint by minting
    a dedicated service-account ``User`` (``role="admin"``, an API token, no
    interactive session) and pointing the scrape config's bearer token at it;
    nothing here can discover or enforce that deployment's actual scrape
    topology, so a misconfigured scraper fails loudly in Prometheus's own
    target health (403/401) rather than this endpoint silently leaking
    cross-tenant data to any authenticated viewer.

    ``CCF_METRICS_REQUIRE_AUTH=false`` -- the pre-existing escape hatch for a
    deployment that scrapes anonymously and restricts this endpoint at the
    network layer instead (an internal listener, a sidecar) -- is honored
    here exactly as ``auth_gate_middleware``/``is_public_path`` already honor
    it. Without this check this role gate would re-require auth an operator
    deliberately turned off, breaking that scrape the same way a blanket role
    gate would.
    """
    settings = get_settings()
    if settings.auth_enabled and settings.metrics_require_auth:
        principal = await get_principal(request)
        if not (principal.is_global or principal.role == "admin"):
            raise HTTPException(403, "requires role: admin")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
