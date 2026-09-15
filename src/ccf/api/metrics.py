"""Prometheus instrumentation."""

from __future__ import annotations

import time

from fastapi import Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

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
# label per check key grows with content nobody controls. So verdict and
# transition kind (small closed vocabularies) are labelled, ``system_id``
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
WAIVER_SUPPRESSIONS = Counter(
    "ccf_posture_waiver_suppressions_total",
    "Failing results whose alert, task and POA&M an approved waiver suppressed",
)
POSTURE_DETAIL_PRUNED = Counter(
    "ccf_posture_resource_detail_pruned_total",
    "Per-resource posture rows deleted by retention",
)
POSTURE_FAILING_RESOURCES = Gauge(
    "ccf_posture_failing_resources",
    "Resources failing at the most recent scan, per system",
    ["system_id"],
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


async def metrics_endpoint(_request: Request) -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
