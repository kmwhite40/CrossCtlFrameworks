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


async def metrics_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    route = request.scope.get("route")
    route_path = getattr(route, "path", request.url.path) if route else request.url.path
    HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
    HTTP_LATENCY.labels(request.method, route_path).observe(elapsed)
    return response


async def metrics_endpoint(_request: Request) -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
