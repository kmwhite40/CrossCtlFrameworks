"""Smoke-test the routes added in 0.2 (no DB rows required)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.etl.validate import HeaderContractError, validate_headers


@pytest.mark.asyncio
async def test_openapi_lists_new_routes() -> None:
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/openapi.json")
        assert r.status_code == 200
        paths = r.json()["paths"]
    for p in (
        "/api/evidence",
        "/api/poams",
        "/api/risks",
        "/api/users",
        "/api/mappings/search",
        "/api/coverage/matrix",
        "/api/oscal/component-definition/{system_id}",
        "/api/diff/workbook",
    ):
        assert p in paths, f"missing {p}"


@pytest.mark.asyncio
async def test_metrics_endpoint_exposes_prom_format() -> None:
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.get("/healthz")
        r = await c.get("/metrics")
    assert r.status_code == 200
    assert b"ccf_http_requests_total" in r.content


def test_header_contract_catches_missing() -> None:
    with pytest.raises(HeaderContractError):
        validate_headers(set())
