"""Smoke test the FastAPI app (in-process)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app


@pytest.mark.asyncio
async def test_healthz_returns_ok() -> None:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_openapi_lists_controls_route() -> None:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/openapi.json")
        assert r.status_code == 200
        paths = r.json()["paths"]
        assert "/api/controls" in paths
        assert "/api/frameworks" in paths
        assert "/api/search" in paths
