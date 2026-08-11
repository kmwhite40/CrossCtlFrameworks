"""``CCF_PREP_ENABLED`` actually gates the prep surface.

Regression coverage for a review finding on Task 16: ``prep_enabled``
appeared exactly once in ``src/`` (its own definition in ``config.py``) --
``api/main.py`` mounted ``prep.router`` unconditionally and ``cli.py``'s
``prep-worker`` never checked it, while ``README.md`` claimed the pipeline
was "disabled by default". Three REST endpoints and a worker that spends real
money on model calls were live in every deployment behind a kill switch that
did nothing.

This module does not use an autouse fixture for the flag (unlike
``test_prep_api.py``/``test_prep_tenant_isolation.py``, which need it on for
everything else they test) — each test below sets/clears
``CCF_PREP_ENABLED`` explicitly, since the whole point here is comparing the
disabled and enabled states of the same app factory call.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _clear_prep_enabled() -> Iterator[None]:
    """Belt-and-suspenders: guarantee a clean slate before and after every
    test in this module, regardless of what an earlier test set.
    """
    os.environ.pop("CCF_PREP_ENABLED", None)
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_PREP_ENABLED", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def test_prep_endpoints_are_absent_when_disabled() -> None:
    """CCF_PREP_ENABLED unset -- the documented default -- means the prep
    router is never registered at all: a 404 (route not found), not a 200
    that confirms the endpoints exist, and absent from the OpenAPI schema.
    """
    async with _client() as client:
        runs = await client.post(
            "/api/prep/runs",
            json={"organization_id": 1, "source_kind": "policy_version", "source_id": 1},
        )
        run_status = await client.get("/api/prep/runs/999999999")
        retrieve = await client.get(
            "/api/prep/retrieve", params={"organization_id": 1, "control": "AC-2"}
        )
        schema = (await client.get("/openapi.json")).json()

    assert runs.status_code == 404
    assert run_status.status_code == 404
    assert retrieve.status_code == 404
    # Starlette's generic "no matching route" body, not the app's own
    # business-logic 404 (`{"detail": "prep run not found"}`) -- this is what
    # actually distinguishes "the route doesn't exist" from "the route exists
    # and correctly reported not-found", which a bare status-code check
    # cannot: both are 404.
    assert run_status.json() == {"detail": "Not Found"}
    assert not any(path.startswith("/api/prep") for path in schema["paths"]), (
        "a disabled feature must not advertise its endpoints in the OpenAPI schema"
    )


async def test_prep_endpoints_are_present_when_enabled() -> None:
    """CCF_PREP_ENABLED=true -- the router is registered and reachable."""
    os.environ["CCF_PREP_ENABLED"] = "true"
    get_settings.cache_clear()
    async with _client() as client:
        run_status = await client.get("/api/prep/runs/999999999")
        schema = (await client.get("/openapi.json")).json()

    # The app's own business-logic 404 (a real run lookup that found
    # nothing), not Starlette's generic route-not-found body -- proves the
    # handler actually ran, not merely that some 404 came back.
    assert run_status.status_code == 404
    assert run_status.json() == {"detail": "prep run not found"}
    assert any(path.startswith("/api/prep") for path in schema["paths"])
