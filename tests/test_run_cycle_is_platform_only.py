"""Running the automation cycle on demand is a platform operation.

``scheduler.run_cycle`` polls platform sources and runs every tenant's ConMon,
digest and collection jobs. It was gated on ``get_principal`` only, so any
tenant member who may write could drive every other tenant's jobs.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.governance import scheduler

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _as(role: str, org_id: int | None) -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id=None if org_id is None else 7, email="x@t", org_id=org_id, role=role
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.parametrize("role", ["admin", "control_owner", "assessor"])
async def test_a_tenant_member_cannot_run_every_tenants_cycle(
    role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[bool] = []

    async def fake_cycle() -> dict:
        ran.append(True)
        return {}

    monkeypatch.setattr(scheduler, "run_cycle", fake_cycle)
    async with _as(role, 1) as c:
        r = await c.post("/api/automation/run-cycle")
    assert r.status_code == 403 and ran == []


async def test_a_platform_principal_can(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_cycle() -> dict:
        return {"ok": True}

    monkeypatch.setattr(scheduler, "run_cycle", fake_cycle)
    async with _as("admin", None) as c:
        r = await c.post("/api/automation/run-cycle")
    assert r.status_code == 200 and r.json() == {"ok": True}
