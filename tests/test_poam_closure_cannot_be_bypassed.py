"""Every route into a closed POA&M status passes the ISSM-08/09 gate.

``POAM_CLOSED_STATUSES`` is ``("completed", "closed")`` and every SLA, dashboard
and package consumer treats both as closed. The gate only ever ran for
``"closed"``, so three paths closed a POA&M with no milestone, evidence or
approval check:

* ``PATCH /api/poams/{id} {"status": "completed"}``
* ``POST /api/poams {"status": "completed"}``
* the practice-state reaction (``reactions.on_scoring_status_changed``), which
  set ``completed`` on any open POA&M titled ``"{control} —..."`` -- the title
  shape the assessment paths give a 3PAO's other-than-satisfied finding. So a
  control owner self-marking a practice closed the assessor's finding.

The reaction now *proposes* closure the way control-test recovery does
(``control_tests._resolve_on_recovery``): a dated note and a notification, and
a human closes through the gate.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Notification, Organization, System
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_PRACTICE = "AC.L2-3.1.1"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_system(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        await s.flush()
        return sysm.id


@pytest.mark.asyncio
async def test_patch_to_completed_is_gated() -> None:
    sys_id = await _make_system("ClosureBypassOrg1")
    async with _client() as c:
        pid = (await c.post("/api/poams", json={"system_id": sys_id, "title": "W1"})).json()["id"]

        r = await c.patch(f"/api/poams/{pid}", json={"status": "completed"})
        assert r.status_code == 409, r.text
        assert (await c.get(f"/api/poams/{pid}")).json()["status"] == "open"


@pytest.mark.asyncio
async def test_create_as_completed_is_gated() -> None:
    sys_id = await _make_system("ClosureBypassOrg2")
    async with _client() as c:
        r = await c.post(
            "/api/poams", json={"system_id": sys_id, "title": "W2", "status": "completed"}
        )
        assert r.status_code == 409, r.text
    async with session_scope() as s:
        rows = (await s.execute(select(POAM).where(POAM.system_id == sys_id))).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_satisfying_a_practice_proposes_closure_instead_of_closing() -> None:
    sys_id = await _make_system("ClosureBypassOrg3")
    async with session_scope() as s:
        await seed_scoring_controls(s)
    async with _client() as c:
        created = await c.post(
            "/api/poams",
            json={
                "system_id": sys_id,
                "title": f"{_PRACTICE} — other than satisfied (assessor finding)",
                "source": "assessment",
            },
        )
        pid = created.json()["id"]

        r = await c.put(
            f"/api/scoring/systems/{sys_id}/controls/{_PRACTICE}",
            json={"state": "implemented"},
        )
        assert r.status_code == 200, r.text

        got = (await c.get(f"/api/poams/{pid}")).json()
        assert got["status"] == "open"
        assert "review for closure" in (got["remediation_plan"] or "")

    async with session_scope() as s:
        note = (
            await s.execute(
                select(Notification).where(
                    Notification.entity_type == "poam", Notification.entity_id == str(pid)
                )
            )
        ).scalar_one_or_none()
        assert note is not None


@pytest.mark.asyncio
async def test_an_unsatisfied_state_proposes_nothing() -> None:
    sys_id = await _make_system("ClosureBypassOrg4")
    async with session_scope() as s:
        await seed_scoring_controls(s)
    async with _client() as c:
        pid = (
            await c.post(
                "/api/poams",
                json={"system_id": sys_id, "title": f"{_PRACTICE} — gap"},
            )
        ).json()["id"]

        r = await c.put(
            f"/api/scoring/systems/{sys_id}/controls/{_PRACTICE}",
            json={"state": "not_implemented"},
        )
        assert r.status_code == 200, r.text
        got = (await c.get(f"/api/poams/{pid}")).json()
        assert got["status"] == "open"
        assert "review for closure" not in (got["remediation_plan"] or "")
