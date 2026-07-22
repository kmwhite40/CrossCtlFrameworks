"""Assessment findings auto-generate provenanced, milestone-bearing POA&Ms.

Covers ``POST /api/assessments/{id}/poams-from-findings``: every
Other-Than-Satisfied finding should yield exactly one POA&M carrying
``source='assessment'``, a stable back-reference (``source_ref``) to the
originating ``AssessmentControlResult``, a due date, and a seeded milestone —
and re-running the generation must not create duplicates, even if the POA&M's
title has since been edited (idempotency keys on ``source_ref``, not title).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.ingest.scanners import SEVERITY_SLA_DAYS
from ccf.models import (
    POAM,
    Assessment,
    AssessmentControlResult,
    Organization,
    ScoringStatus,
    System,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _fresh_system(name: str) -> int:
    """Get-or-create a system (the test DB persists across runs)."""
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "PoamProvOrg"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="PoamProvOrg")
            s.add(org)
            await s.flush()
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org.id, System.name == name)
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org.id, name=name)
            s.add(sys)
            await s.flush()
        await s.execute(delete(ScoringStatus).where(ScoringStatus.system_id == sys.id))
        await s.execute(delete(POAM).where(POAM.system_id == sys.id))
        return sys.id


async def _seed_ots_assessment(client: AsyncClient, system_name: str) -> tuple[int, str]:
    """Create an assessment on a fresh system and mark one practice OTS.

    Returns ``(assessment_id, control_id)``.
    """
    await client.post("/api/scoring/seed")
    sid = await _fresh_system(system_name)
    r = await client.post(
        "/api/assessments",
        json={"system_id": sid, "name": "POA&M Provenance Test", "kind": "self"},
    )
    assert r.status_code == 201
    aid = r.json()["id"]
    control_id = "AC.L2-3.1.12"
    upd = await client.put(
        f"/api/assessments/{aid}/controls/{control_id}",
        json={"finding": "other_than_satisfied", "assessor_note": "no session monitoring"},
    )
    assert upd.status_code == 200
    return aid, control_id


@pytest.mark.asyncio
async def test_poam_generation_sets_provenance_and_milestone() -> None:
    async with _client() as c:
        aid, control_id = await _seed_ots_assessment(c, "ProvSysA")

        gen = await c.post(f"/api/assessments/{aid}/poams-from-findings")
        assert gen.status_code == 200
        assert gen.json()["created"] == 1

        async with session_scope() as s:
            result = (
                await s.execute(
                    select(AssessmentControlResult).where(
                        AssessmentControlResult.assessment_id == aid,
                        AssessmentControlResult.control_id == control_id,
                    )
                )
            ).scalar_one()

            poam = (
                await s.execute(
                    select(POAM).where(POAM.source_ref == f"assessment:{result.id}")
                )
            ).scalar_one_or_none()
            assert poam is not None, "POA&M reachable from the finding via source_ref"

            # Provenance.
            assert poam.source == "assessment"
            assert poam.source_ref == f"assessment:{result.id}"
            assert poam.identified_on is not None
            assert poam.due_on == poam.identified_on + timedelta(
                days=SEVERITY_SLA_DAYS.get("moderate", 90)
            )
            assert control_id in poam.title
            assert control_id in (poam.weakness or "")

            # Reachable both ways: the back-reference resolves to the exact
            # finding that raised it.
            assert poam.source_ref.split(":", 1)[1] == str(result.id)

            # Milestone seeded with a scheduled completion.
            await s.refresh(poam, attribute_names=["milestones"])
            assert len(poam.milestones) >= 1
            m = poam.milestones[0]
            assert m.due_on == poam.due_on
            assert m.status == "pending"


@pytest.mark.asyncio
async def test_poam_generation_is_idempotent_on_back_reference_not_title() -> None:
    async with _client() as c:
        aid, _control_id = await _seed_ots_assessment(c, "ProvSysB")

        first = await c.post(f"/api/assessments/{aid}/poams-from-findings")
        assert first.json()["created"] == 1

        # Simulate a human editing the POA&M title after creation — the old
        # implementation matched on title, so this would defeat idempotency.
        async with session_scope() as s:
            a = (await s.execute(select(Assessment).where(Assessment.id == aid))).scalar_one()
            aval = (
                await s.execute(select(POAM).where(POAM.system_id == a.system_id))
            ).scalars().all()
            assert len(aval) == 1
            aval[0].title = "Edited title, does not match anymore"
            await s.commit()

        second = await c.post(f"/api/assessments/{aid}/poams-from-findings")
        assert second.json()["created"] == 0

        third = await c.post(f"/api/assessments/{aid}/poams-from-findings")
        assert third.json()["created"] == 0

        async with session_scope() as s:
            a = (await s.execute(select(Assessment).where(Assessment.id == aid))).scalar_one()
            count = (
                await s.execute(select(POAM).where(POAM.system_id == a.system_id))
            ).scalars().all()
            assert len(count) == 1, "re-running generation must not duplicate the POA&M"
