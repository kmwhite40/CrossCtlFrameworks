"""A deleted system must not appear in any executive number.

Found against live data: an organization with one live system reported
``systems_total: 3``, and the headline ``worst_system`` was "Nexus" -- deleted
that same day -- carrying an SPRS of -203 that set the organization's average.
Leadership reading that would direct remediation at a system that no longer
exists while the live one went unmentioned, and SPRS scores are reported to DoD.

``api.auth_deps.org_systems_subq`` already excluded deleted systems;
``analytics.posture.org_system_subq`` did not. Two helpers with the same job
and different answers is how it survived, so these drive the analytics helper
directly rather than the API that was already right.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select

from ccf.analytics import overview, posture
from ccf.db import session_scope
from ccf.models import POAM, Organization, Risk, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org_with_live_and_deleted() -> tuple[int, int, int]:
    """An org with one live system and one deleted one, each carrying a POA&M."""
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"Rollup Org {tag}")
        s.add(org)
        await s.flush()

        live = System(organization_id=org.id, name=f"Live {tag}")
        gone = System(
            organization_id=org.id, name=f"Deleted {tag}", deleted_at=datetime.now(UTC)
        )
        s.add_all([live, gone])
        await s.flush()

        s.add_all(
            [
                POAM(system_id=live.id, title="live poam", severity="high", status="open"),
                POAM(system_id=gone.id, title="deleted poam", severity="high", status="open"),
            ]
        )
        await s.flush()
        return org.id, live.id, gone.id


@pytest.mark.asyncio
async def test_the_system_subquery_returns_only_live_systems() -> None:
    org_id, live_id, gone_id = await _org_with_live_and_deleted()
    async with session_scope() as s:
        ids = set((await s.execute(posture.org_system_subq(org_id))).scalars().all())
    assert live_id in ids, "the live system is missing, so this would pass vacuously"
    assert gone_id not in ids


@pytest.mark.asyncio
async def test_the_scorecard_does_not_score_a_deleted_system() -> None:
    """`systems_total` and `worst_system` are both derived from this list."""
    org_id, live_id, gone_id = await _org_with_live_and_deleted()
    async with session_scope() as s:
        cards = await posture.systems_scorecard(s, today=date.today(), org_id=org_id)
    ids = {c["system_id"] for c in cards}
    assert ids == {live_id}, f"expected only the live system, got {ids}"


@pytest.mark.asyncio
async def test_a_deleted_systems_poam_is_not_counted_for_the_organization() -> None:
    org_id, _live_id, gone_id = await _org_with_live_and_deleted()
    async with session_scope() as s:
        scoped = set(
            (
                await s.execute(
                    select(POAM.id).where(POAM.system_id.in_(posture.org_system_subq(org_id)))
                )
            ).scalars().all()
        )
        deleted_poam = (
            await s.execute(select(POAM.id).where(POAM.system_id == gone_id))
        ).scalars().one()
    assert scoped, "no POA&Ms scoped at all, so this would pass vacuously"
    assert deleted_poam not in scoped


@pytest.mark.asyncio
async def test_the_unscoped_view_also_excludes_deleted_systems() -> None:
    """The three overview blocks applied the subquery only when `org_id` was
    set, so a global dashboard counted deleted systems' risks and POA&Ms."""
    _org_id, _live_id, gone_id = await _org_with_live_and_deleted()
    async with session_scope() as s:
        s.add(Risk(system_id=gone_id, title="risk on a deleted system", status="open"))
        await s.flush()

    async with session_scope() as s:
        global_ids = set((await s.execute(posture.org_system_subq(None))).scalars().all())
    assert global_ids, "the global subquery returned nothing, so this proves nothing"
    assert gone_id not in global_ids


@pytest.mark.asyncio
async def test_the_overview_blocks_use_the_live_subquery_unconditionally() -> None:
    """Pins the wiring, not the helper.

    Fixing `org_system_subq` alone left the overview free to keep its
    `if org_id is not None` gate, under which an unscoped call filtered
    nothing -- the helper would be correct and the dashboard still wrong.
    """
    import inspect

    source = inspect.getsource(overview)
    for model in ("Risk", "POAM", "KSIState"):
        gated = f"if org_id is not None:\n        stmt = stmt.where({model}.system_id.in_("
        assert gated not in source, (
            f"the {model} block still applies the live-system filter only when "
            "an organization is given"
        )


# --- an unassessed system has no score ---------------------------------------


async def _org_with_unassessed_system() -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"Unassessed Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Never Assessed {tag}")
        s.add(system)
        await s.flush()
        return org.id, system.id


@pytest.mark.asyncio
async def test_a_system_with_nothing_assessed_carries_no_sprs_score() -> None:
    """SPRS starts at the baseline and subtracts, so an unassessed system lands
    at the floor -- -203 for 800-171, the worst value the scale produces.

    It was rendering on the scorecard as though someone had measured it, while
    the executive summary (correctly) excluded such a system from
    `worst_system`. The two views sat on one page disagreeing: the scorecard
    showed -203 as the worst number present while the headline named a
    different system at -163.
    """
    org_id, system_id = await _org_with_unassessed_system()
    async with session_scope() as s:
        cards = await posture.systems_scorecard(s, today=date.today(), org_id=org_id)

    card = next(c for c in cards if c["system_id"] == system_id)
    assert card["controls_assessed"] == 0
    assert card["assessed"] is False
    assert card["sprs_score"] is None, "the scale's floor was rendered as a measurement"
    assert card["sprs_percentage"] is None


@pytest.mark.asyncio
async def test_an_unassessed_system_is_absent_from_the_headline_numbers() -> None:
    """It must not set the average, nor be named the worst performer."""
    org_id, system_id = await _org_with_unassessed_system()
    async with session_scope() as s:
        summary = await posture.org_summary(s, today=date.today(), org_id=org_id)

    assert summary["systems_total"] == 1, "the system should still be counted as existing"
    assert summary["systems_scored"] == 0
    assert summary["avg_sprs_score"] is None
    assert summary["worst_system"] is None
    assert summary["min_sprs_score"] is None


@pytest.mark.asyncio
async def test_scored_and_the_assessed_flag_cannot_disagree() -> None:
    """Both now read the same predicate, so a system cannot be scored in the
    summary while rendering "not assessed" on the scorecard."""
    org_id, _system_id = await _org_with_unassessed_system()
    async with session_scope() as s:
        cards = await posture.systems_scorecard(s, today=date.today(), org_id=org_id)
        summary = await posture.org_summary(s, today=date.today(), org_id=org_id)

    assert summary["systems_scored"] == len([c for c in cards if c["assessed"]])


@pytest.mark.asyncio
async def test_the_operations_page_renders_with_an_unassessed_system() -> None:
    """Withholding the score broke a template that gauged the percentage.

    `sprs_percentage` became None for a system nothing has been assessed
    against, and `dashboard.html` fed it straight to `max` --
    ``TypeError: '>' not supported between instances of 'int' and 'NoneType'``,
    a 500 on the operations page.

    It was missed because the consumer sweep grepped for ``sprs_score`` and
    this template uses ``sprs_percentage``: one field was guarded and its twin
    was not. And no existing test rendered the page with an unassessed system,
    which is the only state that triggers it -- so the suite stayed green.
    """
    import os

    from httpx import ASGITransport, AsyncClient

    from ccf.api.main import create_app

    org_id, _system_id = await _org_with_unassessed_system()

    from ccf.auth import hash_password, new_api_token
    from ccf.config import get_settings
    from ccf.models import User

    async with session_scope() as s:
        user = User(
            email=f"ops-{uuid.uuid4().hex[:6]}@ops.test",
            organization_id=org_id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        token = user.api_token

    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=create_app()),
            base_url="http://t",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            r = await client.get("/operations")
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()

    assert r.status_code == 200, "an unassessed system 500s the operations page"
    assert "not assessed" in r.text
