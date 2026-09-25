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
