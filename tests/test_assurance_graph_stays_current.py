"""The assurance graph is rebuilt on the cycle, and its freshness check says so.

Two halves of one gap. The graph — the platform's own view of how systems,
controls, POA&Ms, risks, connectors and evidence hang together — was built only
when somebody ran the CLI or posted the endpoint. Nothing rebuilt it, so it aged
silently while every scan, POA&M and control test moved underneath it.

And the check that should have noticed selected ``finished_at`` and then ignored
it: any graph built successfully once reported PASS forever, under the name
``assurance_graph_freshness``. On the live tenant it had been three days stale
and reporting healthy. A check that asserts a property it does not verify is the
defect this codebase keeps finding in its own output.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import scheduler as scheduler_mod
from ccf.governance.scheduler import _run_per_tenant_cycle
from ccf.models import Organization, System
from ccf.models_assurance import AssuranceNode
from ccf.reliability.checks import (
    PASS,
    WARN,
    _assurance_staleness_limit,
    _check_assurance_graph_freshness,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


async def _org_with_a_system() -> tuple[int, int]:
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"Assurance Cycle Org {tag}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"Assurance Sys {tag}", baseline="moderate")
        s.add(sys_)
        await s.flush()
        return org.id, sys_.id


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


# ---------------------------------------------------------------------------
# The cycle rebuilds it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_per_tenant_cycle_rebuilds_the_graph() -> None:
    org_id, _system_id = await _org_with_a_system()
    try:
        async with session_scope() as s:
            before = (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars().all()
            assert before == [], "the graph already had nodes before any cycle ran"

            result = await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())

        assert "assurance_graph" in result, (
            "the cycle does not report the assurance-graph step"
        )
        assert result["assurance_graph"]["organizations_processed"] == [org_id]
        assert result["assurance_graph"]["nodes"] > 0

        async with session_scope() as s:
            after = (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars().all()
        assert after, "the cycle ran but wrote no assurance nodes"
        assert any(n.entity_type == "system" for n in after), (
            "the system the org owns is not in its own graph"
        )
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_one_tenants_rebuild_does_not_carry_another_tenants_records() -> None:
    mine, _ = await _org_with_a_system()
    theirs, _ = await _org_with_a_system()
    try:
        async with session_scope() as s:
            await _run_per_tenant_cycle(s, [mine], today=datetime.now(UTC).date())
        async with session_scope() as s:
            nodes = (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == theirs)
                )
            ).scalars().all()
        assert nodes == [], "rebuilding one organization populated another's graph"
    finally:
        await _cleanup(mine)
        await _cleanup(theirs)


@pytest.mark.asyncio
async def test_a_failing_rebuild_does_not_abort_the_rest_of_the_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each step is savepointed; the graph must obey the same rule.

    Without the savepoint an exception here would poison the session and take
    every later organization's work with it.
    """
    org_id, _ = await _org_with_a_system()
    try:
        async def _boom(session, org):
            raise RuntimeError("graph build exploded")

        monkeypatch.setattr(scheduler_mod.assurance_builder, "rebuild_org", _boom)
        async with session_scope() as s:
            result = await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())
        # The cycle completed and reported the other steps.
        assert result["assurance_graph"]["organizations_processed"] == []
        assert "conmon" in result
    finally:
        await _cleanup(org_id)


# ---------------------------------------------------------------------------
# The check actually checks freshness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_stale_graph_is_reported_stale() -> None:
    """The defect: any successful build reported PASS forever."""
    org_id, _ = await _org_with_a_system()
    try:
        async with session_scope() as s:
            await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())
            fresh = await _check_assurance_graph_freshness(s)
        assert fresh.status == PASS, fresh.message

        limit = _assurance_staleness_limit()
        aged = datetime.now(UTC) - limit - timedelta(hours=1)
        async with session_scope() as s:
            await s.execute(
                text(
                    "UPDATE ccf.assurance_build_runs SET finished_at = :t "
                    "WHERE status = 'ok'"
                ),
                {"t": aged},
            )
        async with session_scope() as s:
            stale = await _check_assurance_graph_freshness(s)
        assert stale.status == WARN, stale.message
        assert "old" in stale.message
        assert stale.remediation, "a warning with no remedy is not actionable"
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_build_with_no_finish_time_is_not_treated_as_fresh() -> None:
    """An age that cannot be established is not a young age."""
    org_id, _ = await _org_with_a_system()
    try:
        async with session_scope() as s:
            await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())
        async with session_scope() as s:
            await s.execute(
                text("UPDATE ccf.assurance_build_runs SET finished_at = NULL WHERE status = 'ok'")
            )
        async with session_scope() as s:
            check = await _check_assurance_graph_freshness(s)
        assert check.status == WARN
        assert "no finish time" in check.message
    finally:
        await _cleanup(org_id)


def test_the_staleness_limit_follows_the_configured_cadence() -> None:
    """A fixed constant would go stale the moment an operator changed the
    interval — which is the failure this whole check was an instance of."""
    settings = get_settings()
    expected = timedelta(hours=max(1.0, settings.scheduler_interval_hours) * 2)
    assert _assurance_staleness_limit() == expected
