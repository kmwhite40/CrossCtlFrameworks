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
            fresh = await _check_assurance_graph_freshness(s, organization_ids=[org_id])
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
            stale = await _check_assurance_graph_freshness(s, organization_ids=[org_id])
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
            check = await _check_assurance_graph_freshness(s, organization_ids=[org_id])
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


# ---------------------------------------------------------------------------
# A partial build is a build, and an incomplete one
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_partial_build_warns_and_names_what_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Counting only ``ok`` runs hid a graph that rebuilt every cycle with a part
    missing: PASS on an older clean run, or "Nd old" aged from it."""
    from ccf.assurance import builder  # noqa: PLC0415

    org_id, _ = await _org_with_a_system()
    try:
        async with session_scope() as s:
            await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())
            clean = await _check_assurance_graph_freshness(s, organization_ids=[org_id])
        assert clean.status == PASS, clean.message  # the positive case

        # The clean run is now old; the partial one below is fresh.
        aged = datetime.now(UTC) - _assurance_staleness_limit() - timedelta(hours=1)
        async with session_scope() as s:
            await s.execute(
                text(
                    "UPDATE ccf.assurance_build_runs SET finished_at = :t "
                    "WHERE organization_id = :o AND status = 'ok'"
                ),
                {"t": aged, "o": org_id},
            )

        async def broken(session, org, g):  # type: ignore[no-untyped-def]
            raise RuntimeError("risk register offline")

        monkeypatch.setattr(builder, "_risks", broken)
        async with session_scope() as s:
            result = await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())
            check = await _check_assurance_graph_freshness(s, organization_ids=[org_id])
        assert result["assurance_graph"]["partial"] == [f"risks@{org_id}"]
        assert check.status == WARN, check.message
        assert "incomplete" in check.message and "risks" in check.message
        # It rebuilt this cycle: the partial run is not reported as days old.
        assert "old" not in check.message and "built 0d ago" in check.message
        assert check.remediation
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_clean_cycle_reports_no_partial_graph() -> None:
    org_id, _ = await _org_with_a_system()
    try:
        async with session_scope() as s:
            result = await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())
        assert result["assurance_graph"]["organizations_processed"] == [org_id]
        assert result["assurance_graph"]["partial"] == []
    finally:
        await _cleanup(org_id)


# ---------------------------------------------------------------------------
# Each organization is judged on its own latest build
# ---------------------------------------------------------------------------


async def _build_org(org_id: int, *, broken: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Build one org's graph, with the risks slice failing when ``broken``."""
    from ccf.assurance import builder  # noqa: PLC0415

    async def boom(session, org, g):  # type: ignore[no-untyped-def]
        raise RuntimeError("risk register offline")

    with monkeypatch.context() as m:
        if broken:
            m.setattr(builder, "_risks", boom)
        async with session_scope() as s:
            await _run_per_tenant_cycle(s, [org_id], today=datetime.now(UTC).date())


@pytest.mark.asyncio
async def test_a_partial_build_in_an_earlier_org_is_not_hidden_by_a_later_clean_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check read the single newest run platform-wide, so in a cycle over N
    orgs only the last one built was judged."""
    org_a, _ = await _org_with_a_system()
    org_b, _ = await _org_with_a_system()
    try:
        await _build_org(org_a, broken=True, monkeypatch=monkeypatch)
        await _build_org(org_b, broken=False, monkeypatch=monkeypatch)
        async with session_scope() as s:
            # Org B alone is clean and fresh (the positive counterpart) ...
            only_b = await _check_assurance_graph_freshness(s, organization_ids=[org_b])
            both = await _check_assurance_graph_freshness(s, organization_ids=[org_a, org_b])
        assert only_b.status == PASS, only_b.message
        # ... but org A, built first and partial, is not hidden behind it.
        assert both.status == WARN, both.message
        assert f"org {org_a} (risks)" in both.message
        assert f"org {org_b}" not in both.message
        assert both.remediation
    finally:
        await _cleanup(org_a)
        await _cleanup(org_b)


@pytest.mark.asyncio
async def test_every_org_clean_and_fresh_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    org_a, _ = await _org_with_a_system()
    org_b, _ = await _org_with_a_system()
    try:
        await _build_org(org_a, broken=False, monkeypatch=monkeypatch)
        await _build_org(org_b, broken=False, monkeypatch=monkeypatch)
        async with session_scope() as s:
            check = await _check_assurance_graph_freshness(s, organization_ids=[org_a, org_b])
        assert check.status == PASS, check.message
    finally:
        await _cleanup(org_a)
        await _cleanup(org_b)


@pytest.mark.asyncio
async def test_the_stalest_org_decides_the_age(monkeypatch: pytest.MonkeyPatch) -> None:
    org_a, _ = await _org_with_a_system()
    org_b, _ = await _org_with_a_system()
    try:
        await _build_org(org_a, broken=False, monkeypatch=monkeypatch)
        await _build_org(org_b, broken=False, monkeypatch=monkeypatch)
        aged = datetime.now(UTC) - _assurance_staleness_limit() - timedelta(days=1, hours=1)
        async with session_scope() as s:
            await s.execute(
                text(
                    "UPDATE ccf.assurance_build_runs SET finished_at = :t "
                    "WHERE organization_id = :o"
                ),
                {"t": aged, "o": org_a},
            )
        async with session_scope() as s:
            fresh_b = await _check_assurance_graph_freshness(s, organization_ids=[org_b])
            both = await _check_assurance_graph_freshness(s, organization_ids=[org_a, org_b])
        assert fresh_b.status == PASS, fresh_b.message
        assert both.status == WARN, both.message
        assert "old" in both.message and f"org {org_a}" in both.message
        assert f"org {org_b}" not in both.message
    finally:
        await _cleanup(org_a)
        await _cleanup(org_b)


@pytest.mark.asyncio
async def test_a_deleted_organizations_old_build_is_not_judged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scheduler rebuilds live organizations only, so a deleted one's last
    run would warn forever with nothing able to clear it."""
    live, _ = await _org_with_a_system()
    gone, _ = await _org_with_a_system()
    try:
        await _build_org(live, broken=False, monkeypatch=monkeypatch)
        await _build_org(gone, broken=True, monkeypatch=monkeypatch)
        async with session_scope() as s:
            pinned = await _check_assurance_graph_freshness(s, organization_ids=[live, gone])
            default_before = await _check_assurance_graph_freshness(s)
        # While it exists the partial org is judged (the positive counterpart).
        assert pinned.status == WARN and f"org {gone} (risks)" in pinned.message
        assert f"org {gone} (" in default_before.message
        async with session_scope() as s:
            await s.execute(
                text("UPDATE ccf.organizations SET deleted_at = now() WHERE id = :o"),
                {"o": gone},
            )
        async with session_scope() as s:
            default = await _check_assurance_graph_freshness(s)
            live_only = await _check_assurance_graph_freshness(s, organization_ids=[live])
        assert f"org {gone} (" not in default.message and f"org {gone}," not in default.message
        assert live_only.status == PASS, live_only.message  # the live org is still judged
    finally:
        await _cleanup(live)
        await _cleanup(gone)
