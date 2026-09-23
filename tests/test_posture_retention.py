"""Retention: window the per-resource detail, keep the series."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import AuditLog, Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.models_waivers import Waiver
from ccf.posture import retention as retention_module
from ccf.posture.retention import prune_resource_detail
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()


def _f(rid: str, verdict: str = "fail") -> ResourceFinding:
    return ResourceFinding(
        resource_id=rid, resource_type="entra_user", verdict=verdict, observed="observed"
    )


async def _test_on_new_system(session) -> ControlTest:
    org = Organization(name=f"RetOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"RetSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="IA-2",
        name="MFA",
        method="connector",
        check_key=f"ret.check.{next(_SEQ)}",
    )
    session.add(test)
    await session.flush()
    return test


async def _age(session, result_id: int, days: int) -> None:
    """Backdate a result, since run_at has a server default."""
    await session.execute(
        update(ControlTestResult)
        .where(ControlTestResult.id == result_id)
        .values(run_at=datetime.now(UTC) - timedelta(days=days))
    )
    await session.flush()


async def _resource_rows(session, test_id: int) -> list[ControlTestResourceResult]:
    return list(
        (
            await session.execute(
                select(ControlTestResourceResult)
                .join(
                    ControlTestResult,
                    ControlTestResult.id == ControlTestResourceResult.result_id,
                )
                .where(ControlTestResult.control_test_id == test_id)
            )
        )
        .scalars()
        .all()
    )


async def _result_count(session, test_id: int) -> int:
    return (
        await session.execute(
            select(func.count())
            .select_from(ControlTestResult)
            .where(ControlTestResult.control_test_id == test_id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_rows_inside_the_window_survive() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 10)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await prune_resource_detail(session, retain_days=30)
        assert len(await _resource_rows(session, test.id)) == 2


@pytest.mark.asyncio
async def test_rows_outside_the_window_are_deleted() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 400)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        out = await prune_resource_detail(session, retain_days=30)
        rows = await _resource_rows(session, test.id)
        assert len(rows) == 1, "only the recent result's detail remains"
        assert out["deleted"] >= 1


@pytest.mark.asyncio
async def test_the_latest_results_rows_survive_at_any_age() -> None:
    """A check that last ran eighteen months ago must still say which resources
    failed, or "3 of 47" becomes an unexplainable number."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        only = await record_result(
            session, test, status="fail", detail="ancient", evaluated=2, failing=2,
            resources=[_f("a@acme.gov"), _f("b@acme.gov")],
        )
        await _age(session, only.id, 540)
        await prune_resource_detail(session, retain_days=30)
        assert len(await _resource_rows(session, test.id)) == 2


@pytest.mark.asyncio
async def test_a_waived_row_survives_at_any_age() -> None:
    """It records which resource an acceptance covered -- the audit question a
    waiver exists to answer."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        w = Waiver(
            organization_id=test.organization_id,
            system_id=test.system_id,
            check_key=test.check_key,
            rationale="accepted",
            status="approved",
        )
        session.add(w)
        await session.flush()
        old = await record_result(
            session, test, status="fail", detail="waived", evaluated=1, failing=1,
            resources=[_f("accepted@acme.gov")],
        )
        old_id = old.id
        await _age(session, old_id, 500)
        # A newer result, so the waived one is not protected by being latest.
        await record_result(
            session, test, status="fail", detail="newer", evaluated=1, failing=1,
            resources=[_f("accepted@acme.gov")],
        )
        await prune_resource_detail(session, retain_days=30)
        rows = await _resource_rows(session, test.id)
        # Asserted against the AGED result specifically. "some row carries the
        # waiver" was satisfied by the latest result's row, which is protected
        # regardless -- a vacuous assertion mutation testing caught.
        assert old_id in {r.result_id for r in rows}, "the aged accepted row was pruned"
        aged = next(r for r in rows if r.result_id == old_id)
        assert aged.waiver_id == w.id


@pytest.mark.asyncio
async def test_no_control_test_result_is_ever_deleted() -> None:
    """The aggregate series is what an authorization package draws on."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        for i in range(3):
            res = await record_result(
                session, test, status="fail", detail=f"{i}", evaluated=1, failing=1,
                resources=[_f("a@acme.gov")],
            )
            await _age(session, res.id, 500 - i)
        await record_result(
            session, test, status="fail", detail="recent", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        before = await _result_count(session, test.id)
        await prune_resource_detail(session, retain_days=30)
        assert await _result_count(session, test.id) == before == 4


@pytest.mark.asyncio
async def test_the_aggregate_counts_survive_the_prune() -> None:
    """Pruning detail must not touch evaluated/failing/waived on the result."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=47, failing=3,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("b@acme.gov")],
        )
        # Captured before expiring: reading old.id afterwards triggers a lazy
        # refresh and raises MissingGreenlet inside the async session.
        old_id = old.id
        await prune_resource_detail(session, retain_days=30)
        session.expire(old)
        kept = (
            await session.execute(select(ControlTestResult).where(ControlTestResult.id == old_id))
        ).scalar_one()
        assert (kept.evaluated, kept.failing, kept.status) == (47, 3, "fail")


@pytest.mark.asyncio
async def test_dry_run_deletes_nothing_and_reports_the_same_count() -> None:
    """An operator must be able to see the blast radius before committing.

    ``deleted`` is a deployment-wide figure in a shared database, so this does
    not assert it equals this test's own two aged rows -- another test's
    leftover data could inflate it. Instead it scopes to this test's own rows
    for the "nothing/two rows" claims, and lets the deployment-wide dry vs wet
    comparison prove the report is trustworthy regardless of what else is in
    the database.
    """
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov"), _f("b@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        before = len(await _resource_rows(session, test.id))
        assert before == 3
        dry = await prune_resource_detail(session, retain_days=30, dry_run=True)
        assert dry["dry_run"] is True
        assert len(await _resource_rows(session, test.id)) == before, "nothing was deleted"
        wet = await prune_resource_detail(session, retain_days=30)
        assert wet["deleted"] == dry["deleted"], "dry run must predict the real delete exactly"
        after = len(await _resource_rows(session, test.id))
        assert before - after == 2, "this test's own two aged rows were pruned"


@pytest.mark.asyncio
async def test_pruning_twice_is_idempotent() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        first = await prune_resource_detail(session, retain_days=30)
        second = await prune_resource_detail(session, retain_days=30)
        assert first["deleted"] >= 1
        assert second["deleted"] == 0


@pytest.mark.asyncio
async def test_the_retain_days_default_comes_from_settings() -> None:
    """Calling with no window must not mean "delete everything"."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        # Just inside the configured default window.
        await _age(session, old.id, get_settings().posture_resource_retention_days - 5)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        try:
            out = await prune_resource_detail(session)
            assert out["retain_days"] == get_settings().posture_resource_retention_days
            assert len(await _resource_rows(session, test.id)) == 2
        finally:
            # The aged row sits inside the default window but would be
            # prunable under the fixed 30-day window most other tests use --
            # clean it up on every exit path (assertion failure included) so
            # a later test, or a reordered/-k run, never inherits it. 1 day
            # guarantees it is caught regardless of the configured default.
            await prune_resource_detail(session, retain_days=1)


@pytest.mark.asyncio
async def test_a_zero_or_negative_window_is_refused() -> None:
    """retain_days=0 would delete every non-exempt row; that must be an
    explicit act, not a fat-fingered flag."""
    async with session_scope() as session:
        with pytest.raises(ValueError):
            await prune_resource_detail(session, retain_days=0)
        with pytest.raises(ValueError):
            await prune_resource_detail(session, retain_days=-1)


@pytest.mark.asyncio
async def test_the_prune_is_deployment_wide_not_per_tenant() -> None:
    """Stated as a test rather than left implied.

    ``prune_resource_detail`` takes no organization: it is an operator action
    over the whole deployment, and its reported count therefore includes other
    tenants' rows. Anyone adding a per-tenant prune has to change this test,
    which is the point -- a maintenance job whose scope is ambiguous is one
    that eventually deletes the wrong tenant's evidence.
    """
    async with session_scope() as session:
        first = await _test_on_new_system(session)
        second = await _test_on_new_system(session)
        aged_ids = []
        for test in (first, second):
            old = await record_result(
                session, test, status="fail", detail="old", evaluated=1, failing=1,
                resources=[_f("a@acme.gov")],
            )
            aged_ids.append(old.id)
            await _age(session, old.id, 500)
            await record_result(
                session, test, status="fail", detail="new", evaluated=1, failing=1,
                resources=[_f("a@acme.gov")],
            )

        await prune_resource_detail(session, retain_days=30)
        for test, aged in zip((first, second), aged_ids, strict=True):
            remaining = {r.result_id for r in await _resource_rows(session, test.id)}
            assert aged not in remaining, "both organizations' aged detail is pruned"
            assert len(remaining) == 1, "each keeps only its latest result's detail"


# ── audit trail ───────────────────────────────────────────────────────────────


async def _audit_count(session) -> int:
    return int(
        (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    )


@pytest.mark.asyncio
async def test_a_real_prune_writes_an_audit_record() -> None:
    """Deleting assessment detail across every tenant with no persistent,
    queryable record of who/when/how-much is not defensible in an
    authorization package -- so a real prune must write one via
    ``record_event``, never a hand-built ``AuditLog`` row."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        before = await _audit_count(session)
        out = await prune_resource_detail(session, retain_days=30, actor="test-operator")
        after = await _audit_count(session)
        assert after == before + 1, "exactly one audit record for the whole prune"

        row = (
            await session.execute(
                select(AuditLog).where(AuditLog.entity_type == "posture_resource_detail")
                .order_by(AuditLog.id.desc())
                .limit(1)
            )
        ).scalar_one()
        assert row.actor == "test-operator"
        assert row.action == "delete"
        assert row.diff["retain_days"] == 30
        assert row.diff["deleted"] == out["deleted"]
        assert row.diff["cutoff"] == out["cutoff"]
        # A hand-built row would break the tamper-evident chain by carrying no
        # hash at all; record_event must always populate both.
        assert row.row_hash is not None
        assert row.prev_hash is not None
        # The prune takes no org_id and deletes across every organization, so
        # the event belongs to no tenant. NULL is what keeps it readable by all
        # of them under migration 0044's tenant_isolation policy; naming any one
        # org here would both hide a deployment-wide deletion from the rest and
        # claim their detail was pruned on that org's behalf.
        assert row.organization_id is None


@pytest.mark.asyncio
async def test_a_dry_run_writes_no_audit_record() -> None:
    """A dry run deletes nothing, so it has nothing to account for."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        try:
            before = await _audit_count(session)
            await prune_resource_detail(session, retain_days=30, dry_run=True)
            after = await _audit_count(session)
            assert after == before
        finally:
            # Clean up on every exit path so the aged row doesn't leak into
            # the deployment-wide assertions in
            # test_the_prune_is_deployment_wide_not_per_tenant and friends.
            await prune_resource_detail(session, retain_days=30)


# ── batching ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_delete_is_batched_and_still_gets_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The module's own premise is ~3.65M rows/year/check -- one unbatched
    DELETE is a multi-million-row, single transaction on a real deployment.
    Force a tiny batch size and confirm a doomed set spanning several batches
    is still deleted in full, with the reported count matching."""
    monkeypatch.setattr(retention_module, "_BATCH_SIZE", 3)
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=8, failing=8,
            resources=[_f(f"batch{i}@acme.gov") for i in range(8)],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        assert len(await _resource_rows(session, test.id)) == 9
        out = await prune_resource_detail(session, retain_days=30)
        assert out["deleted"] == 8, "all eight aged rows, across >2 batches of 3, were counted"
        rows = await _resource_rows(session, test.id)
        assert len(rows) == 1, "only the latest result's row remains"


# ── the evaluated == 0 exemption ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_zero_finding_result_does_not_displace_the_prior_latest() -> None:
    """A connector outcome with zero findings (a permissions error, an empty
    page) records a result with no resource rows. That must not become
    "latest" for retention's exemption either -- otherwise the last
    *informative* result's detail would become prunable at any age, even
    though it is the only result that can currently say which resources were
    failing. The informative result stays protected regardless of how many
    empty scans have run since."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        old = await record_result(
            session, test, status="fail", detail="informative", evaluated=1, failing=1,
            resources=[_f("a@acme.gov")],
        )
        await _age(session, old.id, 500)
        await record_result(
            session, test, status="fail", detail="empty scan", evaluated=0, failing=0,
            resources=[],
        )
        await prune_resource_detail(session, retain_days=30)
        rows = await _resource_rows(session, test.id)
        assert len(rows) == 1, "the informative result stayed 'latest' and was protected"
        assert rows[0].result_id == old.id
