"""Recovery path for ConMon (2026-08-12 recovery-closure design): a control
implementation returning to "healthy" resolves the remediation Task
_upsert_task opened and surfaces (never auto-closes) the POA&M _upsert_poam
opened -- the same shape as tests/test_control_test_recovery.py, keyed on
conmon's own conmon:impl:{impl_id} dedupe_key/source_ref convention.

Unlike control_tests.py, conmon has no persisted "previous health status" on
ControlImplementation -- assess_health recomputes health fresh every scan --
so there is no ordering hazard to guard here; the existence-based dedupe
lookup is sufficient on its own, since a Task/POA&M only exists if a prior
scan actually went at-risk/overdue.

One documented, deliberate interaction: assess_health treats any OPEN
high/critical-severity POA&M as its own at-risk signal, and the POA&M
_upsert_poam opens for an "overdue" control is severity="high" -- so a
control that ever went overdue cannot report "healthy" again until a human
closes that POA&M, even after the original overdue cause is fixed. The Task
still resolves and the POA&M still gets its observation note; assess_health's
crit check simply re-escalates on the next scan. _resolve_on_recovery has no
branching on the original severity, so the at_risk path (severity="moderate",
outside the crit set) is what exercises the full scan()-level transition
below; the overdue interaction is documented, not separately re-tested, since
the resolve function's own behavior does not differ by cause.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import conmon
from ccf.models import (
    POAM,
    Control,
    ControlImplementation,
    Notification,
    Organization,
    System,
    Task,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(session, name: str) -> tuple[int, int]:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sysm = System(organization_id=org.id, name=f"{name} system")
    session.add(sysm)
    await session.flush()
    return org.id, sysm.id


async def _at_risk_impl(session, sys_id: int, identifier: str) -> ControlImplementation:
    """not_implemented with no evidence/assessment-due signal -> at_risk with
    a moderate-severity POA&M (outside assess_health's crit check), so it can
    cleanly reach "healthy" once fixed -- see the module docstring's note on
    the overdue/crit-severity interaction this deliberately avoids.
    """
    ctrl = Control(identifier=identifier, control_name="Test control")
    session.add(ctrl)
    await session.flush()
    impl = ControlImplementation(system_id=sys_id, control_id=ctrl.id, status="not_implemented")
    session.add(impl)
    await session.flush()
    return impl


async def _reload_impl(session, impl_id: int) -> ControlImplementation:
    return (
        await session.execute(
            select(ControlImplementation).where(ControlImplementation.id == impl_id)
        )
    ).scalar_one()


async def test_healthy_transition_resolves_the_task() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery TaskResolve Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-1")
        impl_id = impl.id

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today(), org_id=org_id)
        assert result["findings"] >= 1  # opens the Task/POA&M

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"  # fixes the at_risk trigger without tripping
        # assess_health's separate "no evidence on record" due_soon check,
        # which only fires for impl.status in (implemented, inherited)

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["findings"] == 0
        assert result["by_status"]["healthy"] == 1
        assert result["tasks_resolved"] == 1

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "done"
        assert task.closed_at is not None


async def test_healthy_transition_surfaces_poam_without_closing() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery PoamSurface Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-2")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["poams_recovered"] == 1

    async with session_scope() as s:
        source_ref = f"conmon:impl:{impl_id}"
        poam = (
            await s.execute(select(POAM).where(POAM.source_ref == source_ref))
        ).scalar_one()
        assert poam.status == "open"
        assert poam.remediation_plan is not None
        assert "returned to healthy" in poam.remediation_plan
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"poam-recovery:{poam.id}")
            )
        ).scalars().all()
        assert len(notes) == 1


async def test_still_unhealthy_does_not_resolve() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery StillAtRisk Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-3")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)
    async with session_scope() as s:
        # Nothing fixed -- still at_risk on the second scan.
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["tasks_resolved"] == 0
        assert result["poams_recovered"] == 0

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "open"


async def test_never_unhealthy_is_a_no_op_and_logs_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        conmon.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery NeverUnhealthy Org")
        ctrl = Control(identifier="AC-CONMON-HEALTHY-1", control_name="Test control")
        s.add(ctrl)
        await s.flush()
        # status="partial" (not "implemented"/"inherited") so assess_health's
        # separate "no evidence on record" due_soon check doesn't fire and
        # this fixture is actually healthy from its very first scan.
        impl = ControlImplementation(system_id=sys_id, control_id=ctrl.id, status="partial")
        s.add(impl)
        await s.flush()

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today(), org_id=org_id)
        assert result["findings"] == 0
        assert result["tasks_resolved"] == 0
        assert result["poams_recovered"] == 0
    assert warn_calls == []


async def test_human_edited_task_and_poam_fields_survive_recovery() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery Edited Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-EDIT")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    dedupe = f"conmon:impl:{impl_id}"
    source_ref = f"conmon:impl:{impl_id}"
    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        task.description = "Human note: already investigating, do not touch"
        poam = (await s.execute(select(POAM).where(POAM.source_ref == source_ref))).scalar_one()
        # asymmetric -- auto-created default is "moderate" here. Deliberately
        # NOT "high"/"critical": assess_health's own crit check treats any
        # open high/critical POA&M as its own at-risk signal (the same
        # interaction the overdue path documents), which would prevent this
        # implementation from ever reporting "healthy" again and defeat the
        # very transition this test exercises.
        poam.severity = "low"

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"

    async with session_scope() as s:
        await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)

    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.description == "Human note: already investigating, do not touch"
        assert task.status == "done"
        poam = (await s.execute(select(POAM).where(POAM.source_ref == source_ref))).scalar_one()
        assert poam.severity == "low"
        assert poam.status == "open"
        assert "returned to healthy" in (poam.remediation_plan or "")


async def test_task_a_human_took_up_is_left_alone_on_recovery() -> None:
    """Covers the ``task.status == "open"`` guard directly by actually moving
    a Task's status before recovery -- unlike the fixture above, which only
    edits ``description`` and so would pass unchanged even if the guard were
    deleted (that was Task 1's original, initially-vacuous test gap; see
    ``tests/test_control_test_recovery.py`` for the equivalent fix there).
    A human moving a Task to "in_progress" means they've taken it up; the
    recovery path must not silently mark it "done" out from under them, and
    must not count it in ``tasks_resolved``. The POA&M guard is independent
    and still surfaces normally in the same scan.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery TaskTakenUp Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-TAKEN")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    dedupe = f"conmon:impl:{impl_id}"
    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        task.status = "in_progress"  # a human took it up

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"  # fixes the at_risk trigger

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["by_status"]["healthy"] == 1
        assert result["tasks_resolved"] == 0  # the guard spared it
        assert result["poams_recovered"] == 1  # independent of the Task guard

    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.status == "in_progress"
        assert task.closed_at is None


async def test_only_the_matching_implementation_is_resolved() -> None:
    async with session_scope() as s:
        _org_a, sys_a = await _make_org_system(s, "Conmon Recovery Scope Org A")
        _org_b, sys_b = await _make_org_system(s, "Conmon Recovery Scope Org B")
        impl_a = await _at_risk_impl(s, sys_a, "AC-CONMON-SCOPE-A")
        impl_b = await _at_risk_impl(s, sys_b, "AC-CONMON-SCOPE-B")
        impl_a_id, impl_b_id = impl_a.id, impl_b.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=None)  # global scan, both orgs

    async with session_scope() as s:
        impl_a = await _reload_impl(s, impl_a_id)
        impl_a.status = "partial"  # only org A's implementation is fixed

    async with session_scope() as s:
        await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=None)

    async with session_scope() as s:
        task_a = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_a_id}"))
        ).scalar_one()
        task_b = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_b_id}"))
        ).scalar_one()
        assert task_a.status == "done"
        assert task_b.status == "open"

        poam_a = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"conmon:impl:{impl_a_id}")
            )
        ).scalar_one()
        poam_b = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"conmon:impl:{impl_b_id}")
            )
        ).scalar_one()
        assert "returned to healthy" in (poam_a.remediation_plan or "")
        assert poam_b.remediation_plan is None


async def test_recovery_failure_is_isolated_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        conmon.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    original_notify = conmon.bus.notify

    async def _maybe_raise(*args, **kwargs):
        if str(kwargs.get("dedupe_key", "")).startswith("poam-recovery:"):
            raise RuntimeError("simulated recovery failure")
        return await original_notify(*args, **kwargs)

    monkeypatch.setattr(conmon.bus, "notify", _maybe_raise)

    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery Failure Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-FAIL")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"

    async with session_scope() as s:
        # Must not raise -- scan() must complete for every other implementation.
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["poams_recovered"] == 0  # the forced failure prevented it
        # The Task write happens BEFORE the POA&M half raises, inside the same
        # begin_nested() block -- the savepoint rolls both back together, so
        # the counter must reflect that rollback, not the pre-rollback intent.
        # A dashboard reading "1 task resolved" when the DB still shows it
        # open is worse than reading nothing.
        assert result["tasks_resolved"] == 0

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "open"  # rolled back with the rest of the savepoint
    assert any(event == "conmon.recovery_failed" for event, _ in warn_calls)


async def test_recovery_ignores_a_foreign_poam_with_a_colliding_source_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The POA&M lookup in ``_resolve_on_recovery`` must also filter
    ``POAM.source == "conmon"``, matching ``_upsert_poam``'s own dedupe
    filter exactly. Without it, a same-system, same-``source_ref`` POA&M
    from an unrelated source (e.g. a manually-filed one that happens to
    collide with conmon's ``conmon:impl:{id}`` naming convention) makes the
    lookup return two rows; ``scalar_one_or_none()`` raises
    ``MultipleResultsFound``, the outer ``except Exception`` swallows it as
    a warning, and the whole savepoint -- including the legitimate Task
    resolution that already happened earlier in the same block -- rolls
    back. The result: the real Task never resolves and the real POA&M never
    gets its note, permanently and silently, every scan.
    """
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        conmon.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery Collision Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-COLLIDE")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    source_ref = f"conmon:impl:{impl_id}"
    async with session_scope() as s:
        # A decoy sharing this system + source_ref but a different source --
        # e.g. a manual entry that coincidentally collides with conmon's
        # naming convention.
        decoy = POAM(
            system_id=sys_id,
            title="Manually filed, coincidentally colliding",
            weakness="unrelated manual weakness",
            severity="low",
            status="open",
            source="manual",
            source_ref=source_ref,
        )
        s.add(decoy)
        await s.flush()
        decoy_id = decoy.id

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["tasks_resolved"] == 1
        assert result["poams_recovered"] == 1
    assert warn_calls == []  # a clean match, not a swallowed MultipleResultsFound

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "done"

        real_poam = (
            await s.execute(
                select(POAM).where(POAM.source == "conmon", POAM.source_ref == source_ref)
            )
        ).scalar_one()
        assert "returned to healthy" in (real_poam.remediation_plan or "")

        decoy = (await s.execute(select(POAM).where(POAM.id == decoy_id))).scalar_one()
        assert decoy.remediation_plan is None
        assert decoy.status == "open"


async def test_closed_poam_is_left_alone_on_recovery() -> None:
    """The ``POAM.status.in_(_OPEN_POAM)`` guard on the recovery lookup,
    unexercised until now: deleting that filter entirely still passes every
    other test in this file. A POA&M a human has already closed must not
    gain a "returned to healthy" note (or a recovery notification) when the
    control later recovers -- a closed POA&M mutating in an authorization
    artifact would be a small integrity problem even though it is not a
    status change.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery ClosedPoam Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-CLOSED")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    source_ref = f"conmon:impl:{impl_id}"
    async with session_scope() as s:
        poam = (
            await s.execute(select(POAM).where(POAM.source_ref == source_ref))
        ).scalar_one()
        poam.status = "closed"
        poam.closed_on = date.today()

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "partial"

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["poams_recovered"] == 0  # nothing open left to surface

    async with session_scope() as s:
        poam = (
            await s.execute(select(POAM).where(POAM.source_ref == source_ref))
        ).scalar_one()
        assert poam.status == "closed"
        assert poam.remediation_plan is None
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"poam-recovery:{poam.id}")
            )
        ).scalars().all()
        assert notes == []
