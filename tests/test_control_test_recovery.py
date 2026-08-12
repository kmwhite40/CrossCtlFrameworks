"""Recovery path for control tests (2026-08-12 recovery-closure design):
fail/warn -> pass resolves the remediation Task _alert_on_failure opened and
surfaces (never auto-closes) the POA&M it opened.

A Task is an internal work item with a free status vocabulary and no formal
gate -- auto-resolving one when its triggering condition clears is
uncontroversial. A POA&M has the ISSM-08/09 closure gate
(api/routes/poams.py:216): all milestones complete, or dated closure
evidence, plus a separation-of-duties Approval when auth is enabled --
because closing a POA&M is an assertion, in an authorization package, that a
weakness is remediated. A single passing control test is not that assertion,
so the POA&M instead gains a dated, result-id-stamped observation note (the
same append pattern ingest/scanners.py:410-412 already uses for its own
closure note) and a notification -- surfaced for a human to close through the
gate, never closed here. This is deliberately asymmetric with
ingest/scanners.py:397's scan-absence auto-close: a vulnerability missing
from a scan is direct evidence the weakness is gone; a control test passing
once is weaker evidence that may cover only part of what the POA&M describes.

Both halves act only on the Task/POA&M this machinery itself created,
identified by the exact dedupe_key/source_ref _alert_on_failure/_upsert_poam
use, and only while untouched (Task.status == "open"; POA&M still in
_OPEN_POAM) -- a human's edit to any other field must survive, proven by
changing a field and asserting the change survives, not by a count alone.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import control_tests
from ccf.models import POAM, Notification, Organization, System, Task
from ccf.models_grc import ConnectorConfig, ControlTest, ControlTestResult

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


async def _make_test(session, org_id: int, sys_id: int, control_id: str) -> ControlTest:
    test = ControlTest(
        organization_id=org_id,
        system_id=sys_id,
        control_id=control_id,
        name=f"Recovery test {control_id}",
        method="manual",
    )
    session.add(test)
    await session.flush()
    return test


async def _reload_test(session, test_id: int) -> ControlTest:
    return (
        await session.execute(select(ControlTest).where(ControlTest.id == test_id))
    ).scalar_one()


async def test_fail_then_pass_resolves_the_task() -> None:
    """The ordering-hazard guard: record_result must capture test.last_status
    into previous_status BEFORE reassigning it (control_tests.py:289), or this
    fails -- if the capture reads the just-reassigned value instead, the
    transition condition (previous_status in ("fail","warn") and
    status == "pass") can never be true and the Task never resolves.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery TaskResolve Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-1")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="pass", detail="fixed"
        )

    async with session_scope() as s:
        dedupe = f"ctltest-fix:{test_id}"
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.status == "done", "the Task must resolve when the test recovers to pass"
        assert task.closed_at is not None


async def test_recovery_surfaces_the_poam_without_closing_it() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery PoamSurface Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-2")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        res = await control_tests.record_result(s, test, status="pass", detail="fixed")
        result_id = res.id

    async with session_scope() as s:
        source_ref = f"control_test:{test_id}"
        # Scoped by system_id too, matching _upsert_poam/_resolve_on_recovery's own
        # lookup -- source_ref alone ("control_test:{N}") isn't a safe unique key
        # across the whole suite; see test_only_the_matching_test_is_resolved.
        poam = (
            await s.execute(
                select(POAM).where(POAM.system_id == sys_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        assert poam.status == "open", "recovery must never close the POA&M"
        assert poam.remediation_plan is not None
        assert f"result #{result_id}" in poam.remediation_plan
        assert "now passes" in poam.remediation_plan
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"poam-recovery:{poam.id}")
            )
        ).scalars().all()
        assert len(notes) == 1, "the POA&M must be surfaced via the same notify() mechanism " \
            "_alert_on_failure/conmon.scan already use for 'needs a human's attention'"


@pytest.mark.parametrize("status", ["fail", "warn"])
async def test_no_transition_when_status_repeats(
    status: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fail->fail and warn->warn must never resolve the Task, and must log
    nothing at warning -- a clean skip must be distinguishable from a
    swallowed exception.
    """
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        control_tests.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, f"Recovery NoOp {status} Org")
        test = await _make_test(s, org_id, sys_id, f"AC-NOOP-{status.upper()}")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status=status, detail="first"
        )
    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status=status, detail="second"
        )

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one_or_none()
        if status == "fail":
            # _alert_on_failure only opens a Task for "fail" (not "warn") -- pre-existing
            # behaviour, unrelated to recovery. It must still be untouched: open, not "done".
            assert task is not None
            assert task.status == "open"  # the test never reached "pass" -- no recovery to fire
        else:
            assert task is None  # "warn" never opened a Task in the first place
    assert warn_calls == []


async def test_pass_to_pass_is_a_no_op_and_logs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        control_tests.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery PassPass Org")
        test = await _make_test(s, org_id, sys_id, "AC-PASSPASS-1")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="pass", detail="already fine"
        )
    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="pass", detail="still fine"
        )

    async with session_scope() as s:
        # No Task/POA&M was ever opened -- there was nothing to resolve.
        assert (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one_or_none() is None
    assert warn_calls == []


async def test_human_edited_task_and_poam_fields_survive_recovery() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery Edited Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-EDIT")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    dedupe = f"ctltest-fix:{test_id}"
    source_ref = f"control_test:{test_id}"
    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        task.description = "Human note: already investigating, do not touch"
        # Scoped by system_id too -- source_ref alone isn't a safe unique key across
        # the whole suite; see test_only_the_matching_test_is_resolved.
        poam = (
            await s.execute(
                select(POAM).where(POAM.system_id == sys_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        poam.severity = "critical"  # asymmetric -- auto-created default is "high"

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="pass", detail="fixed"
        )

    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.description == "Human note: already investigating, do not touch"
        assert task.status == "done"  # still resolves -- only status/closed_at are written
        # Scoped by system_id too -- source_ref alone isn't a safe unique key across
        # the whole suite; see test_only_the_matching_test_is_resolved.
        poam = (
            await s.execute(
                select(POAM).where(POAM.system_id == sys_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        assert poam.severity == "critical"  # the human's edit, not clobbered
        assert poam.status == "open"
        assert "now passes" in (poam.remediation_plan or "")


async def test_only_the_matching_test_is_resolved() -> None:
    async with session_scope() as s:
        org_a, sys_a = await _make_org_system(s, "Recovery Scope Org A")
        org_b, sys_b = await _make_org_system(s, "Recovery Scope Org B")
        test_a = await _make_test(s, org_a, sys_a, "AC-SCOPE-A")
        test_b = await _make_test(s, org_b, sys_b, "AC-SCOPE-B")
        test_a_id, test_b_id = test_a.id, test_b.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_a_id), status="fail", detail="A failing"
        )
        await control_tests.record_result(
            s, await _reload_test(s, test_b_id), status="fail", detail="B failing"
        )

    async with session_scope() as s:
        # Only test A recovers; test B stays failing.
        await control_tests.record_result(
            s, await _reload_test(s, test_a_id), status="pass", detail="A fixed"
        )

    async with session_scope() as s:
        task_a = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_a_id}"))
        ).scalar_one()
        task_b = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_b_id}"))
        ).scalar_one()
        assert task_a.status == "done", "org A's recovered test must resolve its own task"
        assert task_b.status == "open", "org B's still-failing test's task must be untouched"

        # Scoped by system_id as well as source_ref -- matching the exact lookup
        # _upsert_poam/_resolve_on_recovery themselves use. source_ref alone is not
        # a safe unique key across the whole suite: it is a bare "control_test:{N}"
        # string, and other test modules mint POA&Ms with that same prefix over an
        # id drawn from an unrelated table/sequence (e.g.
        # test_assessment_closure_trigger.py's decoy, keyed off an
        # AssessmentControlResult id) that can coincidentally equal a ControlTest id
        # minted later in a full-suite run.
        poam_a = (
            await s.execute(
                select(POAM).where(
                    POAM.system_id == sys_a, POAM.source_ref == f"control_test:{test_a_id}"
                )
            )
        ).scalar_one()
        poam_b = (
            await s.execute(
                select(POAM).where(
                    POAM.system_id == sys_b, POAM.source_ref == f"control_test:{test_b_id}"
                )
            )
        ).scalar_one()
        assert "now passes" in (poam_a.remediation_plan or "")
        assert poam_b.remediation_plan is None


async def test_recovery_failure_is_isolated_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the POA&M-surfacing half to raise. The authoritative
    ControlTestResult write and test.last_status must still persist, the
    savepoint must roll the whole derived update back together (the Task
    must NOT resolve either, since it shares control_tests.py's single
    begin_nested() block with the POA&M write that raised), and a warning
    must be logged -- confirming this test fails if the recovery work is
    moved outside its savepoint (see the mutation check below).
    """
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        control_tests.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    original_notify = control_tests.bus.notify

    async def _maybe_raise(*args, **kwargs):
        if str(kwargs.get("dedupe_key", "")).startswith("poam-recovery:"):
            raise RuntimeError("simulated recovery failure")
        return await original_notify(*args, **kwargs)

    monkeypatch.setattr(control_tests.bus, "notify", _maybe_raise)

    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery Failure Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-FAIL")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    async with session_scope() as s:
        # Must not raise -- the ControlTestResult write is authoritative.
        test = await _reload_test(s, test_id)
        await control_tests.record_result(s, test, status="pass", detail="fixed")
        assert test.last_status == "pass"

    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        assert test.last_status == "pass"
        results = (
            await s.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == test_id)
            )
        ).scalars().all()
        assert {r.status for r in results} == {"fail", "pass"}
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one()
        assert task.status == "open"  # rolled back with the rest of the savepoint
    assert any(event == "control_tests.recovery_failed" for event, _ in warn_calls)


async def test_run_due_also_resolves_a_recovered_task() -> None:
    """run_due (the scheduler's own due-test evaluator) must get the same
    recovery behaviour as record_result. Before this task it duplicated
    record_result's write sequence inline instead of calling it, which would
    have made this whole slice a no-op on the scheduler-driven path -- this
    test fails if that delegation regresses back to a duplicated inline write.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery RunDue Org")
        conn = ConnectorConfig(
            organization_id=org_id,
            name="Prod AWS GovCloud",
            connector_type="aws_govcloud",
            status="configured",
            last_sync=datetime.now(UTC),
            objects_discovered=0,  # 0 objects -> evaluate_test returns "fail"
        )
        s.add(conn)
        test = ControlTest(
            organization_id=org_id,
            system_id=sys_id,
            control_id="AC-RUNDUE-RECOVER",
            name="Run-due recovery test",
            method="connector",
            connector_type="aws_govcloud",
            frequency="daily",
            active=True,
        )
        s.add(test)
        await s.flush()
        test_id, conn_id = test.id, conn.id

    async with session_scope() as s:
        await control_tests.run_due(s, today=datetime.now(UTC).date())
    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        assert test.last_status == "fail"  # 0 objects -> fail, opens the task/poam

    async with session_scope() as s:
        conn = (
            await s.execute(select(ConnectorConfig).where(ConnectorConfig.id == conn_id))
        ).scalar_one()
        conn.objects_discovered = 12
        conn.last_sync = datetime.now(UTC)
        test = await _reload_test(s, test_id)
        test.last_tested_at = datetime.now(UTC) - timedelta(days=2)  # due again

    async with session_scope() as s:
        await control_tests.run_due(s, today=datetime.now(UTC).date())

    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        assert test.last_status == "pass"
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one()
        assert task.status == "done", "run_due must delegate to record_result for recovery too"


async def test_closed_poam_is_left_alone_on_recovery() -> None:
    """The ``POAM.status.in_(_OPEN_POAM)`` guard on the recovery lookup,
    unexercised until now: deleting that filter entirely still passes every
    other test in this file (and in ``tests/test_conmon_recovery.py``, whose
    sibling guard shares the same shape). A POA&M a human has already closed
    must not gain a "now passes" note (or a recovery notification) when the
    test later recovers to pass.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery ClosedPoam Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-CLOSED")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    source_ref = f"control_test:{test_id}"
    async with session_scope() as s:
        poam = (
            await s.execute(
                select(POAM).where(POAM.system_id == sys_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        poam.status = "closed"

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="pass", detail="fixed"
        )

    async with session_scope() as s:
        poam = (
            await s.execute(
                select(POAM).where(POAM.system_id == sys_id, POAM.source_ref == source_ref)
            )
        ).scalar_one()
        assert poam.status == "closed"
        assert poam.remediation_plan is None
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"poam-recovery:{poam.id}")
            )
        ).scalars().all()
        assert notes == []


async def test_a_task_a_human_has_taken_up_is_not_resolved() -> None:
    """The untouched-only guard on the Task's own status, which nothing covered.

    ``test_human_edited_task_and_poam_fields_survive_recovery`` edits the
    description and asserts the Task still resolves -- correct, but it leaves
    the ``status == "open"`` guard untested. Removing that guard silently flips
    a human's ``in_progress`` Task to ``done``, retiring work somebody had
    picked up. Verified by mutation: without the guard this test fails and
    every other test in this file still passes.

    ``in_progress`` is used deliberately rather than a made-up value -- it is
    what the UI sets when someone takes a task up.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery InProgress Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-INPROG")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    dedupe = f"ctltest-fix:{test_id}"
    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        task.status = "in_progress"

    async with session_scope() as s:
        await control_tests.record_result(
            s, await _reload_test(s, test_id), status="pass", detail="fixed"
        )

    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.status == "in_progress", (
            "a task somebody had taken up must not be auto-resolved out from under them"
        )
