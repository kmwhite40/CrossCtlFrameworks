"""Scheduler GLOBAL-step savepoint containment (IA-06).

``run_cycle`` runs three GLOBAL steps once per cycle — ``poll_sources``,
``digest.run``, and ``fedramp20x.monitoring.scan`` — each historically wrapped
in a bare ``contextlib.suppress(Exception)``. ``suppress`` catches the
*Python* exception, but a DB-level failure (a real Postgres error, not a
plain ``ValueError``) leaves the shared session's transaction ABORTED, and
that abort survives the ``suppress`` block exiting. The very next statement
on that session then raises, unsuppressed:

* A ``poll_sources`` DB failure aborts ``_active_org_ids`` (the very next
  statement, not itself wrapped in any suppress) and kills the *entire*
  cycle for every tenant.
* A ``digest.run`` DB failure means ``monitoring.scan``'s first statement
  inherits the abort and raises immediately — caught by ITS OWN suppress, so
  the step looks like a clean no-op run rather than a failure that took out
  a completely unrelated step.

Each GLOBAL step is now wrapped in its own SAVEPOINT (``session.begin_nested``),
exactly like ``_run_per_tenant_cycle``'s steps: on exception, ``ROLLBACK TO
SAVEPOINT`` clears the abort so later statements on the session are
unaffected, while the failure itself is still logged and swallowed (the
best-effort contract is unchanged).
"""

from __future__ import annotations

from datetime import date

import pytest
import structlog.testing
from sqlalchemy import delete, select, text

from ccf.db import session_scope
from ccf.fedramp20x import monitoring as monitoring_mod
from ccf.governance import digest as digest_mod
from ccf.governance import scheduler
from ccf.models import MonitoringRun, Organization

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


async def _cleanup(*org_ids: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(MonitoringRun).where(MonitoringRun.organization_id.in_(org_ids)))
        await s.execute(delete(Organization).where(Organization.id.in_(org_ids)))


async def test_poll_sources_db_failure_does_not_kill_the_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DB-level failure in the FIRST global step must not abort the whole
    cycle — the per-tenant work that runs right after it must still complete.
    """
    org_id = await _org("scheduler-global-poll-fail")

    async def flaky_poll(session: object, **_: object) -> list[object]:
        # A genuine DB-level error (Postgres integer division by zero) aborts
        # the current transaction, exactly like a real constraint violation
        # or serialization failure would. A plain ``ValueError`` here would
        # never touch the transaction state and would not reproduce the bug.
        await session.execute(text("SELECT 1/0"))  # type: ignore[attr-defined]
        return []

    monkeypatch.setattr(scheduler, "poll_sources", flaky_poll)

    try:
        with structlog.testing.capture_logs() as cap_logs:
            result = await scheduler.run_cycle()

        # Best-effort contract preserved: the cycle reports success, not an
        # unhandled exception propagating out of run_cycle().
        assert "catalog_checks" not in result

        # The per-tenant work that runs immediately after poll_sources in the
        # same cycle must still have executed. A committed MonitoringRun row
        # is real evidence conmon.scan actually ran for this org -- not just
        # that run_cycle() happened to return without raising.
        async with session_scope() as s:
            runs = (
                await s.execute(
                    select(MonitoringRun).where(MonitoringRun.organization_id == org_id)
                )
            ).scalars().all()
        assert len(runs) == 1, (
            "per-tenant conmon scan must still run after poll_sources' DB failure"
        )

        warnings = [
            e
            for e in cap_logs
            if e.get("event") == "scheduler.global_step_failed" and e.get("log_level") == "warning"
        ]
        assert warnings, f"expected a scheduler.global_step_failed warning, got: {cap_logs}"
        assert warnings[0]["step"] == "poll_sources"
    finally:
        await _cleanup(org_id)


async def test_digest_db_failure_does_not_take_out_monitoring_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DB-level failure in the MIDDLE global step (digest) must not take
    out the global step that runs right after it (fedramp20x monitoring).
    """
    org_id = await _org("scheduler-global-digest-fail")

    async def flaky_digest_run(session: object, **_: object) -> dict[str, object]:
        await session.execute(text("SELECT 1/0"))  # type: ignore[attr-defined]
        return {}

    monkeypatch.setattr(digest_mod, "run", flaky_digest_run)

    # A stub that still does a real DB round trip (proving the transaction is
    # actually usable, not just that Python control flow reached the call)
    # and returns a distinctive sentinel -- so the test can tell "ran to
    # completion and produced its real output" apart from "was invoked but
    # immediately raised on an inherited abort and got swallowed by its own
    # suppress," which is the trap: both look identical if you only assert
    # run_cycle() didn't raise.
    sentinel = {"systems_scanned": 4181, "drift_events": 17}

    async def stub_monitoring_scan(session: object, *, today: date | None = None) -> dict:
        await session.execute(text("SELECT 1"))  # type: ignore[attr-defined]
        return sentinel

    monkeypatch.setattr(monitoring_mod, "scan", stub_monitoring_scan)

    try:
        with structlog.testing.capture_logs() as cap_logs:
            result = await scheduler.run_cycle()

        # Best-effort contract preserved for the failing step.
        assert "digest" not in result

        # The step after digest must have run to completion, not just been
        # invoked-and-immediately-swallowed.
        assert result.get("fedramp20x") == sentinel

        failure_events = [e for e in cap_logs if e.get("event") == "scheduler.global_step_failed"]
        steps_failed = {e["step"] for e in failure_events}
        assert "digest" in steps_failed, f"expected a digest failure warning, got: {cap_logs}"
        assert "fedramp20x_monitoring" not in steps_failed, (
            "fedramp20x monitoring.scan must not have failed -- digest's DB "
            "abort must not have leaked into it"
        )
    finally:
        await _cleanup(org_id)
