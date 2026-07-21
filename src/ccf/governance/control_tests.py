"""Scheduler-driven auto-run of connector-backed control tests.

Continuous Control Monitoring formalizes each control as a repeatable test
(``ControlTest``). Manual tests are recorded by a person via the API; tests with
``method='connector'`` can be evaluated automatically against the matching cloud
connector's last sync. This module is invoked from the scheduler cycle: it finds
tests that are *due* per their frequency, derives a pass/warn/fail from connector
state, records a ``ControlTestResult``, and — on failure — opens the same alert +
remediation task the manual run endpoint creates.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import POAM, CaptureSnapshot, Control, PoamMilestone, Task
from ..models_grc import ConnectorConfig, ControlTest, ControlTestResult
from . import bus

log = get_logger(__name__)

# How stale a test result may be before the test is re-run, by frequency.
_FREQ_DAYS = {"daily": 1, "weekly": 7, "monthly": 30, "quarterly": 91, "annual": 365}
_OPEN_POAM = ("open", "in_progress")


def _coerce(v: str) -> object:
    """Interpret a captured string as a bool/number when it clearly is one."""
    t = v.strip().lower()
    if t in ("true", "enabled", "yes", "on"):
        return True
    if t in ("false", "disabled", "no", "off"):
        return False
    try:
        return float(v)
    except ValueError:
        return v


def evaluate_assertion(assertion: dict[str, Any], captured: str) -> tuple[bool, str]:
    """Check a captured value against an assertion. Returns ``(passed, detail)``.

    Assertion shape: ``{"odp_key", "operator", "value"}`` where operator is one
    of equals, not_equals, contains, gte, lte, gt, lt. Numeric operators coerce
    both sides to floats; equality coerces booleans/numbers so ``"enabled"``
    satisfies ``value: "true"``.
    """
    op = str(assertion.get("operator", "equals")).lower()
    expected_raw = str(assertion.get("value", ""))
    actual = _coerce(captured)
    expected = _coerce(expected_raw)

    if op in ("equals", "eq", "=="):
        ok = actual == expected
    elif op in ("not_equals", "ne", "!="):
        ok = actual != expected
    elif op == "contains":
        ok = expected_raw.lower() in captured.lower()
    elif op in ("gte", "gt", "lte", "lt"):
        try:
            a, e = float(captured), float(expected_raw)
        except ValueError:
            return False, f"non-numeric value {captured!r} for operator {op}"
        ok = {"gte": a >= e, "gt": a > e, "lte": a <= e, "lt": a < e}[op]
    else:
        return False, f"unknown assertion operator: {op}"
    verdict = "meets" if ok else "violates"
    return ok, f"captured {captured!r} {verdict} {op} {expected_raw!r}"


async def _latest_capture(session: AsyncSession, test: ControlTest) -> CaptureSnapshot | None:
    odp_key = (test.assertion or {}).get("odp_key")
    if not odp_key:
        return None
    stmt = select(CaptureSnapshot).where(
        CaptureSnapshot.connector == test.connector_type,
        CaptureSnapshot.odp_key == odp_key,
    )
    if test.organization_id is not None:
        stmt = stmt.where(CaptureSnapshot.organization_id == test.organization_id)
    stmt = stmt.order_by(CaptureSnapshot.captured_at.desc())
    return (await session.execute(stmt)).scalars().first()


def _is_due(test: ControlTest, today: date) -> bool:
    if not test.active:
        return False
    days = _FREQ_DAYS.get((test.frequency or "").lower())
    if days is None:  # no schedule → on-demand / manual only
        return False
    if test.last_tested_at is None:
        return True
    return (today - test.last_tested_at.date()).days >= days


async def _connector_for(
    session: AsyncSession, test: ControlTest
) -> ConnectorConfig | None:
    if not test.connector_type:
        return None
    stmt = select(ConnectorConfig).where(
        ConnectorConfig.connector_type == test.connector_type
    )
    if test.organization_id is not None:
        stmt = stmt.where(ConnectorConfig.organization_id == test.organization_id)
    # Prefer the most recently *successfully synced* connector; a NULL last_sync
    # (never synced) must sort last, not first (Postgres DESC defaults to NULLS
    # FIRST), otherwise a configured connector loses to an un-synced one.
    stmt = stmt.order_by(ConnectorConfig.last_sync.desc().nulls_last())
    return (await session.execute(stmt)).scalars().first()


def _evaluate(test: ControlTest, conn: ConnectorConfig | None, today: date) -> tuple[str, str]:
    """Derive (status, detail) for a connector-backed test from connector state."""
    if conn is None:
        return "warn", f"No {test.connector_type} connector registered to collect evidence."
    if conn.status != "configured" or conn.last_sync is None:
        return "warn", f"Connector '{conn.name}' has not completed a successful sync."
    days = _FREQ_DAYS.get((test.frequency or "").lower(), 30)
    stale = (today - conn.last_sync.date()).days > days
    if stale:
        return "warn", f"Connector '{conn.name}' last synced {conn.last_sync.date()} — stale."
    if conn.objects_discovered <= 0:
        return "fail", f"Connector '{conn.name}' synced but discovered no configuration objects."
    return "pass", (
        f"Connector '{conn.name}' current ({conn.objects_discovered} objects, "
        f"synced {conn.last_sync.date()})."
    )


async def evaluate_test(
    session: AsyncSession, test: ControlTest, today: date
) -> tuple[str, str, str | None]:
    """Evaluate one connector-backed test → ``(status, detail, evidence_ref)``.

    When the test carries a machine-checkable ``assertion``, the latest captured
    value for its ``odp_key`` is checked (real pass/fail on posture). Otherwise
    it falls back to the connector-freshness heuristic in :func:`_evaluate`.
    """
    if test.assertion and test.assertion.get("odp_key"):
        snap = await _latest_capture(session, test)
        if snap is None:
            return (
                "warn",
                f"No captured value for '{test.assertion['odp_key']}' from "
                f"{test.connector_type} yet — run collection first.",
                None,
            )
        ok, detail = evaluate_assertion(test.assertion, snap.value)
        ref = f"{snap.connector}:{snap.odp_key}@{snap.captured_at.date()}"
        return ("pass" if ok else "fail", detail, ref)
    conn = await _connector_for(session, test)
    status, detail = _evaluate(test, conn, today)
    return status, detail, (conn.name if conn else None)


async def _alert_on_failure(
    session: AsyncSession, test: ControlTest, status: str, detail: str
) -> None:
    sev = "critical" if status == "fail" else "warning"
    await bus.notify(
        session,
        category="conmon",
        title=f"Control test {status}: {test.name} ({test.control_id})",
        body=detail,
        org_id=test.organization_id,
        severity=sev,
        entity_type="control_test",
        entity_id=test.id,
        dedupe_key=f"ctltest:{test.id}",
    )
    if status != "fail":
        return
    dedupe = f"ctltest-fix:{test.id}"
    exists = (
        await session.execute(select(Task).where(Task.dedupe_key == dedupe))
    ).scalar_one_or_none()
    if exists is None:
        session.add(
            Task(
                organization_id=test.organization_id,
                system_id=test.system_id,
                title=f"Remediate failed control test: {test.name}",
                description=detail,
                kind="remediation",
                priority="high",
                status="open",
                source="auto",
                entity_type="control_test",
                entity_id=str(test.id),
                dedupe_key=dedupe,
            )
        )
    await _upsert_poam(session, test, detail)


async def _upsert_poam(session: AsyncSession, test: ControlTest, detail: str) -> bool:
    """Open a POA&M for a failed control test (idempotent). True if new.

    ``ControlTest.control_id`` is a free-text catalog/practice id (e.g. a CMMC
    practice) rather than the FK'd int ``Control.id`` the POA&M column wants,
    and often has no matching row in the org's control catalog at all — so
    dedupe keys off the test's own stable id (``source_ref``) rather than
    (system, control, source) directly. That's equivalent grouping whenever
    the control does resolve, and strictly safer when it doesn't: it never
    collapses two different failing tests that both leave ``control_id`` null
    into one POA&M, while still refreshing (not duplicating) the same test's
    POA&M across repeated failures.

    ``POAM.system_id`` is NOT NULL but ``ControlTest.system_id`` isn't — an
    org-wide test (not scoped to one system) has nothing to attach a POA&M to,
    so it keeps the existing Task/Notification alert only.
    """
    if test.system_id is None:
        return False
    source_ref = f"control_test:{test.id}"
    weakness = (
        f"Automated control test '{test.name}' ({test.control_id}) failed: {detail}"
    )
    existing = (
        await session.execute(
            select(POAM).where(
                POAM.source == "control_test",
                POAM.source_ref == source_ref,
                POAM.status.in_(_OPEN_POAM),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.weakness = weakness
        return False

    control_id = (
        await session.execute(select(Control.id).where(Control.identifier == test.control_id))
    ).scalar_one_or_none()
    today = datetime.now(UTC).date()
    due = today + timedelta(days=30)
    poam = POAM(
        system_id=test.system_id,
        control_id=control_id,
        title=f"Control test failed: {test.name} ({test.control_id})",
        weakness=weakness,
        severity="high",
        status="open",
        source="control_test",
        identified_on=today,
        due_on=due,
        original_due_on=due,
        source_ref=source_ref,
    )
    poam.milestones.append(
        PoamMilestone(
            description=f"Remediate {test.control_id}", due_on=due, status="pending", sort_order=0
        )
    )
    session.add(poam)
    return True


async def record_result(
    session: AsyncSession,
    test: ControlTest,
    *,
    status: str,
    detail: str | None = None,
    evidence_ref: str | None = None,
    actor: str = "user",
) -> ControlTestResult:
    """Persist one test result, update the test, and alert on fail/warn.

    Shared by the manual UI run action and the scheduler auto-run so the alert +
    remediation-task behaviour is identical regardless of trigger.
    """
    if status not in ("pass", "warn", "fail"):
        raise ValueError("status must be pass|warn|fail")
    res = ControlTestResult(
        control_test_id=test.id, status=status, detail=detail, evidence_ref=evidence_ref
    )
    session.add(res)
    test.last_status = status
    test.last_tested_at = datetime.now(UTC)
    await session.flush()
    if status in ("fail", "warn"):
        await _alert_on_failure(session, test, status, detail or "")
    await bus.emit(
        session,
        verb="tested",
        entity_type="control_test",
        entity_id=test.id,
        summary=f"Control test {status}: {test.control_id}",
        org_id=test.organization_id,
        actor=actor,
    )
    return res


async def run_due(session: AsyncSession, *, today: date | None = None) -> dict[str, Any]:
    """Auto-run every due connector-backed test. Returns per-status counts."""
    today = today or datetime.now(UTC).date()
    stmt = select(ControlTest).where(
        ControlTest.active.is_(True), ControlTest.method == "connector"
    )
    tests = (await session.execute(stmt)).scalars().all()
    counts = {"evaluated": 0, "pass": 0, "warn": 0, "fail": 0}
    for test in tests:
        if not _is_due(test, today):
            continue
        status, detail, evidence_ref = await evaluate_test(session, test, today)
        session.add(
            ControlTestResult(
                control_test_id=test.id,
                status=status,
                detail=detail,
                evidence_ref=evidence_ref,
            )
        )
        test.last_status = status
        test.last_tested_at = datetime.now(UTC)
        counts["evaluated"] += 1
        counts[status] += 1
        if status in ("fail", "warn"):
            await _alert_on_failure(session, test, status, detail)
        await bus.emit(
            session,
            verb="tested",
            entity_type="control_test",
            entity_id=test.id,
            summary=f"Auto-run control test {status}: {test.control_id}",
            org_id=test.organization_id,
            actor="scheduler",
        )
    if counts["evaluated"]:
        log.info("control_tests.auto_run", **counts)
    return counts
