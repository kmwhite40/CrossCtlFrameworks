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

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Task
from ..models_grc import ConnectorConfig, ControlTest, ControlTestResult
from . import bus

log = get_logger(__name__)

# How stale a test result may be before the test is re-run, by frequency.
_FREQ_DAYS = {"daily": 1, "weekly": 7, "monthly": 30, "quarterly": 91, "annual": 365}


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
        conn = await _connector_for(session, test)
        status, detail = _evaluate(test, conn, today)
        session.add(
            ControlTestResult(
                control_test_id=test.id,
                status=status,
                detail=detail,
                evidence_ref=(conn.name if conn else None),
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
