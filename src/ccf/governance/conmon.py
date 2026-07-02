"""Continuous monitoring — derive control health and drive the work queue.

Health for a control implementation is computed from three live signals that
already exist in the data model: evidence freshness (``expires_on``), assessment
recency (``next_assessment_due``), and open POA&Ms. A scan rolls those into a
status, then generates de-duplicated tasks and notifications for anything that
needs attention — turning static records into an active ConMon program.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    POAM,
    ControlImplementation,
    Evidence,
    MonitoringRun,
    System,
    Task,
)
from . import bus

DUE_SOON_DAYS = 30

# healthy < due_soon < at_risk < overdue
_RANK = {"healthy": 0, "due_soon": 1, "at_risk": 2, "overdue": 3}
_OPEN_POAM = ("open", "in_progress")


def _escalate(current: str, candidate: str) -> str:
    return candidate if _RANK[candidate] > _RANK[current] else current


def assess_health(
    impl: ControlImplementation,
    evidences: list[Evidence],
    open_poams: list[POAM],
    today: date,
) -> tuple[str, list[str]]:
    """Return ``(status, reasons)`` for one control implementation."""
    status = "healthy"
    reasons: list[str] = []
    horizon = today + timedelta(days=DUE_SOON_DAYS)

    dated = [e.expires_on for e in evidences if e.expires_on is not None]
    if any(d < today for d in dated):
        status = _escalate(status, "overdue")
        reasons.append("evidence expired")
    elif any(d <= horizon for d in dated):
        status = _escalate(status, "due_soon")
        reasons.append("evidence expiring soon")
    if not evidences and impl.status in ("implemented", "inherited"):
        status = _escalate(status, "due_soon")
        reasons.append("no evidence on record")

    if impl.next_assessment_due is not None:
        if impl.next_assessment_due < today:
            status = _escalate(status, "overdue")
            reasons.append("assessment overdue")
        elif impl.next_assessment_due <= horizon:
            status = _escalate(status, "due_soon")
            reasons.append("assessment due soon")

    crit = [p for p in open_poams if p.severity in ("high", "critical")]
    if crit:
        status = _escalate(status, "at_risk")
        reasons.append(f"{len(crit)} open high/critical POA&M")

    if impl.status in ("not_implemented", "planned"):
        status = _escalate(status, "at_risk")
        reasons.append(f"implementation status: {impl.status}")

    return status, reasons


def _kind_for(reasons: list[str]) -> str:
    joined = " ".join(reasons)
    if "POA&M" in joined:
        return "remediation"
    if "assessment" in joined:
        return "reassessment"
    if "evidence" in joined:
        return "evidence_refresh"
    return "review"


async def scan(session: AsyncSession, *, today: date, org_id: int | None = None) -> dict[str, Any]:
    """Assess every in-scope control implementation; open tasks/notifications."""
    run = MonitoringRun(organization_id=org_id)
    session.add(run)
    await session.flush()

    stmt = select(ControlImplementation)
    if org_id is not None:
        sys_ids = select(System.id).where(System.organization_id == org_id)
        stmt = stmt.where(ControlImplementation.system_id.in_(sys_ids))
    impls = (await session.execute(stmt)).scalars().all()

    # Preload evidence + open POA&Ms once.
    ev_by_impl: dict[int, list[Evidence]] = {}
    for e in (await session.execute(select(Evidence))).scalars().all():
        ev_by_impl.setdefault(e.implementation_id, []).append(e)
    poams = (await session.execute(select(POAM).where(POAM.status.in_(_OPEN_POAM)))).scalars().all()

    checked = findings = tasks_created = notes_created = 0
    by_status: dict[str, int] = {"healthy": 0, "due_soon": 0, "at_risk": 0, "overdue": 0}

    for impl in impls:
        checked += 1
        impl_poams = [
            p for p in poams if p.system_id == impl.system_id and p.control_id == impl.control_id
        ]
        status, reasons = assess_health(impl, ev_by_impl.get(impl.id, []), impl_poams, today)
        by_status[status] += 1
        if status == "healthy":
            continue
        findings += 1
        severity = {"overdue": "critical", "at_risk": "warning", "due_soon": "info"}[status]
        title = f"Control {impl.control_id} monitoring: {status.replace('_', ' ')}"
        reason_text = "; ".join(reasons)

        note = await bus.notify(
            session,
            category="conmon",
            title=title,
            body=reason_text,
            org_id=org_id,
            severity=severity,
            entity_type="control_implementation",
            entity_id=impl.id,
            dedupe_key=f"conmon:{impl.id}",
        )
        if note is not None:
            notes_created += 1

        if status in ("at_risk", "overdue"):
            created = await _upsert_task(
                session,
                org_id=org_id,
                system_id=impl.system_id,
                impl_id=impl.id,
                title=title,
                description=reason_text,
                kind=_kind_for(reasons),
                priority="high" if status == "overdue" else "medium",
                due_on=today + timedelta(days=14),
            )
            if created:
                tasks_created += 1

    run.controls_checked = checked
    run.findings = findings
    run.tasks_created = tasks_created
    run.notifications_created = notes_created
    run.summary = {"by_status": by_status}
    await session.flush()
    await bus.emit(
        session,
        verb="scanned",
        entity_type="monitoring_run",
        entity_id=run.id,
        summary=f"ConMon scan: {findings} findings across {checked} controls",
        org_id=org_id,
        payload={"by_status": by_status, "tasks": tasks_created},
    )
    return {
        "run_id": run.id,
        "controls_checked": checked,
        "findings": findings,
        "tasks_created": tasks_created,
        "notifications_created": notes_created,
        "by_status": by_status,
    }


async def _upsert_task(
    session: AsyncSession,
    *,
    org_id: int | None,
    system_id: int | None,
    impl_id: int,
    title: str,
    description: str,
    kind: str,
    priority: str,
    due_on: date,
) -> bool:
    """Create an auto task for a control (idempotent by dedupe_key). True if new."""
    dedupe = f"conmon:impl:{impl_id}"
    existing = (
        await session.execute(select(Task).where(Task.dedupe_key == dedupe))
    ).scalar_one_or_none()
    if existing is not None:
        if existing.status in ("done", "cancelled"):
            return False  # respect a human's closure; don't reopen
        existing.title = title
        existing.description = description
        existing.priority = priority
        return False
    session.add(
        Task(
            organization_id=org_id,
            system_id=system_id,
            title=title,
            description=description,
            kind=kind,
            priority=priority,
            status="open",
            source="auto",
            entity_type="control_implementation",
            entity_id=str(impl_id),
            dedupe_key=dedupe,
            due_on=due_on,
        )
    )
    return True


async def health_summary(
    session: AsyncSession, *, today: date, org_id: int | None = None
) -> dict[str, Any]:
    """Compute current control health without persisting (read-only rollup)."""
    stmt = select(ControlImplementation)
    if org_id is not None:
        stmt = stmt.where(
            ControlImplementation.system_id.in_(
                select(System.id).where(System.organization_id == org_id)
            )
        )
    impls = (await session.execute(stmt)).scalars().all()
    ev_by_impl: dict[int, list[Evidence]] = {}
    for e in (await session.execute(select(Evidence))).scalars().all():
        ev_by_impl.setdefault(e.implementation_id, []).append(e)
    poams = (await session.execute(select(POAM).where(POAM.status.in_(_OPEN_POAM)))).scalars().all()
    by_status = {"healthy": 0, "due_soon": 0, "at_risk": 0, "overdue": 0}
    attention: list[dict[str, Any]] = []
    for impl in impls:
        impl_poams = [
            p for p in poams if p.system_id == impl.system_id and p.control_id == impl.control_id
        ]
        status, reasons = assess_health(impl, ev_by_impl.get(impl.id, []), impl_poams, today)
        by_status[status] += 1
        if status != "healthy":
            attention.append(
                {
                    "implementation_id": impl.id,
                    "system_id": impl.system_id,
                    "control_id": impl.control_id,
                    "status": status,
                    "reasons": reasons,
                }
            )
    total = len(impls)
    return {
        "total": total,
        "by_status": by_status,
        "health_pct": round(100 * by_status["healthy"] / total, 1) if total else None,
        "attention": sorted(attention, key=lambda a: _RANK[a["status"]], reverse=True)[:100],
    }
