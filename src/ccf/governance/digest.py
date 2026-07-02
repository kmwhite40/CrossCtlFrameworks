"""Org-level alert digest — the cross-module notification sweep.

Where the ConMon scan works control-by-control, the digest raises portfolio-level
alerts that span modules: ATO expirations, upstream catalog drift, overdue POA&M
load, and policy/vendor reviews coming due. Everything is de-duplicated so a
daily run keeps a single live alert per condition rather than a growing pile.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM, CatalogSource, Policy, Risk, System, Task, Vendor
from . import bus

ATO_WINDOW_DAYS = 90
REVIEW_WINDOW_DAYS = 30


async def _escalate_overdue_tasks(session: AsyncSession, today: date, org_id: int | None) -> int:
    """SLA escalation: overdue open tasks are bumped to high priority + alerted."""
    stmt = select(Task).where(
        Task.status.in_(("open", "in_progress")),
        Task.due_on.is_not(None),
        Task.due_on < today,
        Task.priority != "critical",
    )
    if org_id is not None:
        stmt = stmt.where(Task.organization_id == org_id)
    escalated = 0
    for t in (await session.execute(stmt)).scalars().all():
        t.priority = "critical" if t.priority == "high" else "high"
        escalated += 1
        await bus.notify(
            session,
            category="task",
            title=f"Overdue task escalated: {t.title}",
            body=f"Due {t.due_on}; now {t.priority} priority.",
            org_id=org_id,
            severity="warning",
            entity_type="task",
            entity_id=t.id,
            dedupe_key=f"task-overdue:{t.id}:{t.due_on}",
        )
    return escalated


async def run(session: AsyncSession, *, today: date, org_id: int | None = None) -> dict[str, Any]:
    """Raise/refresh org-level notifications. Returns counts by category."""
    counts = {"ato": 0, "catalog": 0, "poam": 0, "policy": 0, "vendor": 0, "risk": 0}
    counts["tasks_escalated"] = await _escalate_overdue_tasks(session, today, org_id)

    # ATO expiring / expired.
    sys_stmt = select(System).where(System.ato_expires_on.is_not(None))
    if org_id is not None:
        sys_stmt = sys_stmt.where(System.organization_id == org_id)
    for s in (await session.execute(sys_stmt)).scalars().all():
        days = (s.ato_expires_on - today).days
        if days <= ATO_WINDOW_DAYS:
            await bus.notify(
                session,
                category="ato",
                title=(
                    f"ATO expired for {s.name}"
                    if days < 0
                    else f"ATO for {s.name} expires in {days} days"
                ),
                org_id=org_id,
                severity="critical" if days < 0 else "warning",
                entity_type="system",
                entity_id=s.id,
                dedupe_key=f"ato:{s.id}",
            )
            counts["ato"] += 1

    # Upstream catalog drift (a source whose last poll changed).
    for src in (
        (await session.execute(select(CatalogSource).where(CatalogSource.last_status == "changed")))
        .scalars()
        .all()
    ):
        await bus.notify(
            session,
            category="catalog",
            title=f"Catalog drift: {src.name}",
            body=f"Upstream revision {src.revision_label or '?'} differs from ingested baseline.",
            org_id=org_id,
            severity="warning",
            entity_type="catalog_source",
            entity_id=src.id,
            dedupe_key=f"catalog:{src.id}:{src.last_sha256}",
        )
        counts["catalog"] += 1

    # Overdue POA&M load (single rollup alert).
    poam_stmt = select(POAM).where(POAM.status.in_(("open", "in_progress")))
    if org_id is not None:
        poam_stmt = poam_stmt.where(
            POAM.system_id.in_(select(System.id).where(System.organization_id == org_id))
        )
    overdue = [
        p
        for p in (await session.execute(poam_stmt)).scalars().all()
        if p.due_on is not None and p.due_on < today
    ]
    if overdue:
        await bus.notify(
            session,
            category="poam",
            title=f"{len(overdue)} POA&M(s) overdue",
            org_id=org_id,
            severity="warning",
            entity_type="poam",
            dedupe_key=f"poam-overdue:{org_id}",
        )
        counts["poam"] = len(overdue)

    # Policy reviews coming due.
    horizon = today + timedelta(days=REVIEW_WINDOW_DAYS)
    pol_stmt = select(Policy).where(
        Policy.next_review_on.is_not(None), Policy.next_review_on <= horizon
    )
    if org_id is not None:
        pol_stmt = pol_stmt.where(Policy.organization_id == org_id)
    for p in (await session.execute(pol_stmt)).scalars().all():
        await bus.notify(
            session,
            category="policy",
            title=f"Policy review due: {p.name}",
            org_id=org_id,
            severity="info",
            entity_type="policy",
            entity_id=p.id,
            dedupe_key=f"policy-review:{p.id}:{p.next_review_on}",
        )
        counts["policy"] += 1

    # Vendor reviews coming due.
    ven_stmt = select(Vendor).where(
        Vendor.next_review_on.is_not(None), Vendor.next_review_on <= horizon
    )
    if org_id is not None:
        ven_stmt = ven_stmt.where(Vendor.organization_id == org_id)
    for v in (await session.execute(ven_stmt)).scalars().all():
        await bus.notify(
            session,
            category="vendor",
            title=f"Vendor review due: {v.name}",
            org_id=org_id,
            severity="info",
            entity_type="vendor",
            entity_id=v.id,
            dedupe_key=f"vendor-review:{v.id}:{v.next_review_on}",
        )
        counts["vendor"] += 1

    # Risk reviews coming due (open/mitigated risks with a review date).
    risk_stmt = select(Risk).where(
        Risk.next_review_on.is_not(None),
        Risk.next_review_on <= horizon,
        Risk.status.in_(("open", "mitigated")),
    )
    if org_id is not None:
        risk_stmt = risk_stmt.where(
            Risk.system_id.in_(select(System.id).where(System.organization_id == org_id))
        )
    for r in (await session.execute(risk_stmt)).scalars().all():
        await bus.notify(
            session,
            category="risk",
            title=f"Risk review due: {r.title}",
            org_id=org_id,
            severity="info",
            entity_type="risk",
            entity_id=r.id,
            dedupe_key=f"risk-review:{r.id}:{r.next_review_on}",
        )
        counts["risk"] += 1

    return counts
