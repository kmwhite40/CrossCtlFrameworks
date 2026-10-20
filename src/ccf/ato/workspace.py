"""The per-system authorization workspace: one read over Concord's own records.

Everything here is a count or a list of real rows -- packages and their history,
signing roles, blockers, POA&Ms and their deviations, extension requests,
pending approvals, standing acceptances, evidence state, ConMon control health,
FedRAMP 20x readiness. Nothing is weighted, blended or defaulted: where there
is nothing to count, the value is ``None`` and the page says "no data", because
a 0% or a 100% over nothing reads as a finding or an achievement.

The action queue is derived from the same rows, each item pointing at the place
it is resolved. It replaces m365-docs-hub's readiness composite, whose missing
inputs scored 100 and whose gate percentages had no source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
from ..fedramp20x import readiness
from ..governance import conmon
from ..models import POAM, Approval, Risk, System
from ..models_ato import (
    SYSTEM_ROLES,
    AuthorizationPackageEvent,
    PoamExtension,
    SystemRoleAssignment,
)
from ..models_evidence import EvidenceObject
from ..models_packages import AuthorizationPackage
from . import acceptances, lifecycle
from . import roles as system_roles

#: Matches ConMon's own "due soon" window (``governance.conmon.DUE_SOON_DAYS``).
SOON_DAYS = 30
_SEVERITY_RANK = {"critical": 4, "high": 3, "moderate": 2, "low": 1}


@dataclass(frozen=True)
class Action:
    severity: str  # urgent | high | medium
    title: str
    detail: str
    href: str


async def _packages(session: AsyncSession, system_id: int) -> list[AuthorizationPackage]:
    return list(
        (
            await session.execute(
                select(AuthorizationPackage)
                .where(AuthorizationPackage.system_id == system_id)
                .order_by(AuthorizationPackage.id.desc())
            )
        ).scalars()
    )


def _current(packages: list[AuthorizationPackage]) -> AuthorizationPackage | None:
    """The package the workspace is about: the one in review, else the live
    authorization, else the newest draft or returned one, else the newest."""
    for statuses in (
        lifecycle.REVIEW_STATUSES,
        lifecycle.DECIDED_STATUSES,
        ("draft", "returned"),
    ):
        for p in packages:
            if p.status in statuses:
                return p
    return packages[0] if packages else None


async def _poams(session: AsyncSession, system_id: int, today: date) -> dict[str, Any]:
    rows = list(
        (await session.execute(select(POAM).where(POAM.system_id == system_id))).scalars()
    )
    active = [p for p in rows if p.status in POAM_ACTIVE_STATUSES]
    overdue = [p for p in active if p.due_on is not None and p.due_on < today]
    deviated = [
        p for p in active
        if p.original_due_on is not None and p.due_on is not None and p.due_on > p.original_due_on
    ]
    by_sev = {s: 0 for s in ("critical", "high", "moderate", "low")}
    for p in active:
        by_sev[p.severity or "moderate"] = by_sev.get(p.severity or "moderate", 0) + 1
    top = sorted(
        active,
        key=lambda p: (-_SEVERITY_RANK.get(p.severity or "", 0), p.due_on or date.max, p.id),
    )[:12]
    return {
        "total": len(rows),
        "active": len(active),
        "by_severity": by_sev,
        "overdue": len(overdue),
        "overdue_high": sum(1 for p in overdue if p.severity in ("critical", "high")),
        "deviated": len(deviated),
        "no_due_date": sum(1 for p in active if p.due_on is None),
        "top": [
            {
                "id": p.id, "title": p.title, "severity": p.severity, "status": p.status,
                "due_on": p.due_on, "original_due_on": p.original_due_on,
                "overdue": p.due_on is not None and p.due_on < today,
                "control_id": p.control_id,
            }
            for p in top
        ],
        "ids": [p.id for p in rows],
    }


async def _pending_extensions(session: AsyncSession, poam_ids: list[int]) -> list[dict[str, Any]]:
    if not poam_ids:
        return []
    rows = (
        await session.execute(
            select(PoamExtension, POAM.title)
            .join(POAM, POAM.id == PoamExtension.poam_id)
            .where(PoamExtension.poam_id.in_(poam_ids), PoamExtension.status == "requested")
            .order_by(PoamExtension.requested_at)
        )
    ).all()
    return [
        {
            "id": e.id, "poam_id": e.poam_id, "poam_title": title,
            "previous_due_on": e.previous_due_on, "requested_due_on": e.requested_due_on,
            "reason": e.reason, "requested_by": e.requested_by, "requested_at": e.requested_at,
        }
        for e, title in rows
    ]


async def _pending_approvals(
    session: AsyncSession, system_id: int, poam_ids: list[int]
) -> list[dict[str, Any]]:
    risk_ids = list(
        (await session.execute(select(Risk.id).where(Risk.system_id == system_id))).scalars()
    )
    wanted = [("poam", str(i)) for i in poam_ids] + [("risk", str(i)) for i in risk_ids]
    if not wanted:
        return []
    rows = (
        await session.execute(
            select(Approval).where(
                Approval.state == "submitted",
                Approval.entity_type.in_(("poam", "risk")),
                Approval.entity_id.in_([eid for _, eid in wanted]),
            )
        )
    ).scalars().all()
    keys = set(wanted)
    titles: dict[tuple[str, str], str] = {}
    if poam_ids:
        for pid, title in (
            await session.execute(select(POAM.id, POAM.title).where(POAM.id.in_(poam_ids)))
        ).all():
            titles[("poam", str(pid))] = title
    if risk_ids:
        for rid, title in (
            await session.execute(select(Risk.id, Risk.title).where(Risk.id.in_(risk_ids)))
        ).all():
            titles[("risk", str(rid))] = title
    return [
        {
            "entity_type": a.entity_type, "entity_id": a.entity_id,
            "title": titles.get((a.entity_type, a.entity_id), ""),
            "submitted_by": a.submitted_by, "submitted_at": a.submitted_at,
        }
        for a in rows
        if (a.entity_type, a.entity_id) in keys
    ]


async def _evidence(session: AsyncSession, system_id: int, today: date) -> dict[str, Any]:
    rows = (
        await session.execute(
            select(EvidenceObject.status, EvidenceObject.expires_on).where(
                EvidenceObject.system_id == system_id
            )
        )
    ).all()
    by_status: dict[str, int] = {}
    expired = expiring = 0
    for status, expires_on in rows:
        by_status[status] = by_status.get(status, 0) + 1
        if status == "expired" or (expires_on is not None and expires_on < today):
            expired += 1
        elif expires_on is not None and (expires_on - today).days <= SOON_DAYS:
            expiring += 1
    return {
        "total": len(rows),
        "by_status": by_status,
        "awaiting_review": by_status.get("submitted", 0),
        "expired": expired,
        "expiring_soon": expiring,
    }


async def _readiness(session: AsyncSession, system_id: int) -> dict[str, Any] | None:
    """FedRAMP 20x readiness, as that module computes it -- or None when it
    does not apply or cannot be computed. Never persisted from here."""
    try:
        async with session.begin_nested():
            r = await readiness.score_system(session, system_id=system_id, persist=False)
    except Exception:
        return None
    return {"readiness_pct": r.get("readiness_pct"), "status": r.get("status")}


def _actions(ws: dict[str, Any], today: date) -> list[Action]:
    sid = ws["system"]["id"]
    out: list[Action] = []
    for role in system_roles.REVIEW_ROLES:
        if ws["roles"].get(role) is None:
            out.append(Action(
                "high", f"Assign the {system_roles.ROLE_LABELS[role]}",
                "A package cannot be reviewed until the ISSO, ISSM and AO are named.",
                f"/ato/{sid}#roles",
            ))
    pkg = ws["package"]
    if pkg is None:
        out.append(Action(
            "medium", "Capture an authorization package",
            "Freezes the system's current facts so they can be reviewed and signed.",
            f"/ato/{sid}#package",
        ))
    elif pkg["status"] in lifecycle.REVIEW_STATUSES:
        role = lifecycle.STAGE_ROLE[pkg["status"]]
        out.append(Action(
            "high", f"Package {pkg['id']} awaits the {system_roles.ROLE_LABELS[role]}",
            f"In {pkg['status'].replace('_', ' ')} since {pkg['status_changed_at'] or '—'}.",
            f"/ato/{sid}#package",
        ))
    for b in ws["blockers"]:
        out.append(Action("urgent", b["title"], b["detail"], f"/ato/{sid}#blockers"))
    p = ws["poams"]
    if p["overdue"]:
        out.append(Action(
            "urgent" if p["overdue_high"] else "high",
            f"{p['overdue']} overdue POA&M{'s' if p['overdue'] != 1 else ''}",
            f"{p['overdue_high']} of them critical or high.", f"/ato/{sid}#poams",
        ))
    if p["no_due_date"]:
        out.append(Action(
            "medium", f"{p['no_due_date']} open POA&M{'s' if p['no_due_date'] != 1 else ''} "
            "with no due date", "A weakness with no date can never be overdue.",
            f"/ato/{sid}#poams",
        ))
    if ws["extensions"]:
        n = len(ws["extensions"])
        out.append(Action(
            "high", f"{n} extension request{'s' if n != 1 else ''} to decide",
            "ISSM or AO decision.", f"/ato/{sid}#extensions",
        ))
    if ws["approvals"]:
        n = len(ws["approvals"])
        out.append(Action(
            "high", f"{n} approval{'s' if n != 1 else ''} awaiting review",
            "POA&M closures and risk acceptances submitted for a decision.",
            f"/ato/{sid}#approvals",
        ))
    soon = [
        a for a in ws["acceptances"]
        if not a["expired"] and a["expires_on"] is not None
        and (a["expires_on"] - today).days <= SOON_DAYS
    ]
    if soon:
        out.append(Action(
            "medium", f"{len(soon)} risk acceptance{'s' if len(soon) != 1 else ''} expiring "
            f"within {SOON_DAYS} days", "Renew through the AO, or remediate.",
            f"/ato/{sid}#acceptances",
        ))
    ev = ws["evidence"]
    if ev["expired"]:
        out.append(Action(
            "high", f"{ev['expired']} expired evidence object{'s' if ev['expired'] != 1 else ''}",
            "Re-collect before an authorization relies on it.", "/evidence",
        ))
    if ev["awaiting_review"]:
        out.append(Action(
            "medium", f"{ev['awaiting_review']} evidence object"
            f"{'s' if ev['awaiting_review'] != 1 else ''} awaiting review", "", "/evidence",
        ))
    rank = {"urgent": 0, "high": 1, "medium": 2}
    return sorted(out, key=lambda a: rank[a.severity])


async def build(
    session: AsyncSession, system: System, *, today: date | None = None
) -> dict[str, Any]:
    """The workspace for one system the caller has already resolved in scope."""
    today = today or date.today()
    held = await system_roles.holders(session, system.id)
    packages = await _packages(session, system.id)
    current = _current(packages)
    history: list[AuthorizationPackageEvent] = (
        await lifecycle.events(session, current.id) if current is not None else []
    )
    poams = await _poams(session, system.id, today)
    accepted = await acceptances.for_system(session, system.id)
    health = await conmon.health_summary(session, today=today, system_id=system.id)
    days_left = (
        (system.ato_expires_on - today).days if system.ato_expires_on is not None else None
    )
    ws: dict[str, Any] = {
        "today": today,
        "system": {
            "id": system.id, "name": system.name, "baseline": system.baseline,
            "ato_status": system.ato_status or "none",
            "ato_expires_on": system.ato_expires_on, "days_to_expiry": days_left,
        },
        "roles": {
            r: (
                {"user_id": h.user_id, "email": h.email, "name": h.name}
                if (h := held.get(r)) is not None else None
            )
            for r in SYSTEM_ROLES
        },
        "package": (
            {
                "id": current.id, "label": current.label, "kind": current.kind,
                "status": current.status, "created_at": current.created_at,
                "created_by": current.created_by, "fact_count": current.fact_count,
                "readiness_pct": current.readiness_pct,
                "manifest_sha256": current.manifest_sha256,
                "authorization_expires_on": current.authorization_expires_on,
                "status_changed_at": current.status_changed_at,
                "actions": lifecycle.available_actions(current.status),
            }
            if current is not None else None
        ),
        "packages": [
            {"id": p.id, "label": p.label, "status": p.status, "created_at": p.created_at,
             "authorization_expires_on": p.authorization_expires_on}
            for p in packages
        ],
        "history": [
            {"action": e.action, "from": e.from_status, "to": e.to_status, "actor": e.actor,
             "acted_as": e.acted_as, "reason": e.reason, "at": e.created_at,
             "manifest_sha256": e.manifest_sha256}
            for e in history
        ],
        "blockers": [
            {"code": b.code, "title": b.title, "detail": b.detail}
            for b in await lifecycle.blockers(session, system.id, today=today)
        ],
        "poams": poams,
        "extensions": await _pending_extensions(session, poams["ids"]),
        "approvals": await _pending_approvals(session, system.id, poams["ids"]),
        "acceptances": [
            {"kind": a.kind, "label": a.label, "id": a.id, "title": a.title,
             "expires_on": a.expires_on, "expired": a.expired(today),
             "indefinite": a.indefinite, "approved_by": a.approved_by}
            for a in accepted
        ],
        "evidence": await _evidence(session, system.id, today),
        "conmon": {
            "total": health["total"], "by_status": health["by_status"],
            "health_pct": health["health_pct"], "attention": health["attention"][:10],
        },
        "readiness": await _readiness(session, system.id),
    }
    ws["actions"] = [a.__dict__ for a in _actions(ws, today)]
    return ws


async def portfolio(session: AsyncSession, systems: list[System]) -> list[dict[str, Any]]:
    """One row per system for the /ato index: status, package, open blockers."""
    ids = [s.id for s in systems]
    if not ids:
        return []
    latest: dict[int, AuthorizationPackage] = {}
    for p in (
        await session.execute(
            select(AuthorizationPackage)
            .where(AuthorizationPackage.system_id.in_(ids))
            .order_by(AuthorizationPackage.id.desc())
        )
    ).scalars():
        assert p.system_id is not None
        latest.setdefault(p.system_id, p)
    role_counts: dict[int, int] = {
        sid: n
        for sid, n in (
            await session.execute(
                select(
                    SystemRoleAssignment.system_id,
                    func.count(SystemRoleAssignment.id),
                )
                .where(
                    SystemRoleAssignment.system_id.in_(ids),
                    SystemRoleAssignment.role.in_(system_roles.REVIEW_ROLES),
                )
                .group_by(SystemRoleAssignment.system_id)
            )
        ).all()
    }
    today = date.today()
    rows = []
    for s in systems:
        cur = latest.get(s.id)
        rows.append({
            "id": s.id, "name": s.name, "baseline": s.baseline,
            "ato_status": s.ato_status or "none", "ato_expires_on": s.ato_expires_on,
            "days_to_expiry": (s.ato_expires_on - today).days if s.ato_expires_on else None,
            "package_status": cur.status if cur is not None else None,
            "package_id": cur.id if cur is not None else None,
            "roles_assigned": role_counts.get(s.id, 0),
            "blockers": len(await lifecycle.blockers(session, s.id, today=today)),
        })
    return rows
