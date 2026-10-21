"""Pages for records Concord already keeps but had no screen for, plus the
shell's own endpoints (record search, the notification center).

Every page here is a *read* over existing models. Where the records can be
changed, the change goes through the API route that already owns the guard
(approvals, policy attestation, waivers, notification read-state) -- a second
write path here would be a second place to forget the guard, which is how the
UI scan upload lost its own (see ``scans.ingest_upload``).

Tenant scope is explicit in every query, not left to RLS: RLS masks a missing
org predicate in tests, and the platform has shipped that bug before. Records
without their own ``organization_id`` (risks, POA&Ms, implementations) are
scoped through a live system via ``posture.org_system_subq``.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import posture
from ...analytics.command_center import RISK_LEVELS, TASK_OPEN_STATUSES, risk_matrix
from ...constants import POAM_ACTIVE_STATUSES
from ...governance import inbox
from ...governance.risk import band
from ...models import (
    KSI,
    POAM,
    Approval,
    Control,
    ControlImplementation,
    Framework,
    KSIException,
    Notification,
    Policy,
    PolicyAttestation,
    PolicyVersion,
    Risk,
    System,
    Task,
    User,
    Vendor,
)
from ...models_evidence import EvidenceObject
from ...models_grc import AuditEngagement, AuditRequest
from ...models_tprm import VendorQuestionnaire
from ...models_waivers import Waiver
from .. import navigation
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)


def _principal(request: Request) -> Any:
    return getattr(request.state, "principal", None)


def _user_id(request: Request) -> int | None:
    return getattr(_principal(request), "user_id", None)


def _render(request: Request, template: str, active: str, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"active": active, **ctx})


async def _user_names(session: AsyncSession, ids: set[int]) -> dict[int, str]:
    ids = {i for i in ids if i is not None}
    if not ids:
        return {}
    rows = (
        await session.execute(select(User.id, User.full_name, User.email).where(User.id.in_(ids)))
    ).all()
    return {r.id: (r.full_name or r.email) for r in rows}


# ── "Planned" placeholders ───────────────────────────────────────────────────


@router.get("/planned/{slug}", response_class=HTMLResponse)
async def planned_page(request: Request, slug: str) -> HTMLResponse:
    """What a navigation item would be, said plainly, for a capability Concord
    does not have. Never a mock screen: the page names the missing model."""
    found = navigation.planned(slug)
    if found is None:
        raise HTTPException(404, "no such planned capability")
    group, item = found
    nearby = []
    for href in item.nearby:
        label = next((i.label for _, i in navigation.all_items() if i.href == href), href)
        nearby.append({"href": href, "label": label})
    return _render(request, "planned.html", item.key, group=group, item=item, nearby=nearby)


# ── Global record search (command palette) ───────────────────────────────────


def _like(column: Any, q: str) -> Any:
    return column.icontains(q, autoescape=True)


@router.get("/ui/search")
async def record_search(
    request: Request,
    q: str = Query(..., min_length=2, max_length=120),
    session: AsyncSession = Depends(get_session),
) -> JSONResponse:
    """Records whose name matches ``q``, across the record types a user works.

    Scoped to the caller's organization in every query. Catalog controls and
    frameworks are shared reference data and are searched for everyone."""
    org = _principal_org(request)
    live = posture.org_system_subq(org)
    out: list[dict[str, Any]] = []

    def add(kind: str, label: str, href: str) -> None:
        out.append({"kind": kind, "label": label, "href": href})

    for r in (
        await session.execute(
            select(Control.identifier, Control.control_name)
            .where(or_(_like(Control.identifier, q), _like(Control.control_name, q)))
            .order_by(func.length(Control.identifier))
            .limit(5)
        )
    ).all():
        add(
            "Control",
            f"{r.identifier} — {r.control_name or ''}".rstrip(" —"),
            f"/controls/{r.identifier}",
        )
    for r in (
        await session.execute(
            select(Framework.code, Framework.name)
            .where(or_(_like(Framework.code, q), _like(Framework.name, q)))
            .limit(3)
        )
    ).all():
        add("Framework", r.name or r.code, f"/frameworks/{r.code}")

    sys_stmt = (
        select(System.id, System.name).where(System.id.in_(live), _like(System.name, q)).limit(5)
    )
    for r in (await session.execute(sys_stmt)).all():
        add("System", r.name, f"/systems/{r.id}")
    for r in (
        await session.execute(
            select(Risk.id, Risk.title, System.name.label("system"))
            .join(System, System.id == Risk.system_id)
            .where(Risk.system_id.in_(live), _like(Risk.title, q))
            .limit(5)
        )
    ).all():
        add(f"Risk · {r.system}", r.title, f"/risks/heatmap#risk-{r.id}")
    for r in (
        await session.execute(
            select(POAM.id, POAM.title, POAM.system_id, System.name.label("system"))
            .join(System, System.id == POAM.system_id)
            .where(POAM.system_id.in_(live), _like(POAM.title, q))
            .limit(5)
        )
    ).all():
        add(f"POA&M · {r.system}", r.title, f"/poams?system_id={r.system_id}")

    def org_filter(col: Any) -> list[Any]:
        return [col == org] if org is not None else []

    for r in (
        await session.execute(
            select(EvidenceObject.id, EvidenceObject.title)
            .where(*org_filter(EvidenceObject.organization_id), _like(EvidenceObject.title, q))
            .limit(5)
        )
    ).all():
        add("Evidence", r.title, "/evidence")
    for r in (
        await session.execute(
            select(Policy.id, Policy.name)
            .where(*org_filter(Policy.organization_id), _like(Policy.name, q))
            .limit(5)
        )
    ).all():
        add("Policy", r.name, f"/policies#policy-{r.id}")
    for r in (
        await session.execute(
            select(Vendor.id, Vendor.name)
            .where(*org_filter(Vendor.organization_id), _like(Vendor.name, q))
            .limit(5)
        )
    ).all():
        add("Vendor", r.name, f"/vendors#vendor-{r.id}")
    for r in (
        await session.execute(
            select(AuditEngagement.id, AuditEngagement.name)
            .where(*org_filter(AuditEngagement.organization_id), _like(AuditEngagement.name, q))
            .limit(3)
        )
    ).all():
        add("Audit", r.name, f"/audit-workspace/{r.id}")
    for r in (
        await session.execute(
            select(Task.id, Task.title)
            .where(*org_filter(Task.organization_id), _like(Task.title, q))
            .limit(5)
        )
    ).all():
        add("Task", r.title, "/governance#tasks")
    return JSONResponse({"query": q, "results": out[:30]})


# ── Notification center ──────────────────────────────────────────────────────


@router.get("/ui/notifications/badge", response_class=HTMLResponse)
async def notifications_badge(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    principal = _principal(request)
    n = await inbox.unread_count(session, principal) if principal is not None else 0
    label = "99+" if n > 99 else (str(n) if n else "")
    return HTMLResponse(
        f'<span class="topbar__badge" id="notif-badge" hx-get="/ui/notifications/badge" '
        f'hx-trigger="notif-changed from:body" hx-swap="outerHTML" '
        f'aria-label="{n} unread">{label}</span>'
    )


async def _inbox(
    session: AsyncSession,
    principal: Any,
    *,
    limit: int,
    unread: bool = False,
    category: str | None = None,
) -> dict[str, Any]:
    stmt = inbox.visible(principal)
    if unread:
        stmt = inbox.unread_only(stmt, principal)
    if category:
        stmt = stmt.where(Notification.category == category)
    rows = list((await session.execute(stmt.limit(limit))).scalars().all())
    read = await inbox.read_ids(session, principal, rows)
    cats = sorted(
        c
        for c in (
            await session.execute(
                inbox.visible(principal)
                .with_only_columns(Notification.category)
                .distinct()
                .order_by(None)
            )
        )
        .scalars()
        .all()
        if c
    )
    return {
        "entries": rows,
        "read": read,
        "unread": await inbox.unread_count(session, principal),
        "categories": cats,
    }


@router.get("/ui/notifications/panel", response_class=HTMLResponse)
async def notifications_panel(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    principal = _principal(request)
    if principal is None:
        return HTMLResponse('<p class="panel__empty">Sign in to see notifications.</p>')
    box = await _inbox(session, principal, limit=15)
    return templates.TemplateResponse(request, "_notifications.html", {"box": box, "compact": True})


@router.get("/notifications", response_class=HTMLResponse)
async def notifications_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    unread: bool = Query(False),
    category: str | None = Query(None, max_length=32),
) -> HTMLResponse:
    principal = _principal(request)
    box = (
        await _inbox(session, principal, limit=200, unread=unread, category=category)
        if principal
        else None
    )
    return _render(
        request, "notifications.html", "notifications", box=box, unread=unread, category=category
    )


# ── My tasks ─────────────────────────────────────────────────────────────────


@router.get("/my-tasks", response_class=HTMLResponse)
async def my_tasks(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    """Work assigned to the signed-in user: tasks, POA&Ms they own, and
    evidence requests they owe an auditor. Organization scope applies on top
    of assignment, so an assignment that crossed a tenant boundary shows
    nothing rather than leaking a title."""
    uid = _user_id(request)
    org = _principal_org(request)
    today = date.today()
    if uid is None:
        return _render(request, "my_tasks.html", "mytasks", signed_in=False)
    live = posture.org_system_subq(org)
    org_where = [Task.organization_id == org] if org is not None else []
    tasks = (
        (
            await session.execute(
                select(Task)
                .where(Task.assignee_user_id == uid, *org_where)
                .order_by(
                    Task.status.in_(TASK_OPEN_STATUSES).desc(),
                    Task.due_on.asc().nulls_last(),
                    Task.id.desc(),
                )
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    poams = (
        await session.execute(
            select(
                POAM.id,
                POAM.title,
                POAM.severity,
                POAM.status,
                POAM.due_on,
                POAM.system_id,
                System.name.label("system"),
            )
            .join(System, System.id == POAM.system_id)
            .where(
                POAM.owner_user_id == uid,
                POAM.system_id.in_(live),
                POAM.status.in_(POAM_ACTIVE_STATUSES),
            )
            .order_by(POAM.due_on.asc().nulls_last())
        )
    ).all()
    eng_where = [AuditEngagement.organization_id == org] if org is not None else []
    requests = (
        await session.execute(
            select(
                AuditRequest.id,
                AuditRequest.title,
                AuditRequest.status,
                AuditRequest.due_on,
                AuditEngagement.id.label("eid"),
                AuditEngagement.name.label("engagement"),
            )
            .join(AuditEngagement, AuditEngagement.id == AuditRequest.engagement_id)
            .where(AuditRequest.owner_user_id == uid, AuditRequest.status != "accepted", *eng_where)
            .order_by(AuditRequest.due_on.asc().nulls_last())
        )
    ).all()
    unassigned = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Task)
                .where(
                    Task.assignee_user_id.is_(None), Task.status.in_(TASK_OPEN_STATUSES), *org_where
                )
            )
        ).scalar_one()
    )
    open_tasks = [t for t in tasks if t.status in TASK_OPEN_STATUSES]
    return _render(
        request,
        "my_tasks.html",
        "mytasks",
        signed_in=True,
        today=today,
        tasks=tasks,
        open_tasks=open_tasks,
        poams=poams,
        requests=requests,
        unassigned=unassigned,
        overdue=sum(1 for t in open_tasks if t.due_on and t.due_on < today)
        + sum(1 for p in poams if p.due_on and p.due_on < today)
        + sum(1 for r in requests if r.due_on and r.due_on < today),
    )


# ── Risk heat map ────────────────────────────────────────────────────────────


@router.get("/risks/heatmap", response_class=HTMLResponse)
async def risk_heatmap(
    request: Request,
    session: AsyncSession = Depends(get_session),
    *,
    l: str | None = Query(None),  # noqa: E741 -- the spec's drill-down parameter
    i: str | None = Query(None),
    likelihood: str | None = Query(None),
    impact: str | None = Query(None),
) -> HTMLResponse:
    """The 5x5 heat map and its drill-down.

    ``?l=&i=`` (1-5 each) selects one cell by effective score. The older
    ``?likelihood=&impact=`` level parameters still work and select every risk
    recorded at those levels (a level spans up to two scores)."""
    from ...governance.risk import (  # noqa: PLC0415
        IMPACT_LABELS,
        LIKELIHOOD_LABELS,
        SCALE,
        appetite_placements,
        effective_scores,
        impact_expr,
        likelihood_expr,
        risk_in_scope,
    )

    org = _principal_org(request)
    matrix = await risk_matrix(session, org)
    cell: tuple[int, int] | None = None
    if (
        l is not None
        and i is not None
        and l.isdigit()
        and i.isdigit()
        and int(l) in SCALE
        and int(i) in SCALE
    ):
        cell = (int(l), int(i))
    if likelihood not in RISK_LEVELS or impact not in RISK_LEVELS:
        likelihood = impact = None
    stmt = (
        select(Risk, System.name.label("system"))
        .outerjoin(System, System.id == Risk.system_id)
        .where(risk_in_scope(org), Risk.status.in_(("open", "mitigated")))
        .order_by(Risk.residual_score.desc().nulls_last(), Risk.id)
    )
    if cell is not None:
        stmt = stmt.where(likelihood_expr() == cell[0], impact_expr() == cell[1])
        likelihood = impact = None
    elif likelihood:
        stmt = stmt.where(Risk.likelihood == likelihood, Risk.impact == impact)
    rows = (await session.execute(stmt)).all()
    owners = await _user_names(session, {r.Risk.owner_user_id for r in rows})
    placements = (
        await appetite_placements(session, org, risk_ids=[r.Risk.id for r in rows])
        if org is not None
        else {}
    )
    return _render(
        request,
        "risk_heatmap.html",
        "riskheat",
        matrix=matrix,
        levels=list(RISK_LEVELS),
        rows=rows,
        owners=owners,
        band=band,
        placements=placements,
        effective=effective_scores,
        lk_labels=LIKELIHOOD_LABELS,
        im_labels=IMPACT_LABELS,
        selected=cell,
        selected_levels=(likelihood, impact) if likelihood else None,
    )


# ── Exceptions (waivers, KSI exceptions, accepted POA&Ms and risks) ──────────


@router.get("/exceptions", response_class=HTMLResponse)
async def exceptions_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """Every standing departure from a requirement, in one list, and the
    requests still waiting for a decision, in another.

    Concord records four kinds in four tables, each decided where it lives
    (the control-test resolution, the KSI page, the POA&M and risk gates). This
    page reads them together and adds no new way to approve one.

    Only an exception in force is counted as one: an ``approved`` waiver (the
    one status that suppresses anything) and an ``accepted`` KSI exception.
    ``requested`` / ``open`` are pending and listed separately; ``revoked`` /
    ``closed`` are history and left out."""
    org = _principal_org(request)
    live = posture.org_system_subq(org)
    today = date.today()
    sys_names = dict(
        (await session.execute(select(System.id, System.name).where(System.id.in_(live)))).all()
    )
    items: list[dict[str, Any]] = []
    for w in (
        (await session.execute(select(Waiver).where(Waiver.system_id.in_(live)))).scalars().all()
    ):
        items.append(
            {
                "kind": "Control-test waiver",
                "anchor": "waiver",
                "subject": w.control_id or w.check_key or "—",
                "detail": w.rationale,
                "status": w.status,
                "standing": w.status == "approved",
                "pending": w.status == "requested",
                "system": sys_names.get(w.system_id),
                "decided_by": w.approved_by,
                "expires": w.expires_on,
                "href": "/control-tests",
            }
        )
    for e, ksi_code in (
        await session.execute(
            select(KSIException, KSI.identifier)
            .join(KSI, KSI.id == KSIException.ksi_id)
            .where(KSIException.system_id.in_(live))
        )
    ).all():
        items.append(
            {
                "kind": "KSI exception",
                "anchor": "ksi",
                "subject": ksi_code,
                "detail": e.rationale,
                "status": e.status,
                "standing": e.status == "accepted",
                "pending": e.status == "open",
                "system": sys_names.get(e.system_id),
                "decided_by": None,
                "expires": e.expires_on,
                "href": "/fedramp20x",
            }
        )
    for p in (
        (
            await session.execute(
                select(POAM).where(POAM.system_id.in_(live), POAM.status == "risk_accepted")
            )
        )
        .scalars()
        .all()
    ):
        items.append(
            {
                "kind": "Accepted POA&M",
                "anchor": "risk",
                "subject": p.title,
                "detail": p.weakness,
                "status": "risk_accepted",
                "standing": True,
                "pending": False,
                "system": sys_names.get(p.system_id),
                "decided_by": None,
                "expires": None,
                "href": f"/poams?system_id={p.system_id}&status=risk_accepted",
            }
        )
    for r in (
        (
            await session.execute(
                select(Risk).where(Risk.system_id.in_(live), Risk.status == "accepted")
            )
        )
        .scalars()
        .all()
    ):
        items.append(
            {
                "kind": "Accepted risk",
                "anchor": "risk",
                "subject": r.title,
                "detail": r.description,
                "status": "accepted",
                "standing": True,
                "pending": False,
                "system": sys_names.get(r.system_id),
                "decided_by": None,
                "expires": r.next_review_on,
                "href": f"/risks/heatmap#risk-{r.id}",
            }
        )
    standing = [i for i in items if i["standing"]]
    pending = [i for i in items if i["pending"]]
    for i in standing:
        # Lapsed is a property of an exception in force; a revoked waiver whose
        # date has passed is not "lapsed", it is not an exception at all.
        i["expired"] = i["expires"] is not None and i["expires"] < today
    standing.sort(key=lambda i: (not i["expired"], i["expires"] or date.max))
    counts = Counter(i["kind"] for i in standing)
    return _render(
        request,
        "exceptions.html",
        "exceptions",
        items=standing,
        pending=pending,
        counts=counts,
        today=today,
    )


# ── Policies and acknowledgments ─────────────────────────────────────────────


@router.get("/policies", response_class=HTMLResponse)
async def policies_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    uid = _user_id(request)
    where = [Policy.organization_id == org] if org is not None else []
    policies = (
        (await session.execute(select(Policy).where(*where).order_by(Policy.name))).scalars().all()
    )
    ids = [p.id for p in policies]
    versions: dict[int, list[Any]] = defaultdict(list)
    attest: Counter[int] = Counter()
    mine: set[int] = set()
    if ids:
        for v in (
            (
                await session.execute(
                    select(PolicyVersion)
                    .where(PolicyVersion.policy_id.in_(ids))
                    .order_by(PolicyVersion.created_at.desc())
                )
            )
            .scalars()
            .all()
        ):
            versions[v.policy_id].append(v)
        vids = [v.id for vs in versions.values() for v in vs]
        if vids:
            for vid, n in (
                await session.execute(
                    # Distinct active members of this organization, so the
                    # figure is comparable with ``members``: a repeat
                    # attestation, a departed user or an outsider read "5 of 3".
                    select(
                        PolicyAttestation.policy_version_id,
                        func.count(func.distinct(PolicyAttestation.user_id)),
                    )
                    .join(User, User.id == PolicyAttestation.user_id)
                    .where(
                        PolicyAttestation.policy_version_id.in_(vids),
                        User.active.is_(True),
                        *([User.organization_id == org] if org is not None else []),
                    )
                    .group_by(PolicyAttestation.policy_version_id)
                )
            ).all():
                attest[vid] = int(n)
            if uid is not None:
                mine = set(
                    (
                        await session.execute(
                            select(PolicyAttestation.policy_version_id).where(
                                PolicyAttestation.policy_version_id.in_(vids),
                                PolicyAttestation.user_id == uid,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
    members = int(
        (
            await session.execute(
                select(func.count())
                .select_from(User)
                .where(
                    User.active.is_(True),
                    *([User.organization_id == org] if org is not None else []),
                )
            )
        ).scalar_one()
    )
    owners = await _user_names(session, {p.owner_user_id for p in policies})
    return _render(
        request,
        "policies.html",
        "policies",
        policies=policies,
        versions=versions,
        attest=attest,
        mine=mine,
        members=members,
        owners=owners,
        today=date.today(),
    )


# ── Control owners ───────────────────────────────────────────────────────────


@router.get("/control-owners", response_class=HTMLResponse)
async def control_owners(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    rows = (
        await session.execute(
            select(ControlImplementation.owner_user_id, ControlImplementation.status, func.count())
            .where(ControlImplementation.system_id.in_(posture.org_system_subq(org)))
            .group_by(ControlImplementation.owner_user_id, ControlImplementation.status)
        )
    ).all()
    by_owner: dict[int | None, Counter[str]] = defaultdict(Counter)
    for owner, status, n in rows:
        by_owner[owner][status] += int(n)
    names = await _user_names(session, {o for o in by_owner if o is not None})
    owners = sorted(
        (
            {
                "id": o,
                "name": names.get(o, f"User {o}") if o is not None else None,
                "counts": c,
                "total": sum(c.values()),
            }
            for o, c in by_owner.items()
        ),
        key=lambda r: (r["id"] is None, -r["total"]),
    )
    statuses = sorted({s for c in by_owner.values() for s in c})
    total = sum(r["total"] for r in owners)
    unowned = next((r["total"] for r in owners if r["id"] is None), 0)
    return _render(
        request,
        "control_owners.html",
        "ctrl_owners",
        owners=owners,
        statuses=statuses,
        total=total,
        unowned=unowned,
    )


# ── Vendors ──────────────────────────────────────────────────────────────────


@router.get("/vendors", response_class=HTMLResponse)
async def vendors_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    where = [Vendor.organization_id == org] if org is not None else []
    vendors = (
        (await session.execute(select(Vendor).where(*where).order_by(Vendor.name))).scalars().all()
    )
    latest: dict[int, Any] = {}
    counts: Counter[int] = Counter()
    if vendors:
        for q in (
            (
                await session.execute(
                    select(VendorQuestionnaire)
                    .where(VendorQuestionnaire.vendor_id.in_([v.id for v in vendors]))
                    .order_by(VendorQuestionnaire.created_at.desc())
                )
            )
            .scalars()
            .all()
        ):
            counts[q.vendor_id] += 1
            latest.setdefault(q.vendor_id, q)
    risks: Counter[int] = Counter()
    if vendors:
        for vid, n in (
            await session.execute(
                select(Risk.vendor_id, func.count())
                .where(
                    Risk.vendor_id.in_([v.id for v in vendors]),
                    Risk.status.in_(("open", "mitigated")),
                    Risk.system_id.in_(posture.org_system_subq(org)),
                )
                .group_by(Risk.vendor_id)
            )
        ).all():
            risks[vid] = int(n)
    return _render(
        request,
        "vendors.html",
        "vendors",
        vendors=vendors,
        latest=latest,
        counts=counts,
        risks=risks,
        today=date.today(),
    )


# ── Approvals ────────────────────────────────────────────────────────────────

_APPROVAL_LINKS = {
    "ssp_project": "/ssp/{id}",
    "poam": "/poams",
    "risk": "/risks/heatmap#risk-{id}",
    "assessment": "/assessments/{id}",
    "policy": "/policies#policy-{id}",
}


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """The approval queue and its history. Decisions stay on the API
    (``/api/approvals``), which enforces separation of duties and single use;
    this page only shows where each request stands."""
    org = _principal_org(request)
    where = [Approval.organization_id == org] if org is not None else []
    approvals = (
        (
            await session.execute(
                select(Approval).where(*where).order_by(Approval.updated_at.desc()).limit(300)
            )
        )
        .scalars()
        .all()
    )
    rows = [
        {
            "a": a,
            "href": (
                _APPROVAL_LINKS[a.entity_type].format(id=a.entity_id)
                if a.entity_type in _APPROVAL_LINKS
                else None
            ),
        }
        for a in approvals
    ]
    states = Counter(a.state for a in approvals)
    return _render(request, "approvals.html", "approvals", rows=rows, states=states)
