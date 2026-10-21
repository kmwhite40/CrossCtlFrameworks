"""Intelligence and cross-system views (GRC build-out, workstream G).

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, "G -- intel".

* ``/intel`` -- the org's open POA&Ms (scan findings included) whose CVE ids
  CISA's Known Exploited Vulnerabilities catalog lists; admin "sync now".
* ``/analytics`` -- a safe studio: counts by allowlisted dimensions
  (``ccf.analytics.studio``); nothing typed reaches SQL.
* ``/implementations``, ``/inheritance`` -- control implementations across
  live systems; inherited and hybrid ones with their FedRAMP dependencies.
* ``/remediation`` -- remediation plans (``models_enforcement``): plan,
  approve, apply, reverse through the enforcement service, admin-gated.
* ``/issues`` -- one list of open POA&Ms, audit findings, vendor findings and
  failing control tests, by severity and age.

Tenant scope is explicit in every query, never left to RLS. Records without
``organization_id`` scope through a live system (``posture.org_system_subq``).
Writes: the KEV sync, and the remediation-plan transitions; all admin-only
and audited.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import posture, studio
from ...auth import Principal
from ...constants import POAM_ACTIVE_STATUSES
from ...enforcement.service import (
    EnforcementError,
    apply_plan,
    approve_plan,
    create_plan,
    reverse_plan,
)
from ...enforcement.types import provider_for
from ...intel import kev
from ...logging import get_logger
from ...models import (
    POAM,
    Control,
    ControlImplementation,
    FedRAMPDependency,
    System,
    User,
    Vendor,
)
from ...models_enforcement import PLAN_STATUSES, RemediationPlan
from ...models_grc import AuditEngagement, AuditFinding, ControlTest, ControlTestResult
from ...models_program import VendorFinding
from .. import navigation
from ..audit import record_event
from ..auth_deps import require_platform_admin, require_role
from ..deps import get_session
from .enforcement import ENFORCER_ROLES, _require_plan
from .systems import require_system_in_scope
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)
log = get_logger(__name__)


def _key(wanted: str, fallback: str) -> str:
    """The spec's navigation key once the rail has it, else the nearest entry.

    ``intel`` and ``analytics`` are new keys the integrator adds to
    ``navigation.py`` (a shared file this workstream does not edit). Until
    then the page highlights the entry it grew out of, so the rail is never
    left with nothing marked current."""
    return wanted if navigation.locate(wanted)[1] is not None else fallback


def _render(
    request: Request, template: str, active: str, status_code: int = 200, **ctx: Any
) -> HTMLResponse:
    return templates.TemplateResponse(
        request, template, {"active": active, **ctx}, status_code=status_code
    )


async def _user_names(session: AsyncSession, ids: set[int | None]) -> dict[int, str]:
    real = {i for i in ids if i is not None}
    if not real:
        return {}
    rows = (
        await session.execute(select(User.id, User.full_name, User.email).where(User.id.in_(real)))
    ).all()
    return {r.id: (r.full_name or r.email) for r in rows}


async def _live_systems(session: AsyncSession, org: int | None) -> list[Any]:
    stmt = select(System.id, System.name).where(System.id.in_(posture.org_system_subq(org)))
    return list((await session.execute(stmt.order_by(System.name))).all())


# ── /intel: CISA KEV ─────────────────────────────────────────────────────────


async def _intel_page(
    request: Request,
    session: AsyncSession,
    *,
    sync_error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    org = _principal_org(request)
    catalog = await kev.catalog_status(session)
    found = await kev.kev_matches(session, org)
    principal = getattr(request.state, "principal", None)
    return _render(
        request,
        "intel.html",
        _key("intel", "operations"),
        status_code=status_code,
        catalog=catalog,
        found=found,
        # The catalog is global: only a platform-wide principal may refresh it.
        can_sync=principal is None or principal.is_global,
        sync_error=sync_error,
        synced=request.query_params.get("synced"),
        source_url=kev.KEV_URL,
        today=date.today(),
    )


@router.get("/intel", response_class=HTMLResponse)
async def intel_page(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
    return await _intel_page(request, session)


@router.post("/intel/kev/sync")
async def intel_kev_sync(
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_platform_admin()),
) -> Response:
    """Download CISA's catalog now and replace ``kev_entries`` with it.

    Platform administrators only (an unscoped principal): ``kev_entries`` is
    one table shared by every tenant, so a tenant's administrator -- whom
    ``require_role("admin")`` would admit -- has no authority over it. Tenants
    get the catalog from this, the ``ccf kev-sync`` command, or the scheduler
    step (``kev.refresh_kev``). The event is recorded platform-wide
    (``organization_id=None``), as a catalog revision adoption is: every
    tenant can see that the catalog beneath it moved, and who moved it. A
    failure is shown on the page with its reason (502) and audited; the
    catalog is left as it was."""
    try:
        result = await kev.sync_kev(session, await kev.fetch_kev())
    except kev.KevError as exc:
        log.warning("intel.kev_sync_failed", error=str(exc))
        # No rollback: nothing was written (fetch and parse fail before the
        # savepoint), and a ROLLBACK would also undo this session's RLS
        # tenant binding (``db.set_session_tenant``).
        await record_event(
            session,
            organization_id=None,
            actor=principal.email,
            action="kev_sync_failed",
            entity_type="kev_catalog",
            entity_id=None,
            diff={"error": str(exc)[:500]},
        )
        await session.commit()
        return await _intel_page(request, session, sync_error=str(exc), status_code=502)
    await record_event(
        session,
        organization_id=None,
        actor=principal.email,
        action="kev_sync",
        entity_type="kev_catalog",
        entity_id=result["catalog_version"],
        diff={k: v for k, v in result.items() if k != "skipped_detail"},
    )
    await session.commit()
    return RedirectResponse(f"/intel?synced={result['total']}", status_code=303)


# ── /analytics: the safe studio ──────────────────────────────────────────────


@router.get("/analytics", response_class=HTMLResponse)
async def analytics_studio(
    request: Request,
    session: AsyncSession = Depends(get_session),
    register: str | None = Query(None, max_length=40),
    by: str | None = Query(None, max_length=40),
    then: str | None = Query(None, max_length=40),
) -> Response:
    """No register chosen: the picker. Any key not in the allowlist: 400."""
    org = _principal_org(request)
    result = chart = reg = None
    if register:
        try:
            result = await studio.run(session, org, register, [by or "", then or ""])
        except studio.StudioError as exc:
            raise HTTPException(400, str(exc)) from exc
        reg = result["register"]
        chart = studio.chart(result)
    return _render(
        request,
        "analytics_studio.html",
        _key("analytics", "queries"),
        registers=list(studio.REGISTERS.values()),
        reg=reg,
        by=by or "",
        then=then or "",
        result=result,
        chart=chart,
    )


# ── /implementations ─────────────────────────────────────────────────────────

_IMPL_STATUSES = (
    "implemented",
    "partial",
    "planned",
    "not_implemented",
    "inherited",
    "not_applicable",
)
_RESPONSIBILITIES = ("customer", "provider", "shared", "inherited")
_IMPL_LIMIT = 500


@router.get("/implementations", response_class=HTMLResponse)
async def implementations_page(
    request: Request,
    *,
    session: AsyncSession = Depends(get_session),
    status: str | None = Query(None, max_length=32),
    responsibility: str | None = Query(None, max_length=32),
    system: int | None = Query(None),
    q: str | None = Query(None, max_length=80),
) -> HTMLResponse:
    org = _principal_org(request)
    status = status if status in _IMPL_STATUSES else None
    if responsibility not in (*_RESPONSIBILITIES, "unassigned"):
        responsibility = None
    where: list[Any] = [ControlImplementation.system_id.in_(posture.org_system_subq(org))]
    counts = Counter(
        {
            s: int(n)
            for s, n in (
                await session.execute(
                    select(ControlImplementation.status, func.count())
                    .where(*where)
                    .group_by(ControlImplementation.status)
                )
            ).all()
        }
    )
    if status:
        where.append(ControlImplementation.status == status)
    if responsibility == "unassigned":
        where.append(ControlImplementation.responsibility.is_(None))
    elif responsibility:
        where.append(ControlImplementation.responsibility == responsibility)
    if system is not None:
        where.append(ControlImplementation.system_id == system)
    if q and q.strip():
        where.append(Control.identifier.icontains(q.strip(), autoescape=True))
    base = (
        select(ControlImplementation, System.name.label("system"), Control.identifier)
        .join(System, System.id == ControlImplementation.system_id)
        .join(Control, Control.id == ControlImplementation.control_id)
        .where(*where)
    )
    matched = (
        await session.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()
    rows = (
        await session.execute(
            base.order_by(System.name, Control.sort_as, Control.identifier).limit(_IMPL_LIMIT)
        )
    ).all()
    owners = await _user_names(session, {r.ControlImplementation.owner_user_id for r in rows})
    return _render(
        request,
        "implementations.html",
        "ctrl_impl",
        rows=rows,
        owners=owners,
        matched=int(matched),
        limit=_IMPL_LIMIT,
        total=sum(counts.values()),
        counts=counts,
        statuses=_IMPL_STATUSES,
        responsibilities=_RESPONSIBILITIES,
        systems=await _live_systems(session, org),
        f={"status": status, "responsibility": responsibility, "system": system, "q": q or ""},
        today=date.today(),
    )


# ── /inheritance ─────────────────────────────────────────────────────────────


def norm_control(raw: Any) -> str:
    """``ac-02`` and ``AC-2`` name the same control; ``AC-2(1)`` keeps its part."""
    s = str(raw or "").strip().upper().replace(" ", "")
    head, sep, tail = s.partition("-")
    if sep and tail:
        i = 0
        while i < len(tail) - 1 and tail[i] == "0" and tail[i + 1].isdigit():
            i += 1
        tail = tail[i:]
    return f"{head}{sep}{tail}"


def _inherited_kind(impl: ControlImplementation) -> str:
    """``hybrid`` for shared responsibility; otherwise ``inherited``."""
    return "hybrid" if impl.responsibility == "shared" else "inherited"


@router.get("/inheritance", response_class=HTMLResponse)
async def inheritance_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    system: int | None = Query(None),
) -> HTMLResponse:
    org = _principal_org(request)
    live = posture.org_system_subq(org)
    impl_where: list[Any] = [
        ControlImplementation.system_id.in_(live),
        or_(
            ControlImplementation.status == "inherited",
            ControlImplementation.responsibility.in_(("inherited", "provider", "shared")),
        ),
    ]
    dep_where: list[Any] = [FedRAMPDependency.system_id.in_(live)]
    if system is not None:
        impl_where.append(ControlImplementation.system_id == system)
        dep_where.append(FedRAMPDependency.system_id == system)
    impls = (
        await session.execute(
            select(ControlImplementation, System.name.label("system"), Control.identifier)
            .join(System, System.id == ControlImplementation.system_id)
            .join(Control, Control.id == ControlImplementation.control_id)
            .where(*impl_where)
            .order_by(System.name, Control.sort_as, Control.identifier)
        )
    ).all()
    deps = (
        await session.execute(
            select(FedRAMPDependency, System.name.label("system"))
            .join(System, System.id == FedRAMPDependency.system_id)
            .where(*dep_where)
            .order_by(System.name, FedRAMPDependency.name)
        )
    ).all()
    # (system, normalised control) -> the dependencies on that system listing it
    listed: dict[tuple[int, str], list[FedRAMPDependency]] = defaultdict(list)
    for d in deps:
        dep = d.FedRAMPDependency
        for c in dep.inherited_controls or []:
            listed[(dep.system_id, norm_control(c))].append(dep)
    by_system: dict[int, dict[str, Any]] = {}
    recorded: set[tuple[int, str]] = set()
    for r in impls:
        impl = r.ControlImplementation
        kind = _inherited_kind(impl)
        key = (impl.system_id, norm_control(r.identifier))
        recorded.add(key)
        block = by_system.setdefault(
            impl.system_id, {"name": r.system, "id": impl.system_id, "rows": [], "kinds": Counter()}
        )
        block["kinds"][kind] += 1
        block["rows"].append(
            {"impl": impl, "control": r.identifier, "kind": kind, "providers": listed.get(key, [])}
        )
    dep_rows = []
    for d in deps:
        dep = d.FedRAMPDependency
        names = [str(c) for c in dep.inherited_controls or []]
        unrecorded = [c for c in names if (dep.system_id, norm_control(c)) not in recorded]
        dep_rows.append({"dep": dep, "system": d.system, "listed": names, "unrecorded": unrecorded})
    kinds: Counter[str] = Counter()
    for b in by_system.values():
        kinds.update(b["kinds"])
    return _render(
        request,
        "inheritance.html",
        "ctrl_inherit",
        blocks=list(by_system.values()),
        kinds=kinds,
        deps=dep_rows,
        without_provider=sum(
            1 for b in by_system.values() for r in b["rows"] if not r["providers"]
        ),
        systems=await _live_systems(session, org),
        system=system,
    )


# ── /remediation: the plan workflow ──────────────────────────────────────────
#
# The page drives the enforcement service (``ccf.enforcement.service``) through
# exactly the calls the API makes: ``create_plan``, ``approve_plan``,
# ``apply_plan``, ``reverse_plan``. Same role gate (``ENFORCER_ROLES``), same
# plan lookup (``enforcement._require_plan``: another tenant's plan is a 404),
# same system scope (``require_system_in_scope``). Separation of duties (the
# requester may not approve), the write-credential, blast-radius and
# stale-approval re-checks, and the audit events all live in the service, so
# this page cannot weaken them. A refusal is shown with its reason (409).


async def _remediation_page(
    request: Request,
    session: AsyncSession,
    *,
    status: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    org = _principal_org(request)
    live = posture.org_system_subq(org)
    where: list[Any] = [RemediationPlan.system_id.in_(live)]
    if org is not None:
        where.append(RemediationPlan.organization_id == org)
    counts = Counter(
        {
            s: int(n)
            for s, n in (
                await session.execute(
                    select(RemediationPlan.status, func.count())
                    .where(*where)
                    .group_by(RemediationPlan.status)
                )
            ).all()
        }
    )
    status = status if status in PLAN_STATUSES else None
    if status:
        where.append(RemediationPlan.status == status)
    rows = (
        await session.execute(
            select(RemediationPlan, System.name.label("system"))
            .join(System, System.id == RemediationPlan.system_id)
            .where(*where)
            .order_by(RemediationPlan.created_at.desc(), RemediationPlan.id.desc())
            .limit(500)
        )
    ).all()
    # Failing checks a registered provider can remediate: what "plan a
    # remediation" can be asked for. Anything else would only be refused.
    ct_where: list[Any] = [
        ControlTest.system_id.in_(live),
        ControlTest.check_key.is_not(None),
        ControlTest.last_status == "fail",
    ]
    if org is not None:
        ct_where.append(ControlTest.organization_id == org)
    remediable = [
        r
        for r in (
            await session.execute(
                select(
                    ControlTest.system_id,
                    System.name.label("system"),
                    ControlTest.check_key,
                    ControlTest.name.label("test"),
                )
                .join(System, System.id == ControlTest.system_id)
                .where(*ct_where)
                .order_by(System.name, ControlTest.check_key)
            )
        ).all()
        if provider_for(r.check_key) is not None
    ]
    principal = getattr(request.state, "principal", None)
    return _render(
        request,
        "remediation_plans.html",
        "remediation",
        status_code=status_code,
        rows=rows,
        counts=counts,
        total=sum(counts.values()),
        statuses=PLAN_STATUSES,
        status=status,
        remediable=remediable,
        can_act=principal is None or principal.is_global or principal.role in ENFORCER_ROLES,
        me=getattr(principal, "email", None),
        error=error,
    )


@router.get("/remediation", response_class=HTMLResponse)
async def remediation_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    status: str | None = Query(None, max_length=24),
) -> HTMLResponse:
    return await _remediation_page(request, session, status=status)


@router.post("/remediation/plans")
async def remediation_create(
    request: Request,
    *,
    system_id: int = Form(...),
    check_key: str = Form(..., max_length=128),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> Response:
    """Plan a remediation for a failing check (``POST /api/systems/{id}/remediation-plans``).

    A refused plan is a stored row and redirects like any other; only "no plan
    at all" (no provider for the check) is an error."""
    await require_system_in_scope(session, system_id, principal)
    try:
        plan = await create_plan(
            session, system_id=system_id, check_key=check_key.strip(), actor=principal.email
        )
    except EnforcementError as exc:
        return await _remediation_page(request, session, error=str(exc), status_code=409)
    await session.commit()
    return RedirectResponse(f"/remediation#plan-{plan.id}", status_code=303)


async def _transition(
    request: Request,
    session: AsyncSession,
    principal: Principal,
    plan_id: int,
    action: Any,
    **kw: Any,
) -> Response:
    plan = await _require_plan(session, plan_id, principal)
    try:
        await action(session, plan, **kw)
    except EnforcementError as exc:
        return await _remediation_page(
            request, session, error=f"Plan #{plan_id}: {exc}", status_code=409
        )
    await session.commit()
    return RedirectResponse(f"/remediation#plan-{plan_id}", status_code=303)


@router.post("/remediation/{plan_id}/approve")
async def remediation_approve(
    request: Request,
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> Response:
    """Approve (``POST /api/remediation-plans/{id}/approve``); not the requester."""
    return await _transition(
        request, session, principal, plan_id, approve_plan, approver=principal.email
    )


@router.post("/remediation/{plan_id}/apply")
async def remediation_apply(
    request: Request,
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> Response:
    """Apply (``POST /api/remediation-plans/{id}/apply``): writes to the environment."""
    return await _transition(
        request, session, principal, plan_id, apply_plan, actor=principal.email
    )


@router.post("/remediation/{plan_id}/reverse")
async def remediation_reverse(
    request: Request,
    plan_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ENFORCER_ROLES)),
) -> Response:
    """Reverse (``POST /api/remediation-plans/{id}/reverse``)."""
    return await _transition(
        request, session, principal, plan_id, reverse_plan, actor=principal.email
    )


# ── /issues ──────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}
SEVERITIES = ("critical", "high", "moderate", "low", "unrated")
ISSUE_KINDS = ("poam", "audit_finding", "vendor_finding", "control_test")
ISSUE_LABELS = {
    "poam": "POA&M",
    "audit_finding": "Audit finding",
    "vendor_finding": "Vendor finding",
    "control_test": "Failing control test",
}
_VENDOR_OPEN = ("open", "remediating")


def _day(v: Any) -> date | None:
    if v is None:
        return None
    return v.date() if isinstance(v, datetime) else v


def _severity(raw: str | None) -> str:
    s = (raw or "").strip().lower()
    if s == "medium":
        return "moderate"
    return s if s in _SEV_ORDER else "unrated"


async def collect_issues(
    session: AsyncSession, org: int | None, today: date
) -> list[dict[str, Any]]:
    """Every open issue the org has, in one shape: kind, title, severity,
    opened, age in days, due, context, link. Highest severity first, then
    oldest."""
    live = posture.org_system_subq(org)
    out: list[dict[str, Any]] = []

    def add(kind: str, title: str, severity: str | None, opened: Any, due: Any, **kw: Any) -> None:
        o, d = _day(opened), _day(due)
        out.append(
            {
                "kind": kind,
                "label": ISSUE_LABELS[kind],
                "title": title,
                "severity": _severity(severity),
                "opened": o,
                "age": (today - o).days if o else None,
                "due": d,
                "overdue": bool(d and d < today),
                **kw,
            }
        )

    poams = await session.execute(
        select(POAM, System.name)
        .join(System, System.id == POAM.system_id)
        .where(POAM.system_id.in_(live), POAM.status.in_(POAM_ACTIVE_STATUSES))
    )
    for p, sysname in poams.all():
        add(
            "poam",
            p.title,
            p.severity,
            p.identified_on,
            p.due_on,
            context=sysname,
            status=p.status,
            href="/poams",
        )

    af_where: list[Any] = [
        AuditFinding.status != "closed",
        or_(AuditFinding.system_id.is_(None), AuditFinding.system_id.in_(live)),
    ]
    if org is not None:
        af_where.append(AuditEngagement.organization_id == org)
    findings = await session.execute(
        select(AuditFinding, AuditEngagement.name)
        .join(AuditEngagement, AuditEngagement.id == AuditFinding.engagement_id)
        .where(*af_where)
    )
    for f, eng in findings.all():
        add(
            "audit_finding",
            f.title,
            f.severity,
            f.created_at,
            None,
            context=eng,
            status=f.status,
            href=f"/audit-workspace/{f.engagement_id}",
        )

    vf_where: list[Any] = [VendorFinding.status.in_(_VENDOR_OPEN)]
    if org is not None:
        vf_where.append(VendorFinding.organization_id == org)
    vfindings = await session.execute(
        select(VendorFinding, Vendor.name)
        .join(Vendor, Vendor.id == VendorFinding.vendor_id)
        .where(*vf_where)
    )
    for f, vname in vfindings.all():
        add(
            "vendor_finding",
            f.title,
            f.severity,
            f.created_at,
            f.due_on,
            context=vname,
            status=f.status,
            href=f"/vendors#vendor-{f.vendor_id}",
        )

    ct_where: list[Any] = [
        ControlTest.active.is_(True),
        ControlTest.last_status == "fail",
        or_(ControlTest.system_id.is_(None), ControlTest.system_id.in_(live)),
    ]
    if org is not None:
        ct_where.append(ControlTest.organization_id == org)
    tests = (
        await session.execute(
            select(ControlTest, System.name)
            .outerjoin(System, System.id == ControlTest.system_id)
            .where(*ct_where)
        )
    ).all()
    since = await _failing_since(session, [t.id for t, _ in tests])
    for t, sysname in tests:
        add(
            "control_test",
            t.name,
            None,
            since.get(t.id) or t.last_tested_at,
            None,
            context=t.control_id + (f" · {sysname}" if sysname else ""),
            status="failing",
            href=f"/control-tests/{t.id}",
        )

    out.sort(
        key=lambda i: (
            _SEV_ORDER.get(i["severity"], 9),
            -(i["age"] if i["age"] is not None else -1),
            i["title"],
        )
    )
    return out


async def _failing_since(session: AsyncSession, test_ids: list[int]) -> dict[int, datetime]:
    """The first ``fail`` run after each test's latest non-failing run: when
    the current failure began, not merely when it was last observed."""
    if not test_ids:
        return {}
    last_ok = (
        select(
            ControlTestResult.control_test_id.label("tid"),
            func.max(ControlTestResult.run_at).label("ok_at"),
        )
        .where(ControlTestResult.control_test_id.in_(test_ids), ControlTestResult.status != "fail")
        .group_by(ControlTestResult.control_test_id)
        .subquery()
    )
    rows = (
        await session.execute(
            select(ControlTestResult.control_test_id, func.min(ControlTestResult.run_at))
            .outerjoin(last_ok, last_ok.c.tid == ControlTestResult.control_test_id)
            .where(
                ControlTestResult.control_test_id.in_(test_ids),
                ControlTestResult.status == "fail",
                or_(last_ok.c.ok_at.is_(None), ControlTestResult.run_at > last_ok.c.ok_at),
            )
            .group_by(ControlTestResult.control_test_id)
        )
    ).all()
    return {tid: at for tid, at in rows if at is not None}


@router.get("/issues", response_class=HTMLResponse)
async def issues_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    kind: str | None = Query(None, max_length=24),
    severity: str | None = Query(None, max_length=16),
) -> HTMLResponse:
    org = _principal_org(request)
    issues = await collect_issues(session, org, datetime.now(UTC).date())
    by_kind = Counter(i["kind"] for i in issues)
    by_sev = Counter(i["severity"] for i in issues)
    kind = kind if kind in ISSUE_KINDS else None
    severity = severity if severity in SEVERITIES else None
    shown = [
        i
        for i in issues
        if (kind is None or i["kind"] == kind) and (severity is None or i["severity"] == severity)
    ]
    return _render(
        request,
        "issues.html",
        "issues",
        issues=shown,
        total=len(issues),
        by_kind=by_kind,
        by_sev=by_sev,
        kinds=ISSUE_KINDS,
        labels=ISSUE_LABELS,
        severities=SEVERITIES,
        kind=kind,
        severity=severity,
    )
