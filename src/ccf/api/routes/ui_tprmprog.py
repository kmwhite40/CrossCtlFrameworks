"""Pages for the GRC program build-out: third parties, obligations, projects.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md (workstream E).

Every query names the tenant: ``_principal_org`` on reads, and on writes the
record is loaded by id and refused with 404 unless its ``organization_id`` is
the caller's -- the same answer as a missing id, so a write path is never an
existence oracle for another tenant's records. A child record (an obligation,
a project link) is scoped by its parent's organization, which the parent's
own check has already tied to the caller; records without an
``organization_id`` of their own (POA&Ms, risks) are scoped through a live
system (``posture.org_system_subq``).

Role gates, each narrower than "any non-viewer" so that each is observable:

* contracts, contract obligations, due-diligence requests and receipts, the
  obligations register and projects: ``admin`` / ``control_owner``;
* due-diligence review (accept / reject / not applicable): ``admin`` /
  ``assessor`` -- a review is an assessment of what the vendor supplied;
* vendor findings: raised by ``admin`` / ``assessor``, moved through
  remediation by ``admin`` / ``control_owner``;
* the decisions -- waiving a contract obligation, accepting a vendor finding
  -- are ``admin`` only, checked in the handler.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import posture
from ...auth import Principal
from ...constants import POAM_CLOSED_STATUSES
from ...governance import obligations as obl
from ...governance import third_party as tp
from ...models import POAM, Risk, System, Task, User, Vendor
from ...models_program import (
    ComplianceObligation,
    ContractObligation,
    DueDiligenceItem,
    Project,
    ProjectLink,
    VendorContract,
    VendorFinding,
)
from ...models_tprm import QuestionnaireResponse, VendorQuestionnaire
from ..audit import record_event
from ..auth_deps import require_role
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)

PROJECT_STATUSES: tuple[str, ...] = ("planned", "active", "on_hold", "done")
LINK_TYPES: tuple[str, ...] = ("poam", "task", "risk", "system")


# ── helpers ──────────────────────────────────────────────────────────────────


def _render(request: Request, template: str, active: str, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"active": active, **ctx})


def _can(request: Request, *roles: str) -> bool:
    """Whether to offer a form; the route's own gate is what enforces it."""
    p = getattr(request.state, "principal", None)
    if p is None:
        return True
    return bool(getattr(p, "is_global", False) or getattr(p, "role", None) in roles)


def _date(raw: str, name: str) -> date | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise HTTPException(400, f"{name} must be a date (YYYY-MM-DD)") from None


def _number(raw: str, name: str) -> float | None:
    raw = (raw or "").strip().replace(",", "")
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        raise HTTPException(400, f"{name} must be a number") from None
    if not math.isfinite(value) or value < 0:
        raise HTTPException(400, f"{name} must be a non-negative number")
    return value


def _int(raw: str | int, name: str) -> int:
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise HTTPException(400, f"{name} must be a record id") from None
    if value < 1 or value > 2**31 - 1:
        raise HTTPException(404, f"{name} not found")
    return value


def _choice(raw: str, allowed: tuple[str, ...], name: str) -> str:
    if raw not in allowed:
        raise HTTPException(400, f"{name} must be one of: {', '.join(allowed)}")
    return raw


def _text(raw: str, name: str, *, limit: int) -> str:
    value = (raw or "").strip()
    if not value:
        raise HTTPException(400, f"{name} is required")
    if len(value) > limit:
        raise HTTPException(400, f"{name} is longer than {limit} characters")
    return value


def _opt(raw: str, limit: int) -> str | None:
    value = (raw or "").strip()
    return value[:limit] or None


async def _load(session: AsyncSession, model: Any, rid: int, org: int | None, what: str) -> Any:
    """The row iff it belongs to ``org`` (``None`` = a global principal).

    A foreign row and a missing row get the same 404."""
    row = (await session.execute(select(model).where(model.id == rid))).scalar_one_or_none()
    if row is None or (org is not None and row.organization_id != org):
        raise HTTPException(404, f"{what} not found")
    return row


async def _owner(session: AsyncSession, raw: str, org: int) -> int | None:
    """An owner must be an active user of the record's organization."""
    raw = (raw or "").strip()
    if not raw:
        return None
    uid = _int(raw, "owner")
    found = (
        await session.execute(
            select(User.id).where(User.id == uid, User.organization_id == org, User.active)
        )
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(404, "owner not found")
    return uid


def _need_org(principal: Principal) -> int:
    """A top-level record needs a tenant; a global principal has none to give."""
    if principal.org_id is None:
        raise HTTPException(
            400, "a platform-wide session has no organization to create this record in"
        )
    return principal.org_id


async def _record(
    session: AsyncSession,
    principal: Principal,
    *,
    action: str,
    entity_type: str,
    entity_id: Any,
    diff: dict[str, Any],
    organization_id: int,
) -> None:
    await record_event(
        session,
        actor=principal.email,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        diff=diff,
        organization_id=organization_id,
    )


def _where_org(model: Any, org: int | None) -> list[Any]:
    return [model.organization_id == org] if org is not None else []


async def _vendors(session: AsyncSession, org: int | None) -> list[Vendor]:
    return list(
        (
            await session.execute(
                select(Vendor).where(*_where_org(Vendor, org)).order_by(Vendor.name)
            )
        )
        .scalars()
        .all()
    )


async def _users(session: AsyncSession, org: int | None) -> list[User]:
    return list(
        (
            await session.execute(
                select(User)
                .where(User.active.is_(True), *_where_org(User, org))
                .order_by(User.full_name, User.email)
            )
        )
        .scalars()
        .all()
    )


def _names(users: list[User]) -> dict[int, str]:
    return {u.id: (u.full_name or u.email) for u in users}


# ── Contracts ────────────────────────────────────────────────────────────────


@router.get("/contracts", response_class=HTMLResponse)
async def contracts_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    vendor_id: int | None = Query(None),
) -> HTMLResponse:
    org = _principal_org(request)
    today = date.today()
    vendors = await _vendors(session, org)
    vendor_names = {v.id: v.name for v in vendors}
    stmt = select(VendorContract).where(*_where_org(VendorContract, org))
    if vendor_id is not None:
        stmt = stmt.where(VendorContract.vendor_id == vendor_id)
    contracts = list(
        (
            await session.execute(
                stmt.order_by(VendorContract.renewal_on.asc().nulls_last(), VendorContract.id)
            )
        )
        .scalars()
        .all()
    )
    ids = [c.id for c in contracts]
    obligations: list[ContractObligation] = []
    if ids:
        obligations = list(
            (
                await session.execute(
                    select(ContractObligation).where(
                        ContractObligation.contract_id.in_(ids),
                        *_where_org(ContractObligation, org),
                    )
                )
            )
            .scalars()
            .all()
        )
    by_contract: dict[int, Counter[str]] = defaultdict(Counter)
    attention = []
    titles = {c.id: c for c in contracts}
    for ob in obligations:
        state = tp.obligation_state(ob, today)
        by_contract[ob.contract_id][state] += 1
        if state in ("overdue", "missed"):
            attention.append({"ob": ob, "state": state, "contract": titles[ob.contract_id]})
    attention.sort(key=lambda a: a["ob"].due_on or date.max)
    renewals = sorted(
        (c for c in contracts if tp.renewal_due(c, today)),
        key=lambda c: tp.renewal_date(c) or date.max,
    )
    active = [c for c in contracts if c.status == "active"]
    valued = [c for c in active if c.annual_value is not None]
    users = await _users(session, org)
    return _render(
        request,
        "contracts.html",
        "contracts",
        contracts=contracts,
        vendors=vendors,
        vendor_names=vendor_names,
        vendor_id=vendor_id,
        by_contract=by_contract,
        attention=attention,
        renewals=renewals,
        renewal_date=tp.renewal_date,
        window=tp.RENEWAL_WINDOW_DAYS,
        active_count=len(active),
        valued_count=len(valued),
        annual_value=sum(c.annual_value for c in valued) if valued else None,
        users=users,
        owners=_names(users),
        statuses=tp.CONTRACT_STATUSES,
        today=today,
        can_write=_can(request, "admin", "control_owner"),
    )


@router.post("/contracts")
async def contract_create(
    *,
    vendor_id: str = Form(...),
    title: str = Form(...),
    contract_ref: str = Form(""),
    start_on: str = Form(""),
    end_on: str = Form(""),
    renewal_on: str = Form(""),
    annual_value: str = Form(""),
    owner_user_id: str = Form(""),
    status: str = Form("active"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    vendor = await _load(session, Vendor, _int(vendor_id, "vendor"), principal.org_id, "vendor")
    org = vendor.organization_id
    if org is None:
        raise HTTPException(400, "this vendor belongs to no organization")
    start, end = _date(start_on, "start date"), _date(end_on, "end date")
    if start and end and end < start:
        raise HTTPException(400, "the end date is before the start date")
    c = VendorContract(
        organization_id=org,
        vendor_id=vendor.id,
        title=_text(title, "title", limit=255),
        contract_ref=_opt(contract_ref, 128),
        start_on=start,
        end_on=end,
        renewal_on=_date(renewal_on, "renewal date"),
        annual_value=_number(annual_value, "annual value"),
        owner_user_id=await _owner(session, owner_user_id, org),
        status=_choice(status, tp.CONTRACT_STATUSES, "status"),
    )
    session.add(c)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="vendor_contract",
        entity_id=c.id,
        diff={"vendor_id": vendor.id, "title": c.title, "status": c.status},
        organization_id=org,
    )
    await session.commit()
    return RedirectResponse(f"/contracts/{c.id}", status_code=303)


@router.get("/contracts/{contract_id}", response_class=HTMLResponse)
async def contract_detail(
    contract_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    today = date.today()
    c = await _load(session, VendorContract, contract_id, org, "contract")
    vendor = (
        await session.execute(
            select(Vendor).where(
                Vendor.id == c.vendor_id, Vendor.organization_id == c.organization_id
            )
        )
    ).scalar_one_or_none()
    rows = list(
        (
            await session.execute(
                select(ContractObligation)
                .where(
                    ContractObligation.contract_id == c.id,
                    ContractObligation.organization_id == c.organization_id,
                )
                .order_by(ContractObligation.due_on.asc().nulls_last(), ContractObligation.id)
            )
        )
        .scalars()
        .all()
    )
    users = await _users(session, c.organization_id)
    return _render(
        request,
        "contract_detail.html",
        "contracts",
        c=c,
        vendor=vendor,
        rows=[{"ob": ob, "state": tp.obligation_state(ob, today)} for ob in rows],
        users=users,
        owners=_names(users),
        renewal=tp.renewal_date(c),
        renewal_due=tp.renewal_due(c, today),
        statuses=tp.CONTRACT_STATUSES,
        categories=tp.OBLIGATION_CATEGORIES,
        ob_statuses=tp.OBLIGATION_STATUSES,
        today=today,
        can_write=_can(request, "admin", "control_owner"),
        can_waive=_can(request, "admin"),
    )


@router.post("/contracts/{contract_id}")
async def contract_update(
    *,
    contract_id: int,
    title: str = Form(...),
    contract_ref: str = Form(""),
    start_on: str = Form(""),
    end_on: str = Form(""),
    renewal_on: str = Form(""),
    annual_value: str = Form(""),
    owner_user_id: str = Form(""),
    status: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    c = await _load(session, VendorContract, contract_id, principal.org_id, "contract")
    start, end = _date(start_on, "start date"), _date(end_on, "end date")
    if start and end and end < start:
        raise HTTPException(400, "the end date is before the start date")
    before = {"status": c.status, "renewal_on": str(c.renewal_on), "end_on": str(c.end_on)}
    c.title = _text(title, "title", limit=255)
    c.contract_ref = _opt(contract_ref, 128)
    c.start_on, c.end_on = start, end
    c.renewal_on = _date(renewal_on, "renewal date")
    c.annual_value = _number(annual_value, "annual value")
    c.owner_user_id = await _owner(session, owner_user_id, c.organization_id)
    c.status = _choice(status, tp.CONTRACT_STATUSES, "status")
    await _record(
        session,
        principal,
        action="update",
        entity_type="vendor_contract",
        entity_id=c.id,
        diff={
            "before": before,
            "after": {
                "status": c.status,
                "renewal_on": str(c.renewal_on),
                "end_on": str(c.end_on),
            },
        },
        organization_id=c.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/contracts/{c.id}", status_code=303)


@router.post("/contracts/{contract_id}/obligations")
async def contract_obligation_create(
    *,
    contract_id: int,
    description: str = Form(...),
    category: str = Form("security"),
    frequency: str = Form(""),
    due_on: str = Form(""),
    control_id: str = Form(""),
    evidence_ref: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    c = await _load(session, VendorContract, contract_id, principal.org_id, "contract")
    control, ok = await obl.resolve_control_id(session, control_id)
    if not ok:
        raise HTTPException(400, f"control {control_id.strip()!r} is not in the catalog")
    ob = ContractObligation(
        organization_id=c.organization_id,
        contract_id=c.id,
        description=_text(description, "description", limit=4000),
        category=_choice(category, tp.OBLIGATION_CATEGORIES, "category"),
        frequency=_opt(frequency, 32),
        due_on=_date(due_on, "due date"),
        status="pending",
        control_id=control,
        evidence_ref=_opt(evidence_ref, 512),
    )
    session.add(ob)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="contract_obligation",
        entity_id=ob.id,
        diff={"contract_id": c.id, "category": ob.category, "control_id": control},
        organization_id=c.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/contracts/{c.id}", status_code=303)


@router.post("/contracts/{contract_id}/obligations/{obligation_id}/status")
async def contract_obligation_status(
    *,
    contract_id: int,
    obligation_id: int,
    status: str = Form(...),
    evidence_ref: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    c = await _load(session, VendorContract, contract_id, principal.org_id, "contract")
    ob = (
        await session.execute(
            select(ContractObligation).where(
                ContractObligation.id == obligation_id,
                ContractObligation.contract_id == c.id,
                ContractObligation.organization_id == c.organization_id,
            )
        )
    ).scalar_one_or_none()
    if ob is None:
        raise HTTPException(404, "obligation not found")
    status = _choice(status, tp.OBLIGATION_STATUSES, "status")
    if status == "waived" and not (principal.is_global or principal.role == "admin"):
        raise HTTPException(
            403, "waiving a contract obligation is a decision; only an admin can record it"
        )
    before = ob.status
    ob.status = status
    if evidence_ref.strip():
        ob.evidence_ref = _opt(evidence_ref, 512)
    await _record(
        session,
        principal,
        action="update",
        entity_type="contract_obligation",
        entity_id=ob.id,
        diff={"status": [before, status]},
        organization_id=c.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/contracts/{c.id}", status_code=303)


# ── Due diligence ────────────────────────────────────────────────────────────


@router.get("/due-diligence", response_class=HTMLResponse)
async def due_diligence_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    vendor_id: int | None = Query(None),
) -> HTMLResponse:
    org = _principal_org(request)
    today = date.today()
    vendors = await _vendors(session, org)
    shown = [v for v in vendors if vendor_id is None or v.id == vendor_id]
    items: dict[int, list[DueDiligenceItem]] = defaultdict(list)
    if shown:
        for it in (
            (
                await session.execute(
                    select(DueDiligenceItem)
                    .where(
                        DueDiligenceItem.vendor_id.in_([v.id for v in shown]),
                        *_where_org(DueDiligenceItem, org),
                    )
                    .order_by(DueDiligenceItem.id)
                )
            )
            .scalars()
            .all()
        ):
            items[it.vendor_id].append(it)
    summary = {}
    for v in shown:
        its = items.get(v.id, [])
        required = [i for i in its if i.required and i.status != "not_applicable"]
        summary[v.id] = {
            "required": len(required),
            "accepted": sum(1 for i in required if i.status == "accepted"),
            "overdue": sum(1 for i in its if tp.dd_is_overdue(i, today)),
            "awaiting_review": sum(1 for i in its if i.status == "received"),
        }
    return _render(
        request,
        "due_diligence.html",
        "due_diligence",
        vendors=vendors,
        shown=shown,
        vendor_id=vendor_id,
        items=items,
        summary=summary,
        checklist=tp.STANDARD_CHECKLIST,
        decisions=tp.DD_DECISIONS,
        overdue=tp.dd_is_overdue,
        today=today,
        can_request=_can(request, "admin", "control_owner"),
        can_review=_can(request, "admin", "assessor"),
    )


@router.post("/due-diligence/{vendor_id}/standard")
async def due_diligence_apply_standard(
    vendor_id: int,
    due_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    vendor = await _load(session, Vendor, vendor_id, principal.org_id, "vendor")
    if vendor.organization_id is None:
        raise HTTPException(400, "this vendor belongs to no organization")
    created = await tp.apply_standard_checklist(session, vendor, due_on=_date(due_on, "due date"))
    await _record(
        session,
        principal,
        action="create",
        entity_type="due_diligence_checklist",
        entity_id=vendor.id,
        diff={"requested": [i.item for i in created]},
        organization_id=vendor.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/due-diligence?vendor_id={vendor.id}", status_code=303)


@router.post("/due-diligence/{vendor_id}/items")
async def due_diligence_add_item(
    *,
    vendor_id: int,
    item: str = Form(...),
    category: str = Form(""),
    due_on: str = Form(""),
    required: str = Form("1"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    vendor = await _load(session, Vendor, vendor_id, principal.org_id, "vendor")
    if vendor.organization_id is None:
        raise HTTPException(400, "this vendor belongs to no organization")
    it = DueDiligenceItem(
        organization_id=vendor.organization_id,
        vendor_id=vendor.id,
        item=_text(item, "item", limit=255),
        category=_opt(category, 32),
        required=required == "1",
        status="requested",
        due_on=_date(due_on, "due date"),
    )
    session.add(it)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="due_diligence_item",
        entity_id=it.id,
        diff={"vendor_id": vendor.id, "item": it.item},
        organization_id=vendor.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/due-diligence?vendor_id={vendor.id}", status_code=303)


@router.post("/due-diligence/items/{item_id}/receive")
async def due_diligence_receive(
    item_id: int,
    evidence_ref: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    """Record that the vendor supplied the item, and where it is. Receipt is
    not acceptance: the item waits for a reviewer."""
    it = await _load(session, DueDiligenceItem, item_id, principal.org_id, "item")
    if it.status not in ("requested", "rejected", "received"):
        raise HTTPException(409, f"this item is already {it.status.replace('_', ' ')}")
    before = it.status
    it.evidence_ref = _text(evidence_ref, "evidence reference", limit=512)
    it.status = "received"
    it.reviewed_by = None
    it.reviewed_at = None
    await _record(
        session,
        principal,
        action="update",
        entity_type="due_diligence_item",
        entity_id=it.id,
        diff={"status": [before, "received"], "evidence_ref": it.evidence_ref},
        organization_id=it.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/due-diligence?vendor_id={it.vendor_id}", status_code=303)


@router.post("/due-diligence/items/{item_id}/review")
async def due_diligence_review(
    item_id: int,
    decision: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> RedirectResponse:
    it = await _load(session, DueDiligenceItem, item_id, principal.org_id, "item")
    decision = _choice(decision, tp.DD_DECISIONS, "decision")
    if decision in ("accepted", "rejected") and (it.status != "received" or not it.evidence_ref):
        # Accepting a request that nothing answered would record a document
        # nobody has; rejecting one is equally a judgement of nothing.
        raise HTTPException(
            409,
            "only an item the vendor has supplied (received, with a reference) can be reviewed",
        )
    before = it.status
    it.status = decision
    it.reviewed_by = principal.email
    it.reviewed_at = datetime.now(UTC)
    await _record(
        session,
        principal,
        action="review",
        entity_type="due_diligence_item",
        entity_id=it.id,
        diff={"status": [before, decision]},
        organization_id=it.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/due-diligence?vendor_id={it.vendor_id}", status_code=303)


# ── Vendor findings ──────────────────────────────────────────────────────────


def _gap_title(question_id: str, text: str) -> str:
    return f"{question_id}: {text}"[:512]


@router.get("/vendor-findings", response_class=HTMLResponse)
async def vendor_findings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    vendor_id: int | None = Query(None),
) -> HTMLResponse:
    org = _principal_org(request)
    today = date.today()
    vendors = await _vendors(session, org)
    vendor_names = {v.id: v.name for v in vendors}
    stmt = select(VendorFinding).where(*_where_org(VendorFinding, org))
    if severity in tp.FINDING_SEVERITIES:
        stmt = stmt.where(VendorFinding.severity == severity)
    else:
        severity = None
    if status in tp.FINDING_STATUSES:
        stmt = stmt.where(VendorFinding.status == status)
    else:
        status = None
    if vendor_id is not None:
        stmt = stmt.where(VendorFinding.vendor_id == vendor_id)
    findings = list((await session.execute(stmt)).scalars().all())
    sev_rank = {s: i for i, s in enumerate(tp.FINDING_SEVERITIES)}
    findings.sort(
        key=lambda f: (
            f.status not in tp.FINDING_OPEN_STATUSES,
            sev_rank.get(f.severity, 9),
            f.due_on or date.max,
        )
    )
    open_by_sev = Counter(f.severity for f in findings if f.status in tp.FINDING_OPEN_STATUSES)

    # Questionnaire gaps (``no`` answers on a submitted or reviewed
    # questionnaire) that no finding records yet.
    gaps = []
    for q, r in (
        await session.execute(
            select(VendorQuestionnaire, QuestionnaireResponse)
            .join(
                QuestionnaireResponse,
                QuestionnaireResponse.questionnaire_id == VendorQuestionnaire.id,
            )
            .where(
                VendorQuestionnaire.status.in_(("submitted", "reviewed")),
                QuestionnaireResponse.answer == "no",
                *_where_org(VendorQuestionnaire, org),
            )
            .order_by(VendorQuestionnaire.id.desc(), QuestionnaireResponse.sort_order)
        )
    ).all():
        if q.vendor_id not in vendor_names:
            continue
        gaps.append({"q": q, "r": r, "title": _gap_title(r.question_id, r.question_text)})
    if gaps:
        recorded = set(
            (
                await session.execute(
                    select(VendorFinding.questionnaire_id, VendorFinding.title).where(
                        VendorFinding.questionnaire_id.in_({g["q"].id for g in gaps}),
                        *_where_org(VendorFinding, org),
                    )
                )
            )
            .tuples()
            .all()
        )
        gaps = [g for g in gaps if (g["q"].id, g["title"]) not in recorded]
    return _render(
        request,
        "vendor_findings.html",
        "vendor_findings",
        findings=findings,
        vendors=vendors,
        vendor_names=vendor_names,
        open_by_sev=open_by_sev,
        open_total=sum(open_by_sev.values()),
        gaps=gaps,
        severity=severity,
        status=status,
        vendor_id=vendor_id,
        severities=tp.FINDING_SEVERITIES,
        statuses=tp.FINDING_STATUSES,
        open_statuses=tp.FINDING_OPEN_STATUSES,
        today=today,
        can_raise=_can(request, "admin", "assessor"),
        can_update=_can(request, "admin", "control_owner"),
        can_accept=_can(request, "admin"),
    )


@router.post("/vendor-findings")
async def vendor_finding_create(
    *,
    vendor_id: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    severity: str = Form("moderate"),
    due_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> RedirectResponse:
    vendor = await _load(session, Vendor, _int(vendor_id, "vendor"), principal.org_id, "vendor")
    if vendor.organization_id is None:
        raise HTTPException(400, "this vendor belongs to no organization")
    f = VendorFinding(
        organization_id=vendor.organization_id,
        vendor_id=vendor.id,
        title=_text(title, "title", limit=512),
        description=_opt(description, 8000),
        severity=_choice(severity, tp.FINDING_SEVERITIES, "severity"),
        status="open",
        due_on=_date(due_on, "due date"),
    )
    session.add(f)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="vendor_finding",
        entity_id=f.id,
        diff={"vendor_id": vendor.id, "severity": f.severity, "title": f.title},
        organization_id=vendor.organization_id,
    )
    await session.commit()
    return RedirectResponse("/vendor-findings", status_code=303)


@router.post("/vendor-findings/from-gap")
async def vendor_finding_from_gap(
    *,
    questionnaire_id: str = Form(...),
    question_id: str = Form(...),
    severity: str = Form(""),
    due_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> RedirectResponse:
    """A finding from a ``no`` answer on a submitted questionnaire. Severity
    defaults from the question's weight (3+ high, else moderate), the same
    rule the questionnaire review uses for task priority."""
    q = await _load(
        session,
        VendorQuestionnaire,
        _int(questionnaire_id, "questionnaire"),
        principal.org_id,
        "questionnaire",
    )
    vendor = await _load(session, Vendor, q.vendor_id, principal.org_id, "vendor")
    if vendor.organization_id is None or q.organization_id not in (None, vendor.organization_id):
        raise HTTPException(404, "questionnaire not found")
    if q.status not in ("submitted", "reviewed"):
        raise HTTPException(409, "a questionnaire must be submitted before its gaps are findings")
    r = (
        await session.execute(
            select(QuestionnaireResponse).where(
                QuestionnaireResponse.questionnaire_id == q.id,
                QuestionnaireResponse.question_id == question_id.strip(),
            )
        )
    ).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "question not found on this questionnaire")
    if r.answer != "no":
        raise HTTPException(409, f"the vendor answered {r.answer!r}; only a 'no' is a gap")
    title = _gap_title(r.question_id, r.question_text)
    exists = (
        await session.execute(
            select(VendorFinding.id).where(
                VendorFinding.questionnaire_id == q.id,
                VendorFinding.title == title,
                VendorFinding.organization_id == vendor.organization_id,
            )
        )
    ).first()
    if exists is not None:
        raise HTTPException(409, "a finding already records this gap")
    sev = severity.strip() or ("high" if (r.weight or 1) >= 3 else "moderate")
    f = VendorFinding(
        organization_id=vendor.organization_id,
        vendor_id=vendor.id,
        questionnaire_id=q.id,
        title=title,
        description=(
            f"Answered 'no' on {q.name}." + (f" Vendor's detail: {r.detail}" if r.detail else "")
        ),
        severity=_choice(sev, tp.FINDING_SEVERITIES, "severity"),
        status="open",
        due_on=_date(due_on, "due date"),
    )
    session.add(f)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="vendor_finding",
        entity_id=f.id,
        diff={"questionnaire_id": q.id, "question_id": r.question_id, "severity": f.severity},
        organization_id=vendor.organization_id,
    )
    await session.commit()
    return RedirectResponse("/vendor-findings", status_code=303)


@router.post("/vendor-findings/{finding_id}/status")
async def vendor_finding_status(
    finding_id: int,
    status: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    f = await _load(session, VendorFinding, finding_id, principal.org_id, "finding")
    status = _choice(status, tp.FINDING_STATUSES, "status")
    if status == "accepted" and not (principal.is_global or principal.role == "admin"):
        raise HTTPException(
            403, "accepting a vendor finding is a risk acceptance; only an admin can record it"
        )
    before = f.status
    f.status = status
    f.closed_at = datetime.now(UTC) if status in ("closed", "accepted") else None
    await _record(
        session,
        principal,
        action="update",
        entity_type="vendor_finding",
        entity_id=f.id,
        diff={"status": [before, status]},
        organization_id=f.organization_id,
    )
    await session.commit()
    return RedirectResponse("/vendor-findings", status_code=303)


# ── Compliance obligations register ──────────────────────────────────────────


@router.get("/obligations", response_class=HTMLResponse)
async def obligations_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    status: str | None = Query(None),
) -> HTMLResponse:
    org = _principal_org(request)
    today = date.today()
    rows = list(
        (
            await session.execute(
                select(ComplianceObligation)
                .where(*_where_org(ComplianceObligation, org))
                .order_by(ComplianceObligation.due_on.asc().nulls_last(), ComplianceObligation.id)
            )
        )
        .scalars()
        .all()
    )
    counts = obl.summarize(rows, today)
    shown = [r for r in rows if status not in obl.STATUSES or r.status == status]
    users = await _users(session, org)
    return _render(
        request,
        "obligations.html",
        "obligations",
        rows=shown,
        counts=counts,
        status=status if status in obl.STATUSES else None,
        sources=obl.SOURCES,
        statuses=obl.STATUSES,
        open_statuses=obl.OPEN_STATUSES,
        users=users,
        owners=_names(users),
        today=today,
        can_write=_can(request, "admin", "control_owner"),
    )


async def _control_ids(session: AsyncSession, raw: str) -> list[str]:
    ids = obl.parse_control_ids(raw)
    if len(ids) > obl.MAX_CONTROL_IDS:
        raise HTTPException(400, f"at most {obl.MAX_CONTROL_IDS} controls per obligation")
    known, unknown = await obl.resolve_control_ids(session, ids)
    if unknown:
        raise HTTPException(400, f"not in the control catalog: {', '.join(unknown)}")
    return known


@router.post("/obligations")
async def obligation_create(
    *,
    source: str = Form(...),
    title: str = Form(...),
    citation: str = Form(""),
    description: str = Form(""),
    owner_user_id: str = Form(""),
    frequency: str = Form(""),
    due_on: str = Form(""),
    control_ids: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    org = _need_org(principal)
    o = ComplianceObligation(
        organization_id=org,
        source=_choice(source, obl.SOURCES, "source"),
        citation=_opt(citation, 255),
        title=_text(title, "title", limit=512),
        description=_opt(description, 8000),
        owner_user_id=await _owner(session, owner_user_id, org),
        frequency=_opt(frequency, 32),
        due_on=_date(due_on, "due date"),
        status="open",
        control_ids=await _control_ids(session, control_ids),
    )
    session.add(o)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="compliance_obligation",
        entity_id=o.id,
        diff={"source": o.source, "citation": o.citation, "control_ids": o.control_ids},
        organization_id=org,
    )
    await session.commit()
    return RedirectResponse("/obligations", status_code=303)


@router.post("/obligations/{obligation_id}")
async def obligation_update(
    *,
    obligation_id: int,
    status: str = Form(...),
    owner_user_id: str = Form(""),
    due_on: str = Form(""),
    control_ids: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    o = await _load(session, ComplianceObligation, obligation_id, principal.org_id, "obligation")
    before = {"status": o.status, "control_ids": list(o.control_ids or [])}
    o.status = _choice(status, obl.STATUSES, "status")
    o.owner_user_id = await _owner(session, owner_user_id, o.organization_id)
    o.due_on = _date(due_on, "due date")
    o.control_ids = await _control_ids(session, control_ids)
    await _record(
        session,
        principal,
        action="update",
        entity_type="compliance_obligation",
        entity_id=o.id,
        diff={"before": before, "after": {"status": o.status, "control_ids": o.control_ids}},
        organization_id=o.organization_id,
    )
    await session.commit()
    return RedirectResponse("/obligations", status_code=303)


# ── Projects ─────────────────────────────────────────────────────────────────


def progress(closed: int, linked: int) -> int | None:
    """Linked POA&Ms closed ÷ linked POA&Ms, as a whole percent; ``None``
    (rendered —) when the project links none."""
    if linked == 0:
        return None
    return round(100 * closed / linked)


def _risk_in(org: int) -> Any:
    """A risk of ``org``: an enterprise risk (no system) owned by the org, or a
    risk on one of the org's live systems. A risk on a soft-deleted system is
    out even though its ``organization_id`` still names the org."""
    return or_(
        and_(Risk.system_id.is_(None), Risk.organization_id == org),
        Risk.system_id.in_(posture.org_system_subq(org)),
    )


async def _resolve_links(
    session: AsyncSession, links: list[ProjectLink], org: int
) -> dict[str, dict[int, dict[str, Any]]]:
    """Each linked record that still exists in ``org`` (on a live system,
    where it hangs off one), keyed by type and id. A link whose record has
    gone is left out here and shown as unavailable."""
    ids: dict[str, set[int]] = defaultdict(set)
    for ln in links:
        if ln.entity_id.isdigit():
            ids[ln.entity_type].add(int(ln.entity_id))
    live = posture.org_system_subq(org)
    out: dict[str, dict[int, dict[str, Any]]] = {t: {} for t in LINK_TYPES}
    if ids["poam"]:
        for p in (
            await session.execute(
                select(POAM.id, POAM.title, POAM.status, POAM.severity, POAM.due_on).where(
                    POAM.id.in_(ids["poam"]), POAM.system_id.in_(live)
                )
            )
        ).all():
            out["poam"][p.id] = {
                "label": p.title,
                "status": p.status,
                "detail": p.severity,
                "due_on": p.due_on,
                "closed": p.status in POAM_CLOSED_STATUSES,
            }
    if ids["task"]:
        for t in (
            await session.execute(
                select(Task.id, Task.title, Task.status, Task.due_on).where(
                    Task.id.in_(ids["task"]), Task.organization_id == org
                )
            )
        ).all():
            out["task"][t.id] = {"label": t.title, "status": t.status, "due_on": t.due_on}
    if ids["risk"]:
        for r in (
            await session.execute(
                select(Risk.id, Risk.title, Risk.status, Risk.residual_score).where(
                    Risk.id.in_(ids["risk"]), _risk_in(org)
                )
            )
        ).all():
            out["risk"][r.id] = {"label": r.title, "status": r.status, "detail": r.residual_score}
    if ids["system"]:
        for s in (
            await session.execute(
                select(System.id, System.name).where(
                    System.id.in_(ids["system"]), System.id.in_(live)
                )
            )
        ).all():
            out["system"][s.id] = {"label": s.name}
    return out


async def _link_target(session: AsyncSession, etype: str, raw: str, org: int) -> int:
    """The id of a record of ``etype`` in ``org``, else 404 -- the same answer
    for another tenant's record and for one that does not exist."""
    eid = _int(raw, etype)
    live = posture.org_system_subq(org)
    stmt: Any
    if etype == "poam":
        stmt = select(POAM.id).where(POAM.id == eid, POAM.system_id.in_(live))
    elif etype == "task":
        stmt = select(Task.id).where(Task.id == eid, Task.organization_id == org)
    elif etype == "risk":
        stmt = select(Risk.id).where(Risk.id == eid, _risk_in(org))
    else:
        stmt = select(System.id).where(System.id == eid, System.id.in_(live))
    if (await session.execute(stmt)).scalar_one_or_none() is None:
        raise HTTPException(404, f"{etype} not found")
    return eid


@router.get("/projects", response_class=HTMLResponse)
async def projects_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    projects = list(
        (
            await session.execute(
                select(Project)
                .where(*_where_org(Project, org))
                .order_by(Project.status == "done", Project.target_on.asc().nulls_last())
            )
        )
        .scalars()
        .all()
    )
    links: dict[int, list[ProjectLink]] = defaultdict(list)
    if projects:
        for ln in (
            (
                await session.execute(
                    select(ProjectLink).where(
                        ProjectLink.project_id.in_([p.id for p in projects]),
                        *_where_org(ProjectLink, org),
                    )
                )
            )
            .scalars()
            .all()
        ):
            links[ln.project_id].append(ln)
    stats = {}
    for p in projects:
        resolved = await _resolve_links(session, links[p.id], p.organization_id)
        poams = resolved["poam"]
        closed = sum(1 for x in poams.values() if x["closed"])
        stats[p.id] = {
            "counts": {t: len(resolved[t]) for t in LINK_TYPES},
            "closed": closed,
            "linked": len(poams),
            "pct": progress(closed, len(poams)),
        }
    users = await _users(session, org)
    return _render(
        request,
        "projects.html",
        "projects",
        projects=projects,
        stats=stats,
        users=users,
        owners=_names(users),
        statuses=PROJECT_STATUSES,
        today=date.today(),
        can_write=_can(request, "admin", "control_owner"),
    )


@router.post("/projects")
async def project_create(
    *,
    name: str = Form(...),
    description: str = Form(""),
    owner_user_id: str = Form(""),
    status: str = Form("planned"),
    start_on: str = Form(""),
    target_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    org = _need_org(principal)
    start, target = _date(start_on, "start date"), _date(target_on, "target date")
    if start and target and target < start:
        raise HTTPException(400, "the target date is before the start date")
    p = Project(
        organization_id=org,
        name=_text(name, "name", limit=255),
        description=_opt(description, 8000),
        owner_user_id=await _owner(session, owner_user_id, org),
        status=_choice(status, PROJECT_STATUSES, "status"),
        start_on=start,
        target_on=target,
    )
    session.add(p)
    await session.flush()
    await _record(
        session,
        principal,
        action="create",
        entity_type="project",
        entity_id=p.id,
        diff={"name": p.name, "status": p.status},
        organization_id=org,
    )
    await session.commit()
    return RedirectResponse(f"/projects/{p.id}", status_code=303)


@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail(
    project_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    p = await _load(session, Project, project_id, org, "project")
    links = list(
        (
            await session.execute(
                select(ProjectLink)
                .where(
                    ProjectLink.project_id == p.id,
                    ProjectLink.organization_id == p.organization_id,
                )
                .order_by(ProjectLink.entity_type, ProjectLink.id)
            )
        )
        .scalars()
        .all()
    )
    resolved = await _resolve_links(session, links, p.organization_id)
    grouped: dict[str, list[dict[str, Any]]] = {t: [] for t in LINK_TYPES}
    for ln in links:
        key = int(ln.entity_id) if ln.entity_id.isdigit() else -1
        grouped.setdefault(ln.entity_type, []).append(
            {"link": ln, "rec": resolved.get(ln.entity_type, {}).get(key)}
        )
    poams = resolved["poam"]
    closed = sum(1 for x in poams.values() if x["closed"])
    # Candidates for the add-link selects: the project's organization only.
    live = posture.org_system_subq(p.organization_id)
    linked = {(ln.entity_type, ln.entity_id) for ln in links}
    queries = {
        "poam": select(POAM.id, POAM.title)
        .where(POAM.system_id.in_(live))
        .order_by(POAM.id.desc())
        .limit(300),
        "task": select(Task.id, Task.title)
        .where(Task.organization_id == p.organization_id)
        .order_by(Task.id.desc())
        .limit(300),
        "risk": select(Risk.id, Risk.title)
        .where(_risk_in(p.organization_id))
        .order_by(Risk.id.desc())
        .limit(300),
        "system": select(System.id, System.name).where(System.id.in_(live)).order_by(System.name),
    }
    candidates = {
        t: [
            (i, label)
            for i, label in (await session.execute(stmt)).tuples().all()
            if (t, str(i)) not in linked
        ]
        for t, stmt in queries.items()
    }
    users = await _users(session, p.organization_id)
    return _render(
        request,
        "project_detail.html",
        "projects",
        p=p,
        grouped=grouped,
        closed=closed,
        linked=len(poams),
        pct=progress(closed, len(poams)),
        candidates=candidates,
        users=users,
        owners=_names(users),
        statuses=PROJECT_STATUSES,
        link_types=LINK_TYPES,
        today=date.today(),
        can_write=_can(request, "admin", "control_owner"),
    )


@router.post("/projects/{project_id}")
async def project_update(
    *,
    project_id: int,
    name: str = Form(...),
    description: str = Form(""),
    owner_user_id: str = Form(""),
    status: str = Form(...),
    start_on: str = Form(""),
    target_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    p = await _load(session, Project, project_id, principal.org_id, "project")
    start, target = _date(start_on, "start date"), _date(target_on, "target date")
    if start and target and target < start:
        raise HTTPException(400, "the target date is before the start date")
    before = p.status
    p.name = _text(name, "name", limit=255)
    p.description = _opt(description, 8000)
    p.owner_user_id = await _owner(session, owner_user_id, p.organization_id)
    p.status = _choice(status, PROJECT_STATUSES, "status")
    p.start_on, p.target_on = start, target
    await _record(
        session,
        principal,
        action="update",
        entity_type="project",
        entity_id=p.id,
        diff={"status": [before, p.status]},
        organization_id=p.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/projects/{p.id}", status_code=303)


@router.post("/projects/{project_id}/links")
async def project_link_add(
    project_id: int,
    entity_type: str = Form(...),
    entity_id: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    p = await _load(session, Project, project_id, principal.org_id, "project")
    etype = _choice(entity_type, LINK_TYPES, "entity type")
    eid = await _link_target(session, etype, entity_id, p.organization_id)
    exists = (
        await session.execute(
            select(func.count())
            .select_from(ProjectLink)
            .where(
                ProjectLink.project_id == p.id,
                ProjectLink.entity_type == etype,
                ProjectLink.entity_id == str(eid),
            )
        )
    ).scalar_one()
    if not exists:
        ln = ProjectLink(
            organization_id=p.organization_id,
            project_id=p.id,
            entity_type=etype,
            entity_id=str(eid),
        )
        session.add(ln)
        await session.flush()
        await _record(
            session,
            principal,
            action="link",
            entity_type="project",
            entity_id=p.id,
            diff={"linked": {"type": etype, "id": eid}},
            organization_id=p.organization_id,
        )
        await session.commit()
    return RedirectResponse(f"/projects/{p.id}", status_code=303)


@router.post("/projects/{project_id}/links/{link_id}/delete")
async def project_link_remove(
    project_id: int,
    link_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "control_owner")),
) -> RedirectResponse:
    p = await _load(session, Project, project_id, principal.org_id, "project")
    ln = (
        await session.execute(
            select(ProjectLink).where(
                ProjectLink.id == link_id,
                ProjectLink.project_id == p.id,
                ProjectLink.organization_id == p.organization_id,
            )
        )
    ).scalar_one_or_none()
    if ln is None:
        raise HTTPException(404, "link not found")
    await session.delete(ln)
    await _record(
        session,
        principal,
        action="unlink",
        entity_type="project",
        entity_id=p.id,
        diff={"unlinked": {"type": ln.entity_type, "id": ln.entity_id}},
        organization_id=p.organization_id,
    )
    await session.commit()
    return RedirectResponse(f"/projects/{p.id}", status_code=303)
