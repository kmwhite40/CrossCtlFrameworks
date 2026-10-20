"""Audit and assurance pages: workpapers, cross-engagement findings and
evidence requests, authorization packages, the assessment schedule,
compensating controls and audit readiness.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md (D -- auditprog).
Registered in ccf.api.main. The rules live in ``ccf.governance.audit_program``;
this module authenticates, scopes, records the event and renders.

Every write is role-gated with ``require_role`` and recorded with
``record_event`` under the record's own organization. Ownership is resolved
from the record, never from the form: a foreign id is a 404.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import posture
from ...auth import Principal
from ...governance import audit_program as program
from ...models import System
from ..audit import record_event
from ..auth_deps import require_role
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)


def _now() -> datetime:
    return datetime.now(UTC)


def _http(exc: program.RefusalError) -> HTTPException:
    return HTTPException(exc.status_code, exc.message)


def _int_or_none(raw: str, name: str) -> int | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        raise HTTPException(422, f"{name} must be a whole number") from None


def _date_or_none(raw: str, name: str) -> date | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise HTTPException(422, f"{name} must be a date (YYYY-MM-DD)") from None


async def _event(
    session: AsyncSession,
    principal: Principal,
    *,
    org: int,
    entity_type: str,
    entity_id: int,
    action: str,
    diff: dict[str, Any],
) -> None:
    await record_event(
        session,
        organization_id=org,
        actor=principal.email,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        diff=diff,
    )


# ── Workpapers ───────────────────────────────────────────────────────────────


@router.get("/audit/workpapers", response_class=HTMLResponse)
async def workpapers_page(
    request: Request,
    engagement: int | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    org = _principal_org(request)
    selected = None
    if engagement is not None:
        try:
            selected = await program.engagement_in_scope(session, engagement, org)
        except program.RefusalError as exc:
            raise _http(exc) from None
    rows = await program.list_workpapers(session, org, engagement_id=engagement)
    counts = {s: sum(1 for wp, _ in rows if wp.status == s) for s in program.WORKPAPER_STATUSES}
    return templates.TemplateResponse(
        request,
        "workpapers.html",
        {
            "active": "workpapers",
            "rows": rows,
            "counts": counts,
            "selected": selected,
            "engagements": await program.engagements(session, org),
            "conclusions": program.WORKPAPER_CONCLUSIONS,
            "wp": None,
        },
    )


@router.post("/audit/workpapers")
async def workpaper_create(  # noqa: PLR0917 -- FastAPI binds these by keyword
    request: Request,
    engagement_id: int = Form(...),
    title: str = Form(...),
    control_id: str = Form(""),
    procedure: str = Form(""),
    sample_size: str = Form(""),
    exceptions_found: str = Form(""),
    conclusion: str = Form(""),
    evidence_refs: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.WORKPAPER_ROLES)),
) -> RedirectResponse:
    try:
        engagement = await program.engagement_in_scope(
            session, engagement_id, _principal_org(request)
        )
        wp = await program.create_workpaper(
            session,
            engagement,
            actor=principal.email,
            title=title,
            control_id=control_id,
            procedure=procedure,
            sample_size=_int_or_none(sample_size, "sample size"),
            exceptions_found=_int_or_none(exceptions_found, "exceptions found"),
            conclusion=conclusion,
            evidence_refs=evidence_refs,
        )
    except program.RefusalError as exc:
        raise _http(exc) from None
    await _event(
        session,
        principal,
        org=wp.organization_id,
        entity_type="audit_workpaper",
        entity_id=wp.id,
        action="create",
        diff={"event": "prepared", "engagement_id": engagement.id, "title": wp.title},
    )
    await session.commit()
    return RedirectResponse(f"/audit/workpapers/{wp.id}", status_code=303)


@router.get("/audit/workpapers/{wp_id}", response_class=HTMLResponse)
async def workpaper_detail(
    wp_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    try:
        wp = await program.workpaper_in_scope(session, wp_id, org)
        engagement = await program.engagement_in_scope(session, wp.engagement_id, org)
    except program.RefusalError as exc:
        raise _http(exc) from None
    principal = getattr(request.state, "principal", None)
    me = getattr(principal, "email", None)
    return templates.TemplateResponse(
        request,
        "workpapers.html",
        {
            "active": "workpapers",
            "wp": wp,
            "engagement": engagement,
            "conclusions": program.WORKPAPER_CONCLUSIONS,
            "is_preparer": bool(me) and not program.may_sign_off(wp.prepared_by, me),
        },
    )


@router.post("/audit/workpapers/{wp_id}/edit")
async def workpaper_edit(  # noqa: PLR0917 -- FastAPI binds these by keyword
    wp_id: int,
    request: Request,
    title: str = Form(...),
    control_id: str = Form(""),
    procedure: str = Form(""),
    sample_size: str = Form(""),
    exceptions_found: str = Form(""),
    conclusion: str = Form(""),
    evidence_refs: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.WORKPAPER_ROLES)),
) -> RedirectResponse:
    try:
        wp = await program.workpaper_in_scope(session, wp_id, _principal_org(request))
        diff = program.edit_workpaper(
            wp,
            actor=principal.email,
            title=title,
            control_id=control_id,
            procedure=procedure,
            sample_size=_int_or_none(sample_size, "sample size"),
            exceptions_found=_int_or_none(exceptions_found, "exceptions found"),
            conclusion=conclusion,
            evidence_refs=evidence_refs,
        )
    except program.RefusalError as exc:
        raise _http(exc) from None
    await _event(
        session,
        principal,
        org=wp.organization_id,
        entity_type="audit_workpaper",
        entity_id=wp.id,
        action="update",
        diff={"event": "edited", "changed": sorted(diff)},
    )
    await session.commit()
    return RedirectResponse(f"/audit/workpapers/{wp.id}", status_code=303)


async def _transition(
    request: Request,
    session: AsyncSession,
    principal: Principal,
    wp_id: int,
    event: str,
) -> RedirectResponse:
    try:
        wp = await program.workpaper_in_scope(session, wp_id, _principal_org(request))
        before = wp.status
        if event == "submitted":
            program.submit_workpaper(wp)
        elif event == "returned":
            program.return_workpaper(wp)
        else:
            program.finalise_workpaper(wp, actor=principal.email, now=_now())
    except program.RefusalError as exc:
        raise _http(exc) from None
    await _event(
        session,
        principal,
        org=wp.organization_id,
        entity_type="audit_workpaper",
        entity_id=wp.id,
        action="update",
        diff={"event": event, "from": before, "to": wp.status},
    )
    await session.commit()
    return RedirectResponse(f"/audit/workpapers/{wp.id}", status_code=303)


@router.post("/audit/workpapers/{wp_id}/submit")
async def workpaper_submit(
    wp_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.WORKPAPER_ROLES)),
) -> RedirectResponse:
    return await _transition(request, session, principal, wp_id, "submitted")


@router.post("/audit/workpapers/{wp_id}/return")
async def workpaper_return(
    wp_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.WORKPAPER_ROLES)),
) -> RedirectResponse:
    return await _transition(request, session, principal, wp_id, "returned")


@router.post("/audit/workpapers/{wp_id}/finalise")
async def workpaper_finalise(
    wp_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.WORKPAPER_ROLES)),
) -> RedirectResponse:
    return await _transition(request, session, principal, wp_id, "finalised")


# ── Findings and evidence requests across engagements ────────────────────────


@router.get("/audit/findings", response_class=HTMLResponse)
async def audit_findings_page(
    request: Request,
    severity: str | None = Query(None),
    status: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    data = await program.findings(
        session, _principal_org(request), severity=severity or None, status=status or None
    )
    return templates.TemplateResponse(
        request,
        "audit_findings.html",
        {
            "active": "audit_findings",
            **data,
            "severities": program.SEVERITIES,
            "severity": severity or "",
            "status": status or "",
        },
    )


@router.get("/evidence/requests", response_class=HTMLResponse)
async def evidence_requests_page(
    request: Request,
    status: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    today = date.today()
    data = await program.pbc_requests(
        session, _principal_org(request), today, status=status or None
    )
    return templates.TemplateResponse(
        request,
        "evidence_requests.html",
        {"active": "evidence_req", **data, "status": status or "", "today": today},
    )


@router.get("/evidence/packages", response_class=HTMLResponse)
async def evidence_packages_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    rows = await program.packages(session, _principal_org(request))
    return templates.TemplateResponse(
        request, "evidence_packages.html", {"active": "evidence_pkg", "rows": rows}
    )


# ── Assessment schedule ──────────────────────────────────────────────────────


@router.get("/assessments/schedule", response_class=HTMLResponse)
async def assessment_schedule_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    today = date.today()
    data = await program.assessment_schedule(session, _principal_org(request), today)
    return templates.TemplateResponse(
        request,
        "assessment_schedule.html",
        {
            "active": "scheduled",
            **data,
            "windows": program.SCHEDULE_WINDOWS,
            "today": today,
        },
    )


# ── Compensating controls ────────────────────────────────────────────────────


@router.get("/compensating-controls", response_class=HTMLResponse)
async def compensating_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    today = date.today()
    rows = await program.compensating_controls(session, org)
    systems = (
        await session.execute(
            select(System.id, System.name)
            .where(System.id.in_(posture.org_system_subq(org)))
            .order_by(System.name)
        )
    ).all()
    principal = getattr(request.state, "principal", None)
    return templates.TemplateResponse(
        request,
        "compensating_controls.html",
        {
            "active": "compensating",
            "rows": rows,
            "systems": systems,
            "today": today,
            "me": getattr(principal, "email", None),
            "counts": {s: sum(1 for cc, _ in rows if cc.status == s) for s in program.CC_STATUSES},
        },
    )


@router.post("/compensating-controls")
async def compensating_propose(  # noqa: PLR0917 -- FastAPI binds these by keyword
    request: Request,
    system_id: int = Form(...),
    control_identifier: str = Form(...),
    measure: str = Form(...),
    rationale: str = Form(...),
    expires_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.CC_PROPOSE_ROLES)),
) -> RedirectResponse:
    try:
        cc = await program.propose_compensating(
            session,
            _principal_org(request),
            actor=principal.email,
            system_id=system_id,
            control_identifier=control_identifier,
            measure=measure,
            rationale=rationale,
            expires_on=_date_or_none(expires_on, "expiry"),
            today=date.today(),
        )
    except program.RefusalError as exc:
        raise _http(exc) from None
    await _event(
        session,
        principal,
        org=cc.organization_id,
        entity_type="compensating_control",
        entity_id=cc.id,
        action="create",
        diff={
            "event": "proposed",
            "system_id": cc.system_id,
            "control": cc.control_identifier,
            "expires_on": cc.expires_on.isoformat() if cc.expires_on else None,
        },
    )
    await session.commit()
    return RedirectResponse("/compensating-controls", status_code=303)


async def _decide(
    request: Request,
    session: AsyncSession,
    principal: Principal,
    cc_id: int,
    event: str,
) -> RedirectResponse:
    try:
        cc = await program.compensating_in_scope(session, cc_id, _principal_org(request))
        if event == "retired":
            program.retire_compensating(cc)
        else:
            program.decide_compensating(
                cc, actor=principal.email, approve=event == "approved", now=_now()
            )
    except program.RefusalError as exc:
        raise _http(exc) from None
    await _event(
        session,
        principal,
        org=cc.organization_id,
        entity_type="compensating_control",
        entity_id=cc.id,
        action="update",
        diff={"event": event, "control": cc.control_identifier},
    )
    await session.commit()
    return RedirectResponse("/compensating-controls", status_code=303)


@router.post("/compensating-controls/{cc_id}/approve")
async def compensating_approve(
    cc_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.CC_DECIDE_ROLES)),
) -> RedirectResponse:
    return await _decide(request, session, principal, cc_id, "approved")


@router.post("/compensating-controls/{cc_id}/reject")
async def compensating_reject(
    cc_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.CC_DECIDE_ROLES)),
) -> RedirectResponse:
    return await _decide(request, session, principal, cc_id, "rejected")


@router.post("/compensating-controls/{cc_id}/retire")
async def compensating_retire(
    cc_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*program.CC_DECIDE_ROLES)),
) -> RedirectResponse:
    return await _decide(request, session, principal, cc_id, "retired")


# ── Audit readiness ──────────────────────────────────────────────────────────


@router.get("/audit/readiness", response_class=HTMLResponse)
async def audit_readiness_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    today = date.today()
    rows = await program.readiness(session, _principal_org(request), today)
    return templates.TemplateResponse(
        request,
        "audit_readiness.html",
        {
            "active": "audit_ready",
            "rows": rows,
            "severities": program.SEVERITIES,
            "today": today,
        },
    )
