"""Server-rendered UI for the GRC operating-system modules — Trust Center,
Audit Workspace, Regulatory Change, Connector registry, and Control Tests.

Kept separate from the large ``ui.py`` and reuses its configured Jinja
environment (same base.html + light theme, asset-version cache-busting).
"""

from __future__ import annotations

import contextlib
from datetime import UTC, date, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...governance import insights
from ...models_grc import (
    AuditEngagement,
    AuditFinding,
    AuditRequest,
    ConnectorConfig,
    ControlTest,
    RegulatoryUpdate,
    TrustProfile,
)
from ..deps import get_session
from .grc import _MOCK_DISCOVERY, CONNECTOR_TYPES
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)


def _now() -> datetime:
    return datetime.now(UTC)


# ── Executive dashboard ──────────────────────────────────────────────────────
@router.get("/executive", response_class=HTMLResponse)
async def executive_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    rollup = await insights.executive(session, org_id=org)
    dq = await insights.data_quality(session, org_id=org)
    unified = await insights.unified_controls(session, limit=10)
    return templates.TemplateResponse(
        request,
        "executive.html",
        {"active": "executive", "r": rollup, "dq": dq, "unified": unified},
    )


# ── Trust Center ─────────────────────────────────────────────────────────────
@router.get("/trust", response_class=HTMLResponse)
async def trust_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    t = (
        await session.execute(select(TrustProfile).where(TrustProfile.organization_id == org))
    ).scalar_one_or_none()
    return templates.TemplateResponse(request, "trust.html", {"active": "trust", "t": t})


@router.post("/trust")
async def trust_save(
    request: Request,
    headline: str = Form(""),
    summary: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    t = (
        await session.execute(select(TrustProfile).where(TrustProfile.organization_id == org))
    ).scalar_one_or_none()
    if t is None:
        t = TrustProfile(organization_id=org)
        session.add(t)
    t.headline = headline or None
    t.summary = summary or None
    await session.commit()
    return RedirectResponse("/trust", status_code=303)


# ── Regulatory Change ────────────────────────────────────────────────────────
@router.get("/regulatory", response_class=HTMLResponse)
async def regulatory_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    stmt = select(RegulatoryUpdate).order_by(RegulatoryUpdate.due_on.nulls_last())
    if org is not None:
        stmt = stmt.where(RegulatoryUpdate.organization_id == org)
    rows = (await session.execute(stmt)).scalars().all()
    return templates.TemplateResponse(
        request, "regulatory.html", {"active": "regulatory", "rows": rows}
    )


@router.post("/regulatory")
async def regulatory_create(
    request: Request,
    title: str = Form(...),
    source: str = Form(""),
    framework_impacted: str = Form(""),
    status: str = Form("new"),
    due_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    due = None
    if due_on:
        with contextlib.suppress(ValueError):
            due = date.fromisoformat(due_on)
    session.add(
        RegulatoryUpdate(
            organization_id=org,
            title=title,
            source=source or None,
            framework_impacted=framework_impacted or None,
            status=status,
            due_on=due,
        )
    )
    await session.commit()
    return RedirectResponse("/regulatory", status_code=303)


# ── Connector registry ───────────────────────────────────────────────────────
@router.get("/connectors", response_class=HTMLResponse)
async def connectors_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    stmt = select(ConnectorConfig).order_by(ConnectorConfig.name)
    if org is not None:
        stmt = stmt.where(ConnectorConfig.organization_id == org)
    rows = (await session.execute(stmt)).scalars().all()
    return templates.TemplateResponse(
        request,
        "connectors.html",
        {"active": "connectors", "rows": rows, "types": CONNECTOR_TYPES},
    )


@router.post("/connectors")
async def connectors_create(
    request: Request,
    name: str = Form(...),
    connector_type: str = Form(...),
    environment: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if connector_type not in CONNECTOR_TYPES:
        raise HTTPException(422, "invalid connector type")
    org = _principal_org(request)
    session.add(
        ConnectorConfig(
            organization_id=org,
            name=name,
            connector_type=connector_type,
            environment=environment or None,
        )
    )
    await session.commit()
    return RedirectResponse("/connectors", status_code=303)


@router.post("/connectors/{cfg_id}/sync")
async def connectors_sync(
    cfg_id: int, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    c = await session.get(ConnectorConfig, cfg_id)
    if c is not None:
        discovered = _MOCK_DISCOVERY.get(c.connector_type, 100)
        c.objects_discovered = discovered
        c.evidence_produced = max(1, discovered // 10)
        c.status = "configured"
        c.last_sync = _now()
        await session.commit()
    return RedirectResponse("/connectors", status_code=303)


# ── Control Tests ────────────────────────────────────────────────────────────
@router.get("/control-tests", response_class=HTMLResponse)
async def control_tests_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    stmt = select(ControlTest).order_by(ControlTest.control_id)
    if org is not None:
        stmt = stmt.where(ControlTest.organization_id == org)
    rows = (await session.execute(stmt)).scalars().all()
    metrics = {
        "total": len(rows),
        "passing": sum(1 for r in rows if r.last_status == "pass"),
        "failing": sum(1 for r in rows if r.last_status == "fail"),
        "untested": sum(1 for r in rows if not r.last_status),
    }
    return templates.TemplateResponse(
        request,
        "control_tests.html",
        {"active": "controltests", "rows": rows, "metrics": metrics},
    )


@router.post("/control-tests")
async def control_tests_create(
    request: Request,
    control_id: str = Form(...),
    name: str = Form(...),
    method: str = Form("manual"),
    frequency: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    session.add(
        ControlTest(
            organization_id=org,
            control_id=control_id,
            name=name,
            method=method,
            frequency=frequency or None,
        )
    )
    await session.commit()
    return RedirectResponse("/control-tests", status_code=303)


# ── Audit Workspace ──────────────────────────────────────────────────────────
@router.get("/audit-workspace", response_class=HTMLResponse)
async def audit_workspace_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    stmt = select(AuditEngagement).order_by(AuditEngagement.id.desc())
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    rows = (await session.execute(stmt)).scalars().all()
    return templates.TemplateResponse(
        request, "audit_workspace.html", {"active": "auditws", "rows": rows}
    )


@router.post("/audit-workspace")
async def audit_engagement_create(
    request: Request,
    name: str = Form(...),
    auditor_org: str = Form(""),
    framework: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    session.add(
        AuditEngagement(
            organization_id=org,
            name=name,
            auditor_org=auditor_org or None,
            framework=framework or None,
        )
    )
    await session.commit()
    return RedirectResponse("/audit-workspace", status_code=303)


@router.get("/audit-workspace/{eng_id}", response_class=HTMLResponse)
async def audit_engagement_detail(
    eng_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    e = (
        await session.execute(
            select(AuditEngagement)
            .options(selectinload(AuditEngagement.requests), selectinload(AuditEngagement.findings))
            .where(AuditEngagement.id == eng_id)
        )
    ).scalar_one_or_none()
    if e is None:
        raise HTTPException(404, "engagement not found")
    return templates.TemplateResponse(request, "audit_detail.html", {"active": "auditws", "e": e})


@router.post("/audit-workspace/{eng_id}/requests")
async def audit_add_request(
    eng_id: int,
    request: Request,
    title: str = Form(...),
    due_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    due = None
    if due_on:
        with contextlib.suppress(ValueError):
            due = date.fromisoformat(due_on)
    session.add(AuditRequest(engagement_id=eng_id, title=title, due_on=due))
    await session.commit()
    return RedirectResponse(f"/audit-workspace/{eng_id}", status_code=303)


@router.post("/audit-workspace/{eng_id}/findings")
async def audit_add_finding(
    eng_id: int,
    request: Request,
    title: str = Form(...),
    severity: str = Form("moderate"),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    session.add(AuditFinding(engagement_id=eng_id, title=title, severity=severity))
    await session.commit()
    return RedirectResponse(f"/audit-workspace/{eng_id}", status_code=303)
