"""Server-rendered UI for the GRC operating-system modules — Trust Center,
Audit Workspace, Regulatory Change, Connector registry, and Control Tests.

Kept separate from the large ``ui.py`` and reuses its configured Jinja
environment (same base.html + light theme, asset-version cache-busting).
"""

from __future__ import annotations

import contextlib
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...evidence import service as evidence_service
from ...governance import control_tests, insights, personnel, tprm
from ...ingest import parse_scan, reconcile_findings
from ...models import CaptureSnapshot, ScanIngestion, System, Task, Vendor
from ...models_evidence import EvidenceObject
from ...models_grc import (
    AuditEngagement,
    AuditFinding,
    AuditRequest,
    ConnectorConfig,
    ControlTest,
    ControlTestResult,
    RegulatoryUpdate,
    TrustAccessRequest,
    TrustProfile,
)
from ...models_people import AccessReview, Person
from ...models_tprm import QuestionnaireResponse, VendorQuestionnaire
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
    ar_stmt = select(TrustAccessRequest).order_by(TrustAccessRequest.id.desc())
    if org is not None:
        ar_stmt = ar_stmt.where(TrustAccessRequest.organization_id == org)
    access_requests = (await session.execute(ar_stmt)).scalars().all()
    return templates.TemplateResponse(
        request, "trust.html", {"active": "trust", "t": t, "access_requests": access_requests}
    )


@router.post("/trust/access-requests")
async def trust_access_create(
    request: Request,
    requester_name: str = Form(...),
    company: str = Form(""),
    email: str = Form(""),
    reason: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    session.add(
        TrustAccessRequest(
            organization_id=org,
            requester_name=requester_name,
            company=company or None,
            email=email or None,
            reason=reason or None,
        )
    )
    await session.commit()
    return RedirectResponse("/trust", status_code=303)


@router.post("/trust/access-requests/{req_id}/decide")
async def trust_access_decide(
    req_id: int,
    request: Request,
    approve: str = Form("1"),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    r = await session.get(TrustAccessRequest, req_id)
    if r is not None:
        r.status = "approved" if approve == "1" else "denied"
        r.decided_at = _now()
        await session.commit()
    return RedirectResponse("/trust", status_code=303)


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


@router.post("/regulatory/{upd_id}/update")
async def regulatory_update(
    upd_id: int,
    applicability: str = Form(""),
    status: str = Form(""),
    owner: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    u = await session.get(RegulatoryUpdate, upd_id)
    if u is not None:
        if applicability:
            u.applicability = applicability
        if status:
            u.status = status
        if owner:
            u.owner = owner or None
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


@router.get("/connectors/{cfg_id}", response_class=HTMLResponse)
async def connector_detail(
    cfg_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    c = await session.get(ConnectorConfig, cfg_id)
    if c is None or (org is not None and c.organization_id != org):
        raise HTTPException(404, "connector not found")
    cap_stmt = (
        select(CaptureSnapshot)
        .where(CaptureSnapshot.connector == c.connector_type)
        .order_by(CaptureSnapshot.captured_at.desc())
        .limit(50)
    )
    if org is not None:
        cap_stmt = cap_stmt.where(CaptureSnapshot.organization_id == org)
    captures = (await session.execute(cap_stmt)).scalars().all()
    return templates.TemplateResponse(
        request,
        "connector_detail.html",
        {"active": "connectors", "c": c, "captures": captures},
    )


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


@router.post("/control-tests/{test_id}/run")
async def control_tests_run(
    test_id: int,
    request: Request,
    status: str = Form(...),
    detail: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    test = await session.get(ControlTest, test_id)
    if test is not None:
        principal = getattr(request.state, "principal", None)
        actor = getattr(principal, "email", None) or "user"
        with contextlib.suppress(ValueError):
            await control_tests.record_result(
                session, test, status=status, detail=detail or None, actor=actor
            )
            await session.commit()
    return RedirectResponse("/control-tests", status_code=303)


@router.get("/control-tests/{test_id}", response_class=HTMLResponse)
async def control_test_detail(
    test_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    test = await session.get(ControlTest, test_id)
    if test is None or (org is not None and test.organization_id != org):
        raise HTTPException(404, "control test not found")
    results = (
        await session.execute(
            select(ControlTestResult)
            .where(ControlTestResult.control_test_id == test_id)
            .order_by(ControlTestResult.run_at.desc())
            .limit(100)
        )
    ).scalars().all()
    return templates.TemplateResponse(
        request,
        "control_test_detail.html",
        {"active": "controltests", "test": test, "results": results},
    )


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


def _actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "email", None) or "user"


def _parse_date(raw: str) -> date | None:
    if raw:
        with contextlib.suppress(ValueError):
            return date.fromisoformat(raw)
    return None


# ── Personnel & Access ───────────────────────────────────────────────────────
@router.get("/personnel", response_class=HTMLResponse)
async def personnel_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    people_stmt = select(Person).order_by(Person.full_name)
    ar_stmt = select(AccessReview).order_by(AccessReview.id.desc())
    if org is not None:
        people_stmt = people_stmt.where(Person.organization_id == org)
        ar_stmt = ar_stmt.where(AccessReview.organization_id == org)
    people = (await session.execute(people_stmt)).scalars().all()
    reviews = (await session.execute(ar_stmt)).scalars().all()
    summary = await personnel.summary(session, org_id=org)
    return templates.TemplateResponse(
        request,
        "personnel.html",
        {"active": "personnel", "people": people, "reviews": reviews, "summary": summary},
    )


@router.post("/personnel")
async def personnel_create(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(""),
    employment_type: str = Form("employee"),
    position: str = Form(""),
    risk_designation: str = Form("low"),
    background_check_status: str = Form("not_started"),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    p = Person(
        organization_id=org,
        full_name=full_name,
        email=email or None,
        employment_type=employment_type,
        position=position or None,
        risk_designation=risk_designation,
        background_check_status=background_check_status,
        status="active",
    )
    session.add(p)
    await session.flush()
    await personnel.onboard(session, p, actor=_actor(request))
    await session.commit()
    return RedirectResponse("/personnel", status_code=303)


@router.post("/personnel/{pid}/offboard")
async def personnel_offboard(
    pid: int, request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    p = await session.get(Person, pid)
    if p is not None:
        await personnel.offboard(session, p, actor=_actor(request))
        await session.commit()
    return RedirectResponse("/personnel", status_code=303)


@router.post("/access-reviews")
async def access_review_create(
    request: Request,
    name: str = Form(...),
    reviewer: str = Form(""),
    due_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    session.add(
        AccessReview(
            organization_id=org,
            name=name,
            reviewer=reviewer or None,
            status="open",
            due_on=_parse_date(due_on),
        )
    )
    await session.commit()
    return RedirectResponse("/personnel", status_code=303)


# ── Scan ingestion ───────────────────────────────────────────────────────────
@router.get("/scans", response_class=HTMLResponse)
async def scans_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    ing_stmt = select(ScanIngestion).order_by(ScanIngestion.id.desc()).limit(50)
    sys_stmt = select(System).order_by(System.name)
    if org is not None:
        sys_stmt = sys_stmt.where(System.organization_id == org)
    ingestions = (await session.execute(ing_stmt)).scalars().all()
    systems = (await session.execute(sys_stmt)).scalars().all()
    return templates.TemplateResponse(
        request,
        "scans.html",
        {"active": "scans", "ingestions": ingestions, "systems": systems},
    )


@router.post("/scans")
async def scans_upload(
    request: Request,
    system_id: int = Form(...),
    scanner: str = Form("auto"),
    file: UploadFile | None = None,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if file is None:
        raise HTTPException(400, "a scan file is required")
    data = await file.read()
    if not data:
        raise HTTPException(400, "uploaded scan file is empty")
    resolved, findings = parse_scan(scanner, data, file.filename)
    result = await reconcile_findings(
        session, system_id=system_id, scanner=resolved, findings=findings
    )
    session.add(
        ScanIngestion(
            organization_id=_principal_org(request),
            system_id=system_id,
            scanner=resolved,
            filename=file.filename,
            findings_total=result.findings_total,
            poams_created=result.created,
            poams_updated=result.updated,
            poams_reopened=result.reopened,
            poams_closed=result.closed,
            summary=result.as_dict(),
        )
    )
    await session.commit()
    return RedirectResponse("/scans", status_code=303)


# ── Vendor questionnaires ────────────────────────────────────────────────────
@router.get("/vendor-questionnaires", response_class=HTMLResponse)
async def questionnaires_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    q_stmt = select(VendorQuestionnaire).order_by(VendorQuestionnaire.id.desc())
    v_stmt = select(Vendor).order_by(Vendor.name)
    if org is not None:
        q_stmt = q_stmt.where(VendorQuestionnaire.organization_id == org)
        v_stmt = v_stmt.where(Vendor.organization_id == org)
    questionnaires = (await session.execute(q_stmt)).scalars().all()
    vendors = (await session.execute(v_stmt)).scalars().all()
    return templates.TemplateResponse(
        request,
        "vendor_questionnaires.html",
        {
            "active": "questionnaires",
            "questionnaires": questionnaires,
            "vendors": vendors,
            "template": tprm.DEFAULT_TEMPLATE,
        },
    )


@router.post("/vendor-questionnaires")
async def questionnaire_create(
    request: Request,
    vendor_id: int = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    vendor = await session.get(Vendor, vendor_id)
    if vendor is None:
        raise HTTPException(404, "vendor not found")
    template = tprm.DEFAULT_TEMPLATE
    q = VendorQuestionnaire(
        organization_id=org,
        vendor_id=vendor_id,
        template_key=template["key"],
        name=f"{vendor.name} — {template['name']}",
        status="sent",
        sent_on=_now().date(),
    )
    session.add(q)
    await session.flush()
    for i, question in enumerate(template["questions"]):
        session.add(
            QuestionnaireResponse(
                questionnaire_id=q.id,
                question_id=str(question["id"]),
                domain=question.get("domain"),
                question_text=question.get("text", ""),
                weight=int(question.get("weight", 1)),
                answer="unanswered",
                sort_order=i,
            )
        )
    await session.commit()
    return RedirectResponse(f"/vendor-questionnaires/{q.id}", status_code=303)


@router.get("/vendor-questionnaires/{qid}", response_class=HTMLResponse)
async def questionnaire_detail(
    qid: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    q = (
        await session.execute(
            select(VendorQuestionnaire)
            .options(selectinload(VendorQuestionnaire.responses))
            .where(VendorQuestionnaire.id == qid)
        )
    ).scalar_one_or_none()
    if q is None:
        raise HTTPException(404, "questionnaire not found")
    return templates.TemplateResponse(
        request, "questionnaire_detail.html", {"active": "questionnaires", "q": q}
    )


@router.get("/vendor-questionnaires/{qid}/export", response_class=HTMLResponse)
async def questionnaire_export(
    qid: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """Render a modern, print-to-PDF assessment report for a questionnaire."""
    org = _principal_org(request)
    q = (
        await session.execute(
            select(VendorQuestionnaire)
            .options(selectinload(VendorQuestionnaire.responses))
            .where(VendorQuestionnaire.id == qid)
        )
    ).scalar_one_or_none()
    if q is None or (org is not None and q.organization_id != org):
        raise HTTPException(404, "questionnaire not found")

    vendor = await session.get(Vendor, q.vendor_id)
    responses = sorted(q.responses, key=lambda r: (r.sort_order or 0, r.id))

    def _score(items: list[QuestionnaireResponse]) -> dict[str, Any]:
        return tprm.score_responses(
            [
                {"answer": r.answer, "weight": r.weight, "question_id": r.question_id}
                for r in items
            ]
        )

    scored = _score(responses)

    # Per-domain rollup, preserving first-seen domain order.
    grouped: dict[str, list[QuestionnaireResponse]] = {}
    for r in responses:
        grouped.setdefault(r.domain or "General", []).append(r)
    domain_rows = [
        {
            "domain": dom,
            "items": items,
            **_score(items),
            "gaps": sum(1 for r in items if r.answer == "no"),
        }
        for dom, items in grouped.items()
    ]

    return templates.TemplateResponse(
        request,
        "questionnaire_report.html",
        {
            "q": q,
            "vendor": vendor,
            "responses": responses,
            "scored": scored,
            "flagged": set(scored["flagged"]),
            "domain_rows": domain_rows,
            "generated": _now(),
        },
    )


@router.post("/vendor-questionnaires/{qid}/responses/{rid}")
async def questionnaire_answer(
    qid: int,
    rid: int,
    answer: str = Form(...),
    detail: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    r = await session.get(QuestionnaireResponse, rid)
    if r is not None and r.questionnaire_id == qid:
        r.answer = answer
        r.detail = detail or None
        q = await session.get(VendorQuestionnaire, qid)
        if q is not None and q.status in ("draft", "sent"):
            q.status = "in_progress"
        await session.commit()
    return RedirectResponse(f"/vendor-questionnaires/{qid}", status_code=303)


@router.post("/vendor-questionnaires/{qid}/review")
async def questionnaire_review(
    qid: int,
    request: Request,
    open_tasks: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    q = (
        await session.execute(
            select(VendorQuestionnaire)
            .options(selectinload(VendorQuestionnaire.responses))
            .where(VendorQuestionnaire.id == qid)
        )
    ).scalar_one_or_none()
    if q is None:
        raise HTTPException(404, "questionnaire not found")
    scored = tprm.score_responses(
        [
            {"answer": r.answer, "weight": r.weight, "question_id": r.question_id}
            for r in q.responses
        ]
    )
    q.status = "reviewed"
    q.reviewed_on = _now().date()
    q.reviewer = _actor(request)
    q.score = scored["score"]
    q.risk_rating = scored["rating"]
    vendor = await session.get(Vendor, q.vendor_id)
    if vendor is not None:
        vendor.risk_rating = scored["rating"]
        vendor.last_reviewed_on = q.reviewed_on
        if open_tasks and scored["flagged"]:
            flagged = set(scored["flagged"])
            for r in q.responses:
                if r.question_id not in flagged:
                    continue
                dedupe = f"vendorq-gap:{q.id}:{r.question_id}"
                exists = (
                    await session.execute(select(Task).where(Task.dedupe_key == dedupe))
                ).scalar_one_or_none()
                if exists is None:
                    session.add(
                        Task(
                            organization_id=_principal_org(request),
                            title=f"Vendor security gap ({vendor.name}): {r.question_id}",
                            description=r.question_text,
                            kind="vendor_risk",
                            priority="high" if r.weight >= 3 else "medium",
                            status="open",
                            source="auto",
                            entity_type="vendor",
                            entity_id=str(vendor.id),
                            dedupe_key=dedupe,
                        )
                    )
    await session.commit()
    return RedirectResponse(f"/vendor-questionnaires/{qid}", status_code=303)


# ── Evidence repository ──────────────────────────────────────────────────────
@router.get("/evidence", response_class=HTMLResponse)
async def evidence_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    stmt = (
        select(EvidenceObject)
        .options(selectinload(EvidenceObject.versions))
        .order_by(EvidenceObject.id.desc())
    )
    if org is not None:
        stmt = stmt.where(EvidenceObject.organization_id == org)
    objs = (await session.execute(stmt)).scalars().all()
    rows = [evidence_service.object_summary(o) for o in objs]
    metrics = {
        "total": len(rows),
        "approved": sum(1 for r in rows if r["status"] == "approved"),
        "submitted": sum(1 for r in rows if r["status"] == "submitted"),
        "expired": sum(1 for r in rows if r["status"] == "expired"),
    }
    return templates.TemplateResponse(
        request, "evidence.html", {"active": "evidence_repo", "rows": rows, "metrics": metrics}
    )


@router.post("/evidence")
async def evidence_create(
    request: Request,
    title: str = Form(...),
    control_id: str = Form(""),
    framework: str = Form(""),
    owner: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    await evidence_service.create_object(
        session,
        org_id=_principal_org(request),
        title=title,
        control_id=control_id or None,
        framework=framework or None,
        owner=owner or None,
    )
    await session.commit()
    return RedirectResponse("/evidence", status_code=303)


# ── Assurance graph (authorization digital twin) ─────────────────────────────
@router.get("/assurance", response_class=HTMLResponse)
async def assurance_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    from ...assurance import impact as assurance_impact  # noqa: PLC0415
    from ...models_assurance import AssuranceNode  # noqa: PLC0415

    org = _principal_org(request)
    latest = await assurance_impact.latest_build(session, org)
    node_stmt = select(AssuranceNode)
    sys_stmt = select(System).order_by(System.name)
    if org is not None:
        node_stmt = node_stmt.where(AssuranceNode.organization_id == org)
        sys_stmt = sys_stmt.where(System.organization_id == org)
    nodes = (await session.execute(node_stmt)).scalars().all()
    by_type: dict[str, int] = {}
    for n in nodes:
        by_type[n.entity_type] = by_type.get(n.entity_type, 0) + 1
    systems = (await session.execute(sys_stmt)).scalars().all()
    return templates.TemplateResponse(
        request,
        "assurance.html",
        {
            "active": "assurance",
            "latest": latest,
            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "systems": systems,
            "node_total": len(nodes),
        },
    )


@router.post("/assurance/rebuild")
async def assurance_rebuild(
    request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    from ...assurance import builder as assurance_builder  # noqa: PLC0415

    await assurance_builder.rebuild(session, org_id=_principal_org(request))
    await session.commit()
    return RedirectResponse("/assurance", status_code=303)


# ── AI agent governance ──────────────────────────────────────────────────────
@router.get("/ai-agents", response_class=HTMLResponse)
async def ai_agents_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    from ...models_ai_agents import AiAgent  # noqa: PLC0415

    org = _principal_org(request)
    stmt = select(AiAgent).order_by(AiAgent.name)
    if org is not None:
        stmt = stmt.where(AiAgent.organization_id == org)
    agents = (await session.execute(stmt)).scalars().all()
    metrics = {
        "total": len(agents),
        "approved": sum(1 for a in agents if a.approval_status == "approved"),
        "high_risk": sum(1 for a in agents if a.risk_rating in ("high", "critical")),
        "engaged": sum(1 for a in agents if a.kill_switch_status == "engaged"),
    }
    return templates.TemplateResponse(
        request, "ai_agents.html", {"active": "ai_agents", "agents": agents, "metrics": metrics}
    )


@router.post("/ai-agents")
async def ai_agents_create_ui(
    request: Request,
    name: str = Form(...),
    autonomy_level: str = Form("low"),
    production: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    from ...ai_governance import risk_assess  # noqa: PLC0415
    from ...models_ai_agents import AiAgent  # noqa: PLC0415

    agent = AiAgent(
        organization_id=_principal_org(request), name=name, autonomy_level=autonomy_level,
        production_access=bool(production),
    )
    session.add(agent)
    await session.flush()
    await risk_assess(session, agent, actor=_actor(request))
    await session.commit()
    return RedirectResponse("/ai-agents", status_code=303)


@router.post("/ai-agents/{aid}/kill-switch")
async def ai_agents_kill_ui(
    aid: int, request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    from ...ai_governance import engage_kill_switch  # noqa: PLC0415
    from ...models_ai_agents import AiAgent  # noqa: PLC0415

    agent = await session.get(AiAgent, aid)
    if agent is not None:
        await engage_kill_switch(session, agent, reason="UI", actor=_actor(request))
        await session.commit()
    return RedirectResponse("/ai-agents", status_code=303)


# ── Compliance packs ─────────────────────────────────────────────────────────
@router.get("/packs", response_class=HTMLResponse)
async def packs_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    from ...models_packs import CompliancePack  # noqa: PLC0415
    from ...packs import list_available  # noqa: PLC0415

    org = _principal_org(request)
    stmt = select(CompliancePack).order_by(CompliancePack.pack_key)
    if org is not None:
        stmt = stmt.where(CompliancePack.organization_id == org)
    installed = (await session.execute(stmt)).scalars().all()
    installed_keys = {p.pack_key for p in installed}
    available = [a for a in list_available() if a["id"] not in installed_keys]
    return templates.TemplateResponse(
        request, "packs.html",
        {"active": "packs", "installed": installed, "available": available},
    )


@router.post("/packs/install")
async def packs_install_ui(
    request: Request,
    pack_id: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    from ...packs import install_pack, load_pack  # noqa: PLC0415
    from ...packs import service as pack_service  # noqa: PLC0415

    with contextlib.suppress(FileNotFoundError, pack_service.PackError):
        manifest = load_pack(pack_id)
        await install_pack(
            session, org_id=_principal_org(request), manifest=manifest,
            source=pack_id, actor=_actor(request),
        )
        await session.commit()
    return RedirectResponse("/packs", status_code=303)


# ── Concord self-assurance ───────────────────────────────────────────────────
@router.get("/admin/self-assurance", response_class=HTMLResponse)
async def self_assurance_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    from ...self_assurance import status as self_status  # noqa: PLC0415

    st = await self_status(session)
    return templates.TemplateResponse(
        request, "self_assurance.html", {"active": "selfassurance", "st": st}
    )


@router.post("/admin/self-assurance/run")
async def self_assurance_run_ui(
    request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    from ...self_assurance import run_self_assessment  # noqa: PLC0415

    await run_self_assessment(session, actor=_actor(request))
    await session.commit()
    return RedirectResponse("/admin/self-assurance", status_code=303)


# ── External collaboration portal (admin) ────────────────────────────────────
# NB: the page lives at /admin/portal, NOT /portal* — the latter is a public
# prefix (the external, token-authenticated surface) and would bypass the gate.
@router.get("/admin/portal", response_class=HTMLResponse)
async def portal_admin_page(
    request: Request,
    organization_id: int | None = None,
    issued_token: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    from ...models_packages import AuthorizationPackage  # noqa: PLC0415
    from ...models_portal import ExternalPrincipal  # noqa: PLC0415
    from ...portal import list_grants  # noqa: PLC0415

    org_id = organization_id if organization_id is not None else _principal_org(request)
    rows: list[dict[str, Any]] = []
    packages: list[Any] = []
    evidence: list[Any] = []
    if org_id is not None:
        grants = await list_grants(session, org_id=org_id)
        principals = {
            p.id: p
            for p in (
                await session.execute(
                    select(ExternalPrincipal).where(ExternalPrincipal.organization_id == org_id)
                )
            ).scalars().all()
        }
        _now = datetime.now(UTC)
        rows = [
            {"g": g,
             "principal": principals.get(g.principal_id) if g.principal_id else None,
             "status": ("revoked" if g.revoked
                        else "expired" if (g.expires_at and g.expires_at < _now)
                        else "active")}
            for g in grants
        ]
        packages = list(
            (
                await session.execute(
                    select(AuthorizationPackage)
                    .where(AuthorizationPackage.organization_id == org_id)
                    .order_by(AuthorizationPackage.id.desc())
                )
            ).scalars().all()
        )
        evidence = list(
            (
                await session.execute(
                    select(EvidenceObject)
                    .where(EvidenceObject.organization_id == org_id)
                    .order_by(EvidenceObject.id.desc())
                )
            ).scalars().all()
        )
    issued_link = f"{request.base_url}portal?token={issued_token}" if issued_token else None
    return templates.TemplateResponse(
        request, "portal_admin.html",
        {"active": "portaladmin", "org_id": org_id, "rows": rows,
         "packages": packages, "evidence": evidence, "issued_link": issued_link},
    )


@router.post("/admin/portal/grants")
async def portal_admin_create(
    request: Request,
    organization_id: int = Form(...),
    principal_name: str = Form(...),
    kind: str = Form("customer"),
    ttl_days: int = Form(30),
    label: str = Form(""),
    package_ids: list[int] = Form(default=[]),
    evidence_ids: list[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    from urllib.parse import quote  # noqa: PLC0415

    from ...portal import create_grant  # noqa: PLC0415

    grant = await create_grant(
        session, org_id=organization_id, principal_name=principal_name, kind=kind,
        package_ids=package_ids, evidence_ids=evidence_ids, ttl_days=ttl_days,
        label=label or None, actor=_actor(request),
    )
    # The plaintext token is only ever available on this in-memory `grant`
    # (IA-09: the DB stores its hash only) — carry it through the redirect so
    # the page can show it exactly once, right after issuance.
    issued_token = quote(grant.token or "")
    await session.commit()
    return RedirectResponse(
        f"/admin/portal?organization_id={organization_id}&issued_token={issued_token}",
        status_code=303,
    )


@router.post("/admin/portal/grants/{grant_id}/revoke")
async def portal_admin_revoke(
    request: Request,
    grant_id: int,
    organization_id: int = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    from ...portal import revoke_grant  # noqa: PLC0415

    await revoke_grant(session, grant_id, actor=_actor(request))
    await session.commit()
    return RedirectResponse(f"/admin/portal?organization_id={organization_id}", status_code=303)
