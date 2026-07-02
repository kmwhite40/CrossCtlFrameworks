"""GRC operating-system API — Trust Center, Regulatory Change, Audit Workspace,
Connector registry, and Control Tests. All mutations emit events onto the bus.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...governance import bus, control_tests
from ...models import Task
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
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["grc"])

CONNECTOR_TYPES = (
    "azure",
    "azure_gov",
    "m365",
    "m365_gcc_high",
    "aws",
    "aws_govcloud",
    "gcp",
    "github",
    "jira",
    "servicenow",
)
# Deterministic mock discovery volumes per connector type (no live creds needed).
_MOCK_DISCOVERY = {
    "azure": 240,
    "azure_gov": 210,
    "m365": 180,
    "m365_gcc_high": 165,
    "aws": 320,
    "aws_govcloud": 290,
    "gcp": 200,
    "github": 90,
    "jira": 60,
    "servicenow": 75,
}


def _now() -> datetime:
    return datetime.now(UTC)


# ── Trust Center ────────────────────────────────────────────────────────────
class TrustProfileIn(BaseModel):
    headline: str | None = None
    summary: str | None = None
    framework_badges: list[dict[str, Any]] | None = None
    approved_reports: list[Any] | None = None
    approved_policies: list[Any] | None = None
    approved_evidence: list[Any] | None = None
    faq: list[dict[str, str]] | None = None
    published: bool | None = None


async def _get_trust(session: AsyncSession, org_id: int | None) -> TrustProfile:
    row = (
        await session.execute(select(TrustProfile).where(TrustProfile.organization_id == org_id))
    ).scalar_one_or_none()
    if row is None:
        row = TrustProfile(organization_id=org_id)
        session.add(row)
        await session.flush()
    return row


def _trust_out(t: TrustProfile) -> dict[str, Any]:
    return {
        "headline": t.headline,
        "summary": t.summary,
        "framework_badges": t.framework_badges,
        "approved_reports": t.approved_reports,
        "approved_policies": t.approved_policies,
        "approved_evidence": t.approved_evidence,
        "faq": t.faq,
        "published": t.published,
    }


@router.get("/trust/profile")
async def get_trust_profile(
    session: AsyncSession = Depends(get_session), principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    return _trust_out(await _get_trust(session, principal.org_id))


@router.put("/trust/profile")
async def update_trust_profile(
    body: TrustProfileIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    t = await _get_trust(session, principal.org_id)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(t, k, v)
    await session.commit()
    return _trust_out(t)


@router.get("/trust/package", response_model=None)
async def trust_package(
    fmt: str = Query("json"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    """Export the trust package (json|md) — internal-first, share on request."""
    t = await _get_trust(session, principal.org_id)
    data = _trust_out(t)
    if fmt == "md":
        lines = [f"# {data['headline'] or 'Security & Compliance'}", ""]
        if data["summary"]:
            lines += [data["summary"], ""]
        lines.append("## Framework status")
        for b in data["framework_badges"] or []:
            lines.append(f"- **{b.get('framework')}** — {b.get('status')}")
        lines.append("\n## Approved reports")
        lines += [f"- {r}" for r in (data["approved_reports"] or [])]
        lines.append("\n## FAQ")
        for f in data["faq"] or []:
            lines += [f"**{f.get('q')}**", f"{f.get('a')}", ""]
        body = "\n".join(lines).encode()
        return Response(
            body,
            media_type="text/markdown",
            headers={"Content-Disposition": 'attachment; filename="trust-package.md"'},
        )
    return Response(json.dumps(data, indent=2, default=str).encode(), media_type="application/json")


class AccessRequestIn(BaseModel):
    requester_name: str
    email: str | None = None
    company: str | None = None
    reason: str | None = None


@router.get("/trust/access-requests")
async def list_access_requests(
    session: AsyncSession = Depends(get_session), principal: Principal = Depends(get_principal)
) -> list[dict[str, Any]]:
    stmt = select(TrustAccessRequest).order_by(TrustAccessRequest.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(TrustAccessRequest.organization_id == principal.org_id)
    return [
        {
            "id": r.id,
            "requester_name": r.requester_name,
            "company": r.company,
            "status": r.status,
            "created_at": r.created_at,
        }
        for r in (await session.execute(stmt)).scalars().all()
    ]


@router.post("/trust/access-requests", status_code=201)
async def create_access_request(
    body: AccessRequestIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = TrustAccessRequest(organization_id=principal.org_id, **body.model_dump())
    session.add(r)
    await session.flush()
    await bus.emit(
        session,
        verb="requested",
        entity_type="trust_access_request",
        entity_id=r.id,
        summary=f"Trust access requested by {r.requester_name}",
        org_id=principal.org_id,
    )
    await session.commit()
    return {"id": r.id, "status": r.status}


@router.post("/trust/access-requests/{req_id}/decide")
async def decide_access_request(
    req_id: int,
    approve: bool = True,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = (
        await session.execute(select(TrustAccessRequest).where(TrustAccessRequest.id == req_id))
    ).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "request not found")
    r.status = "approved" if approve else "denied"
    r.decided_by = principal.email
    r.decided_at = _now()
    await session.commit()
    return {"id": r.id, "status": r.status}


# ── Regulatory Change Management ─────────────────────────────────────────────
class RegulatoryIn(BaseModel):
    title: str
    source: str | None = None
    framework_impacted: str | None = None
    requirement_impacted: str | None = None
    summary: str | None = None
    applicability: str = "assessing"
    control_impact: str | None = None
    policy_impact: str | None = None
    system_impact: str | None = None
    owner: str | None = None
    due_on: date | None = None
    status: str = "new"


def _reg_out(r: RegulatoryUpdate) -> dict[str, Any]:
    return {
        "id": r.id,
        "title": r.title,
        "source": r.source,
        "framework_impacted": r.framework_impacted,
        "requirement_impacted": r.requirement_impacted,
        "applicability": r.applicability,
        "owner": r.owner,
        "due_on": r.due_on,
        "status": r.status,
    }


@router.get("/regulatory")
async def list_regulatory(
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(RegulatoryUpdate).order_by(RegulatoryUpdate.due_on.nulls_last())
    if principal.org_id is not None:
        stmt = stmt.where(RegulatoryUpdate.organization_id == principal.org_id)
    if status:
        stmt = stmt.where(RegulatoryUpdate.status == status)
    return [_reg_out(r) for r in (await session.execute(stmt)).scalars().all()]


@router.post("/regulatory", status_code=201)
async def create_regulatory(
    body: RegulatoryIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = RegulatoryUpdate(organization_id=principal.org_id, **body.model_dump())
    session.add(r)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="regulatory_update",
        entity_id=r.id,
        summary=f"Regulatory update logged: {r.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _reg_out(r)


@router.patch("/regulatory/{reg_id}")
async def update_regulatory(
    reg_id: int,
    body: RegulatoryIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = (
        await session.execute(select(RegulatoryUpdate).where(RegulatoryUpdate.id == reg_id))
    ).scalar_one_or_none()
    if r is None:
        raise HTTPException(404, "not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(r, k, v)
    await session.commit()
    return _reg_out(r)


# ── Audit Collaboration Workspace ────────────────────────────────────────────
class EngagementIn(BaseModel):
    name: str
    auditor_org: str | None = None
    framework: str | None = None
    scope: str | None = None
    systems: list[int] = []
    started_on: date | None = None
    target_on: date | None = None
    status: str = "planning"


class RequestIn(BaseModel):
    title: str
    description: str | None = None
    owner_user_id: int | None = None
    due_on: date | None = None


class RequestUpdate(BaseModel):
    status: str | None = None
    auditor_note: str | None = None
    internal_note: str | None = None
    evidence_ref: str | None = None


class FindingIn(BaseModel):
    title: str
    severity: str = "moderate"
    description: str | None = None


class FindingUpdate(BaseModel):
    status: str | None = None
    management_response: str | None = None
    closure_evidence: str | None = None


@router.get("/audit/engagements")
async def list_engagements(
    session: AsyncSession = Depends(get_session), principal: Principal = Depends(get_principal)
) -> list[dict[str, Any]]:
    stmt = select(AuditEngagement).order_by(AuditEngagement.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(AuditEngagement.organization_id == principal.org_id)
    return [
        {
            "id": e.id,
            "name": e.name,
            "auditor_org": e.auditor_org,
            "framework": e.framework,
            "status": e.status,
            "target_on": e.target_on,
        }
        for e in (await session.execute(stmt)).scalars().all()
    ]


@router.post("/audit/engagements", status_code=201)
async def create_engagement(
    body: EngagementIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    e = AuditEngagement(organization_id=principal.org_id, **body.model_dump())
    session.add(e)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="audit_engagement",
        entity_id=e.id,
        summary=f"Audit engagement opened: {e.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": e.id, "name": e.name, "status": e.status}


@router.get("/audit/engagements/{eng_id}")
async def get_engagement(
    eng_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    e = (
        await session.execute(
            select(AuditEngagement)
            .options(selectinload(AuditEngagement.requests), selectinload(AuditEngagement.findings))
            .where(AuditEngagement.id == eng_id)
        )
    ).scalar_one_or_none()
    if e is None:
        raise HTTPException(404, "engagement not found")
    return {
        "id": e.id,
        "name": e.name,
        "auditor_org": e.auditor_org,
        "framework": e.framework,
        "scope": e.scope,
        "status": e.status,
        "systems": e.systems,
        "requests": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status,
                "due_on": r.due_on,
                "owner_user_id": r.owner_user_id,
                "evidence_ref": r.evidence_ref,
            }
            for r in e.requests
        ],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "status": f.status}
            for f in e.findings
        ],
    }


@router.post("/audit/engagements/{eng_id}/requests", status_code=201)
async def add_request(
    eng_id: int,
    body: RequestIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if (await session.get(AuditEngagement, eng_id)) is None:
        raise HTTPException(404, "engagement not found")
    r = AuditRequest(engagement_id=eng_id, **body.model_dump())
    session.add(r)
    await session.commit()
    return {"id": r.id, "status": r.status}


@router.patch("/audit/requests/{req_id}")
async def update_request(
    req_id: int,
    body: RequestUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    r = await session.get(AuditRequest, req_id)
    if r is None:
        raise HTTPException(404, "request not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(r, k, v)
    await session.commit()
    return {"id": r.id, "status": r.status}


@router.post("/audit/engagements/{eng_id}/findings", status_code=201)
async def add_finding(
    eng_id: int,
    body: FindingIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if (await session.get(AuditEngagement, eng_id)) is None:
        raise HTTPException(404, "engagement not found")
    f = AuditFinding(engagement_id=eng_id, **body.model_dump())
    session.add(f)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="audit_finding",
        entity_id=f.id,
        summary=f"Audit finding raised: {f.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": f.id, "status": f.status}


@router.patch("/audit/findings/{find_id}")
async def update_finding(
    find_id: int,
    body: FindingUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    f = await session.get(AuditFinding, find_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(f, k, v)
    await session.commit()
    return {"id": f.id, "status": f.status}


# ── Cloud Connector registry ─────────────────────────────────────────────────
class ConnectorIn(BaseModel):
    name: str
    connector_type: str
    environment: str | None = None
    auth_method: str | None = None
    config: dict[str, Any] = {}


def _conn_out(c: ConnectorConfig) -> dict[str, Any]:
    return {
        "id": c.id,
        "name": c.name,
        "connector_type": c.connector_type,
        "environment": c.environment,
        "auth_method": c.auth_method,
        "status": c.status,
        "last_sync": c.last_sync,
        "error_message": c.error_message,
        "objects_discovered": c.objects_discovered,
        "evidence_produced": c.evidence_produced,
        "controls_impacted": c.controls_impacted,
    }


@router.get("/connector-configs")
async def list_connectors(
    session: AsyncSession = Depends(get_session), principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    stmt = select(ConnectorConfig).order_by(ConnectorConfig.name)
    if principal.org_id is not None:
        stmt = stmt.where(ConnectorConfig.organization_id == principal.org_id)
    return {
        "connector_types": list(CONNECTOR_TYPES),
        "configs": [_conn_out(c) for c in (await session.execute(stmt)).scalars().all()],
    }


@router.post("/connector-configs", status_code=201)
async def create_connector(
    body: ConnectorIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if body.connector_type not in CONNECTOR_TYPES:
        raise HTTPException(422, f"connector_type must be one of {', '.join(CONNECTOR_TYPES)}")
    c = ConnectorConfig(organization_id=principal.org_id, **body.model_dump())
    session.add(c)
    await session.commit()
    return _conn_out(c)


@router.post("/connector-configs/{cfg_id}/sync")
async def sync_connector(
    cfg_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Mock sync path — records discovery + sets status until live auth is wired."""
    c = await session.get(ConnectorConfig, cfg_id)
    if c is None:
        raise HTTPException(404, "connector not found")
    discovered = _MOCK_DISCOVERY.get(c.connector_type, 100)
    c.objects_discovered = discovered
    c.evidence_produced = max(1, discovered // 10)
    c.status = "configured"
    c.last_sync = _now()
    c.error_message = None
    await bus.emit(
        session,
        verb="synced",
        entity_type="connector_config",
        entity_id=c.id,
        summary=f"Connector '{c.name}' sync: {discovered} objects (mock)",
        org_id=principal.org_id,
        actor=principal.email,
        payload={"objects": discovered, "mock": True},
    )
    await session.commit()
    return _conn_out(c)


# ── Continuous Control Monitoring: test definitions + results ────────────────
class ControlTestIn(BaseModel):
    control_id: str
    name: str
    description: str | None = None
    method: str = "manual"
    connector_type: str | None = None
    frequency: str | None = None
    expected: str | None = None
    # Optional machine-checkable assertion evaluated against captured config,
    # e.g. {"odp_key": "mfa_enforced", "operator": "equals", "value": "true"}.
    assertion: dict[str, Any] | None = None
    system_id: int | None = None
    active: bool = True


class TestRunIn(BaseModel):
    status: str  # pass|fail|warn
    detail: str | None = None
    evidence_ref: str | None = None


def _test_out(t: ControlTest) -> dict[str, Any]:
    return {
        "id": t.id,
        "control_id": t.control_id,
        "name": t.name,
        "method": t.method,
        "connector_type": t.connector_type,
        "frequency": t.frequency,
        "assertion": t.assertion,
        "active": t.active,
        "last_status": t.last_status,
        "last_tested_at": t.last_tested_at,
    }


@router.get("/control-tests")
async def list_control_tests(
    control_id: str | None = None,
    system_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(ControlTest).order_by(ControlTest.control_id)
    if principal.org_id is not None:
        stmt = stmt.where(ControlTest.organization_id == principal.org_id)
    if control_id:
        stmt = stmt.where(ControlTest.control_id == control_id)
    if system_id is not None:
        stmt = stmt.where(ControlTest.system_id == system_id)
    return [_test_out(t) for t in (await session.execute(stmt)).scalars().all()]


@router.post("/control-tests", status_code=201)
async def create_control_test(
    body: ControlTestIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    t = ControlTest(organization_id=principal.org_id, **body.model_dump())
    session.add(t)
    await session.commit()
    return _test_out(t)


@router.post("/control-tests/{test_id}/run")
async def run_control_test(
    test_id: int,
    body: TestRunIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Record a test result; a failing test opens an alert + remediation task."""
    if body.status not in ("pass", "fail", "warn"):
        raise HTTPException(422, "status must be pass|fail|warn")
    t = await session.get(ControlTest, test_id)
    if t is None:
        raise HTTPException(404, "control test not found")
    res = ControlTestResult(
        control_test_id=test_id,
        status=body.status,
        detail=body.detail,
        evidence_ref=body.evidence_ref,
    )
    session.add(res)
    t.last_status = body.status
    t.last_tested_at = _now()
    await session.flush()

    if body.status in ("fail", "warn"):
        sev = "critical" if body.status == "fail" else "warning"
        await bus.notify(
            session,
            category="conmon",
            title=f"Control test {body.status}: {t.name} ({t.control_id})",
            body=body.detail,
            org_id=principal.org_id,
            severity=sev,
            entity_type="control_test",
            entity_id=t.id,
            dedupe_key=f"ctltest:{t.id}",
        )
        if body.status == "fail":
            dedupe = f"ctltest-fix:{t.id}"
            exists = (
                await session.execute(select(Task).where(Task.dedupe_key == dedupe))
            ).scalar_one_or_none()
            if exists is None:
                session.add(
                    Task(
                        organization_id=principal.org_id,
                        system_id=t.system_id,
                        title=f"Remediate failed control test: {t.name}",
                        description=body.detail,
                        kind="remediation",
                        priority="high",
                        status="open",
                        source="auto",
                        entity_type="control_test",
                        entity_id=str(t.id),
                        dedupe_key=dedupe,
                    )
                )
    await bus.emit(
        session,
        verb="tested",
        entity_type="control_test",
        entity_id=t.id,
        summary=f"Control test {body.status}: {t.control_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"test_id": t.id, "status": body.status, "last_tested_at": t.last_tested_at}


@router.post("/control-tests/{test_id}/evaluate")
async def evaluate_control_test(
    test_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Evaluate a connector-backed test now against the latest captured config.

    Runs the test's machine-checkable assertion (or connector-freshness
    heuristic) immediately and records the result — the on-demand counterpart to
    the scheduler's auto-run. Returns the derived status + evidence reference.
    """
    t = await session.get(ControlTest, test_id)
    if t is None or (principal.org_id is not None and t.organization_id != principal.org_id):
        raise HTTPException(404, "control test not found")
    status, detail, evidence_ref = await control_tests.evaluate_test(
        session, t, _now().date()
    )
    await control_tests.record_result(
        session,
        t,
        status=status,
        detail=detail,
        evidence_ref=evidence_ref,
        actor=principal.email or "user",
    )
    await session.commit()
    return {
        "test_id": t.id,
        "status": status,
        "detail": detail,
        "evidence_ref": evidence_ref,
        "last_tested_at": t.last_tested_at,
    }


@router.get("/control-tests/{test_id}/results")
async def test_results(
    test_id: int,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    rows = (
        (
            await session.execute(
                select(ControlTestResult)
                .where(ControlTestResult.control_test_id == test_id)
                .order_by(ControlTestResult.id.desc())
                .limit(min(limit, 200))
            )
        )
        .scalars()
        .all()
    )
    return [{"id": r.id, "status": r.status, "run_at": r.run_at, "detail": r.detail} for r in rows]
