"""Server-rendered UI for the GRC operating-system modules — Trust Center,
Audit Workspace, Regulatory Change, Connector registry, and Control Tests.

Kept separate from the large ``ui.py`` and reuses its configured Jinja
environment (same base.html + light theme, asset-version cache-busting).
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...config import get_settings, is_dev_env
from ...evidence import service as evidence_service
from ...governance import control_tests, insights, personnel, tprm, trust_corroboration
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
from ..auth_deps import require_role, resolve_caller_org
from ..deps import get_session
from .grc import (
    _emit_access_decision,
    _load_access_request,
)
from urllib.parse import quote

from ...ai.cipher import CredentialStorageError
from ...connectors import credentials as connector_credentials
from ...connectors import get_connector
from ...connectors.credential_spec import SPECS, IncompleteCredential, missing_fields, spec_for
from ...posture.checks import checks_for
from .ui import _principal_org, templates


def _principal_email(request: Request) -> str:
    """Who to attribute a recorded scan result to."""
    principal = getattr(request.state, 'principal', None)
    return getattr(principal, 'email', None) or 'ui'


router = APIRouter(include_in_schema=False)

#: last_status -> KPI bucket key, for every value with its own bucket.
#: Everything else (None, or the explicit "not_tested" status) is "untested".
_CONTROL_TEST_BUCKET_BY_STATUS = {
    "pass": "passing",
    "warn": "warn",
    "fail": "failing",
    "not_applicable": "not_applicable",
    "manual_review_required": "manual_review_required",
}


def _control_test_metrics(rows: Sequence[ControlTest]) -> dict[str, int]:
    """KPI buckets for the control-tests page, covering the full
    ``fedramp20x.VALIDATION_STATUSES`` vocabulary.

    Previously only pass/fail had their own bucket and everything else
    (including warn, not_applicable, and manual_review_required) fell into
    "untested" -- so "passing + failing + untested" no longer summed to
    "total" once any of those other statuses appeared, and a test that had
    actually run reported as never tested. not_applicable and
    manual_review_required now each get their own bucket -- a test that ran
    and produced one of those verdicts was tested, just not pass/warn/fail.
    Only a missing result (``last_status is None``) or the explicit
    ``not_tested`` status counts as "untested". Every row lands in exactly
    one bucket, so the buckets always sum to "total".
    """
    metrics = {
        "total": len(rows),
        "passing": 0,
        "warn": 0,
        "failing": 0,
        "not_applicable": 0,
        "manual_review_required": 0,
        "untested": 0,
    }
    for r in rows:
        key = _CONTROL_TEST_BUCKET_BY_STATUS.get(r.last_status or "", "untested")
        metrics[key] += 1
    return metrics


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


# ── Catalog integrity (advisory OSCAL reconciliation) ────────────────────────
@router.get("/catalog/integrity", response_class=HTMLResponse)
async def catalog_integrity_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(require_role("admin")),
) -> HTMLResponse:
    from ...catalog.report import latest_report  # noqa: PLC0415

    report = await latest_report(session)
    return templates.TemplateResponse(
        request, "catalog_integrity.html", {"active": "catalogintegrity", "report": report}
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
    # Computed beside the operator's badges, never in place of them: the
    # template renders ``c.badge`` -- the typed text, in the typed order --
    # with the state alongside. Run even when ``t`` is None, because a lapsed
    # authorization must still be reported on a page with no badges at all.
    corroboration = await trust_corroboration.corroborate_badges(
        session, t.framework_badges if t else [], org_id=org
    )
    return templates.TemplateResponse(
        request,
        "trust.html",
        {
            "active": "trust",
            "t": t,
            "access_requests": access_requests,
            "corroboration": corroboration,
        },
    )


@router.post("/trust/access-requests")
async def trust_access_create(
    request: Request,
    *,
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
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    """Admin only, and the same record as the API twin.

    The role is a literal rather than ``grc.TRUST_ADMIN_ROLES``:
    ``tests/test_role_names_are_real`` resolves every ``require_role``
    argument per file and refuses what it cannot read, and an imported
    constant is exactly that. The two paths are held to the same roles
    behaviourally instead -- ``tests/test_trust_rbac`` refuses the same caller
    on both.

    This handler previously set the status and nothing else: no bus event and
    no ``decided_by``, so the same decision made through the UI left no record
    of who made it. It also loaded the row with a bare ``session.get``, which
    relies entirely on RLS for tenant scoping -- unlike the list query above
    it. Both now go through the API's ``_load_access_request`` /
    ``_emit_access_decision``, so the two paths cannot drift apart again.
    """
    r = await _load_access_request(session, req_id, principal)
    r.status = "approved" if approve == "1" else "denied"
    r.decided_by = principal.email
    r.decided_at = _now()
    await _emit_access_decision(session, r, principal)
    await session.commit()
    return RedirectResponse("/trust", status_code=303)


@router.post("/trust")
async def trust_save(
    request: Request,
    headline: str = Form(""),
    summary: str = Form(""),
    session: AsyncSession = Depends(get_session),
    _principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    """Admin only: this is the content of the page the organization presents
    as its security posture. ``GET /trust`` stays open to any org member."""
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
    *,
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
    request: Request,
    *,
    applicability: str = Form(""),
    status: str = Form(""),
    owner: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    # The handler took no principal at all, so ``upd_id`` addressed every
    # tenant's regulatory updates: a tenant could rewrite another's
    # applicability, status and owner by posting to an id. ``regulatory_page``
    # above already carries this predicate on the read.
    #
    # A foreign row falls into the same silent no-op branch a missing one
    # always has, rather than 404-ing: this route redirects to the listing for
    # an unknown id, and answering differently for a real-but-foreign id would
    # turn the write path into an existence oracle it is not today.
    org = _principal_org(request)
    u = await session.get(RegulatoryUpdate, upd_id)
    if u is not None and (org is None or u.organization_id == org):
        if applicability:
            u.applicability = applicability
        if status:
            u.status = status
        if owner:
            u.owner = owner or None
        await session.commit()
    return RedirectResponse("/regulatory", status_code=303)




#: The connector types this page offers, derived from the credential registry.
#:
#: NOT ``grc.CONNECTOR_TYPES``, which is the demo vocabulary paired with
#: ``_MOCK_DISCOVERY``: of its ten entries, seven (azure, azure_gov, m365,
#: m365_gcc_high, aws, github, servicenow) have no connector and no credential
#: spec, so creating one produced a row that could never capture anything --
#: while msgraph, azure_arm, puppetdb, msgraph_write and emass, which do work,
#: could not be created here at all. Deriving the list from ``SPECS`` means a
#: type is offered exactly when a credential for it can be stored.
def _configurable_types() -> tuple[tuple[str, str], ...]:
    """``(connector_type, label)`` for everything with a credential spec."""
    return tuple((key, spec.label) for key, spec in sorted(SPECS.items()))


# ── Connector registry ───────────────────────────────────────────────────────
@router.get("/connectors", response_class=HTMLResponse)
async def connectors_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    # A connector credential is bound to an organization -- `set_credential`
    # refuses to store one otherwise. This page used to tolerate `None`: it
    # listed every tenant's connectors unfiltered and created rows with a NULL
    # organization that could never hold a usable credential. The two halves
    # of the same feature disagreed about whether an org was required.
    if org is None:
        return templates.TemplateResponse(
            request,
            "connectors.html",
            {"active": "connectors", "rows": [], "types": _configurable_types(), "no_org": True},
            status_code=400,
        )
    rows = (
        await session.execute(
            select(ConnectorConfig)
            .where(ConnectorConfig.organization_id == org)
            .order_by(ConnectorConfig.name)
        )
    ).scalars().all()
    return templates.TemplateResponse(
        request,
        "connectors.html",
        {
            "active": "connectors",
            "rows": rows,
            "types": _configurable_types(),
            "no_org": False,
            "specs": SPECS,
        },
    )


@router.post("/connectors")
async def connectors_create(
    request: Request,
    name: str = Form(...),
    connector_type: str = Form(...),
    environment: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if spec_for(connector_type) is None:
        raise HTTPException(
            422,
            "connector_type must be one of "
            + ", ".join(key for key, _label in _configurable_types()),
        )
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "organization context required to add a connector")
    # One row per (organization, connector type), because that is how the
    # credential is keyed: `resolve_credential` looks it up by type, so a
    # second row of the same type can never hold a usable credential of its
    # own -- it just makes which row owns the one credential ambiguous.
    existing = (
        await session.execute(
            select(ConnectorConfig.id).where(
                ConnectorConfig.organization_id == org,
                ConnectorConfig.connector_type == connector_type,
            )
        )
    ).first()
    if existing is not None:
        raise HTTPException(
            409,
            f"this organization already has a {connector_type} connector; "
            "configure that one rather than adding a second",
        )
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
    cfg_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    """Verify the connector against its provider. Writes no capture counts.

    This used to run a mock discovery: it set ``objects_discovered``,
    ``evidence_produced``, ``status`` and ``last_sync`` to fixed numbers
    without contacting anything. Those are exactly the four columns
    ``connector_backing_state`` reads to decide a control is "evidenced by
    automated capture", so the button manufactured that claim -- and did, in a
    real deployment: a connector displayed ``configured, 100 objects, 10
    evidence`` while its stored credential could not authenticate at all,
    which read as a working integration and hid the actual error for days.

    Gating it on a credential being *present* was not enough, because a
    present credential is not a working one. So it now asks the provider.
    Capture counts are left to real capture (``governance.collection``), and
    ``last_sync`` is set only when the provider answered.

    ``grc.sync_connector`` remains a development-only mock on the JSON API; it
    is a separate surface and is named as such there.
    """
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "organization context required")
    c = await session.get(ConnectorConfig, cfg_id)
    if c is None or c.organization_id != org:
        raise HTTPException(404, "connector not found")

    secret = await connector_credentials.resolve_credential(session, org, c.connector_type)
    if not secret:
        return RedirectResponse(
            f"/connectors/{cfg_id}?error="
            + quote("this connector has no stored credential"),
            status_code=303,
        )
    connector = get_connector(c.connector_type)
    if connector is None:
        return RedirectResponse(
            f"/connectors/{cfg_id}?error="
            + quote(f"no capture connector exists for {c.connector_type}"),
            status_code=303,
        )
    connector.credential = secret

    result = await connector.verify()
    if result.get("connected"):
        c.status = "configured"
        c.error_message = None
        c.last_sync = _now()
        await session.commit()
        return RedirectResponse(f"/connectors/{cfg_id}?tested=1", status_code=303)

    reason = str(result.get("reason") or "the provider did not say why")
    c.status = "error"
    c.error_message = reason[:2000]
    await session.commit()
    return RedirectResponse(f"/connectors/{cfg_id}?error={quote(reason)}", status_code=303)


@router.get("/connectors/{cfg_id}", response_class=HTMLResponse)
async def connector_detail(
    cfg_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "organization context required")
    c = await session.get(ConnectorConfig, cfg_id)
    if c is None or c.organization_id != org:
        raise HTTPException(404, "connector not found")
    cap_stmt = (
        select(CaptureSnapshot)
        .where(CaptureSnapshot.connector == c.connector_type)
        .order_by(CaptureSnapshot.captured_at.desc())
        .limit(50)
    )
    cap_stmt = cap_stmt.where(CaptureSnapshot.organization_id == org)
    captures = (await session.execute(cap_stmt)).scalars().all()
    spec = spec_for(c.connector_type)
    return templates.TemplateResponse(
        request,
        "connector_detail.html",
        {
            "active": "connectors",
            "c": c,
            "captures": captures,
            "spec": spec,
            "outstanding": missing_fields(c.connector_type, {})
            if c.encrypted_credential is None
            else (),
            "systems": (
                await session.execute(
                    select(System)
                    .where(System.organization_id == org, System.deleted_at.is_(None))
                    .order_by(System.name)
                )
            ).scalars().all(),
            "scan_checks": len(checks_for(c.connector_type)),
        },
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
    metrics = _control_test_metrics(rows)
    return templates.TemplateResponse(
        request,
        "control_tests.html",
        {"active": "controltests", "rows": rows, "metrics": metrics},
    )


@router.post("/control-tests")
async def control_tests_create(
    request: Request,
    *,
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


async def _audit_engagement_in_scope(
    session: AsyncSession, eng_id: int, org: int | None
) -> AuditEngagement:
    """The engagement ``eng_id`` names, iff ``org`` may see it (None = global).

    Its two write handlers below took ``eng_id`` straight from the path and
    never loaded the parent at all, so a PBC request or an audit finding could
    be written into another tenant's engagement. 404 rather than 403: the
    engagement's existence is itself the disclosure, and it matches what
    ``grc.add_request`` / ``grc.add_finding`` already answer.
    """
    stmt = select(AuditEngagement).where(AuditEngagement.id == eng_id)
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    engagement = (await session.execute(stmt)).scalar_one_or_none()
    if engagement is None:
        raise HTTPException(404, "engagement not found")
    return engagement


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
    # The twin of ``grc.get_engagement``, which got this predicate already:
    # the page renders the engagement's whole request and finding tree.
    org = _principal_org(request)
    stmt = (
        select(AuditEngagement)
        .options(selectinload(AuditEngagement.requests), selectinload(AuditEngagement.findings))
        .where(AuditEngagement.id == eng_id)
    )
    if org is not None:
        stmt = stmt.where(AuditEngagement.organization_id == org)
    e = (await session.execute(stmt)).scalar_one_or_none()
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
    # The parent engagement was never fetched, so ``eng_id`` wrote a PBC item
    # straight into another tenant's audit. 404 for a foreign parent, matching
    # ``grc.add_request``.
    await _audit_engagement_in_scope(session, eng_id, _principal_org(request))
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
    engagement = await _audit_engagement_in_scope(session, eng_id, _principal_org(request))
    # ISSM-04: mirror the parent engagement's org, exactly as ``grc.add_finding``
    # does. This handler left ``organization_id`` NULL, so a finding raised
    # through the UI fell out of every org-scoped filter of the findings table
    # while its API twin's did not. The column already exists (migration for
    # ISSM-04); nothing new is needed on the schema.
    session.add(
        AuditFinding(
            engagement_id=eng_id,
            organization_id=engagement.organization_id,
            title=title,
            severity=severity,
        )
    )
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
    *,
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
    # ``questionnaire_export`` below already carries this predicate on the same
    # row; this page renders the same vendor answers without it.
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
    request: Request,
    *,
    answer: str = Form(...),
    detail: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    # No principal at all: ``qid``/``rid`` reached any tenant's questionnaire,
    # so another org's vendor answers could be rewritten and its score with
    # them. Scoped through the parent, which is where the org lives --
    # ``QuestionnaireResponse`` has no ``organization_id`` of its own.
    #
    # As in ``regulatory_update``, a foreign row takes the same silent no-op
    # branch a missing one already takes; this route does not 404 on an unknown
    # id and must not start disclosing which ids are real.
    org = _principal_org(request)
    q = await session.get(VendorQuestionnaire, qid)
    r = await session.get(QuestionnaireResponse, rid)
    in_scope = q is not None and (org is None or q.organization_id == org)
    if in_scope and r is not None and r.questionnaire_id == qid:
        r.answer = answer
        r.detail = detail or None
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
    # Not on the reported list, but the third unscoped handler on this same
    # row and the most consequential: it writes ``risk_rating`` onto the
    # **vendor**, marks the questionnaire reviewed under this caller's name,
    # and opens tasks against the other tenant's vendor. Guarding only the read
    # and the answer path would have been half a matched pair.
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
    *,
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
async def _portal_admin_context(
    request: Request,
    session: AsyncSession,
    org_id: int | None,
    issued_token: str | None = None,
) -> dict[str, Any]:
    """Build the template context for the portal-admin page.

    Shared by the GET page and the POST-grant handler so the latter can
    render the page directly — with the freshly issued plaintext token — in
    the response body instead of round-tripping it through a redirect query
    param (which would land in access logs / browser history; see the
    ``issued_link`` note below).
    """
    from ...constants import EXTERNAL_PRINCIPAL_KINDS  # noqa: PLC0415
    from ...models_packages import AuthorizationPackage  # noqa: PLC0415
    from ...models_portal import ExternalPrincipal  # noqa: PLC0415
    from ...portal import current_engagement_ids, grant_status, list_grants  # noqa: PLC0415

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
        # One query for every engagement on the page, then the SAME classifier
        # the resolution path uses. This used to compute the status from the
        # grant row alone, so a grant whose engagement had ended displayed as
        # "active" while resolving to nothing -- the operator surface asserting
        # access that does not exist.
        current = await current_engagement_ids(
            session, [g.engagement_id for g in grants if g.engagement_id is not None]
        )
        rows = [
            {"g": g,
             "principal": principals.get(g.principal_id) if g.principal_id else None,
             "status": grant_status(g, current)}
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
    # The plaintext token, when present, comes straight from the in-memory
    # grant just issued in this same request — never from a query param — so
    # it never transits a URL (IA-09: the DB stores only the hash).
    issued_link = f"{request.base_url}portal?token={issued_token}" if issued_token else None
    # The form's kind options come from the one vocabulary, not a hard-coded list in
    # the template: a second copy is a second place for a typo to live.
    return {"active": "portaladmin", "org_id": org_id, "rows": rows,
            "packages": packages, "evidence": evidence, "issued_link": issued_link,
            "kinds": EXTERNAL_PRINCIPAL_KINDS}


@router.get("/admin/portal", response_class=HTMLResponse)
async def portal_admin_page(
    request: Request,
    organization_id: int | None = None,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    # The server-rendered twin of ``portal.list_grants_endpoint``: the query
    # parameter used to win over the principal, so a tenant admin could render
    # another org's grant table by changing the URL.
    org_id = resolve_caller_org(_principal_org(request), organization_id)
    context = await _portal_admin_context(request, session, org_id)
    return templates.TemplateResponse(request, "portal_admin.html", context)


@router.post("/admin/portal/grants", response_class=HTMLResponse)
async def portal_admin_create(
    request: Request,
    *,
    organization_id: int = Form(...),
    principal_name: str = Form(...),
    kind: str = Form("customer"),
    ttl_days: int = Form(30),
    label: str = Form(""),
    package_ids: list[int] = Form(default=[]),
    evidence_ids: list[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    from ...portal import create_grant  # noqa: PLC0415

    # The server-rendered twin of ``portal.create_grant_endpoint``: the form
    # field named the tenant the grant was issued against.
    org_id = resolve_caller_org(_principal_org(request), organization_id)
    try:
        grant = await create_grant(
            session, org_id=org_id, principal_name=principal_name, kind=kind,
            package_ids=package_ids, evidence_ids=evidence_ids, ttl_days=ttl_days,
            label=label or None, actor=_actor(request),
        )
    except ValueError as exc:  # a kind outside the vocabulary — the form offers only members
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # The plaintext token is only ever available on this in-memory `grant`
    # (IA-09: the DB stores its hash only). Render the page directly with it
    # in the template context — never put it in a redirect URL/query param,
    # where it would land in web-server access logs and browser history.
    issued_token = grant.token or ""
    await session.commit()
    context = await _portal_admin_context(
        request, session, org_id, issued_token=issued_token
    )
    return templates.TemplateResponse(request, "portal_admin.html", context)


@router.post("/admin/portal/grants/{grant_id}/revoke")
async def portal_admin_revoke(
    request: Request,
    grant_id: int,
    organization_id: int = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    from ...models_portal import ExternalAccessGrant  # noqa: PLC0415
    from ...portal import revoke_grant  # noqa: PLC0415

    # Two separate checks, and both are needed. The form's ``organization_id``
    # only decides where the redirect lands, so guarding it alone would be
    # theatre: a caller can name its OWN org and still pass any ``grant_id``.
    # ``revoke_grant`` takes the id unscoped, so the path id needs the same
    # predicate ``portal.revoke_grant_endpoint`` got at 2a2137f -- 404 there,
    # because a grant id's existence is itself a disclosure; 403 here, because
    # naming a foreign org discloses nothing (see ``resolve_caller_org``).
    org = resolve_caller_org(_principal_org(request), organization_id)
    if org is not None:
        row = await session.get(ExternalAccessGrant, grant_id)
        if row is None or row.organization_id != org:
            raise HTTPException(status_code=404, detail="grant not found")
    await revoke_grant(session, grant_id, actor=_actor(request))
    await session.commit()
    return RedirectResponse(f"/admin/portal?organization_id={organization_id}", status_code=303)


@router.post("/connectors/{cfg_id}/credential")
async def connectors_set_credential(
    cfg_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Store this organization's own credential for a connector.

    The form fields come from the same ``CredentialSpec`` that validates them,
    so the inputs offered and the values required cannot drift apart. A blank
    secret field is dropped rather than stored as an empty string: an operator
    changing only a project key must not have to re-enter a key they cannot
    read back.
    """
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "organization context required")
    cfg = await session.get(ConnectorConfig, cfg_id)
    if cfg is None or cfg.organization_id != org:
        raise HTTPException(404, "connector not found")
    spec = spec_for(cfg.connector_type)
    if spec is None:
        raise HTTPException(422, f"no credential spec for {cfg.connector_type}")

    form = await request.form()
    secret = {
        field.name: str(form.get(field.name) or "").strip()
        for field in spec.fields
        if str(form.get(field.name) or "").strip()
    }
    # Merge over what is already stored, so a partial edit is an edit and not
    # a silent wipe of the fields the form did not carry.
    if cfg.encrypted_credential is not None:
        existing = await connector_credentials.resolve_credential(
            session, org, cfg.connector_type
        )
        if existing:
            secret = {**existing, **secret}

    config = dict(cfg.config or {})
    for field in spec.config_fields:
        value = str(form.get(field.name) or "").strip()
        if value:
            config[field.name] = value
    cfg.config = config

    try:
        await connector_credentials.set_credential(
            session, org, cfg.connector_type, secret, name=cfg.name, config=cfg
        )
    except IncompleteCredential as exc:
        return RedirectResponse(
            f"/connectors/{cfg_id}?error={quote(str(exc))}", status_code=303
        )
    except CredentialStorageError as exc:
        return RedirectResponse(
            f"/connectors/{cfg_id}?error={quote(str(exc))}", status_code=303
        )
    await session.commit()
    return RedirectResponse(f"/connectors/{cfg_id}?saved=1", status_code=303)


@router.post("/connectors/{cfg_id}/test")
async def connectors_test_credential(
    cfg_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Actually authenticate, and report what the provider said.

    Distinct from the mock sync above, which writes the four columns
    ``connector_backing_state`` reads and is development-only for that reason.
    This calls the connector's own ``verify()``, stores nothing, and reports
    the provider's own refusal -- which is the part an operator can act on.
    """
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "organization context required")
    cfg = await session.get(ConnectorConfig, cfg_id)
    if cfg is None or cfg.organization_id != org:
        raise HTTPException(404, "connector not found")

    secret = await connector_credentials.resolve_credential(session, org, cfg.connector_type)
    connector = get_connector(cfg.connector_type)
    if connector is None:
        return RedirectResponse(
            f"/connectors/{cfg_id}?error={quote('no capture connector for this type')}",
            status_code=303,
        )
    connector.credential = secret
    if not connector.is_configured():
        outstanding = missing_fields(cfg.connector_type, secret or {})
        detail = ", ".join(outstanding) if outstanding else "no credential is stored"
        return RedirectResponse(
            f"/connectors/{cfg_id}?error={quote('not configured: ' + detail)}",
            status_code=303,
        )

    result = await connector.verify()
    if result.get("connected"):
        cfg.status = "configured"
        cfg.error_message = None
        await session.commit()
        return RedirectResponse(f"/connectors/{cfg_id}?tested=1", status_code=303)

    reason = str(result.get("reason") or "the provider did not say why")
    cfg.status = "error"
    cfg.error_message = reason[:2000]
    await session.commit()
    return RedirectResponse(f"/connectors/{cfg_id}?error={quote(reason)}", status_code=303)


@router.post("/connectors/{cfg_id}/scan")
async def connectors_scan(
    cfg_id: int,
    request: Request,
    system_id: int = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Run a real posture scan of one system with this connector.

    Nothing like the development sync above, which writes capture counts and
    touches no provider. This resolves the organization's own credential,
    runs the checks registered for the connector, and records a control-test
    result per check with its per-resource findings.

    Reachable from the UI because it previously was not: scanning was CLI and
    JSON API only, so a deployment could configure a connector, see the mock
    sync's counts, and reasonably conclude a scan had run when none ever had.
    """
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "organization context required")
    cfg = await session.get(ConnectorConfig, cfg_id)
    if cfg is None or cfg.organization_id != org:
        raise HTTPException(404, "connector not found")

    system = await session.get(System, system_id)
    if system is None or system.organization_id != org or system.deleted_at is not None:
        raise HTTPException(404, "system not found")

    if cfg.encrypted_credential is None:
        return RedirectResponse(
            f"/connectors/{cfg_id}?error="
            + quote("this connector has no stored credential; nothing to scan with"),
            status_code=303,
        )

    from ...posture.scan import scan_for_system  # noqa: PLC0415

    try:
        out = await scan_for_system(
            session,
            system_id=system_id,
            connector_key=cfg.connector_type,
            actor=_principal_email(request),
        )
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        await session.rollback()
        return RedirectResponse(
            f"/connectors/{cfg_id}?error={quote(str(exc)[:300])}", status_code=303
        )
    await session.commit()

    if not out.get("checks_run"):
        # "Zero checks" and "everything passed" are different answers and must
        # not render the same: azure_arm and gcp register no posture checks at
        # all, so a scan there is a no-op that would otherwise look clean.
        reason = out.get("reason") or (
            f"no posture checks are registered for {cfg.connector_type}"
        )
        return RedirectResponse(
            f"/connectors/{cfg_id}?error={quote('scan ran but did nothing: ' + reason)}",
            status_code=303,
        )
    return RedirectResponse(
        f"/connectors/{cfg_id}?scanned={out['checks_run']}"
        f"&failing={out.get('failing_total', 0)}",
        status_code=303,
    )
