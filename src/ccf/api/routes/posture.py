"""Enterprise posture API — compliance rollups plus live security posture.

This module deliberately serves both senses of "posture". The original
endpoints roll up internal records (POA&M aging, evidence freshness); the
``failing-resources`` endpoint reports what a live scan observed in the
environment, and ``scan_router`` carries the cross-cutting paths that do not
fit under the ``/api/posture`` prefix. They live together so one concept is
not split across two modules.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import (
    evidence_freshness,
    org_summary,
    poam_aging,
    systems_scorecard,
)
from ...analytics.framework_posture import (
    org_framework_posture,
    system_framework_posture,
)
from ...auth import Principal
from ...connectors.readiness import provider_readiness
from ...governance.control_tests import ensure_poam_for_control_test
from ...logging import get_logger
from ...models import SSPProject
from ...models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ...posture.checks import known_providers
from ...posture.drift import latest_drift, resource_timeline
from ...posture.latest import latest_result_ids
from ..auth_deps import get_principal
from ..deps import get_session
from .systems import require_system_in_scope

log = get_logger(__name__)

router = APIRouter(prefix="/api/posture", tags=["posture"])

#: Cross-cutting posture paths that do not sit under /api/posture. Two routers
#: in one module follows the precedent in api/routes/packages.py.
scan_router = APIRouter(prefix="/api", tags=["posture"])


def _today() -> Any:
    return datetime.now(UTC).date()


@router.get("/summary")
async def summary(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Executive rollup: avg SPRS, POA&M aging, evidence freshness, risk posture."""
    return await org_summary(session, today=_today(), org_id=principal.org_id)


@router.get("/systems")
async def systems(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Per-system scorecard."""
    return await systems_scorecard(session, today=_today(), org_id=principal.org_id)


@router.get("/framework")
async def framework(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """This organization's scan results, expressed in each system's own framework.

    The answer a consumer needs after scanning an organization, which nothing
    served before: ``POST /api/systems/{id}/scan`` returns check keys and
    verdicts, and turning those into "where do we stand against the framework
    we are held to" meant knowing Concord's internal check vocabulary, the
    800-53 ids behind it, and which framework each system had been categorized
    under. `framework_posture` computed exactly this and was wired only to an
    HTML page.

    Per system, because the framework is a property of a system, not of an
    organization -- one tenant here has a Moderate-baseline system and an
    800-171 system side by side. ``by_framework`` sums within a framework and
    never across: a requirement count added to a control count is a number that
    means nothing while looking authoritative.
    """
    return await org_framework_posture(session, principal.org_id)


@router.get("/poam-aging")
async def poams(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await poam_aging(session, today=_today(), org_id=principal.org_id)


@router.get("/evidence-freshness")
async def evidence(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await evidence_freshness(session, today=_today(), org_id=principal.org_id)


@router.get("/failing-resources")
async def failing_resources(
    resource_type: str | None = None,
    limit: int = 200,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every resource failing a control test *as of its latest run*, newest first.

    The org-wide question resource granularity exists to answer.

    Restricted to each test's most recent result. Without that restriction this
    read the append-only resource history as though it were current state and
    reported resources fixed weeks earlier, carrying the stale ``observed``
    text from the scan that found them broken -- so an operator's queue named
    work that no longer existed. "Latest" comes from
    :func:`ccf.posture.latest.latest_result_ids`, which is the one definition
    every current-state read shares.
    """
    latest = latest_result_ids()
    stmt = (
        select(
            ControlTestResourceResult,
            ControlTest.control_id,
            ControlTest.system_id,
            ControlTest.id,
        )
        .join(
            ControlTestResult,
            ControlTestResult.id == ControlTestResourceResult.result_id,
        )
        .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
        .join(latest, latest.c.result_id == ControlTestResult.id)
        .where(ControlTestResourceResult.verdict == "fail")
        .order_by(ControlTestResourceResult.created_at.desc())
        .limit(min(max(limit, 1), 1000))
    )
    if principal.org_id is not None:
        stmt = stmt.where(ControlTest.organization_id == principal.org_id)
    if resource_type:
        stmt = stmt.where(ControlTestResourceResult.resource_type == resource_type)
    return [
        {
            "resource_id": row[0].resource_id,
            "resource_type": row[0].resource_type,
            "observed": row[0].observed,
            "detail": row[0].detail,
            "result_id": row[0].result_id,
            "created_at": row[0].created_at,
            "control_id": row[1],
            "system_id": row[2],
            "test_id": row[3],
        }
        for row in (await session.execute(stmt)).all()
    ]


@scan_router.post("/systems/{system_id}/scan")
async def scan_system(
    system_id: int,
    connector: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Scan one system with one connector, recording per-resource findings."""
    from ...posture.scan import scan_for_system  # noqa: PLC0415

    await require_system_in_scope(session, system_id, principal)
    readiness = await provider_readiness(
        session,
        organization_id=principal.org_id,
        connector_key=connector,
        persist=True,
    )
    if not readiness["ready"]:
        await session.commit()
        return {
            "system_id": system_id,
            "connector": connector,
            "readiness": readiness,
            "checks_expected": readiness["checks_expected"],
            "checks_run": 0,
            "results": [],
            "skipped_checks": [
                {**check, "reason": readiness.get("reason") or readiness["status"]}
                for check in readiness["checks"]
            ],
            "reason": readiness.get("reason") or readiness["status"],
        }
    try:
        out = await scan_for_system(
            session,
            system_id=system_id,
            connector_key=connector,
            actor=principal.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    out["readiness"] = readiness
    await session.commit()
    return out


@scan_router.post("/systems/{system_id}/scan-all")
async def scan_system_all_connectors(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Scan one system with every posture provider the platform knows.

    This is the end-user path: the operator asks to scan the system, and the
    response states which providers ran, which were unavailable, and where to
    read the framework posture. Provider-specific scan remains available for
    troubleshooting and targeted re-runs.

    The orchestration lives in ``posture.scan_all`` rather than here, because the
    scheduler needs it too -- while it lived in this handler the only way to run
    a full posture scan was for a person to ask, so verdicts never refreshed on
    their own.
    """
    from ...posture.scan_all import scan_all_providers  # noqa: PLC0415

    await require_system_in_scope(session, system_id, principal)
    return await scan_all_providers(
        session,
        system_id=system_id,
        organization_id=principal.org_id,
        actor=principal.email,
    )


@scan_router.post("/systems/{system_id}/attestations")
async def ingest_system_attestations(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Read the cloud provider's own control results for one system.

    A targeted re-run. The end-user path is ``scan-all``, which runs this as part
    of a full scan -- the same relationship the per-connector ``scan`` route has
    with it -- so this exists for troubleshooting and for re-reading one account
    without re-scanning every provider.

    Returns the ingest's own report rather than a bare count, because "nothing
    was written" has several causes an operator would otherwise have to guess
    between: no credential bound, the NIST standard not enabled in Security Hub,
    the standard enabled but still populating, a missing IAM action, or a page
    walk that was truncated and therefore refused.
    """
    from ...posture.attested_scan import ingest_attestations  # noqa: PLC0415

    await require_system_in_scope(session, system_id, principal)
    try:
        out = await ingest_attestations(
            session, system_id=system_id, actor=principal.email
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    await session.commit()
    return out


@scan_router.post("/systems/{system_id}/provider-readiness")
async def check_system_provider_readiness(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Verify every scan provider before running a live audit."""
    await require_system_in_scope(session, system_id, principal)
    rows = [
        await provider_readiness(
            session,
            organization_id=principal.org_id,
            connector_key=key,
            persist=True,
        )
        for key in sorted(known_providers())
    ]
    await session.commit()
    return {
        "system_id": system_id,
        "providers": rows,
        "ready": [r for r in rows if r["ready"]],
        "providers_unavailable": [r for r in rows if not r["ready"]],
    }


@scan_router.get("/systems/{system_id}/audit-plan")
async def get_system_audit_plan(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Resolve applicable API checks and manual-review gaps before scanning."""
    from ...posture.audit_plan import live_audit_plan  # noqa: PLC0415

    system = await require_system_in_scope(session, system_id, principal)
    return await live_audit_plan(
        session,
        system=system,
        org_id=principal.org_id,
        persist_readiness=False,
    )


@scan_router.get("/systems/{system_id}/control-evaluations")
async def get_system_control_evaluations(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Latest control evaluations with resource, waiver, evidence and POA&M links."""
    from ...posture.evaluations import control_evaluations_for_system  # noqa: PLC0415

    await require_system_in_scope(session, system_id, principal)
    return await control_evaluations_for_system(
        session,
        system_id=system_id,
        org_id=principal.org_id,
    )


@scan_router.get("/systems/{system_id}/live-audit-workflow")
async def get_live_audit_workflow(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """One system-centered flow: readiness, scan, findings, POA&M, SSP."""
    from ...posture.audit_plan import live_audit_plan  # noqa: PLC0415
    from ...posture.evaluations import control_evaluations_for_system  # noqa: PLC0415
    from ...ssp.completeness_query import project_completeness  # noqa: PLC0415
    from ...ssp.sync import project_scan_sync  # noqa: PLC0415

    system = await require_system_in_scope(session, system_id, principal)
    audit_plan = await live_audit_plan(
        session,
        system=system,
        org_id=principal.org_id,
        persist_readiness=False,
    )
    evaluations = await control_evaluations_for_system(
        session,
        system_id=system_id,
        org_id=principal.org_id,
    )
    failed = [e for e in evaluations if e["status"] in {"fail", "warn"}]
    manual = [e for e in evaluations if e["status"] == "manual_review_required"]
    failed_without_poam = [e for e in failed if not e.get("poam")]
    project = (
        await session.execute(
            select(SSPProject)
            .where(SSPProject.system_id == system_id)
            .order_by(SSPProject.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if (
        project is not None
        and principal.org_id is not None
        and project.organization_id != principal.org_id
    ):
        project = None

    ssp: dict[str, Any] | None = None
    if project is not None:
        sync = await project_scan_sync(session, project)
        completeness = await project_completeness(session, project)
        ssp = {
            "project_id": project.id,
            "url": f"/ssp/{project.id}",
            "api_url": f"/api/ssp/projects/{project.id}",
            "scan_sync_url": f"/api/ssp/projects/{project.id}/scan-sync",
            "ready": completeness["ready"],
            "score": completeness["score"],
            "readiness_blockers": completeness["readiness_blockers"],
            "scan_summary": sync["summary"],
        }

    if audit_plan["summary"]["providers_ready"] < audit_plan["summary"]["providers"]:
        next_action = "verify_connectors"
    elif not evaluations:
        next_action = "run_live_audit"
    elif failed_without_poam:
        next_action = "create_poams"
    elif manual:
        next_action = "resolve_manual_review"
    elif ssp is None:
        next_action = "create_ssp"
    elif not ssp["ready"]:
        next_action = "update_ssp"
    else:
        next_action = "ready_for_review"

    return {
        "system_id": system_id,
        "system_name": system.name,
        "next_action": next_action,
        "steps": [
            {
                "key": "verify_connectors",
                "status": (
                    "complete"
                    if audit_plan["summary"]["providers_ready"]
                    == audit_plan["summary"]["providers"]
                    else "needs_attention"
                ),
                "url": f"/api/systems/{system_id}/provider-readiness",
            },
            {
                "key": "run_live_audit",
                "status": "complete" if evaluations else "not_started",
                "url": f"/api/systems/{system_id}/scan-all",
            },
            {
                "key": "review_controls",
                "status": "needs_attention" if failed or manual else "complete",
                "url": f"/api/systems/{system_id}/control-evaluations",
            },
            {
                "key": "create_poams",
                "status": "needs_attention" if failed_without_poam else "complete",
                "url": "/api/control-tests/{control_test_id}/poam",
            },
            {
                "key": "update_ssp",
                "status": (
                    "not_started"
                    if ssp is None
                    else "complete"
                    if ssp["ready"]
                    else "needs_attention"
                ),
                "url": ssp["url"] if ssp else "/ssp",
            },
        ],
        "audit_plan": {
            "framework": audit_plan["framework"],
            "summary": audit_plan["summary"],
            "framework_controls": audit_plan.get("framework_controls", []),
            "framework_manual_review_required": audit_plan.get(
                "framework_manual_review_required", []
            ),
            "providers_unavailable": [
                {
                    "connector": p["connector"],
                    "status": p["status"],
                    "reason": p.get("reason"),
                }
                for p in audit_plan["providers"]
                if not p["ready"]
            ],
        },
        "control_evaluations": {
            "total": len(evaluations),
            "failed": len(failed),
            "manual_review_required": len(manual),
            "failed_without_poam": len(failed_without_poam),
            "url": f"/api/systems/{system_id}/control-evaluations",
        },
        "ssp": ssp,
    }


@scan_router.get("/systems/{system_id}/framework-posture")
async def system_framework(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """One system's scan results in its own framework's units.

    Sits beside ``POST /api/systems/{system_id}/scan`` on purpose: scan, then
    read the same system's posture in the terms the framework uses.
    """
    await require_system_in_scope(session, system_id, principal)
    return await system_framework_posture(
        session, org_id=principal.org_id, system_id=system_id
    )


@scan_router.get("/control-tests/{test_id}/results/{result_id}/resources")
async def result_resources(
    test_id: int,
    result_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every resource row for one result -- passing and failing alike.

    Unlike the org-wide failing view, the per-result view shows what was
    evaluated, not only what broke: "3 of 47" is only meaningful alongside
    the 44.
    """
    owner = (
        await session.execute(
            select(ControlTest)
            .join(ControlTestResult, ControlTestResult.control_test_id == ControlTest.id)
            .where(ControlTest.id == test_id, ControlTestResult.id == result_id)
        )
    ).scalars().first()
    if owner is None:
        raise HTTPException(status_code=404, detail="Unknown result for that test")
    if principal.org_id is not None and owner.organization_id != principal.org_id:
        # Indistinguishable from absent: never confirm existence across tenants.
        raise HTTPException(status_code=404, detail="Unknown result for that test")
    rows = (
        await session.execute(
            select(ControlTestResourceResult)
            .where(ControlTestResourceResult.result_id == result_id)
            .order_by(
                ControlTestResourceResult.verdict, ControlTestResourceResult.resource_id
            )
        )
    ).scalars().all()
    return [
        {
            "resource_id": r.resource_id,
            "resource_type": r.resource_type,
            "verdict": r.verdict,
            "observed": r.observed,
            "detail": r.detail,
        }
        for r in rows
    ]


@scan_router.get("/controls/{control_id}/effective-verdict")
async def control_effective_verdict(
    control_id: str,
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Which verdict should be believed for this control on this system."""
    from ...posture.scan import effective_verdict  # noqa: PLC0415

    await require_system_in_scope(session, system_id, principal)
    return await effective_verdict(session, system_id=system_id, control_id=control_id)


@scan_router.post("/control-tests/{test_id}/poam")
async def open_control_test_poam(
    test_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Create or refresh a POA&M from the latest failed/manual-review evaluation."""
    test = await _owned_test(session, test_id, principal)
    latest = (
        await session.execute(
            select(ControlTestResult)
            .where(ControlTestResult.control_test_id == test.id)
            .order_by(ControlTestResult.run_at.desc(), ControlTestResult.id.desc())
            .limit(1)
        )
    ).scalars().first()
    if latest is None:
        raise HTTPException(
            status_code=409,
            detail="Control test has no recorded evaluation to turn into a POA&M",
        )
    if latest.status not in {"fail", "warn", "manual_review_required"}:
        raise HTTPException(
            status_code=409,
            detail=f"Latest control evaluation is {latest.status}; no POA&M is needed",
        )

    poam, created = await ensure_poam_for_control_test(
        session,
        test,
        latest.detail or latest.status,
    )
    if poam is None:
        raise HTTPException(
            status_code=409,
            detail="Control test is not attached to a system and cannot open a POA&M",
        )
    await session.commit()
    return {
        "created": created,
        "poam": {
            "id": poam.id,
            "system_id": poam.system_id,
            "control_id": poam.control_id,
            "title": poam.title,
            "weakness": poam.weakness,
            "severity": poam.severity,
            "status": poam.status,
            "source": poam.source,
            "source_ref": poam.source_ref,
            "remediation_plan": poam.remediation_plan,
            "remediation_plan_source": poam.remediation_plan_source,
            "due_on": poam.due_on,
        },
    }


async def _owned_test(
    session: AsyncSession, test_id: int, principal: Principal
) -> ControlTest:
    """One control test, or 404 -- including when it belongs to another tenant.

    404 rather than 403, matching ``result_resources``: confirming an id exists
    is itself a disclosure.
    """
    test = (
        await session.execute(select(ControlTest).where(ControlTest.id == test_id))
    ).scalars().first()
    if test is None or (
        principal.org_id is not None and test.organization_id != principal.org_id
    ):
        raise HTTPException(status_code=404, detail="Unknown control test")
    return test


@scan_router.get("/control-tests/{test_id}/drift")
async def control_test_drift(
    test_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """What changed between this check's two most recent runs.

    Empty for a check with fewer than two results: there is no baseline, and a
    first scan is not wholesale change.
    """
    await _owned_test(session, test_id, principal)
    return [
        {
            "resource_id": t.resource_id,
            "kind": t.kind,
            "before": t.before,
            "after": t.after,
            "observed": t.observed,
        }
        for t in await latest_drift(session, test_id=test_id)
    ]


@scan_router.get("/control-tests/{test_id}/resources/{resource_id}/timeline")
async def control_test_resource_timeline(
    test_id: int,
    resource_id: str,
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """One resource's verdict history for this check, newest first."""
    await _owned_test(session, test_id, principal)
    return await resource_timeline(
        session, test_id=test_id, resource_id=resource_id, limit=limit
    )
