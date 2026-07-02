"""FedRAMP 20x API — KSI catalog, validation, readiness, dependencies, assessor
review, and the machine-readable package foundation. Mounted at /api/fedramp/20x.

Kept separate from the traditional FedRAMP Rev. 5 scoring endpoints. All system-
scoped routes enforce the caller's organization (via the System join), matching
the platform's tenant-isolation pattern.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...fedramp20x import (
    DEPENDENCY_STATUSES,
    READINESS_STATUSES,
    catalog,
    package,
    readiness,
    validation,
)
from ...governance import bus
from ...models import (
    KSI,
    FedRAMP20xProfile,
    FedRAMPDependency,
    KSIAssessorReview,
    KSIState,
    KSIValidationResult,
    System,
)
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api/fedramp/20x", tags=["fedramp-20x"])

_DEP_RE = r"^(authorized|in_process|not_authorized|unknown)$"
_ASSESSOR_RE = (
    r"^(not_reviewed|in_review|accepted|rejected|needs_clarification|"
    r"retest_required|finding_opened|closed)$"
)


async def _require_system(session: AsyncSession, system_id: int, principal: Principal) -> System:
    system = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if system is None:
        raise HTTPException(404, "system not found")
    if principal.org_id is not None and system.organization_id != principal.org_id:
        raise HTTPException(404, "system not found")
    return system


def _ksi_out(k: KSI) -> dict[str, Any]:
    return {
        "id": k.id,
        "identifier": k.identifier,
        "category": k.category,
        "category_name": k.category_name,
        "name": k.name,
        "description": k.description,
        "expected_outcome": k.expected_outcome,
        "validation_method": k.validation_method,
        "validation_frequency": k.validation_frequency,
        "automation_level": k.automation_level,
        "evidence_required": k.evidence_required,
        "nist_refs": list(k.nist_refs or []),
        "cmmc_refs": list(k.cmmc_refs or []),
        "provider_services": list(k.provider_services or []),
        "rule": k.rule,
    }


# --- KSI catalog ------------------------------------------------------------


@router.get("/ksis")
async def list_ksis(
    session: AsyncSession = Depends(get_session),
    category: str | None = None,
    _p: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    return [_ksi_out(k) for k in await catalog.list_ksis(session, category)]


@router.get("/ksis/{ident}")
async def get_ksi(
    ident: str,
    session: AsyncSession = Depends(get_session),
    _p: Principal = Depends(get_principal),
) -> dict[str, Any]:
    stmt = select(KSI)
    stmt = (
        stmt.where(KSI.id == int(ident)) if ident.isdigit() else stmt.where(KSI.identifier == ident)
    )
    k = (await session.execute(stmt)).scalar_one_or_none()
    if k is None:
        raise HTTPException(404, "KSI not found")
    return _ksi_out(k)


@router.post("/ksis/seed")
async def seed_ksis(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "platform_admin")),
) -> dict[str, int]:
    result = await catalog.seed_ksis(session)
    await bus.emit(
        session,
        verb="seeded",
        entity_type="ksi_catalog",
        summary=f"KSI catalog seeded: {result}",
        actor=principal.email,
        payload=result,
    )
    await session.commit()
    return result


# --- readiness + validation -------------------------------------------------


@router.get("/systems/{system_id}/readiness")
async def get_readiness(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_system(session, system_id, principal)
    return await readiness.score_system(session, system_id=system_id, persist=False)


@router.post("/systems/{system_id}/validate")
async def validate(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_system(session, system_id, principal)
    results = await validation.validate_system(session, system_id=system_id)
    score = await readiness.score_system(session, system_id=system_id, persist=True)
    await bus.emit(
        session,
        verb="validated",
        entity_type="system",
        entity_id=system_id,
        summary=f"20x validation: {score['readiness_pct']}% ready, "
        f"{score['high_risk_findings']} high-risk findings",
        org_id=principal.org_id,
        actor=principal.email,
        payload={"readiness": score, "count": len(results)},
    )
    await session.commit()
    return {"results": results, "readiness": score}


@router.get("/systems/{system_id}/validations")
async def list_validations(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
    ksi: str | None = None,
    limit: int = Query(200, le=1000),
) -> list[dict[str, Any]]:
    await _require_system(session, system_id, principal)
    stmt = (
        select(KSIValidationResult)
        .where(KSIValidationResult.system_id == system_id)
        .order_by(KSIValidationResult.validated_at.desc())
        .limit(limit)
    )
    if ksi:
        stmt = stmt.where(KSIValidationResult.ksi_identifier == ksi)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "ksi_identifier": r.ksi_identifier,
            "status": r.status,
            "confidence": r.confidence,
            "source": r.source,
            "evidence_refs": list(r.evidence_refs or []),
            "failure_reason": r.failure_reason,
            "remediation_hint": r.remediation_hint,
            "assessor_review_required": r.assessor_review_required,
            "validated_at": r.validated_at.isoformat(),
        }
        for r in rows
    ]


# --- dependencies -----------------------------------------------------------


class DependencyIn(BaseModel):
    name: str
    provider: str | None = None
    service_type: str | None = Field(None, pattern=r"^(iaas|paas|saas)$")
    fedramp_status: str = Field("unknown", pattern=_DEP_RE)
    marketplace_url: str | None = None
    authorization_level: str | None = None
    impact_level: str | None = Field(None, pattern=r"^(low|moderate|high)$")
    boundary_role: str | None = None
    inherited_controls: list[str] = Field(default_factory=list)
    shared_responsibilities: str | None = None
    dependency_risk: str | None = Field(None, pattern=r"^(low|moderate|high|critical)$")


def _dep_out(d: FedRAMPDependency) -> dict[str, Any]:
    return {
        "id": d.id,
        "system_id": d.system_id,
        "name": d.name,
        "provider": d.provider,
        "service_type": d.service_type,
        "fedramp_status": d.fedramp_status,
        "marketplace_url": d.marketplace_url,
        "authorization_level": d.authorization_level,
        "impact_level": d.impact_level,
        "boundary_role": d.boundary_role,
        "inherited_controls": list(d.inherited_controls or []),
        "shared_responsibilities": d.shared_responsibilities,
        "dependency_risk": d.dependency_risk,
    }


@router.get("/systems/{system_id}/dependencies")
async def list_dependencies(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_system(session, system_id, principal)
    deps = (
        (
            await session.execute(
                select(FedRAMPDependency).where(FedRAMPDependency.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    buckets: dict[str, int] = {s: 0 for s in DEPENDENCY_STATUSES}
    for d in deps:
        buckets[d.fedramp_status] = buckets.get(d.fedramp_status, 0) + 1
    return {"dependencies": [_dep_out(d) for d in deps], "by_status": buckets}


@router.post("/systems/{system_id}/dependencies", status_code=201)
async def add_dependency(
    system_id: int,
    body: DependencyIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_system(session, system_id, principal)
    dep = FedRAMPDependency(system_id=system_id, **body.model_dump())
    session.add(dep)
    await session.flush()
    await bus.emit(
        session,
        verb="created",
        entity_type="fedramp_dependency",
        entity_id=dep.id,
        summary=f"Dependency '{dep.name}' ({dep.fedramp_status})",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _dep_out(dep)


# --- CSO profile ------------------------------------------------------------


class ProfileIn(BaseModel):
    service_name: str | None = None
    service_description: str | None = None
    deployment_model: str | None = Field(None, pattern=r"^(iaas|paas|saas)$")
    cloud_environment: str | None = None
    boundary_description: str | None = None
    data_types: list[str] | None = None
    federal_data: bool | None = None
    cui_support: bool | None = None
    external_services: list[str] | None = None
    customer_responsibilities: str | None = None
    provider_responsibilities: str | None = None
    shared_responsibilities: str | None = None
    cryptographic_boundary: str | None = None
    logging_boundary: str | None = None
    incident_response_boundary: str | None = None
    backup_recovery_boundary: str | None = None
    administrative_access_boundary: str | None = None
    readiness_status: str | None = Field(None, pattern=r"^(" + "|".join(READINESS_STATUSES) + r")$")


@router.get("/systems/{system_id}/profile")
async def get_profile(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_system(session, system_id, principal)
    p = (
        await session.execute(
            select(FedRAMP20xProfile).where(FedRAMP20xProfile.system_id == system_id)
        )
    ).scalar_one_or_none()
    if p is None:
        return {"system_id": system_id, "exists": False}
    return {c.name: getattr(p, c.name) for c in p.__table__.columns}


@router.put("/systems/{system_id}/profile")
async def upsert_profile(
    system_id: int,
    body: ProfileIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_system(session, system_id, principal)
    p = (
        await session.execute(
            select(FedRAMP20xProfile).where(FedRAMP20xProfile.system_id == system_id)
        )
    ).scalar_one_or_none()
    if p is None:
        p = FedRAMP20xProfile(system_id=system_id)
        session.add(p)
    for field_name, value in body.model_dump(exclude_none=True).items():
        setattr(p, field_name, value)
    await session.flush()
    await bus.emit(
        session,
        verb="updated",
        entity_type="fedramp20x_profile",
        entity_id=system_id,
        summary=f"20x CSO profile updated for system {system_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {c.name: getattr(p, c.name) for c in p.__table__.columns}


# --- package export ---------------------------------------------------------


@router.get("/systems/{system_id}/package")
async def export_package(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
    format: str = Query("json", pattern=r"^(json|markdown|oscal)$"),
) -> Any:
    await _require_system(session, system_id, principal)
    pkg = await package.build_package(session, system_id=system_id)
    if format == "markdown":
        return PlainTextResponse(package.render_markdown(pkg))
    if format == "oscal":
        return package.to_oscal_shaped(pkg)
    return pkg


# --- assessor review --------------------------------------------------------


class AssessorReviewIn(BaseModel):
    system_id: int
    ksi_id: int
    assessor: str | None = None
    status: str = Field("in_review", pattern=_ASSESSOR_RE)
    notes: str | None = None
    evidence_accepted: bool | None = None
    retest_requested: bool = False
    finding: str | None = None
    management_response: str | None = None
    closure_evidence: str | None = None


class AssessorReviewPatch(BaseModel):
    status: str | None = Field(None, pattern=_ASSESSOR_RE)
    assessor: str | None = None
    notes: str | None = None
    evidence_accepted: bool | None = None
    retest_requested: bool | None = None
    finding: str | None = None
    management_response: str | None = None
    closure_evidence: str | None = None


def _review_out(r: KSIAssessorReview) -> dict[str, Any]:
    return {
        "id": r.id,
        "system_id": r.system_id,
        "ksi_id": r.ksi_id,
        "assessor": r.assessor,
        "status": r.status,
        "notes": r.notes,
        "evidence_accepted": r.evidence_accepted,
        "retest_requested": r.retest_requested,
        "finding": r.finding,
        "management_response": r.management_response,
        "closure_evidence": r.closure_evidence,
        "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
    }


@router.post("/assessor-reviews", status_code=201)
async def create_review(
    body: AssessorReviewIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "platform_admin", "assessor")),
) -> dict[str, Any]:
    await _require_system(session, body.system_id, principal)
    rv = KSIAssessorReview(**body.model_dump())
    session.add(rv)
    # Reflect the assessor verdict on the KSI state.
    st = (
        await session.execute(
            select(KSIState).where(
                KSIState.system_id == body.system_id, KSIState.ksi_id == body.ksi_id
            )
        )
    ).scalar_one_or_none()
    if st is not None:
        st.assessor_status = body.status
        st.reviewer_user_id = principal.user_id
    await session.flush()
    await bus.emit(
        session,
        verb="reviewed",
        entity_type="ksi_assessor_review",
        entity_id=rv.id,
        summary=f"Assessor review {body.status} for KSI {body.ksi_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _review_out(rv)


@router.patch("/assessor-reviews/{review_id}")
async def update_review(
    review_id: int,
    body: AssessorReviewPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "platform_admin", "assessor")),
) -> dict[str, Any]:
    rv = (
        await session.execute(select(KSIAssessorReview).where(KSIAssessorReview.id == review_id))
    ).scalar_one_or_none()
    if rv is None:
        raise HTTPException(404, "review not found")
    await _require_system(session, rv.system_id, principal)
    for field_name, value in body.model_dump(exclude_none=True).items():
        setattr(rv, field_name, value)
    rv.reviewed_at = datetime.now(UTC)
    if body.status is not None:
        st = (
            await session.execute(
                select(KSIState).where(
                    KSIState.system_id == rv.system_id, KSIState.ksi_id == rv.ksi_id
                )
            )
        ).scalar_one_or_none()
        if st is not None:
            st.assessor_status = body.status
    await session.flush()
    await bus.emit(
        session,
        verb="updated",
        entity_type="ksi_assessor_review",
        entity_id=rv.id,
        summary=f"Assessor review {rv.status} for KSI {rv.ksi_id}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return _review_out(rv)
