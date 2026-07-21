"""CMMC L2 assessment workflow API.

Create an assessment for a system → results auto-seed from the scoring matrix →
the assessor records examine/interview/test findings per practice (and per
NIST 800-171A objective) → generate the Security Assessment Report (.docx) and
auto-create POA&Ms from every Other-Than-Satisfied finding.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from slugify import slugify
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...assessment import (
    FINDINGS,
    generate_sar_docx,
    result_to_dict,
    seed_assessment_results,
    summarize_results,
)
from ...auth import Principal
from ...ingest.scanners import SEVERITY_SLA_DAYS
from ...models import POAM, Assessment, AssessmentControlResult, Control, PoamMilestone, System
from ..auth_deps import get_principal
from ..deps import get_session
from .systems import require_system_in_scope

router = APIRouter(prefix="/api/assessments", tags=["assessments"])

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_KINDS = ("self", "internal", "3pao", "ig", "audit")


class AssessmentCreate(BaseModel):
    system_id: int
    name: str = "CMMC L2 Assessment"
    kind: str = "self"
    assessor: str | None = None
    started_on: date | None = None


class ResultUpdate(BaseModel):
    finding: str | None = None
    objective_findings: list[dict[str, str]] | None = None
    examine_note: str | None = None
    interview_note: str | None = None
    test_note: str | None = None
    assessor_note: str | None = None
    evidence_ref: str | None = None
    reviewed: bool | None = None
    reviewer: str | None = None


class AssessmentOut(BaseModel):
    id: int
    system_id: int
    name: str
    kind: str
    assessor: str | None
    started_on: date | None
    finished_on: date | None

    model_config = {"from_attributes": True}


async def _require_assessment(
    session: AsyncSession, assessment_id: int, principal: Principal
) -> Assessment:
    a = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if a is None:
        raise HTTPException(404, "assessment not found")
    # Scope via the owning system's organization.
    await require_system_in_scope(session, a.system_id, principal)
    return a


async def _results(session: AsyncSession, assessment_id: int) -> list[AssessmentControlResult]:
    return list(
        (
            await session.execute(
                select(AssessmentControlResult)
                .where(AssessmentControlResult.assessment_id == assessment_id)
                .order_by(AssessmentControlResult.sort_order)
            )
        )
        .scalars()
        .all()
    )


@router.get("", response_model=list[AssessmentOut])
async def list_assessments(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[AssessmentOut]:
    stmt = select(Assessment).order_by(Assessment.id.desc())
    if principal.org_id is not None:
        stmt = stmt.join(System, System.id == Assessment.system_id).where(
            System.organization_id == principal.org_id
        )
    rows = (await session.execute(stmt)).scalars().all()
    return [AssessmentOut.model_validate(r) for r in rows]


@router.post("", response_model=AssessmentOut, status_code=201)
async def create_assessment(
    body: AssessmentCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> AssessmentOut:
    await require_system_in_scope(session, body.system_id, principal)
    if body.kind not in _KINDS:
        raise HTTPException(422, f"kind must be one of {', '.join(_KINDS)}")
    a = Assessment(
        system_id=body.system_id,
        name=body.name,
        kind=body.kind,
        assessor=body.assessor,
        started_on=body.started_on or datetime.now(UTC).date(),
    )
    session.add(a)
    await session.flush()
    await seed_assessment_results(session, a)
    await session.refresh(a)
    return AssessmentOut.model_validate(a)


@router.get("/{assessment_id}")
async def get_assessment(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    a = await _require_assessment(session, assessment_id, principal)
    results = await _results(session, assessment_id)
    return {
        "assessment": AssessmentOut.model_validate(a).model_dump(),
        "summary": summarize_results(results),
        "results": [result_to_dict(r) for r in results],
    }


@router.get("/{assessment_id}/summary")
async def assessment_summary(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_assessment(session, assessment_id, principal)
    return summarize_results(await _results(session, assessment_id))


@router.put("/{assessment_id}/controls/{control_id}")
async def update_result(
    assessment_id: int,
    control_id: str,
    body: ResultUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await _require_assessment(session, assessment_id, principal)
    if body.finding is not None and body.finding not in FINDINGS:
        raise HTTPException(422, f"finding must be one of {', '.join(FINDINGS)}")
    result = (
        await session.execute(
            select(AssessmentControlResult)
            .where(AssessmentControlResult.assessment_id == assessment_id)
            .where(AssessmentControlResult.control_id == control_id)
        )
    ).scalar_one_or_none()
    if result is None:
        raise HTTPException(404, "control not found in assessment")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(result, k, v)
    result.observed_on = datetime.now(UTC).date()
    await session.commit()
    await session.refresh(result)
    return result_to_dict(result)


@router.post("/{assessment_id}/poams-from-findings")
async def poams_from_findings(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, int]:
    """Create a provenanced POA&M (with a seeded milestone) for each
    Other-Than-Satisfied finding.

    Idempotent on a stable back-reference to the originating assessment
    control result (``source_ref``), not on the POA&M title — re-running
    after a title edit, or after the same finding recurs, still creates
    exactly one POA&M per finding.
    """
    a = await _require_assessment(session, assessment_id, principal)
    results = await _results(session, assessment_id)
    findings = [r for r in results if r.finding == "other_than_satisfied"]

    existing_refs = {
        ref
        for (ref,) in (
            await session.execute(
                select(POAM.source_ref).where(
                    POAM.system_id == a.system_id, POAM.source_ref.is_not(None)
                )
            )
        ).all()
    }

    # Best-effort link to the org's control catalog (a separate framework from
    # the CMMC scoring matrix these findings are recorded against); left null
    # when there's no catalog control with a matching identifier.
    nist_ids = {r.nist_id for r in findings if r.nist_id}
    control_by_identifier: dict[str, int] = {}
    if nist_ids:
        control_by_identifier = {
            identifier: control_id
            for identifier, control_id in (
                await session.execute(
                    select(Control.identifier, Control.id).where(
                        Control.identifier.in_(nist_ids)
                    )
                )
            ).all()
        }

    today = datetime.now(UTC).date()
    created = 0
    for r in findings:
        source_ref = f"assessment:{r.id}"
        if source_ref in existing_refs:
            continue
        due = today + timedelta(days=SEVERITY_SLA_DAYS.get("moderate", 90))
        poam = POAM(
            system_id=a.system_id,
            control_id=control_by_identifier.get(r.nist_id) if r.nist_id else None,
            title=f"{r.control_id} — {r.title or 'Other than satisfied'}",
            weakness=(
                f"Practice {r.control_id} ({r.nist_id}) assessed Other Than Satisfied. "
                f"{r.assessor_note or ''}"
            ).strip(),
            severity="moderate",
            status="open",
            identified_on=today,
            due_on=due,
            original_due_on=due,
            source="assessment",
            source_ref=source_ref,
        )
        poam.milestones.append(
            PoamMilestone(
                description=(
                    f"Remediate {r.control_id}"
                    f"{f' ({r.nist_id})' if r.nist_id else ''}: "
                    f"{r.title or 'other-than-satisfied finding'}"
                ),
                due_on=due,
                status="pending",
                sort_order=0,
            )
        )
        session.add(poam)
        created += 1
    await session.commit()
    return {"created": created}


@router.get("/{assessment_id}/sar", response_model=None)
async def generate_sar(
    assessment_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> StreamingResponse:
    a = await _require_assessment(session, assessment_id, principal)
    sys = (await session.execute(select(System).where(System.id == a.system_id))).scalar_one()
    results = await _results(session, assessment_id)
    summary = summarize_results(results)
    meta = {
        "customer_name": sys.name,
        "system_name": sys.name,
        "assessment_name": a.name,
        "kind": a.kind,
        "assessor": a.assessor,
        "period": f"{a.started_on or ''} to {a.finished_on or 'ongoing'}",
        "date": datetime.now(UTC).date().strftime("%m/%d/%Y"),
    }
    data = await asyncio.to_thread(
        generate_sar_docx, meta, summary, [result_to_dict(r) for r in results]
    )
    slug = slugify(f"{sys.name}-cmmc-l2-sar") or "sar"
    return StreamingResponse(
        iter([data]),
        media_type=DOCX_MIME,
        headers={"Content-Disposition": f'attachment; filename="{slug}.docx"'},
    )
