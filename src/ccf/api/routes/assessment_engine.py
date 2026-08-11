"""REST surface for the objective-level assessment engine.

Evaluation runs asynchronously (see ``ccf.assessment.engine.jobs``), so the write
endpoint here enqueues and returns identifiers rather than blocking on a run that
calls a model once per objective. Retrieval and acceptance are synchronous.

**Tenant scoping.** Unlike ``ccf.api.routes.prep``, the create request never
carries an ``organization_id`` at all -- the body is only ``{assessment_id,
control_identifier}``. The organization is derived by resolving the named
assessment's own ``System -> Organization`` (the same join
``service.open_control_proposal`` performs internally) and compared against the
authenticated principal's own organization. A mismatch -- or an ``assessment_id``
that does not exist -- is a 404, never a 403, exactly matching
``evidence_repo.py``'s ``_require_object`` convention: the response must not
confirm that another tenant's assessment id exists at all. This closes the
laundering shape from the prior slice, where a client-supplied
``organization_id`` was trusted outright on three endpoints. ``GET`` and
``accept`` resolve org the same way, from the proposal's own
``organization_id`` column, via ``_require_proposal`` below.

One case is worth stating plainly rather than leaving implicit, exactly as
``prep.py`` does: with ``CCF_AUTH_ENABLED=false`` (the default), every
principal resolves to the unscoped ``SYSTEM_PRINCIPAL`` -- this is true of the
whole app, not specific to this module -- so ``principal.org_id`` is ``None``
and every organization check below is skipped entirely; the assessment/proposal
named in the request is trusted outright, the same as it is for every other
endpoint in that mode. Do not run with auth disabled against data from more
than one real tenant.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...assessment.engine import jobs as engine_jobs
from ...assessment.engine.service import AcceptanceRefused, ProposalError, accept_control_proposal
from ...auth import Principal
from ...models import Assessment, AssessmentControlResult, System
from ...models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal
from ...models_prep import PrepUnit
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/assessment-engine", tags=["assessment-engine"])


class ProposalCreate(BaseModel):
    assessment_id: int
    control_identifier: str


async def _assessment_organization_id(session: AsyncSession, assessment_id: int) -> int | None:
    """The organization that owns ``assessment_id``, or ``None`` if it doesn't exist."""
    row = (
        await session.execute(
            select(System.organization_id)
            .join(Assessment, Assessment.system_id == System.id)
            .where(Assessment.id == assessment_id)
        )
    ).scalar_one_or_none()
    return None if row is None else int(row)


async def _require_proposal(
    session: AsyncSession, proposal_id: int, principal: Principal
) -> AssessmentControlProposal:
    """The proposal, scoped to the caller's org -- 404 (not 403) otherwise.

    Mirrors ``evidence_repo.py``'s ``_require_object``: an unscoped principal
    (``CCF_AUTH_ENABLED=false``) passes through untouched; a scoped principal
    whose org does not own this proposal gets the identical 404 a nonexistent
    proposal id would, so the response cannot be used to confirm that another
    tenant's proposal id exists at all.
    """
    proposal = (
        await session.execute(
            select(AssessmentControlProposal).where(AssessmentControlProposal.id == proposal_id)
        )
    ).scalar_one_or_none()
    if proposal is None or (
        principal.org_id is not None and proposal.organization_id != principal.org_id
    ):
        raise HTTPException(404, "control proposal not found")
    return proposal


async def _citations(session: AsyncSession, cited_unit_ids: list[Any]) -> list[dict[str, Any]]:
    """Resolve cited prep_unit ids to their page numbers/section for review.

    Preserves citation order and silently drops an id that no longer resolves
    (e.g. its prep run was later cleaned up) rather than failing the whole
    response over one stale reference.
    """
    if not cited_unit_ids:
        return []
    ids = [int(u) for u in cited_unit_ids]
    rows = (await session.execute(select(PrepUnit).where(PrepUnit.id.in_(ids)))).scalars().all()
    by_id = {u.id: u for u in rows}
    return [
        {
            "unit_id": uid,
            "page_numbers": by_id[uid].page_numbers,
            "section_path": by_id[uid].section_path,
        }
        for uid in ids
        if uid in by_id
    ]


async def _proposal_detail(
    session: AsyncSession, proposal: AssessmentControlProposal
) -> dict[str, Any]:
    objectives = (
        (
            await session.execute(
                select(AssessmentObjectiveProposal)
                .where(AssessmentObjectiveProposal.control_proposal_id == proposal.id)
                .order_by(AssessmentObjectiveProposal.sort_order)
            )
        )
        .scalars()
        .all()
    )
    objectives_out = [
        {
            "label": o.label,
            "objective_text": o.objective_text,
            "state": o.state,
            "verdict": o.verdict,
            "rationale": o.rationale,
            "model_confidence": o.model_confidence,
            "gaps": o.gaps,
            "contradictions": o.contradictions,
            "citations": await _citations(session, o.cited_unit_ids),
        }
        for o in objectives
    ]
    return {
        "id": proposal.id,
        "assessment_id": proposal.assessment_id,
        "control_identifier": proposal.control_identifier,
        "state": proposal.state,
        "proposed_finding": proposal.proposed_finding,
        "rollup_rationale": proposal.rollup_rationale,
        "objectives_total": proposal.objectives_total,
        "objectives_evaluated": proposal.objectives_evaluated,
        "objectives": objectives_out,
    }


@router.post("/proposals", status_code=201)
async def create_proposal(
    body: ProposalCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Open (or reuse) a control proposal and queue its evaluation.

    See the module docstring: the organization is derived from ``assessment_id``,
    never supplied by the caller, and a foreign assessment 404s before any
    proposal or job row is created.
    """
    org_id = await _assessment_organization_id(session, body.assessment_id)
    if org_id is None or (principal.org_id is not None and org_id != principal.org_id):
        raise HTTPException(404, "assessment not found")
    try:
        job = await engine_jobs.enqueue_control(
            session,
            assessment_id=body.assessment_id,
            control_identifier=body.control_identifier,
        )
    except ProposalError as exc:
        raise HTTPException(404, "assessment not found") from exc
    await session.commit()
    return {"proposal_id": job.control_proposal_id, "job_id": job.id, "status": job.status}


@router.get("/proposals/{proposal_id}")
async def get_proposal(
    proposal_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """The proposal with its objectives, verdicts and citations."""
    proposal = await _require_proposal(session, proposal_id, principal)
    return await _proposal_detail(session, proposal)


def _result_out(result: AssessmentControlResult) -> dict[str, Any]:
    return {
        "id": result.id,
        "assessment_id": result.assessment_id,
        "control_id": result.control_id,
        "finding": result.finding,
        "objective_findings": result.objective_findings,
        "reviewed": result.reviewed,
        "reviewer": result.reviewer,
        "assessor_note": result.assessor_note,
    }


@router.post("/proposals/{proposal_id}/accept")
async def accept_proposal(
    proposal_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Project an accepted proposal into ``AssessmentControlResult``.

    ``accept_control_proposal`` refuses (``AcceptanceRefused``) a proposal that
    is not ``complete`` -- including one already ``accepted``, since an
    accepted row still carries a ``proposed_finding`` and nothing else guards
    a repeat POST from re-accepting it. That refusal surfaces here as 409, not
    a 500: the request is understood and rejected, not a server fault.
    """
    proposal = await _require_proposal(session, proposal_id, principal)
    try:
        result = await accept_control_proposal(
            session, proposal.id, accepted_by=principal.email
        )
    except AcceptanceRefused as exc:
        raise HTTPException(409, str(exc)) from exc
    except ProposalError as exc:
        raise HTTPException(404, str(exc)) from exc
    await session.commit()
    return _result_out(result)
