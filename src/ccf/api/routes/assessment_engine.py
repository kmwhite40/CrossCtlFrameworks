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

``reject`` is acceptance's other outcome and resolves org identically, through
``_require_proposal``. ``GET /calibration`` carries no id at all to resolve
against -- it derives its organization solely from ``principal.org_id``, never
from a query argument, which is the one case in this module with nothing else
to check it against; an unscoped principal (``CCF_AUTH_ENABLED=false``) has no
single organization's metrics to report and gets a 400, not a guess.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...assessment.engine import jobs as engine_jobs
from ...assessment.engine.calibration import compute_metrics
from ...assessment.engine.service import (
    AcceptanceRefused,
    ProposalError,
    RejectionRefused,
    accept_control_proposal,
    reject_control_proposal,
)
from ...auth import Principal
from ...models import POAM, Assessment, AssessmentControlResult, System
from ...models_assessment_engine import (
    AssessmentControlProposal,
    AssessmentJob,
    AssessmentObjectiveProposal,
)
from ...models_prep import PrepUnit
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/assessment-engine", tags=["assessment-engine"])

#: Assessment.id is a Postgres INTEGER; a value past this overflows the asyncpg
#: bind and raises DataError -> an unhandled 500 rather than a 422, on input
#: that never needed to reach the database at all.
_MAX_INT32 = 2**31 - 1
#: AssessmentControlProposal.id (the {proposal_id} path param) is BIGINT; same
#: reasoning, same fix, one order of magnitude higher.
_MAX_INT64 = 2**63 - 1


class ProposalCreate(BaseModel):
    assessment_id: int = Field(ge=1, le=_MAX_INT32)
    #: Matches the assessment_control_proposals.control_identifier column
    #: (String(64)); empty is rejected here rather than silently opening a
    #: proposal for control "".
    control_identifier: str = Field(min_length=1, max_length=64)


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


async def _citations(
    session: AsyncSession, cited_unit_ids: list[Any], organization_id: int
) -> list[dict[str, Any]]:
    """Resolve cited prep_unit ids to their page numbers/section for review.

    Preserves citation order and silently drops an id that no longer resolves
    (e.g. its prep run was later cleaned up) rather than failing the whole
    response over one stale reference.

    Scoped to ``organization_id`` explicitly -- ``prep_units`` carries no RLS
    policy (see migration 0059), so this cannot rely on the database to keep a
    foreign unit id out. In practice ``evaluate.py`` only ever cites ids from
    its own org-scoped retrieval, but that invariant lives two modules away;
    this join re-derives the tenant boundary itself rather than trusting it,
    exactly as ``_require_proposal`` and the create-proposal check above do
    for their own tables.
    """
    if not cited_unit_ids:
        return []
    ids = [int(u) for u in cited_unit_ids]
    rows = (
        await session.execute(
            select(PrepUnit).where(
                PrepUnit.id.in_(ids), PrepUnit.organization_id == organization_id
            )
        )
    ).scalars().all()
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


async def _latest_job(session: AsyncSession, control_proposal_id: int) -> AssessmentJob | None:
    """The most recently queued job for this proposal, if any.

    ``enqueue_control`` (see ``ccf.assessment.engine.jobs``) now reuses an
    outstanding ``pending``/``claimed`` job rather than always inserting one,
    but a proposal can still have accumulated more than one job over its
    lifetime (a first run that failed, then a later re-enqueue) -- the most
    recent one is what an operator checking "why is this stuck" wants.
    """
    return (
        await session.execute(
            select(AssessmentJob)
            .where(AssessmentJob.control_proposal_id == control_proposal_id)
            .order_by(AssessmentJob.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


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
            "citations": await _citations(session, o.cited_unit_ids, proposal.organization_id),
            # AI dissent path (slice 6): NULL on every un-challenged
            # objective, and NULL again -- not the challenger's last output
            # -- if CCF_ASSESSMENT_DISSENT_ENABLED was on but the challenge
            # itself failed. See ccf.assessment.engine.evaluate's module
            # docstring: the two NULL cases are distinguishable only in the
            # logs, not in this response.
            # primary_verdict is what the primary call concluded before a
            # disagreement rewrote `verdict` above. It is returned because
            # this response is what an assessor reads to adjudicate a
            # contested objective: without it the body says only "the engine
            # could not tell", losing the fact that one reviewer did reach a
            # conclusion and which one. Deliberately not inferred from the
            # satisfied-only policy -- that policy is expected to broaden.
            "primary_verdict": o.primary_verdict,
            "challenger_verdict": o.challenger_verdict,
            "challenger_rationale": o.challenger_rationale,
        }
        for o in objectives
    ]
    # Surfaces what happened to a proposal a worker failed to evaluate: before
    # this, a failed evaluation left the proposal looking merely "draft" (see
    # ccf.assessment.engine.jobs._drive_one) with nothing in the API response
    # to explain why -- an operator had no way to tell "queued, not started
    # yet" from "started and crashed" without querying the database directly.
    job = await _latest_job(session, proposal.id)
    return {
        "id": proposal.id,
        "assessment_id": proposal.assessment_id,
        "control_identifier": proposal.control_identifier,
        "state": proposal.state,
        "error": proposal.error,
        "job_status": job.status if job is not None else None,
        "job_last_error": job.last_error if job is not None else None,
        "proposed_finding": proposal.proposed_finding,
        "rollup_rationale": proposal.rollup_rationale,
        "objectives_total": proposal.objectives_total,
        "objectives_evaluated": proposal.objectives_evaluated,
        "dissent_count": proposal.dissent_count,
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
    proposal_id: int = Path(ge=1, le=_MAX_INT64),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """The proposal with its objectives, verdicts and citations."""
    proposal = await _require_proposal(session, proposal_id, principal)
    return await _proposal_detail(session, proposal)


@router.get("/proposals")
async def list_reevaluation_proposals(
    *,
    source_poam_id: int = Query(ge=1, le=_MAX_INT32),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """The re-evaluation proposal(s) triggered by one closed POA&M's closure.

    ``source_poam_id`` names a POA&M, not a proposal -- so it is validated
    against ``POAM.system_id -> System.organization_id`` the same way
    ``_require_proposal`` validates a proposal id: a POA&M belonging to
    another tenant 404s here too, not 403, so the response cannot be used to
    confirm that id exists at all.
    """
    poam_org_id = (
        await session.execute(
            select(System.organization_id)
            .join(POAM, POAM.system_id == System.id)
            .where(POAM.id == source_poam_id)
        )
    ).scalar_one_or_none()
    if poam_org_id is None or (
        principal.org_id is not None and int(poam_org_id) != principal.org_id
    ):
        raise HTTPException(404, "poam not found")

    rows = (
        (
            await session.execute(
                select(AssessmentControlProposal)
                .where(AssessmentControlProposal.source_poam_id == source_poam_id)
                .order_by(AssessmentControlProposal.id)
            )
        )
        .scalars()
        .all()
    )
    return [await _proposal_detail(session, p) for p in rows]


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
    proposal_id: int = Path(ge=1, le=_MAX_INT64),
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


class ProposalReject(BaseModel):
    #: Not a Literal/enum here on purpose: an invalid value (including
    #: "insufficient_evidence", which is proposal-only and never a valid
    #: correction) must reach reject_control_proposal's own check and come
    #: back as a 409 explaining why, not a generic 422 from the schema layer.
    corrected_finding: str = Field(min_length=1, max_length=32)
    #: Blank is rejected here at the edge, matching control_identifier above;
    #: a whitespace-only note still reaches reject_control_proposal's own
    #: ``note.strip()`` check and comes back as a 409.
    note: str = Field(min_length=1)


@router.post("/proposals/{proposal_id}/reject")
async def reject_proposal(
    *,
    proposal_id: int = Path(ge=1, le=_MAX_INT64),
    body: ProposalReject,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Record an assessor's correction to a proposed finding.

    Mirrors ``accept_proposal`` exactly: ``reject_control_proposal`` refuses
    (``RejectionRefused``) a proposal that is already ``accepted`` or already
    ``rejected`` -- both terminal, neither re-enterable -- a ``corrected_finding``
    that is not a valid correction (``insufficient_evidence`` included), or a
    blank note. All three surface here as 409, not a 500: the request is
    understood and rejected, not a server fault. Never writes an
    ``AssessmentControlResult`` -- see ``reject_control_proposal``'s own
    docstring for why.
    """
    proposal = await _require_proposal(session, proposal_id, principal)
    try:
        rejected = await reject_control_proposal(
            session,
            proposal.id,
            rejected_by=principal.email,
            corrected_finding=body.corrected_finding,
            note=body.note,
        )
    except RejectionRefused as exc:
        raise HTTPException(409, str(exc)) from exc
    except ProposalError as exc:
        raise HTTPException(404, str(exc)) from exc
    await session.commit()
    return {
        "id": rejected.id,
        "state": rejected.state,
        "corrected_finding": rejected.corrected_finding,
        "rejected_by": rejected.rejected_by,
        "rejection_note": rejected.rejection_note,
    }


@router.get("/calibration")
async def get_calibration(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Live calibration metrics for the caller's own organization.

    Deliberately takes no ``organization_id`` anywhere -- not in a query
    argument, not in a body -- the organization comes only from
    ``Depends(get_principal)``. This is the shape that leaked cross-tenant
    on three endpoints in the prior slice; this endpoint has no id of its own
    to check a supplied value against, so it never accepts one at all rather
    than trusting it the way ``prep.py``'s create endpoint does.
    """
    if principal.org_id is None:
        # No single organization to report on for an unscoped principal, and
        # nothing here to derive one from (unlike _require_proposal, which
        # falls back to trusting the request when auth is disabled) -- there
        # is no id in this request to trust in the first place.
        raise HTTPException(400, "calibration requires an organization-scoped principal")
    metrics = await compute_metrics(session, organization_id=principal.org_id)
    out = metrics.as_dict()
    # decided == 0 must read as "no decisions recorded yet", not as 0% --
    # collapsing an empty denominator into 0.0 would misrepresent an engine
    # that has made zero calls as one that is always wrong. Mirrors
    # ccf.analytics.posture.org_summary's identical
    # `avg_sprs = ... if scored else None` convention for the same reason.
    out["agreement_rate"] = out["agreement_rate"] if metrics.decided else None
    return out
