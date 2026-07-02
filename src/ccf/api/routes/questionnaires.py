"""Vendor security questionnaires (CAIQ/SIG) — third-party risk assessment.

Instantiate a questionnaire for a vendor from a template, answer it, and submit
to score the vendor's security posture (0-100 → risk rating). Reviewing pushes
the rating onto the Vendor record and can open risks from flagged (``no``) gaps.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...auth import Principal
from ...governance import bus, tprm
from ...models import Task, Vendor
from ...models_tprm import (
    QuestionnaireResponse,
    QuestionnaireTemplate,
    VendorQuestionnaire,
)
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["questionnaires"])

ANSWERS = r"^(yes|no|partial|na|unanswered)$"


# --- schemas ----------------------------------------------------------------


class TemplateIn(BaseModel):
    key: str
    name: str
    framework: str | None = None
    version: str = "1.0"
    questions: list[dict[str, Any]] = Field(default_factory=list)


class InstantiateIn(BaseModel):
    template_key: str = tprm.DEFAULT_TEMPLATE["key"]
    name: str | None = None
    due_on: date | None = None


class AnswerIn(BaseModel):
    answer: str = Field(..., pattern=ANSWERS)
    detail: str | None = None
    evidence_ref: str | None = None


class ReviewIn(BaseModel):
    reviewer: str | None = None
    summary: str | None = None
    open_tasks: bool = False  # open a remediation Task for each flagged (no) response


# --- serializers ------------------------------------------------------------


def _resp_out(r: QuestionnaireResponse) -> dict[str, Any]:
    return {
        "id": r.id,
        "question_id": r.question_id,
        "domain": r.domain,
        "question_text": r.question_text,
        "weight": r.weight,
        "answer": r.answer,
        "detail": r.detail,
        "evidence_ref": r.evidence_ref,
    }


def _qnr_out(q: VendorQuestionnaire) -> dict[str, Any]:
    return {
        "id": q.id,
        "vendor_id": q.vendor_id,
        "template_key": q.template_key,
        "name": q.name,
        "status": q.status,
        "sent_on": q.sent_on,
        "due_on": q.due_on,
        "submitted_on": q.submitted_on,
        "reviewed_on": q.reviewed_on,
        "reviewer": q.reviewer,
        "score": q.score,
        "risk_rating": q.risk_rating,
        "summary": q.summary,
        "responses": [_resp_out(r) for r in (q.responses or [])],
    }


async def _require_qnr(
    session: AsyncSession, qid: int, principal: Principal
) -> VendorQuestionnaire:
    q = (
        await session.execute(
            select(VendorQuestionnaire)
            .options(selectinload(VendorQuestionnaire.responses))
            .where(VendorQuestionnaire.id == qid)
        )
    ).scalar_one_or_none()
    if q is None or (principal.org_id is not None and q.organization_id != principal.org_id):
        raise HTTPException(404, "questionnaire not found")
    return q


async def _require_vendor(session: AsyncSession, vid: int, principal: Principal) -> Vendor:
    v = (await session.execute(select(Vendor).where(Vendor.id == vid))).scalar_one_or_none()
    if v is None or (principal.org_id is not None and v.organization_id != principal.org_id):
        raise HTTPException(404, "vendor not found")
    return v


async def _resolve_template(
    session: AsyncSession, key: str, principal: Principal
) -> dict[str, Any]:
    """Resolve a template by key: a stored org template wins over the built-in."""
    stmt = select(QuestionnaireTemplate).where(QuestionnaireTemplate.key == key)
    if principal.org_id is not None:
        stmt = stmt.where(QuestionnaireTemplate.organization_id == principal.org_id)
    row = (await session.execute(stmt)).scalars().first()
    if row is not None:
        return {"key": row.key, "name": row.name, "questions": row.questions or []}
    if key == tprm.DEFAULT_TEMPLATE["key"]:
        return tprm.DEFAULT_TEMPLATE
    raise HTTPException(404, f"template '{key}' not found")


# --- templates --------------------------------------------------------------


@router.get("/questionnaire-templates")
async def list_templates(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(QuestionnaireTemplate).order_by(QuestionnaireTemplate.key)
    if principal.org_id is not None:
        stmt = stmt.where(QuestionnaireTemplate.organization_id == principal.org_id)
    stored = [
        {"key": t.key, "name": t.name, "framework": t.framework, "version": t.version,
         "questions": t.questions, "builtin": False}
        for t in (await session.execute(stmt)).scalars().all()
    ]
    # Always surface the built-in unless an org template shadows its key.
    if not any(t["key"] == tprm.DEFAULT_TEMPLATE["key"] for t in stored):
        stored.insert(0, {**tprm.DEFAULT_TEMPLATE, "builtin": True})
    return stored


@router.post("/questionnaire-templates", status_code=201)
async def create_template(
    body: TemplateIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    t = QuestionnaireTemplate(organization_id=principal.org_id, **body.model_dump())
    session.add(t)
    await session.commit()
    return {"id": t.id, "key": t.key, "name": t.name}


# --- questionnaires ---------------------------------------------------------


@router.get("/questionnaires")
async def list_questionnaires(
    vendor_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = (
        select(VendorQuestionnaire)
        .options(selectinload(VendorQuestionnaire.responses))
        .order_by(VendorQuestionnaire.id.desc())
    )
    if principal.org_id is not None:
        stmt = stmt.where(VendorQuestionnaire.organization_id == principal.org_id)
    if vendor_id is not None:
        stmt = stmt.where(VendorQuestionnaire.vendor_id == vendor_id)
    return [_qnr_out(q) for q in (await session.execute(stmt)).scalars().all()]


@router.post("/vendors/{vendor_id}/questionnaires", status_code=201)
async def instantiate(
    vendor_id: int,
    body: InstantiateIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Create a questionnaire for a vendor, seeding a response per template question."""
    vendor = await _require_vendor(session, vendor_id, principal)
    template = await _resolve_template(session, body.template_key, principal)
    today = datetime.now(UTC).date()
    q = VendorQuestionnaire(
        organization_id=principal.org_id,
        vendor_id=vendor_id,
        template_key=template["key"],
        name=body.name or f"{vendor.name} — {template['name']}",
        status="sent",
        sent_on=today,
        due_on=body.due_on,
    )
    session.add(q)
    await session.flush()
    for i, question in enumerate(template["questions"]):
        session.add(
            QuestionnaireResponse(
                questionnaire_id=q.id,
                question_id=str(question.get("id", f"Q{i + 1}")),
                domain=question.get("domain"),
                question_text=question.get("text", ""),
                weight=int(question.get("weight", 1) or 1),
                answer="unanswered",
                sort_order=i,
            )
        )
    await bus.emit(
        session,
        verb="created",
        entity_type="vendor_questionnaire",
        entity_id=q.id,
        summary=f"Security questionnaire sent to {vendor.name}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    q = await _require_qnr(session, q.id, principal)
    return _qnr_out(q)


@router.get("/questionnaires/{qid}")
async def get_questionnaire(
    qid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _qnr_out(await _require_qnr(session, qid, principal))


@router.patch("/questionnaires/{qid}/responses/{rid}")
async def answer_response(
    qid: int,
    rid: int,
    body: AnswerIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    q = await _require_qnr(session, qid, principal)
    resp = next((r for r in q.responses if r.id == rid), None)
    if resp is None:
        raise HTTPException(404, "response not found")
    resp.answer = body.answer
    resp.detail = body.detail
    if body.evidence_ref is not None:
        resp.evidence_ref = body.evidence_ref
    if q.status in ("draft", "sent"):
        q.status = "in_progress"
    await session.commit()
    return _resp_out(resp)


@router.post("/questionnaires/{qid}/submit")
async def submit_questionnaire(
    qid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Score the questionnaire and record the vendor's posture score + rating."""
    q = await _require_qnr(session, qid, principal)
    scored = tprm.score_responses(
        [
            {"answer": r.answer, "weight": r.weight, "question_id": r.question_id}
            for r in q.responses
        ]
    )
    q.status = "submitted"
    q.submitted_on = datetime.now(UTC).date()
    q.score = scored["score"]
    q.risk_rating = scored["rating"]
    await bus.emit(
        session,
        verb="submitted",
        entity_type="vendor_questionnaire",
        entity_id=q.id,
        summary=f"Questionnaire submitted: score {scored['score']} ({scored['rating']} risk)",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": q.id, "status": q.status, **scored}


@router.post("/questionnaires/{qid}/review")
async def review_questionnaire(
    qid: int,
    body: ReviewIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Accept a submitted questionnaire: push the rating to the vendor, optionally
    opening a remediation Task for each flagged (``no``) response."""
    q = await _require_qnr(session, qid, principal)
    if q.status not in ("submitted", "in_progress", "reviewed"):
        raise HTTPException(409, "questionnaire must be submitted before review")
    # Ensure a score exists even if reviewed without an explicit submit.
    scored = tprm.score_responses(
        [
            {"answer": r.answer, "weight": r.weight, "question_id": r.question_id}
            for r in q.responses
        ]
    )
    q.status = "reviewed"
    q.reviewed_on = datetime.now(UTC).date()
    q.reviewer = body.reviewer or principal.email
    q.summary = body.summary
    q.score = scored["score"]
    q.risk_rating = scored["rating"]

    vendor = await _require_vendor(session, q.vendor_id, principal)
    vendor.risk_rating = scored["rating"]
    vendor.last_reviewed_on = q.reviewed_on

    tasks_opened = 0
    if body.open_tasks and scored["flagged"]:
        flagged_ids = set(scored["flagged"])
        for r in q.responses:
            if r.question_id not in flagged_ids:
                continue
            dedupe = f"vendorq-gap:{q.id}:{r.question_id}"
            exists = (
                await session.execute(select(Task).where(Task.dedupe_key == dedupe))
            ).scalar_one_or_none()
            if exists is not None:
                continue
            session.add(
                Task(
                    organization_id=principal.org_id,
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
            tasks_opened += 1
    await bus.emit(
        session,
        verb="reviewed",
        entity_type="vendor_questionnaire",
        entity_id=q.id,
        summary=(
            f"Questionnaire reviewed for {vendor.name}: {scored['rating']} risk"
            + (f", {tasks_opened} remediation task(s) opened" if tasks_opened else "")
        ),
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    return {"id": q.id, "status": q.status, "tasks_opened": tasks_opened, **scored}
