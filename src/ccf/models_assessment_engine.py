"""Objective-level assessment engine — proposal tables.

The engine evaluates individual 800-53A assessment objectives against evidence
retrieved from the preparation pipeline, then rolls the objective verdicts into a
*proposed* control finding. Proposals are inert: nothing here reaches
``AssessmentControlResult`` — and therefore nothing reaches the SAR or an
auto-created POA&M — until an assessor accepts it. A failed control creates real
remediation work, so the model never holds that authority.

The objectives themselves are not stored. They already exist as sub-clause rows in
``ccf.controls`` (``control_name IS NULL``); an objective proposal records the
objective's label and a SHA-256 of its text, so a catalog re-ingest that changes
wording makes a stale proposal detectable rather than silently wrong.

**These three tables carry no row-level-security policies**, matching the seven
``prep_*`` tables (see ``models_prep.py``'s identical note) rather than the
110 of Concord's 131 ``ccf`` tables that do. Isolation is application-layer
instead: every route and service function filters by ``organization_id``
explicitly (derived from ``Assessment -> System -> Organization``, never from a
caller-supplied id -- see ``ccf.assessment.engine.service``), and
``ccf.assessment.engine.jobs``'s job claim is intentionally unscoped by
organization, since one worker drains every organization's queued jobs by
design. This is an explicit, deliberate exemption, not an oversight to be
inferred -- see ``docs/ARCHITECTURE.md``'s "Objective-level assessment engine"
section for the same note alongside the rest of the engine's description.

**No governed-AI-action audit trail.** Objective evaluation
(``ccf.assessment.engine.evaluate``) calls ``ccf.ai.gateway.generate_structured``
directly, the same as slice 1's prep classification -- neither routes through
``ccf.ai_actions.run_action``, so neither produces an ``ai_action_runs`` row, a
citation record in that subsystem, or a guardrail evaluation. An ``ActionDef``
is registered for prep classification in ``ccf.ai_actions.registry``, but
registration is not dispatch: nothing calls ``run_action`` with it, and there is
no equivalent ``ActionDef`` for objective evaluation at all. For a product whose
output becomes FedRAMP citations, wiring both through the typed AI-action layer
is the standing follow-up.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base

#: A model's verdict on one objective.
OBJECTIVE_VERDICTS = ("satisfied", "not_satisfied", "not_applicable", "insufficient_evidence")

#: What the rollup may propose for a control. ``insufficient_evidence`` is
#: proposal-only and is refused by the acceptance path — "the engine could not
#: tell" is not "the control fails", and conflating them manufactures POA&Ms out
#: of missing evidence.
CONTROL_PROPOSAL_FINDINGS = (
    "satisfied",
    "other_than_satisfied",
    "not_applicable",
    "insufficient_evidence",
)

#: Lifecycle of a proposal row. ``stale`` means the catalog objective text changed
#: after evaluation; ``failed`` means the model call could not be completed.
PROPOSAL_STATES = ("draft", "complete", "accepted", "rejected", "failed", "stale")

ASSESSMENT_JOB_STATES = ("pending", "claimed", "done", "failed")


class AssessmentControlProposal(Base):
    """A proposed finding for one control within one assessment."""

    __tablename__ = "assessment_control_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessments.id", ondelete="CASCADE"), index=True
    )
    #: Canonical (unpadded) form, per ccf.prep.screen.normalize_control_identifier.
    control_identifier: Mapped[str] = mapped_column(String(64), index=True)

    state: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    proposed_finding: Mapped[str | None] = mapped_column(String(32))
    rollup_rationale: Mapped[str | None] = mapped_column(Text)
    #: Thresholds in force when this proposal was evaluated, so a later settings
    #: change cannot retroactively reinterpret it.
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    objectives_total: Mapped[int] = mapped_column(Integer, default=0)
    objectives_evaluated: Mapped[int] = mapped_column(Integer, default=0)

    accepted_by: Mapped[str | None] = mapped_column(String(255))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "assessment_id", "control_identifier", name="uq_control_proposal_assessment_control"
        ),
        Index("ix_control_proposal_state", "organization_id", "state"),
    )


class AssessmentObjectiveProposal(Base):
    """A model's verdict on one assessment objective, with its citations."""

    __tablename__ = "assessment_objective_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    control_proposal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessment_control_proposals.id", ondelete="CASCADE"), index=True
    )

    #: e.g. "AC-02a" from ap_acronym, or an ordinal-derived label when sparse.
    label: Mapped[str] = mapped_column(String(64))
    objective_text: Mapped[str] = mapped_column(Text)
    #: Detects a catalog re-ingest that reworded the objective under a stored verdict.
    objective_text_sha256: Mapped[str] = mapped_column(String(64))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    state: Mapped[str] = mapped_column(String(16), default="complete")
    verdict: Mapped[str | None] = mapped_column(String(32))
    #: prep_units the model cited. Validated against what retrieval actually
    #: returned — a model cannot cite a passage it was never shown.
    cited_unit_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    #: Ids retrieved and offered to the model, so a reviewer can see what it had.
    retrieved_unit_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    gaps: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    contradictions: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    rationale: Mapped[str | None] = mapped_column(Text)
    model_name: Mapped[str | None] = mapped_column(String(128))
    model_confidence: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("control_proposal_id", "label", name="uq_objective_proposal_label"),
        Index("ix_objective_proposal_sort", "control_proposal_id", "sort_order"),
    )


class AssessmentJob(Base):
    """Queue entry driving evaluation of one control proposal."""

    __tablename__ = "assessment_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    control_proposal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessment_control_proposals.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_assessment_jobs_claimable", "status", "created_at"),)
