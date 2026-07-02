"""Typed agentic GRC action models — auditable, citation-first, human-approved.

AI here executes *typed* GRC actions (draft a POA&M remediation, propose a control
test, find evidence for a control, …) rather than free-form chat. Each
:class:`AiActionRun` records the input/output hashes, citations, reviewer, and
disposition; mutations to authoritative records happen only after approval, and
:class:`AiGuardrailViolation` captures blocked attempts. Tenant-isolated.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class AiActionDefinition(Base):
    """A registered typed action (seeded from the in-code registry)."""

    __tablename__ = "ai_action_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    input_entity_types: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    citation_required: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_mutation: Mapped[str | None] = mapped_column(String(64))
    output_kind: Mapped[str] = mapped_column(String(32), default="text")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiActionRun(Base):
    """One execution of a typed action, from run through review/disposition."""

    __tablename__ = "ai_action_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    action_key: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(48))
    entity_id: Mapped[str | None] = mapped_column(String(128))
    # draft|pending_review|approved|rejected|completed|blocked
    status: Mapped[str] = mapped_column(String(16), default="pending_review")
    provider: Mapped[str] = mapped_column(String(24), default="stub")
    prompt_version: Mapped[str] = mapped_column(String(24), default="v1")
    input_hash: Mapped[str | None] = mapped_column(String(64))
    output_hash: Mapped[str | None] = mapped_column(String(64))
    actor: Mapped[str | None] = mapped_column(String(255))
    reviewer: Mapped[str | None] = mapped_column(String(255))
    disposition: Mapped[str | None] = mapped_column(String(24))
    mutation_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    inputs: Mapped[list[AiActionInput]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    outputs: Mapped[list[AiActionOutput]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    citations: Mapped[list[AiActionCitation]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class AiActionInput(Base):
    """The (tenant-scoped) context an action run was given."""

    __tablename__ = "ai_action_inputs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str | None] = mapped_column(String(48))
    entity_id: Mapped[str | None] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    hash: Mapped[str | None] = mapped_column(String(64))

    run: Mapped[AiActionRun] = relationship(back_populates="inputs")


class AiActionOutput(Base):
    """The generated output for a run (text + structured payload)."""

    __tablename__ = "ai_action_outputs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), index=True
    )
    content: Mapped[str] = mapped_column(Text)
    uncited: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    hash: Mapped[str | None] = mapped_column(String(64))

    run: Mapped[AiActionRun] = relationship(back_populates="outputs")


class AiActionCitation(Base):
    """A source (evidence/policy/control/…) the output is grounded in."""

    __tablename__ = "ai_action_citations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), index=True
    )
    source_type: Mapped[str] = mapped_column(String(48))
    source_id: Mapped[str | None] = mapped_column(String(128))
    label: Mapped[str | None] = mapped_column(String(512))
    note: Mapped[str | None] = mapped_column(Text)

    run: Mapped[AiActionRun] = relationship(back_populates="citations")


class AiActionReview(Base):
    """A human approve/reject decision on a run."""

    __tablename__ = "ai_action_reviews"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), index=True
    )
    reviewer: Mapped[str | None] = mapped_column(String(255))
    decision: Mapped[str] = mapped_column(String(16))  # approved|rejected
    note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AiActionEvaluation(Base):
    """A quality/guardrail metric recorded for a run."""

    __tablename__ = "ai_action_evaluations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), index=True
    )
    metric: Mapped[str] = mapped_column(String(48))
    value: Mapped[str | None] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiApprovedMutation(Base):
    """A record of the authoritative change an approved run applied."""

    __tablename__ = "ai_approved_mutations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="CASCADE"), index=True
    )
    mutation_type: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(48))
    target_id: Mapped[str | None] = mapped_column(String(128))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiGuardrailViolation(Base):
    """A blocked/flagged guardrail event (cross-tenant, unapproved mutation, …)."""

    __tablename__ = "ai_guardrail_violations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    run_id: Mapped[int | None] = mapped_column(BigInteger)
    kind: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
