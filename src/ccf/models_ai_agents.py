"""AI agent governance models — agents as privileged non-human actors.

An :class:`AiAgent` is inventoried with its autonomy, data access, tools, and
system/vendor/policy/control mappings (the lighter sub-entities — owners, tools,
permissions, data/system/vendor/policy/control links — are folded into JSONB on
the agent to keep the table set reviewable; the assurance graph reads them to
create agent→system/vendor/policy/control/risk edges). Risk assessments, the
approval workflow, monitoring events, incidents, and kill-switch events are their
own tenant-isolated tables.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class AiAgent(Base):
    """An inventoried AI agent (privileged non-human actor)."""

    __tablename__ = "ai_agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255))
    business_purpose: Mapped[str | None] = mapped_column(Text)
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="SET NULL"))
    model_provider: Mapped[str | None] = mapped_column(String(128))
    vendor_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.vendors.id", ondelete="SET NULL"))
    # low|medium|high|full (autonomy) ; none|human_in_loop|human_on_loop|human_over_loop
    autonomy_level: Mapped[str] = mapped_column(String(16), default="low")
    human_oversight: Mapped[str] = mapped_column(String(24), default="human_in_loop")
    external_action_capability: Mapped[bool] = mapped_column(Boolean, default=False)
    external_communication: Mapped[bool] = mapped_column(Boolean, default=False)
    production_access: Mapped[bool] = mapped_column(Boolean, default=False)
    regulated_data_access: Mapped[bool] = mapped_column(Boolean, default=False)
    # public|internal|cui|pii|phi
    data_classification: Mapped[str | None] = mapped_column(String(32))
    financial_impact: Mapped[str] = mapped_column(String(16), default="low")  # low|moderate|high
    operational_impact: Mapped[str] = mapped_column(String(16), default="low")
    # none|partial|full
    monitoring_coverage: Mapped[str] = mapped_column(String(16), default="none")
    evaluation_coverage: Mapped[str] = mapped_column(String(16), default="none")
    # Folded relationship/detail arrays (ids/labels) the graph + UI read.
    tools: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    data_stores: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    permissions: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    system_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    vendor_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    policy_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    control_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    risk_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    # Governance state. draft|approved|rejected
    approval_status: Mapped[str] = mapped_column(String(16), default="draft")
    risk_rating: Mapped[str | None] = mapped_column(String(16))  # low|moderate|high|critical
    risk_score: Mapped[float | None] = mapped_column(Float)
    review_frequency: Mapped[str | None] = mapped_column(String(32))
    last_reviewed_on: Mapped[date | None] = mapped_column(Date)
    next_review_on: Mapped[date | None] = mapped_column(Date)
    kill_switch_status: Mapped[str] = mapped_column(String(16), default="ready")  # ready|engaged
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    assessments: Mapped[list[AiAgentRiskAssessment]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )


class AiAgentRiskAssessment(Base):
    """A scored risk assessment of an agent (dimensions + result)."""

    __tablename__ = "ai_agent_risk_assessments"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_agents.id", ondelete="CASCADE"), index=True
    )
    score: Mapped[float] = mapped_column(Float, default=0.0)
    rating: Mapped[str] = mapped_column(String(16), default="low")
    factors: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    assessed_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agent: Mapped[AiAgent] = relationship(back_populates="assessments")


class AiAgentApproval(Base):
    """An approve/reject decision on an agent."""

    __tablename__ = "ai_agent_approvals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_agents.id", ondelete="CASCADE"), index=True
    )
    decision: Mapped[str] = mapped_column(String(16))  # approved|rejected
    reviewer: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiAgentMonitoringEvent(Base):
    """A monitoring signal observed for an agent."""

    __tablename__ = "ai_agent_monitoring_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_agents.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|warning|critical
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiAgentIncident(Base):
    """A tracked incident involving an agent."""

    __tablename__ = "ai_agent_incidents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_agents.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), default="moderate")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|investigating|closed
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiAgentKillSwitchEvent(Base):
    """A kill-switch engage/reset event for an agent."""

    __tablename__ = "ai_agent_kill_switch_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ai_agents.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(16), default="engage")  # engage|reset
    reason: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
