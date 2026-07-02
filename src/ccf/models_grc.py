"""GRC operating-system models — Trust Center, Regulatory Change, Audit
Workspace, Connector registry, and Control Tests.

Kept in a dedicated module (imported by :mod:`ccf.models`) so this net-new layer
is easy to review and doesn't churn the core ORM file. All tables live in the
``ccf`` schema via the shared :class:`Base` and reference core tables by
string-named foreign keys.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


# --- Trust Center -----------------------------------------------------------
class TrustProfile(Base):
    """Internal-first trust-center posture summary (one per organization)."""

    __tablename__ = "trust_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), unique=True, index=True
    )
    headline: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[str | None] = mapped_column(Text)
    framework_badges: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # [{framework,status}]
    approved_reports: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    approved_policies: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    approved_evidence: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    faq: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # [{q,a}]
    published: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TrustAccessRequest(Base):
    """A request to access the trust package (approval workflow)."""

    __tablename__ = "trust_access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    requester_name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    company: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|approved|denied
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# --- Regulatory Change Management -------------------------------------------
class RegulatoryUpdate(Base):
    """A regulatory/framework change entered manually or imported."""

    __tablename__ = "regulatory_updates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    source: Mapped[str | None] = mapped_column(String(255))
    framework_impacted: Mapped[str | None] = mapped_column(String(64))
    requirement_impacted: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[str | None] = mapped_column(Text)
    applicability: Mapped[str] = mapped_column(String(24), default="assessing")
    control_impact: Mapped[str | None] = mapped_column(Text)
    policy_impact: Mapped[str | None] = mapped_column(Text)
    system_impact: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255))
    due_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="new")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# --- Audit Collaboration Workspace ------------------------------------------
class AuditEngagement(Base):
    __tablename__ = "audit_engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    auditor_org: Mapped[str | None] = mapped_column(String(255))
    framework: Mapped[str | None] = mapped_column(String(64))
    scope: Mapped[str | None] = mapped_column(Text)
    systems: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # system ids in scope
    status: Mapped[str] = mapped_column(String(16), default="planning")
    started_on: Mapped[date | None] = mapped_column(Date)
    target_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    requests: Mapped[list[AuditRequest]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    findings: Mapped[list[AuditFinding]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class AuditRequest(Base):
    """An evidence request within an audit engagement (PBC list item)."""

    __tablename__ = "audit_requests"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.audit_engagements.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    due_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="open")
    auditor_note: Mapped[str | None] = mapped_column(Text)
    internal_note: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped[AuditEngagement] = relationship(back_populates="requests")


class AuditFinding(Base):
    __tablename__ = "audit_findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.audit_engagements.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), default="moderate")
    status: Mapped[str] = mapped_column(String(24), default="open")
    description: Mapped[str | None] = mapped_column(Text)
    management_response: Mapped[str | None] = mapped_column(Text)
    closure_evidence: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    engagement: Mapped[AuditEngagement] = relationship(back_populates="findings")


# --- Cloud Connector registry -----------------------------------------------
class ConnectorConfig(Base):
    """Persisted configuration + sync status for a cloud connector instance."""

    __tablename__ = "connector_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    # azure|azure_gov|m365|m365_gcc_high|aws|aws_govcloud|gcp|github|jira|servicenow
    connector_type: Mapped[str] = mapped_column(String(32), index=True)
    environment: Mapped[str | None] = mapped_column(String(64))
    auth_method: Mapped[str | None] = mapped_column(String(64))  # placeholder
    status: Mapped[str] = mapped_column(String(16), default="not_configured")
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    objects_discovered: Mapped[int] = mapped_column(Integer, default=0)
    evidence_produced: Mapped[int] = mapped_column(Integer, default=0)
    controls_impacted: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# --- Continuous Control Monitoring: test definitions + results --------------
class ControlTest(Base):
    """A repeatable test definition for a control (formalizes ConMon)."""

    __tablename__ = "control_tests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="CASCADE"))
    control_id: Mapped[str] = mapped_column(String(64), index=True)  # CMMC practice or catalog id
    name: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16), default="manual")  # manual|automated|connector
    connector_type: Mapped[str | None] = mapped_column(String(32))
    frequency: Mapped[str | None] = mapped_column(String(32))
    expected: Mapped[str | None] = mapped_column(Text)
    # Optional machine-checkable assertion for connector-backed tests, e.g.
    # {"odp_key": "mfa_enforced", "operator": "equals", "value": "true"}. When
    # present the auto-runner evaluates the captured value instead of only
    # checking that the connector synced. See ccf.governance.control_tests.
    assertion: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str | None] = mapped_column(String(8))  # pass|fail|warn
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    results: Mapped[list[ControlTestResult]] = relationship(
        back_populates="test", cascade="all, delete-orphan"
    )


class ControlTestResult(Base):
    """One recorded execution of a control test."""

    __tablename__ = "control_test_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    control_test_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.control_tests.id", ondelete="CASCADE"), index=True
    )
    run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    status: Mapped[str] = mapped_column(String(8))  # pass|fail|warn
    detail: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))

    test: Mapped[ControlTest] = relationship(back_populates="results")

    __table_args__ = (Index("ix_control_test_results_test_run", "control_test_id", "run_at"),)


__all__ = [
    "AuditEngagement",
    "AuditFinding",
    "AuditRequest",
    "ConnectorConfig",
    "ControlTest",
    "ControlTestResult",
    "RegulatoryUpdate",
    "TrustAccessRequest",
    "TrustProfile",
]
