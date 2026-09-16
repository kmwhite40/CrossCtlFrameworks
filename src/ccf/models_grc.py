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
    UniqueConstraint,
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
    # ISSM-04: findings were orphaned from the remediation program — no link to
    # the system they concern, nor to any POA&M/Risk opened from them. These
    # are nullable (a finding may be raised before the system/remediation is
    # known) but let a finding be promoted into a provenanced POA&M ("promote
    # to POA&M", mirroring the assessment->POA&M pattern) or Risk
    # ("accept-finding -> Risk", mirroring the risks.py acceptance gate) and be
    # traced both ways once it is. ``organization_id`` mirrors the parent
    # engagement's org at creation time so findings can be scoped/filtered
    # without a join.
    system_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="SET NULL"), index=True
    )
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="SET NULL"), index=True
    )
    poam_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.poams.id", ondelete="SET NULL"), index=True
    )
    risk_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.risks.id", ondelete="SET NULL"), index=True
    )
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
    # Envelope-encrypted credential bundle (JSON secret payload) for the live
    # config-capture connectors (ccf.connectors.*) — never plaintext. Reuses the
    # Slice-3a cipher (ccf.ai.cipher); see ccf.connectors.credentials. One row
    # per (organization_id, connector_type) is used for automated capture; only
    # ``key_last4`` is ever surfaced to callers/UI.
    encrypted_credential: Mapped[str | None] = mapped_column(Text)
    key_last4: Mapped[str | None] = mapped_column(String(8))
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
    # Provenance. 'generated' rows are created by a posture scan from a
    # PostureCheck definition; 'authored' is a human-defined test. Defaults to
    # authored so every pre-existing row is correctly labelled without a data
    # migration, and so a scan can never be mistaken for someone's intent.
    source: Mapped[str] = mapped_column(
        String(16), default="authored", server_default="authored"
    )
    #: The PostureCheck this test was generated from; null for authored tests.
    check_key: Mapped[str | None] = mapped_column(String(128), index=True)
    #: Which expectation produced this test's checks: ``"platform"`` for the
    #: built-in registry, ``"pack:<pack_key>"`` for a tenant-installed pack
    #: (mirrors ``posture.resolve.ResolvedCheck.source``). Null for a manually
    #: authored test (``source == "authored"``), which has no check behind it.
    #: Without this, a self-attested tenant verdict and a platform assessment
    #: are indistinguishable in the record -- see CRITICAL 3, PR #13 review.
    check_source: Mapped[str | None] = mapped_column(String(64))
    #: Optional: this test evidences a capability directly (P1 ontology).
    #: SET NULL on delete -- removing a capability must not destroy validation
    #: history.
    capability_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="SET NULL"), index=True
    )
    # Widened from String(8) in 0068: the vocabulary is now
    # ccf.fedramp20x.VALIDATION_STATUSES, whose longest member
    # ('manual_review_required') is 22 characters.
    last_status: Mapped[str | None] = mapped_column(String(32))
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        # Nulls are distinct in Postgres unique indexes, so authored tests
        # (check_key NULL) are deliberately unconstrained while a generated
        # (system_id, check_key) pair can exist only once -- which is what
        # makes re-scanning idempotent.
        UniqueConstraint("system_id", "check_key", name="uq_control_test_system_check"),
    )

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
    status: Mapped[str] = mapped_column(String(32))  # widened in 0068
    detail: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))
    #: Resources considered by this run, and how many failed -- so "47
    #: evaluated, 3 failing" is answerable without counting child rows.
    evaluated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    failing: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    #: How many of the failing resources an approved waiver accepted. Beside
    #: evaluated/failing so "failing but accepted" is answerable without a
    #: join. A waived result is still recorded as failing -- the waiver
    #: suppresses the consequence, never the observation.
    waived: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    #: The expectation as evaluated, recorded with the result so a later
    #: change to the check definition cannot rewrite history.
    expected: Mapped[str | None] = mapped_column(Text)

    test: Mapped[ControlTest] = relationship(back_populates="results")

    __table_args__ = (Index("ix_control_test_results_test_run", "control_test_id", "run_at"),)


class ControlTestResourceResult(Base):
    """One resource's verdict within a control-test run.

    This is what lets the platform say *which* resources failed -- "47 storage
    accounts evaluated, 3 allow public access, here are their ids" -- rather
    than only that a test failed.

    Deliberately carries no ``organization_id``: ``control_test_results`` has
    none either and is policied through ``control_tests``, and
    ``poam_milestones`` chains through ``poams -> systems``. This table follows
    that established parent-chain shape one hop further. Adding an org column
    would denormalize against the convention and create a second source of
    truth for the row's tenant.
    """

    __tablename__ = "control_test_resource_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    result_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.control_test_results.id", ondelete="CASCADE"), index=True
    )
    resource_id: Mapped[str] = mapped_column(String(512))
    resource_type: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    observed: Mapped[str | None] = mapped_column(Text)
    #: The waiver that accepted this resource's finding, if any. ON DELETE SET
    #: NULL, never CASCADE: deleting an acceptance must not delete the
    #: observation it accepted -- the evidence outlives the waiver.
    waiver_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ccf.waivers.id", ondelete="SET NULL")
    )
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (Index("ix_ctrr_type_verdict", "resource_type", "verdict"),)


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
