"""GRC program models added by the 2026-10 build-out (migration ``0099_grc_program``).

Every table here is tenant data and carries its own ``organization_id`` --
child tables included -- so the ``tenant_isolation`` RLS policy applies to each
row directly rather than through a parent join (``tests/test_rls_registry_no_gap``
fails any table that has the column and no policy). The one global table is
``kev_entries``: CISA's Known Exploited Vulnerabilities catalog is the same for
every tenant.

Nothing here decides compliance. Objectives, KRIs, committees and obligations
are records people keep; posture snapshots are copies of what the existing
analytics computed on a day, so a trend can be drawn from history rather than
invented. Status vocabularies are listed beside each column and enforced by
the services and their tests, not by the database, matching the rest of the
schema.
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
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


def _org() -> Mapped[int]:
    return mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )


def _user() -> Mapped[int | None]:
    return mapped_column(ForeignKey("ccf.users.id", ondelete="SET NULL"), nullable=True)


def _created() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


# ── Posture history ──────────────────────────────────────────────────────────


class PostureSnapshot(Base):
    """One organization's computed posture on one day.

    ``metrics`` is a copy of what ``analytics.command_center`` reported that
    day (KPI counts, per-framework addressed counts, SPRS, risk bands). It is
    written by the scheduler and by an explicit "capture now"; it is never
    edited, so a trend drawn from it is a record, not a reconstruction.
    """

    __tablename__ = "posture_snapshots"
    __table_args__ = (
        UniqueConstraint("organization_id", "taken_on", name="uq_posture_snapshot_day"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = _org()
    taken_on: Mapped[date] = mapped_column(Date, index=True)
    taken_at: Mapped[datetime] = _created()
    source: Mapped[str] = mapped_column(String(16), default="scheduler")  # scheduler|manual
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


# ── Risk appetite and key risk indicators ────────────────────────────────────


class RiskAppetite(Base):
    """The most residual risk the organization will carry, per category.

    ``category`` NULL is the default applied to any risk whose category has no
    statement of its own. ``max_residual_score`` is on the same 1-25 scale as
    ``Risk.residual_score``."""

    __tablename__ = "risk_appetites"
    __table_args__ = (
        UniqueConstraint("organization_id", "category", name="uq_risk_appetite_category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    category: Mapped[str | None] = mapped_column(String(64))
    statement: Mapped[str] = mapped_column(Text)
    max_residual_score: Mapped[int] = mapped_column(Integer)
    owner_user_id: Mapped[int | None] = _user()
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = _created()


class KeyRiskIndicator(Base):
    """A measured signal with thresholds.

    ``metric_key`` names a built-in computed metric (``governance.kri``
    registry); NULL means readings are entered by hand. ``direction`` says
    which way is bad, so a threshold is never read backwards."""

    __tablename__ = "key_risk_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    metric_key: Mapped[str | None] = mapped_column(String(64))
    unit: Mapped[str | None] = mapped_column(String(32))
    direction: Mapped[str] = mapped_column(String(16), default="higher_is_worse")  # |lower_is_worse
    warn_threshold: Mapped[float | None] = mapped_column(Float)
    critical_threshold: Mapped[float | None] = mapped_column(Float)
    owner_user_id: Mapped[int | None] = _user()
    risk_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.risks.id", ondelete="SET NULL"))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _created()


class KriReading(Base):
    __tablename__ = "kri_readings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = _org()
    kri_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.key_risk_indicators.id", ondelete="CASCADE"), index=True
    )
    value: Mapped[float] = mapped_column(Float)
    recorded_at: Mapped[datetime] = _created()
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual|computed
    recorded_by: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)


# ── Organization structure and governance bodies ─────────────────────────────


class BusinessUnit(Base):
    __tablename__ = "business_units"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_business_unit_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.business_units.id", ondelete="SET NULL")
    )
    owner_user_id: Mapped[int | None] = _user()
    created_at: Mapped[datetime] = _created()


class Team(Base):
    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_team_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    business_unit_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.business_units.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = _created()


class TeamMember(Base):
    __tablename__ = "team_members"
    __table_args__ = (UniqueConstraint("team_id", "user_id", name="uq_team_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    team_id: Mapped[int] = mapped_column(ForeignKey("ccf.teams.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("ccf.users.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(32), default="member")  # lead|member


class Committee(Base):
    __tablename__ = "committees"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_committee_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    name: Mapped[str] = mapped_column(String(255))
    charter: Mapped[str | None] = mapped_column(Text)
    cadence: Mapped[str | None] = mapped_column(String(32))  # monthly|quarterly|...
    chair_user_id: Mapped[int | None] = _user()
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _created()


class CommitteeMember(Base):
    __tablename__ = "committee_members"
    __table_args__ = (UniqueConstraint("committee_id", "user_id", name="uq_committee_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    committee_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.committees.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("ccf.users.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(32), default="member")  # chair|secretary|member


class CommitteeMeeting(Base):
    __tablename__ = "committee_meetings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    committee_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.committees.id", ondelete="CASCADE"), index=True
    )
    held_on: Mapped[date] = mapped_column(Date)
    attendee_user_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    minutes: Mapped[str | None] = mapped_column(Text)
    decisions: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # [{text, owner, due_on}]
    recorded_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = _created()


class StrategicObjective(Base):
    __tablename__ = "strategic_objectives"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    measure: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[int | None] = _user()
    target_on: Mapped[date | None] = mapped_column(Date)
    # planned|on_track|at_risk|off_track|achieved|retired
    status: Mapped[str] = mapped_column(String(16), default="planned")
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ObjectiveLink(Base):
    """An objective's tie to a record: risk, control, system, policy or KRI."""

    __tablename__ = "objective_links"
    __table_args__ = (
        UniqueConstraint("objective_id", "entity_type", "entity_id", name="uq_objective_link"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    objective_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.strategic_objectives.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str] = mapped_column(String(32))  # risk|control|system|policy|kri
    entity_id: Mapped[str] = mapped_column(String(64))


# ── Obligations and compensating controls ────────────────────────────────────


class ComplianceObligation(Base):
    """Something the organization must do, with its source and owner.

    ``source`` is where the duty comes from (statute, regulation, contract,
    framework, policy); ``control_ids`` are the catalog identifiers that
    satisfy it, as a list of strings."""

    __tablename__ = "compliance_obligations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    source: Mapped[str] = mapped_column(String(32))  # statute|regulation|contract|framework|policy
    citation: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[int | None] = _user()
    frequency: Mapped[str | None] = mapped_column(String(32))
    due_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(
        String(16), default="open"
    )  # open|met|not_met|not_applicable
    control_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = _created()


class CompensatingControl(Base):
    """A substitute measure accepted in place of a control, with its expiry.

    Proposed by one person and decided by another: the service refuses an
    approval by the proposer (separation of duties, as approvals do)."""

    __tablename__ = "compensating_controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    control_identifier: Mapped[str] = mapped_column(String(64))
    measure: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    # proposed|approved|rejected|retired
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    proposed_by: Mapped[str | None] = mapped_column(String(255))
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = _created()


# ── Audit workpapers ─────────────────────────────────────────────────────────


class AuditWorkpaper(Base):
    """A test procedure and its result within an audit engagement.

    ``final`` requires a reviewer who is not the preparer."""

    __tablename__ = "audit_workpapers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.audit_engagements.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    control_id: Mapped[str | None] = mapped_column(String(64))
    procedure: Mapped[str | None] = mapped_column(Text)
    sample_size: Mapped[int | None] = mapped_column(Integer)
    exceptions_found: Mapped[int | None] = mapped_column(Integer)
    # effective|ineffective|not_tested
    conclusion: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="draft")  # draft|in_review|final
    prepared_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Third parties ────────────────────────────────────────────────────────────


class VendorContract(Base):
    __tablename__ = "vendor_contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    vendor_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.vendors.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(255))
    contract_ref: Mapped[str | None] = mapped_column(String(128))
    start_on: Mapped[date | None] = mapped_column(Date)
    end_on: Mapped[date | None] = mapped_column(Date)
    renewal_on: Mapped[date | None] = mapped_column(Date)
    annual_value: Mapped[float | None] = mapped_column(Float)
    owner_user_id: Mapped[int | None] = _user()
    status: Mapped[str] = mapped_column(
        String(16), default="active"
    )  # draft|active|expired|terminated
    created_at: Mapped[datetime] = _created()


class ContractObligation(Base):
    __tablename__ = "contract_obligations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    contract_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.vendor_contracts.id", ondelete="CASCADE"), index=True
    )
    description: Mapped[str] = mapped_column(Text)
    # security|privacy|sla|audit_right|breach_notice|other
    category: Mapped[str] = mapped_column(String(32), default="security")
    frequency: Mapped[str | None] = mapped_column(String(32))
    due_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|met|missed|waived
    control_id: Mapped[str | None] = mapped_column(String(64))
    evidence_ref: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = _created()


class DueDiligenceItem(Base):
    __tablename__ = "due_diligence_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    vendor_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.vendors.id", ondelete="CASCADE"), index=True
    )
    item: Mapped[str] = mapped_column(String(255))
    category: Mapped[str | None] = mapped_column(String(32))
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    # requested|received|accepted|rejected|not_applicable
    status: Mapped[str] = mapped_column(String(16), default="requested")
    evidence_ref: Mapped[str | None] = mapped_column(String(512))
    due_on: Mapped[date | None] = mapped_column(Date)
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()


class VendorFinding(Base):
    __tablename__ = "vendor_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    vendor_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.vendors.id", ondelete="CASCADE"), index=True
    )
    questionnaire_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.vendor_questionnaires.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(
        String(16), default="moderate"
    )  # low|moderate|high|critical
    status: Mapped[str] = mapped_column(
        String(16), default="open"
    )  # open|remediating|closed|accepted
    due_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = _created()
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ── Projects ─────────────────────────────────────────────────────────────────


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[int | None] = _user()
    status: Mapped[str] = mapped_column(
        String(16), default="planned"
    )  # planned|active|on_hold|done
    start_on: Mapped[date | None] = mapped_column(Date)
    target_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = _created()


class ProjectLink(Base):
    """A project's tie to the work it delivers: POA&Ms, tasks, risks, systems."""

    __tablename__ = "project_links"
    __table_args__ = (
        UniqueConstraint("project_id", "entity_type", "entity_id", name="uq_project_link"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    project_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.projects.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str] = mapped_column(String(32))  # poam|task|risk|system
    entity_id: Mapped[str] = mapped_column(String(64))


# ── Threat intelligence (global reference data) ──────────────────────────────


class KevEntry(Base):
    """One row of CISA's Known Exploited Vulnerabilities catalog.

    Global: the catalog is the same for every tenant, so it carries no
    ``organization_id`` and is on ``test_rls_registry_no_gap``'s allowlist.
    Matching against a tenant's own scan findings happens in the query, under
    that tenant's scope."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(255))
    product: Mapped[str | None] = mapped_column(String(255))
    name: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    date_added: Mapped[date | None] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware: Mapped[str | None] = mapped_column(String(16))
    catalog_version: Mapped[str | None] = mapped_column(String(32))
    synced_at: Mapped[datetime] = _created()


# ── Risk assessments and treatment (0100) ────────────────────────────────────


class RiskAssessment(Base):
    """One dated assessment of a risk: who scored it, how, and to what.

    Qualitative: likelihood and impact on 1-5. Quantitative: single-loss
    expectancy (SLE, currency) and annual rate of occurrence (ARO), whose
    product is the annualized loss expectancy (ALE). Either or both may be
    recorded; the risk's current scores are the latest assessment's."""

    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    risk_id: Mapped[int] = mapped_column(ForeignKey("ccf.risks.id", ondelete="CASCADE"), index=True)
    assessed_on: Mapped[date] = mapped_column(Date)
    method: Mapped[str] = mapped_column(String(16), default="qualitative")  # |quantitative|both
    likelihood_score: Mapped[int | None] = mapped_column(Integer)
    impact_score: Mapped[int | None] = mapped_column(Integer)
    inherent_score: Mapped[int | None] = mapped_column(Integer)
    residual_score: Mapped[int | None] = mapped_column(Integer)
    sle: Mapped[float | None] = mapped_column(Float)
    aro: Mapped[float | None] = mapped_column(Float)
    ale: Mapped[float | None] = mapped_column(Float)
    assessor: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created()


class RiskTreatmentPlan(Base):
    __tablename__ = "risk_treatment_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    risk_id: Mapped[int] = mapped_column(ForeignKey("ccf.risks.id", ondelete="CASCADE"), index=True)
    strategy: Mapped[str] = mapped_column(String(16))  # mitigate|transfer|accept|avoid
    description: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[int | None] = _user()
    due_on: Mapped[date | None] = mapped_column(Date)
    # planned|in_progress|done|cancelled
    status: Mapped[str] = mapped_column(String(16), default="planned")
    target_residual_score: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RiskTreatmentAction(Base):
    __tablename__ = "risk_treatment_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = _org()
    plan_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.risk_treatment_plans.id", ondelete="CASCADE"), index=True
    )
    description: Mapped[str] = mapped_column(Text)
    owner_user_id: Mapped[int | None] = _user()
    due_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|done
    poam_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.poams.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created()


#: Tenant tables created by 0099, in dependency order (the migration and the
#: RLS tests read this list rather than restating it).
TENANT_TABLES: tuple[str, ...] = (
    "posture_snapshots",
    "risk_appetites",
    "key_risk_indicators",
    "kri_readings",
    "business_units",
    "teams",
    "team_members",
    "committees",
    "committee_members",
    "committee_meetings",
    "strategic_objectives",
    "objective_links",
    "compliance_obligations",
    "compensating_controls",
    "audit_workpapers",
    "vendor_contracts",
    "contract_obligations",
    "due_diligence_items",
    "vendor_findings",
    "projects",
    "project_links",
)

#: Tenant tables created by 0100.
RISK_PROGRAM_TABLES: tuple[str, ...] = (
    "risk_assessments",
    "risk_treatment_plans",
    "risk_treatment_actions",
)
