"""SQLAlchemy 2.0 ORM models.

Layered schema:
    Reference layer  — Frameworks, ControlFamilies, Controls, FrameworkMappings,
                       Worksheets/WorksheetRows (the ingested NIST workbook).
    Operational layer — Organizations, Systems, ControlImplementations, Evidence,
                       Assessments, AssessmentResults, POAMs, Risks, AuditLog.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    metadata = MetaData(schema="ccf")
    type_annotation_map = {dict[str, Any]: JSONB, list[Any]: JSONB}


# ---------------------------------------------------------------------------
# Reference layer — the NIST workbook, canonicalized.
# ---------------------------------------------------------------------------


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_file: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="running")
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Framework(Base):
    __tablename__ = "frameworks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    family: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)

    mappings: Mapped[list[FrameworkMapping]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )


class ControlFamily(Base):
    __tablename__ = "control_families"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(16), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str | None] = mapped_column(String(64))

    controls: Mapped[list[Control]] = relationship(back_populates="family")


class Control(Base):
    __tablename__ = "controls"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    sequence_control: Mapped[str | None] = mapped_column(String(64), index=True)
    sort_as: Mapped[str | None] = mapped_column(String(64))

    family_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.control_families.id", ondelete="SET NULL")
    )
    family: Mapped[ControlFamily | None] = relationship(back_populates="controls")

    control_number: Mapped[str | None] = mapped_column(String(64))
    control_name: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    discussion: Mapped[str | None] = mapped_column(Text)
    related_controls: Mapped[str | None] = mapped_column(Text)
    assessment_objective: Mapped[str | None] = mapped_column(Text)
    examine: Mapped[str | None] = mapped_column(Text)
    interview: Mapped[str | None] = mapped_column(Text)
    test: Mapped[str | None] = mapped_column(Text)

    ap_acronym: Mapped[str | None] = mapped_column(String(64))
    assurance_control: Mapped[str | None] = mapped_column(String(16))
    implemented_by: Mapped[str | None] = mapped_column(String(64))
    owner: Mapped[str | None] = mapped_column(String(64))
    overall_control_type: Mapped[str | None] = mapped_column(String(64))
    opd: Mapped[bool | None] = mapped_column(Boolean)

    fisma_low: Mapped[bool | None] = mapped_column(Boolean)
    fisma_mod: Mapped[bool | None] = mapped_column(Boolean)
    fisma_high: Mapped[bool | None] = mapped_column(Boolean)

    audit_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    search_vector: Mapped[Any] = mapped_column(TSVECTOR, nullable=True)

    source_row: Mapped[int | None] = mapped_column(Integer)
    loaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    mappings: Mapped[list[FrameworkMapping]] = relationship(
        back_populates="control", cascade="all, delete-orphan"
    )
    implementations: Mapped[list[ControlImplementation]] = relationship(
        back_populates="control"
    )

    __table_args__ = (
        Index("idx_controls_search_vector", "search_vector", postgresql_using="gin"),
        Index("idx_controls_audit_payload_gin", "audit_payload", postgresql_using="gin"),
    )


class FrameworkMapping(Base):
    __tablename__ = "framework_mappings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    control_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.controls.id", ondelete="CASCADE"), index=True
    )
    framework_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.frameworks.id", ondelete="SET NULL"), index=True
    )
    column_key: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str] = mapped_column(Text)

    control: Mapped[Control] = relationship(back_populates="mappings")
    framework: Mapped[Framework | None] = relationship(back_populates="mappings")

    __table_args__ = (
        UniqueConstraint("control_id", "column_key", name="uq_mapping_control_column"),
    )


class Worksheet(Base):
    __tablename__ = "worksheets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True)
    headers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    loaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    rows: Mapped[list[WorksheetRow]] = relationship(
        back_populates="worksheet", cascade="all, delete-orphan"
    )


class WorksheetRow(Base):
    __tablename__ = "worksheet_rows"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    worksheet_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.worksheets.id", ondelete="CASCADE"), index=True
    )
    row_index: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)

    worksheet: Mapped[Worksheet] = relationship(back_populates="rows")

    __table_args__ = (
        Index("idx_worksheet_rows_payload_gin", "payload", postgresql_using="gin"),
    )


# ---------------------------------------------------------------------------
# Operational layer — an organization running a compliance program.
# ---------------------------------------------------------------------------


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    systems: Mapped[list[System]] = relationship(back_populates="organization")
    users: Mapped[list[User]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(
        Enum("admin", "control_owner", "assessor", "viewer",
             name="user_role", schema="ccf"),
        default="viewer",
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    organization: Mapped[Organization] = relationship(back_populates="users")


class System(Base):
    """FISMA / FedRAMP system boundary (ATO package)."""

    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    fips199_confidentiality: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high",
             name="fips199_level", schema="ccf")
    )
    fips199_integrity: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high",
             name="fips199_level", schema="ccf",
             create_type=False)
    )
    fips199_availability: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high",
             name="fips199_level", schema="ccf",
             create_type=False)
    )
    baseline: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high",
             name="fedramp_baseline", schema="ccf")
    )
    ato_status: Mapped[str | None] = mapped_column(
        Enum("none", "in_progress", "authorized", "expired",
             name="ato_status", schema="ccf"),
        default="none",
    )
    ato_expires_on: Mapped[date | None] = mapped_column(Date)

    organization: Mapped[Organization] = relationship(back_populates="systems")
    implementations: Mapped[list[ControlImplementation]] = relationship(
        back_populates="system", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_system_org_name"),
    )


class ControlImplementation(Base):
    """Per-system implementation state for a reference control."""

    __tablename__ = "control_implementations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.controls.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(
        Enum("not_implemented", "planned", "partial",
             "implemented", "inherited", "not_applicable",
             name="impl_status", schema="ccf"),
        default="not_implemented",
    )
    responsibility: Mapped[str | None] = mapped_column(
        Enum("customer", "provider", "shared", "inherited",
             name="impl_responsibility", schema="ccf")
    )
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    narrative: Mapped[str | None] = mapped_column(Text)
    conmon_frequency: Mapped[str | None] = mapped_column(String(32))
    last_assessed_on: Mapped[date | None] = mapped_column(Date)
    next_assessment_due: Mapped[date | None] = mapped_column(Date)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    system: Mapped[System] = relationship(back_populates="implementations")
    control: Mapped[Control] = relationship(back_populates="implementations")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="implementation", cascade="all, delete-orphan"
    )
    assessment_results: Mapped[list[AssessmentResult]] = relationship(
        back_populates="implementation"
    )

    __table_args__ = (
        UniqueConstraint("system_id", "control_id", name="uq_impl_system_control"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    implementation_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.control_implementations.id", ondelete="CASCADE"),
        index=True,
    )
    kind: Mapped[str] = mapped_column(
        Enum("document", "screenshot", "config_export", "attestation",
             "scan_result", "ticket", "link", "other",
             name="evidence_kind", schema="ccf")
    )
    title: Mapped[str] = mapped_column(String(512))
    uri: Mapped[str | None] = mapped_column(String(1024))
    collected_on: Mapped[date | None] = mapped_column(Date)
    expires_on: Mapped[date | None] = mapped_column(Date)
    hash_sha256: Mapped[str | None] = mapped_column(String(64))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    implementation: Mapped[ControlImplementation] = relationship(back_populates="evidence")


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(
        Enum("self", "internal", "3pao", "ig", "audit",
             name="assessment_kind", schema="ccf")
    )
    started_on: Mapped[date | None] = mapped_column(Date)
    finished_on: Mapped[date | None] = mapped_column(Date)
    assessor: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[str | None] = mapped_column(Text)

    results: Mapped[list[AssessmentResult]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class AssessmentResult(Base):
    __tablename__ = "assessment_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessments.id", ondelete="CASCADE"), index=True
    )
    implementation_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.control_implementations.id", ondelete="CASCADE"),
        index=True,
    )
    finding: Mapped[str] = mapped_column(
        Enum("satisfied", "other_than_satisfied", "not_applicable",
             name="finding_status", schema="ccf")
    )
    rationale: Mapped[str | None] = mapped_column(Text)
    observed_on: Mapped[date | None] = mapped_column(Date)

    assessment: Mapped[Assessment] = relationship(back_populates="results")
    implementation: Mapped[ControlImplementation] = relationship(
        back_populates="assessment_results"
    )


class POAM(Base):
    """Plan of Action & Milestones — remediation tracking for findings."""

    __tablename__ = "poams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.controls.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(512))
    weakness: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(
        Enum("low", "moderate", "high", "critical",
             name="severity", schema="ccf"),
        default="moderate",
    )
    status: Mapped[str] = mapped_column(
        Enum("open", "in_progress", "completed", "risk_accepted", "closed",
             name="poam_status", schema="ccf"),
        default="open",
    )
    identified_on: Mapped[date | None] = mapped_column(Date)
    due_on: Mapped[date | None] = mapped_column(Date)
    closed_on: Mapped[date | None] = mapped_column(Date)
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )


class Risk(Base):
    __tablename__ = "risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE")
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    likelihood: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high",
             name="risk_level", schema="ccf")
    )
    impact: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high",
             name="risk_level", schema="ccf",
             create_type=False)
    )
    treatment: Mapped[str | None] = mapped_column(
        Enum("mitigate", "transfer", "accept", "avoid",
             name="risk_treatment", schema="ccf")
    )
    status: Mapped[str] = mapped_column(
        Enum("open", "mitigated", "accepted", "closed",
             name="risk_status", schema="ccf"),
        default="open",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    actor: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    diff: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
