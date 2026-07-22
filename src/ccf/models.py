"""SQLAlchemy 2.0 ORM models.

Reference layer  — Frameworks, ControlFamilies, Controls, FrameworkMappings,
                   Worksheets/WorksheetRows (ingested NIST workbook).
Provenance layer — WorkbookVersion, IngestionRun (FK'd),
                   ControlHistory, MappingHistory, RejectedRow (ccf_audit schema).
Operational layer — Organizations, Users, Systems, ControlImplementations,
                   Evidence, Assessments, AssessmentResults, POAMs, Risks, AuditLog.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, ClassVar

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
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .auth import hash_token


class Base(DeclarativeBase):
    metadata: ClassVar[MetaData] = MetaData(schema="ccf")
    type_annotation_map: ClassVar[dict[object, object]] = {
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
    }


# ---------------------------------------------------------------------------
# Reference layer
# ---------------------------------------------------------------------------


class WorkbookVersion(Base):
    __tablename__ = "workbook_versions"
    __table_args__ = {"schema": "ccf_audit"}  # noqa: RUF012

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    source_path: Mapped[str] = mapped_column(String(512))
    revision_label: Mapped[str | None] = mapped_column(String(64))
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    imported_by: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_file: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str | None] = mapped_column(String(64))
    workbook_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf_audit.workbook_versions.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="running")
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class RejectedRow(Base):
    __tablename__ = "rejected_rows"
    __table_args__ = {"schema": "ccf_audit"}  # noqa: RUF012

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ingestion_runs.id", ondelete="CASCADE"), index=True
    )
    sheet: Mapped[str] = mapped_column(String(255))
    row_index: Mapped[int] = mapped_column(Integer)
    rule: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    rejected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ControlHistory(Base):
    """SCD-2 snapshot of ccf.controls rows as seen by a specific workbook version."""

    __tablename__ = "control_history"
    __table_args__ = (
        Index("ix_control_history_ident", "identifier"),
        {"schema": "ccf_audit"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(128))
    workbook_version_id: Mapped[int] = mapped_column(
        ForeignKey("ccf_audit.workbook_versions.id", ondelete="CASCADE"),
        index=True,
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MappingHistory(Base):
    """SCD-2 snapshot of ccf.framework_mappings keyed by (identifier, column_key)."""

    __tablename__ = "mapping_history"
    __table_args__ = (
        Index("ix_mapping_history_ident", "identifier"),
        Index("ix_mapping_history_col", "column_key"),
        {"schema": "ccf_audit"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(128))
    workbook_version_id: Mapped[int] = mapped_column(
        ForeignKey("ccf_audit.workbook_versions.id", ondelete="CASCADE"),
        index=True,
    )
    column_key: Mapped[str] = mapped_column(String(255))
    value: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    mappings: Mapped[list[FrameworkMapping]] = relationship(
        back_populates="control", cascade="all, delete-orphan"
    )
    implementations: Mapped[list[ControlImplementation]] = relationship(back_populates="control")

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
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

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

    __table_args__ = (Index("idx_worksheet_rows_payload_gin", "payload", postgresql_using="gin"),)


# ---------------------------------------------------------------------------
# Operational layer
# ---------------------------------------------------------------------------


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # DATA-04: soft-delete marker. Set instead of issuing a hard DELETE so the
    # CASCADE to systems/users never fires; NULL means active. Callers must
    # filter ``deleted_at IS NULL`` in list/get queries — see systems.py.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

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
        Enum("admin", "control_owner", "assessor", "viewer", name="user_role", schema="ccf"),
        default="viewer",
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    # IA-09: only the one-way hash is persisted — see the ``api_token`` property
    # below for the plaintext write/read-once path.
    api_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    organization: Mapped[Organization] = relationship(back_populates="users")

    @property
    def api_token(self) -> str | None:
        """Plaintext bearer token — available only in-memory, only on the
        instance that just set it (issuance/rotation). Never persisted: the
        DB holds ``api_token_hash`` only, so a freshly loaded ``User`` always
        reports ``None`` here. Authenticate via ``api_token_hash`` instead.
        """
        return getattr(self, "_api_token_plain", None)

    @api_token.setter
    def api_token(self, value: str | None) -> None:
        self._api_token_plain = value
        self.api_token_hash = hash_token(value) if value else None


class System(Base):
    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    fips199_confidentiality: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high", name="fips199_level", schema="ccf")
    )
    fips199_integrity: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high", name="fips199_level", schema="ccf", create_type=False)
    )
    fips199_availability: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high", name="fips199_level", schema="ccf", create_type=False)
    )
    baseline: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high", name="fedramp_baseline", schema="ccf")
    )
    ato_status: Mapped[str | None] = mapped_column(
        Enum("none", "in_progress", "authorized", "expired", name="ato_status", schema="ccf"),
        default="none",
    )
    ato_expires_on: Mapped[date | None] = mapped_column(Date)
    # DATA-04: soft-delete marker (see Organization.deleted_at). Set instead of
    # a hard DELETE so the CASCADE to poams/assessments/evidence/implementations/
    # risks never fires; NULL means active.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="systems")
    implementations: Mapped[list[ControlImplementation]] = relationship(
        back_populates="system", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_system_org_name"),)


class SystemProfile(Base):
    """The environment definition that drives control applicability + inheritance.

    Captured via the intake questionnaire; ``derivation`` holds the computed
    per-control result (responsibility, state, source) so coverage, SPRS, SSP,
    and POA&M all read from one snapshot.
    """

    __tablename__ = "system_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), unique=True, index=True
    )
    environment_type: Mapped[str | None] = mapped_column(String(32))  # cloud|hybrid|on_prem|enclave
    cloud_platform: Mapped[str | None] = mapped_column(String(32))  # m365_gcc_high|azure_gov|...
    tenant_ref: Mapped[str | None] = mapped_column(String(255))
    identity_model: Mapped[str | None] = mapped_column(String(32))
    connectivity: Mapped[str | None] = mapped_column(String(32))
    cui_present: Mapped[bool] = mapped_column(Boolean, default=True)
    workloads: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    endpoint_scope: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    data_types: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    inherited_sources: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # vendor ids/keys
    frameworks: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # targeted framework codes
    answers: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict
    )  # raw questionnaire answers
    derivation: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)  # control_id -> result
    derived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FrameworkControl(Base):
    """An uploadable control from any framework — lets new frameworks be added
    without a code change or the NIST workbook. Keyed by (organization_id,
    framework_code, identifier).

    ``organization_id`` is NULL for globally-seeded/shared reference rows
    (visible to every tenant) and set to the uploading tenant's org for
    controls uploaded via ``POST /api/framework-controls/{code}`` (DATA-03) —
    RLS-enforced via the ``tenant_isolation`` policy added in migration 0046,
    following the ``audit_log``/0044 NULL-visible-to-all predicate shape.
    """

    __tablename__ = "framework_controls"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    framework_code: Mapped[str] = mapped_column(String(64), index=True)
    identifier: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(String(64))
    baseline: Mapped[str | None] = mapped_column(String(32))  # low|moderate|high|l1|l2|...
    default_responsibility: Mapped[str | None] = mapped_column(String(16))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    source: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "framework_code", "identifier", name="uq_framework_control"
        ),
        # Postgres unique constraints default to NULLS DISTINCT, so the
        # constraint above does not stop two global (organization_id IS
        # NULL) rows from colliding on (framework_code, identifier). This
        # partial index restores that global uniqueness (migration 0047)
        # without constraining per-org uploaded rows.
        Index(
            "uq_framework_controls_global",
            "framework_code",
            "identifier",
            unique=True,
            postgresql_where=text("organization_id IS NULL"),
        ),
    )


class ControlImplementation(Base):
    __tablename__ = "control_implementations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.controls.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "not_implemented",
            "planned",
            "partial",
            "implemented",
            "inherited",
            "not_applicable",
            name="impl_status",
            schema="ccf",
        ),
        default="not_implemented",
    )
    responsibility: Mapped[str | None] = mapped_column(
        Enum(
            "customer", "provider", "shared", "inherited", name="impl_responsibility", schema="ccf"
        )
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

    __table_args__ = (UniqueConstraint("system_id", "control_id", name="uq_impl_system_control"),)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    implementation_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.control_implementations.id", ondelete="CASCADE"),
        index=True,
    )
    kind: Mapped[str] = mapped_column(
        Enum(
            "document",
            "screenshot",
            "config_export",
            "attestation",
            "scan_result",
            "ticket",
            "link",
            "other",
            name="evidence_kind",
            schema="ccf",
        )
    )
    title: Mapped[str] = mapped_column(String(512))
    uri: Mapped[str | None] = mapped_column(String(1024))
    collected_on: Mapped[date | None] = mapped_column(Date)
    expires_on: Mapped[date | None] = mapped_column(Date)
    hash_sha256: Mapped[str | None] = mapped_column(String(64))
    # Optional link to a stored artifact (evidence collected via the intake API).
    artifact_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.artifacts.id", ondelete="SET NULL")
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    implementation: Mapped[ControlImplementation] = relationship(back_populates="evidence")


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(
        Enum("self", "internal", "3pao", "ig", "audit", name="assessment_kind", schema="ccf")
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
        Enum(
            "satisfied",
            "other_than_satisfied",
            "not_applicable",
            name="finding_status",
            schema="ccf",
        )
    )
    rationale: Mapped[str | None] = mapped_column(Text)
    observed_on: Mapped[date | None] = mapped_column(Date)

    assessment: Mapped[Assessment] = relationship(back_populates="results")
    implementation: Mapped[ControlImplementation] = relationship(
        back_populates="assessment_results"
    )


class AssessmentControlResult(Base):
    """An assessor's finding for one CMMC L2 practice within an assessment.

    Keyed to ``scoring_controls`` (the 110 practices) by ``control_id`` so the
    assessor works the live matrix' objectives + examine/interview/test methods.
    """

    __tablename__ = "assessment_control_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessments.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    nist_id: Mapped[str | None] = mapped_column(String(16))
    domain: Mapped[str | None] = mapped_column(String(8))
    title: Mapped[str | None] = mapped_column(String(512))
    requirement: Mapped[str | None] = mapped_column(Text)

    # satisfied | other_than_satisfied | not_applicable | not_assessed
    finding: Mapped[str] = mapped_column(String(32), default="not_assessed")
    objective_findings: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    examine_note: Mapped[str | None] = mapped_column(Text)
    interview_note: Mapped[str | None] = mapped_column(Text)
    test_note: Mapped[str | None] = mapped_column(Text)
    assessor_note: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))

    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewer: Mapped[str | None] = mapped_column(String(255))
    observed_on: Mapped[date | None] = mapped_column(Date)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("assessment_id", "control_id", name="uq_assess_ctrl"),
        Index("ix_assess_ctrl_assessment_sort", "assessment_id", "sort_order"),
    )


class POAM(Base):
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
        Enum("low", "moderate", "high", "critical", name="severity", schema="ccf"),
        default="moderate",
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "open",
            "in_progress",
            "completed",
            "risk_accepted",
            "closed",
            name="poam_status",
            schema="ccf",
        ),
        default="open",
    )
    identified_on: Mapped[date | None] = mapped_column(Date)
    due_on: Mapped[date | None] = mapped_column(Date)
    closed_on: Mapped[date | None] = mapped_column(Date)
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    # FedRAMP / eMASS POA&M fields.
    source: Mapped[str | None] = mapped_column(String(32))  # assessment|scan|conmon|self_identified
    point_of_contact: Mapped[str | None] = mapped_column(String(255))
    remediation_plan: Mapped[str | None] = mapped_column(Text)
    resources_required: Mapped[str | None] = mapped_column(Text)
    cost_estimate: Mapped[str | None] = mapped_column(String(64))
    scheduled_completion: Mapped[date | None] = mapped_column(Date)
    original_due_on: Mapped[date | None] = mapped_column(Date)  # for deviation tracking
    risk_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.risks.id", ondelete="SET NULL"))
    vendor_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.vendors.id", ondelete="SET NULL"))
    # Scanner-ingested findings (source='scan'): the tool that reported it and a
    # stable per-system fingerprint so re-ingesting the same scan reconciles
    # (updates/reopens/auto-closes) instead of creating duplicate POA&Ms.
    scanner: Mapped[str | None] = mapped_column(String(32))  # nessus|tenable|qualys|inspector|csv
    finding_uid: Mapped[str | None] = mapped_column(String(64), index=True)
    # Stable back-reference to the originating record for any source (e.g.
    # "assessment:{assessment_control_result_id}"), so re-running generation
    # from that origin is idempotent on this reference rather than a title match.
    source_ref: Mapped[str | None] = mapped_column(String(128), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    milestones: Mapped[list[PoamMilestone]] = relationship(
        back_populates="poam", cascade="all, delete-orphan", order_by="PoamMilestone.sort_order"
    )


class PoamMilestone(Base):
    """A scheduled remediation milestone within a POA&M (FedRAMP-style)."""

    __tablename__ = "poam_milestones"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    poam_id: Mapped[int] = mapped_column(ForeignKey("ccf.poams.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(Text)
    due_on: Mapped[date | None] = mapped_column(Date)
    completed_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(
        String(16), default="pending"
    )  # pending|in_progress|completed|delayed
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    poam: Mapped[POAM] = relationship(back_populates="milestones")


class Risk(Base):
    __tablename__ = "risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(64))  # taxonomy: operational|technical|...
    source: Mapped[str | None] = mapped_column(String(32))
    # ISSM-05: stable back-reference to the originating record (e.g.
    # "audit_finding:{id}"), mirroring POAM.source_ref (0038) — so a Risk
    # created from an accepted finding is traceable back to what generated it,
    # and re-running that origin's promotion is idempotent on this reference
    # rather than a title match.
    source_ref: Mapped[str | None] = mapped_column(String(128), index=True)
    likelihood: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high", name="risk_level", schema="ccf")
    )
    impact: Mapped[str | None] = mapped_column(
        Enum("low", "moderate", "high", name="risk_level", schema="ccf", create_type=False)
    )
    treatment: Mapped[str | None] = mapped_column(
        Enum("mitigate", "transfer", "accept", "avoid", name="risk_treatment", schema="ccf")
    )
    status: Mapped[str] = mapped_column(
        Enum("open", "mitigated", "accepted", "closed", name="risk_status", schema="ccf"),
        default="open",
    )
    # Quantitative scoring (likelihood x impact on a 1-5 scale, 1-25 exposure).
    inherent_score: Mapped[int | None] = mapped_column(Integer)
    residual_score: Mapped[int | None] = mapped_column(Integer)
    # Ownership, review cadence, and cross-links to the rest of the program.
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    next_review_on: Mapped[date | None] = mapped_column(Date)
    control_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.controls.id", ondelete="SET NULL")
    )
    vendor_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.vendors.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ---------------------------------------------------------------------------
# CMMC Level 2 live scoring layer (replaces the static scoring-matrix workbook)
# ---------------------------------------------------------------------------


class ScoringControl(Base):
    """Reference row for one CMMC L2 practice from the scoring matrix.

    Loaded from ``ccf.scoring.seed`` — one row per the 110 Level 2 practices,
    carrying the SPRS point value, NIST 800-171A objective parts, assessment
    cases, and the Microsoft 365 placemat evidence/inheritance guidance.
    """

    __tablename__ = "scoring_controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    control_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    nist_id: Mapped[str | None] = mapped_column(String(16), index=True)
    domain: Mapped[str] = mapped_column(String(8), index=True)
    title: Mapped[str | None] = mapped_column(String(512))

    point_value: Mapped[str] = mapped_column(String(8))  # "5" | "3" | "1" | "3/5" | "Special"
    scoring_bucket: Mapped[str | None] = mapped_column(String(64))
    scoring_notes: Mapped[str | None] = mapped_column(Text)

    requirement: Mapped[str | None] = mapped_column(Text)
    objectives: Mapped[str | None] = mapped_column(Text)
    objective_parts: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    examine_cases: Mapped[str | None] = mapped_column(Text)
    interview_cases: Mapped[str | None] = mapped_column(Text)
    test_cases: Mapped[str | None] = mapped_column(Text)
    considerations: Mapped[str | None] = mapped_column(Text)
    key_references: Mapped[str | None] = mapped_column(Text)
    guide_page: Mapped[str | None] = mapped_column(String(16))
    pdf_page: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str | None] = mapped_column(Text)

    m365_coverage_status: Mapped[str | None] = mapped_column(String(64), index=True)
    m365_primary_services: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    m365_secondary_services: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    m365_implementation_statement: Mapped[str | None] = mapped_column(Text)
    m365_inheritance: Mapped[str | None] = mapped_column(Text)
    recommended_customer_evidence: Mapped[str | None] = mapped_column(Text)
    recommended_provider_evidence: Mapped[str | None] = mapped_column(Text)
    evidence_notes: Mapped[str | None] = mapped_column(Text)
    m365_source: Mapped[str | None] = mapped_column(Text)

    # Organization-defined parameters (fill-in-the-blank slots) for this practice.
    odp_definitions: Mapped[list[Any]] = mapped_column(JSONB, default=list)

    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    statuses: Mapped[list[ScoringStatus]] = relationship(
        back_populates="scoring_control", cascade="all, delete-orphan"
    )


class ScoringStatus(Base):
    """Per-system live implementation state for a scoring control (drives SPRS)."""

    __tablename__ = "scoring_statuses"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    scoring_control_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.scoring_controls.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[str] = mapped_column(String(32), default="not_assessed")
    notes: Mapped[str | None] = mapped_column(Text)
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    scoring_control: Mapped[ScoringControl] = relationship(back_populates="statuses")

    __table_args__ = (
        UniqueConstraint("system_id", "scoring_control_id", name="uq_scoring_system_control"),
    )


# ---------------------------------------------------------------------------
# System Security Plan (SSP) authoring layer — FedRAMP Appendix A style
# ---------------------------------------------------------------------------


class SSPProject(Base):
    """A per-customer SSP document project that can be edited and re-generated."""

    __tablename__ = "ssp_projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="SET NULL"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="SET NULL"), index=True
    )
    customer_name: Mapped[str] = mapped_column(String(255))
    system_name: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(32), default="m365")
    title: Mapped[str] = mapped_column(String(512), default="System Security Plan (SSP)")
    version: Mapped[str] = mapped_column(String(32), default="0.1")
    prepared_by: Mapped[str | None] = mapped_column(String(255))
    document_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(32), default="draft")
    # Enterprise SSP front matter: system characterization, FIPS-199, roles,
    # authorization boundary, interconnections, ports, laws, leveraged auths.
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    revision_history: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    entries: Mapped[list[SSPControlEntry]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class SSPControlEntry(Base):
    """One control's authored content within an SSP project."""

    __tablename__ = "ssp_control_entries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.ssp_projects.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(32), index=True)
    nist_id: Mapped[str | None] = mapped_column(String(16))
    domain: Mapped[str | None] = mapped_column(String(8))
    title: Mapped[str | None] = mapped_column(String(512))
    requirement: Mapped[str | None] = mapped_column(Text)
    responsible_role: Mapped[str | None] = mapped_column(String(255))
    implementation_status: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    control_origination: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    part_narratives: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    # Customer fill-ins for this control's organization-defined parameters:
    # {odp_key: value}. Consumed when rendering canned statement templates.
    odp_values: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    project: Mapped[SSPProject] = relationship(back_populates="entries")

    __table_args__ = (
        UniqueConstraint("project_id", "control_id", name="uq_ssp_project_control"),
        Index("ix_ssp_entry_project_sort", "project_id", "sort_order"),
    )


class StatementTemplate(Base):
    """A reusable, canned implementation-statement template for the SSP builder.

    ``body`` may embed ``{{odp_key}}`` (organization-defined parameter) and
    ``{{environment}}`` / ``{{services}}`` context tokens, resolved at apply time.
    ``scope`` (``global`` | ``domain`` | ``control``) with ``domain`` / ``control_id``
    controls which controls the template offers itself to.
    """

    __tablename__ = "statement_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(String(16), default="global")
    domain: Mapped[str | None] = mapped_column(String(8), index=True)
    control_id: Mapped[str | None] = mapped_column(String(32), index=True)
    platform: Mapped[str | None] = mapped_column(String(32))
    body: Mapped[str] = mapped_column(Text)
    tags: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    source: Mapped[str | None] = mapped_column(String(255))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Catalog currency layer — track authoritative upstream sources (NIST OSCAL,
# the cross-mapping workbook) and detect when they drift from what we ingested.
# ---------------------------------------------------------------------------


class CatalogSource(Base):
    """A registered upstream authority we poll for control updates.

    ``kind`` selects how a change is detected/handled:
      - ``oscal_catalog`` — fetch NIST OSCAL JSON, index controls, diff prose.
      - ``xlsx``          — fetch a workbook; on change optionally re-ingest.
      - ``generic``       — content-hash only (any URL); drift = sha changed.
    """

    __tablename__ = "catalog_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    authority: Mapped[str | None] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32), default="oscal_catalog")
    url: Mapped[str] = mapped_column(String(1024))
    framework_code: Mapped[str | None] = mapped_column(String(64))

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_ingest: Mapped[bool] = mapped_column(Boolean, default=False)

    etag: Mapped[str | None] = mapped_column(String(255))
    last_sha256: Mapped[str | None] = mapped_column(String(64))
    last_status: Mapped[str | None] = mapped_column(String(32))
    last_error: Mapped[str | None] = mapped_column(Text)
    revision_label: Mapped[str | None] = mapped_column(String(64))
    item_count: Mapped[int | None] = mapped_column(Integer)
    # Per-control content hashes from the last successful fetch, for diffing.
    content_index: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    checks: Mapped[list[CatalogCheck]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class CatalogCheck(Base):
    """One poll of a :class:`CatalogSource` — the audit trail of drift checks."""

    __tablename__ = "catalog_checks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.catalog_sources.id", ondelete="CASCADE"), index=True
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    # unchanged | changed | ingested | error
    status: Mapped[str] = mapped_column(String(32))
    http_status: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    source: Mapped[CatalogSource] = relationship(back_populates="checks")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    # SCOPING column only (DATA-06) — deliberately excluded from the row_hash/
    # prev_hash chain payload (see ``ccf.api.audit.row_hash``) so it can be
    # backfilled/corrected without invalidating the tamper-evident chain.
    # NULL for system/global events (no resolvable tenant); RLS-enforced via the
    # ``tenant_isolation`` policy added in migration 0044.
    organization_id: Mapped[int | None] = mapped_column(Integer, index=True)
    actor: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    diff: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    row_hash: Mapped[str | None] = mapped_column(String(64))


# ---------------------------------------------------------------------------
# Enterprise governance layer — the connective tissue that turns the compliance
# data model into a living program: tasks, notifications, an event bus/webhooks,
# policies, vendors (TPRM), an artifact store, and continuous-monitoring runs.
# Generic entity links (entity_type + entity_id) let any record point at any
# other, so modules interoperate without a web of hard foreign keys.
# ---------------------------------------------------------------------------


class Task(Base):
    """A governance work item — remediation, review, evidence refresh, etc."""

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(32), default="general")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    assignee_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    # Generic link to any entity (control_implementation | poam | risk | policy |
    # vendor | evidence | catalog_source | system | assessment).
    entity_type: Mapped[str | None] = mapped_column(String(32))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual | auto
    # Stable key for auto-generated tasks so a rescan updates rather than dupes.
    dedupe_key: Mapped[str | None] = mapped_column(String(160), unique=True)
    due_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_tasks_entity", "entity_type", "entity_id"),)


class Notification(Base):
    """An alert surfaced to a user or broadcast to an org (user_id NULL)."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="CASCADE"), index=True
    )
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|warning|critical
    category: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512))
    body: Mapped[str | None] = mapped_column(Text)
    entity_type: Mapped[str | None] = mapped_column(String(32))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    dedupe_key: Mapped[str | None] = mapped_column(String(200), unique=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class Event(Base):
    """Append-only activity/event stream — the internal integration bus."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    actor: Mapped[str | None] = mapped_column(String(255))
    verb: Mapped[str] = mapped_column(String(48))  # created|updated|closed|captured|drifted|alerted
    entity_type: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(String(512))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    __table_args__ = (Index("ix_events_entity", "entity_type", "entity_id"),)


class Webhook(Base):
    """Outbound HTTP subscription so external systems receive events."""

    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(String(1024))
    secret: Mapped[str | None] = mapped_column(String(128))
    events: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # subscribed verbs/categories
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Artifact(Base):
    """Content-addressed artifact store for collected evidence files."""

    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(512))
    media_type: Mapped[str | None] = mapped_column(String(255))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    storage: Mapped[str] = mapped_column(String(16), default="inline")  # inline | external
    content: Mapped[bytes | None] = mapped_column(LargeBinary)
    uri: Mapped[str | None] = mapped_column(String(1024))
    uploaded_by: Mapped[str | None] = mapped_column(String(255))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("organization_id", "sha256", name="uq_artifact_org_sha"),)


class Policy(Base):
    """A governance policy document with a review cadence and versions."""

    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String(64))
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(16), default="draft")  # draft|active|retired
    review_frequency: Mapped[str | None] = mapped_column(String(32))
    next_review_on: Mapped[date | None] = mapped_column(Date)
    # Control identifiers this policy supports/implements.
    linked_controls: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    versions: Mapped[list[PolicyVersion]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_policy_org_name"),)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.policies.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[str] = mapped_column(String(32))
    body: Mapped[str | None] = mapped_column(Text)
    uri: Mapped[str | None] = mapped_column(String(1024))
    effective_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    policy: Mapped[Policy] = relationship(back_populates="versions")
    attestations: Mapped[list[PolicyAttestation]] = relationship(
        back_populates="policy_version", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class PolicyAttestation(Base):
    """A user's acknowledgement of a specific policy version."""

    __tablename__ = "policy_attestations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    policy_version_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.policy_versions.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.users.id", ondelete="SET NULL"))
    attestor: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)
    attested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    policy_version: Mapped[PolicyVersion] = relationship(back_populates="attestations")


class Vendor(Base):
    """A third party / supplier tracked for supply-chain risk (TPRM)."""

    __tablename__ = "vendors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    service_type: Mapped[str | None] = mapped_column(String(128))
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(
        String(16), default="active"
    )  # prospective|active|offboarded
    risk_rating: Mapped[str | None] = mapped_column(String(16))  # low|moderate|high
    contact_email: Mapped[str | None] = mapped_column(String(255))
    # e.g. "FedRAMP High Authorized" — supports control inheritance.
    authorization: Mapped[str | None] = mapped_column(String(128))
    review_frequency: Mapped[str | None] = mapped_column(String(32))
    last_reviewed_on: Mapped[date | None] = mapped_column(Date)
    next_review_on: Mapped[date | None] = mapped_column(Date)
    linked_controls: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_vendor_org_name"),)


class Approval(Base):
    """Review/approval workflow record for a governed entity (one per entity).

    Drives a draft → submitted → approved/rejected lifecycle with separation of
    duties: the approver must differ from the submitter (enforced when auth is on).
    """

    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    entity_type: Mapped[str] = mapped_column(String(32))  # ssp_project|poam|risk|assessment
    entity_id: Mapped[str] = mapped_column(String(64))
    # draft | submitted | approved | rejected
    state: Mapped[str] = mapped_column(String(16), default="draft")
    submitted_by: Mapped[str | None] = mapped_column(String(255))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", name="uq_approval_entity"),
        Index("ix_approvals_entity", "entity_type", "entity_id"),
    )


class CaptureSnapshot(Base):
    """Last value a connector captured for a parameter — the config-drift baseline."""

    __tablename__ = "capture_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    connector: Mapped[str] = mapped_column(String(32))
    odp_key: Mapped[str] = mapped_column(String(64))
    value: Mapped[str] = mapped_column(Text)
    nist_id: Mapped[str | None] = mapped_column(String(16))
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "connector", "odp_key", name="uq_capture_snapshot"),
    )


class MonitoringRun(Base):
    """Log of a continuous-monitoring scan and what it produced."""

    __tablename__ = "monitoring_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    controls_checked: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    tasks_created: Mapped[int] = mapped_column(Integer, default=0)
    notifications_created: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class ScanIngestion(Base):
    """Provenance for one vulnerability-scan import and the POA&Ms it reconciled."""

    __tablename__ = "scan_ingestions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    scanner: Mapped[str] = mapped_column(String(32))  # nessus|tenable|qualys|inspector|csv
    filename: Mapped[str | None] = mapped_column(String(512))
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    poams_created: Mapped[int] = mapped_column(Integer, default=0)
    poams_updated: Mapped[int] = mapped_column(Integer, default=0)
    poams_reopened: Mapped[int] = mapped_column(Integer, default=0)
    poams_closed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


# ---------------------------------------------------------------------------
# FedRAMP 20x layer
# ---------------------------------------------------------------------------
# FedRAMP 20x is a cloud-assurance model built on Key Security Indicators (KSIs),
# automated validation, machine-readable evidence, and continuous monitoring. It
# is kept logically SEPARATE from the traditional FedRAMP Rev. 5 baseline/scoring
# (systems.baseline, scoring_controls) but stays TRACEABLE to NIST 800-53 via the
# ``KSI.nist_refs`` catalog mapping. Statuses use plain strings (like SystemProfile)
# because the 20x program is still evolving; the vocabularies are documented in the
# ``ccf.fedramp20x`` services and enforced at the API layer.


class KSI(Base):
    """A FedRAMP 20x Key Security Indicator (reference catalog, org-agnostic).

    Seeded from ``data/fedramp_20x_ksi_catalog.json`` via ``ccf.fedramp20x.catalog``.
    ``rule`` is the machine-readable validation spec the validation engine evaluates.
    """

    __tablename__ = "ksis"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    category: Mapped[str] = mapped_column(String(8), index=True)  # KSI family key (IAM, CNA, ...)
    category_name: Mapped[str | None] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    expected_outcome: Mapped[str | None] = mapped_column(Text)
    validation_method: Mapped[str | None] = mapped_column(String(32))  # automated|manual
    validation_frequency: Mapped[str | None] = mapped_column(String(32))
    automation_level: Mapped[str | None] = mapped_column(String(32))  # automated|partial|manual
    evidence_required: Mapped[bool] = mapped_column(Boolean, default=True)
    nist_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list)  # 800-53 control ids
    cmmc_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    provider_services: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    rule: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FedRAMP20xProfile(Base):
    """Cloud Service Offering (CSO) profile for FedRAMP 20x — one per system."""

    __tablename__ = "fedramp20x_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), unique=True, index=True
    )
    service_name: Mapped[str | None] = mapped_column(String(255))
    service_description: Mapped[str | None] = mapped_column(Text)
    deployment_model: Mapped[str | None] = mapped_column(String(32))  # iaas|paas|saas
    cloud_environment: Mapped[str | None] = mapped_column(String(48))
    boundary_description: Mapped[str | None] = mapped_column(Text)
    data_types: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    federal_data: Mapped[bool] = mapped_column(Boolean, default=True)
    cui_support: Mapped[bool] = mapped_column(Boolean, default=False)
    external_services: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    customer_responsibilities: Mapped[str | None] = mapped_column(Text)
    provider_responsibilities: Mapped[str | None] = mapped_column(Text)
    shared_responsibilities: Mapped[str | None] = mapped_column(Text)
    cryptographic_boundary: Mapped[str | None] = mapped_column(Text)
    logging_boundary: Mapped[str | None] = mapped_column(Text)
    incident_response_boundary: Mapped[str | None] = mapped_column(Text)
    backup_recovery_boundary: Mapped[str | None] = mapped_column(Text)
    administrative_access_boundary: Mapped[str | None] = mapped_column(Text)
    readiness_status: Mapped[str] = mapped_column(String(32), default="not_started")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class KSIState(Base):
    """Per-system tracking of a single KSI: current state, ownership, review."""

    __tablename__ = "ksi_states"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    ksi_id: Mapped[int] = mapped_column(ForeignKey("ccf.ksis.id", ondelete="CASCADE"), index=True)
    # pass|warn|fail|not_tested|manual_review_required|not_applicable
    status: Mapped[str] = mapped_column(String(32), default="not_tested")
    assessor_status: Mapped[str] = mapped_column(String(32), default="not_reviewed")
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    reviewer_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="SET NULL")
    )
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_validation_due: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (UniqueConstraint("system_id", "ksi_id", name="uq_ksi_state_system_ksi"),)


class KSIValidationResult(Base):
    """Append-only history of KSI validation runs — the 20x continuous-monitoring trail."""

    __tablename__ = "ksi_validation_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    ksi_id: Mapped[int] = mapped_column(ForeignKey("ccf.ksis.id", ondelete="CASCADE"), index=True)
    ksi_identifier: Mapped[str] = mapped_column(String(32), index=True)
    # pass|warn|fail|not_tested|manual_review_required
    status: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str | None] = mapped_column(String(16))  # high|medium|low
    source: Mapped[str | None] = mapped_column(String(64))  # rule kind / connector name
    evidence_refs: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    remediation_hint: Mapped[str | None] = mapped_column(Text)
    assessor_review_required: Mapped[bool] = mapped_column(Boolean, default=False)
    validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class KSIAssessorReview(Base):
    """Assessor (3PAO) review of a KSI for a system."""

    __tablename__ = "ksi_assessor_reviews"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    ksi_id: Mapped[int] = mapped_column(ForeignKey("ccf.ksis.id", ondelete="CASCADE"), index=True)
    assessor: Mapped[str | None] = mapped_column(String(255))
    # See fedramp20x.ASSESSOR_STATUSES: not_reviewed|in_review|accepted|rejected|
    # needs_clarification|retest_required|finding_opened|closed
    status: Mapped[str] = mapped_column(String(32), default="not_reviewed")
    notes: Mapped[str | None] = mapped_column(Text)
    evidence_accepted: Mapped[bool | None] = mapped_column(Boolean)
    retest_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    finding: Mapped[str | None] = mapped_column(Text)
    management_response: Mapped[str | None] = mapped_column(Text)
    closure_evidence: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class KSIException(Base):
    """A documented exception / deviation for a KSI (like a risk acceptance)."""

    __tablename__ = "ksi_exceptions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    ksi_id: Mapped[int] = mapped_column(ForeignKey("ccf.ksis.id", ondelete="CASCADE"), index=True)
    rationale: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open|accepted|closed
    risk_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.risks.id", ondelete="SET NULL"))
    expires_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FedRAMPDependency(Base):
    """A FedRAMP-authorized (or not) underlying service the CSO depends on."""

    __tablename__ = "fedramp_dependencies"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str | None] = mapped_column(String(255))
    service_type: Mapped[str | None] = mapped_column(String(16))  # iaas|paas|saas
    # authorized|in_process|not_authorized|unknown
    fedramp_status: Mapped[str] = mapped_column(String(32), default="unknown")
    marketplace_url: Mapped[str | None] = mapped_column(String(1024))
    authorization_level: Mapped[str | None] = mapped_column(String(32))  # jab|agency|li-saas
    impact_level: Mapped[str | None] = mapped_column(String(16))  # low|moderate|high
    boundary_role: Mapped[str | None] = mapped_column(String(255))
    inherited_controls: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    shared_responsibilities: Mapped[str | None] = mapped_column(Text)
    dependency_risk: Mapped[str | None] = mapped_column(String(16))  # low|moderate|high|critical
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("system_id", "name", name="uq_fedramp_dep_system_name"),
    )


class FedRAMP20xReadinessSnapshot(Base):
    """Point-in-time 20x readiness rollup — separate from traditional FedRAMP scoring."""

    __tablename__ = "fedramp20x_readiness_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    readiness_pct: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="not_started")
    ksi_pass_rate: Mapped[int | None] = mapped_column(Integer)
    automation_coverage: Mapped[int | None] = mapped_column(Integer)
    evidence_completeness: Mapped[int | None] = mapped_column(Integer)
    conmon_coverage: Mapped[int | None] = mapped_column(Integer)
    assessor_completion: Mapped[int | None] = mapped_column(Integer)
    dependency_readiness: Mapped[int | None] = mapped_column(Integer)
    open_exceptions: Mapped[int] = mapped_column(Integer, default=0)
    high_risk_findings: Mapped[int] = mapped_column(Integer, default=0)
    expired_validations: Mapped[int] = mapped_column(Integer, default=0)
    manual_review_burden: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
