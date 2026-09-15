"""Compliance pack runtime models.

A :class:`CompliancePack` is an installed framework/control/evidence/rule pack for
a tenant. Its controls / mappings / evidence requirements / rules are materialized
into queryable child tables (used by coverage), while the full manifest (including
policy/questionnaire templates, connector mappings, and dashboard cards) is kept
as JSONB. Install runs and per-version history give provenance; pack tests record
conformance. All tables are tenant-isolated.
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
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class CompliancePack(Base):
    """An installed compliance pack (per tenant + pack key)."""

    __tablename__ = "compliance_packs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    pack_key: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(24))
    schema_version: Mapped[str] = mapped_column(String(8), default="1")
    source: Mapped[str | None] = mapped_column(String(255))
    manifest_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="installed")
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    controls: Mapped[list[PackControl]] = relationship(
        back_populates="pack", cascade="all, delete-orphan"
    )
    mappings: Mapped[list[PackMapping]] = relationship(
        back_populates="pack", cascade="all, delete-orphan"
    )
    evidence_requirements: Mapped[list[PackEvidenceRequirement]] = relationship(
        back_populates="pack", cascade="all, delete-orphan"
    )
    rules: Mapped[list[PackRule]] = relationship(
        back_populates="pack", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "pack_key", name="uq_compliance_pack"),
    )


class CompliancePackVersion(Base):
    """A record of one installed version of a pack (history).

    The manifest is retained per version, not just its sha: a sha proves two
    versions differ without saying how, and a declared posture rule IS desired
    state -- so "what changed in my expectations between v1 and v2" has to be
    answerable. Rows written before migration 0069 keep ``{}``; no backfill is
    possible because those manifests were never stored.
    """

    __tablename__ = "compliance_pack_versions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pack_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[str] = mapped_column(String(24))
    manifest_sha: Mapped[str | None] = mapped_column(String(64))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PackInstallRun(Base):
    """Provenance for one install/upgrade/validate operation."""

    __tablename__ = "pack_install_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    pack_key: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(16))  # install|upgrade|validate
    status: Mapped[str] = mapped_column(String(16), default="ok")  # ok|error
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PackControl(Base):
    """A control contributed by a pack (used for coverage)."""

    __tablename__ = "pack_controls"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pack_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    family: Mapped[str | None] = mapped_column(String(64))

    pack: Mapped[CompliancePack] = relationship(back_populates="controls")


class PackMapping(Base):
    """A cross-framework mapping contributed by a pack."""

    __tablename__ = "pack_mappings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pack_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(64))
    framework: Mapped[str] = mapped_column(String(64))
    reference: Mapped[str | None] = mapped_column(String(255))

    pack: Mapped[CompliancePack] = relationship(back_populates="mappings")

    __table_args__ = (
        UniqueConstraint(
            "pack_id", "control_id", "framework", name="uq_pack_mapping_pack_control_framework"
        ),
    )


class PackEvidenceRequirement(Base):
    """An evidence requirement contributed by a pack."""

    __tablename__ = "pack_evidence_requirements"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pack_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)

    pack: Mapped[CompliancePack] = relationship(back_populates="evidence_requirements")


class PackRule(Base):
    """A validation rule contributed by a pack."""

    __tablename__ = "pack_rules"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pack_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), index=True
    )
    rule_key: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str | None] = mapped_column(String(48))
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    pack: Mapped[CompliancePack] = relationship(back_populates="rules")


class PackTestResult(Base):
    """The result of running one of a pack's conformance tests."""

    __tablename__ = "pack_test_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    pack_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.compliance_packs.id", ondelete="CASCADE"), index=True
    )
    test_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(8))  # pass|fail
    detail: Mapped[str | None] = mapped_column(Text)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PackSource(Base):
    """A git-backed location a tenant's desired state is declared in.

    GitOps for desired state (CC&E #10). The repository holds the pack
    manifest, changes arrive as reviewed commits, and the commit sha is the
    version identity.

    Deliberately **not** ``CatalogSource``, even though the polling mechanics
    are shared. That table is global reference data -- NIST's catalog is the
    same for every tenant -- while a desired-state repository belongs to one
    organization. The *functions* in ``etl/sources.py`` are reused; the table
    is not.

    ``auto_install`` defaults to False for the reason ``CatalogSource``'s
    ``auto_ingest`` does, and with more force: a pack rule executes against a
    customer tenant, so a changed manifest is stored as ``pending_manifest``
    and reviewed -- with the change-impact report -- before it takes effect. A
    platform that silently changes what it asserts about a system because
    someone merged a PR is one whose SSP no longer describes a reviewed
    decision.
    """

    __tablename__ = "pack_sources"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    #: Which pack this source provides. Matches ``CompliancePack.pack_key``.
    pack_key: Mapped[str] = mapped_column(String(64), index=True)
    #: Raw manifest URL. A ``file://`` path is supported, which is what the
    #: tests and an air-gapped deployment use.
    url: Mapped[str] = mapped_column(String(1024))
    #: The branch or tag being polled, for display. The authoritative identity
    #: is the resolved commit sha, not this.
    ref: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_install: Mapped[bool] = mapped_column(Boolean, default=False)

    etag: Mapped[str | None] = mapped_column(String(255))
    #: SHA-256 of the raw bytes at the URL. Answers "did the file change",
    #: which is what change detection needs.
    last_sha256: Mapped[str | None] = mapped_column(String(64))
    #: Canonical SHA of the parsed manifest, the same digest
    #: ``install_pack`` stores on ``CompliancePack.manifest_sha``. Answers "is
    #: the installed manifest the one this source provided", which is a
    #: different question -- whitespace and key order change the raw bytes
    #: without changing the manifest, so comparing the raw sha to an installed
    #: pack would never match.
    last_manifest_sha: Mapped[str | None] = mapped_column(String(64))
    last_commit_sha: Mapped[str | None] = mapped_column(String(64))
    #: unchanged | pending | installed | invalid | error
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: A fetched, validated manifest awaiting review. Empty when nothing is
    #: pending.
    pending_manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    pending_sha256: Mapped[str | None] = mapped_column(String(64))
    pending_manifest_sha: Mapped[str | None] = mapped_column(String(64))
    pending_commit_sha: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "pack_key", "url", name="uq_pack_source_org_key_url"
        ),
    )
