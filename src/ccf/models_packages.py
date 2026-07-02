"""Authorization package provenance, diff, and replay models.

An :class:`AuthorizationPackage` persists the metadata + the normalized *facts*
(per-KSI/control/evidence/dependency/risk/POA&M/readiness values) captured when an
authorization package is exported, so two packages can be diffed and a package can
be *replayed* against the current database to detect drift. Kept in a dedicated
module (imported by the package routes); all tables are tenant-isolated.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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

PACKAGE_KINDS = (
    "fedramp20x", "oscal_ssp", "oscal_poam", "component", "docx", "markdown", "json", "bundle",
)


class AuthorizationPackage(Base):
    """A persisted authorization-package export with its captured facts."""

    __tablename__ = "authorization_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(24), default="fedramp20x")
    label: Mapped[str] = mapped_column(String(255))
    readiness_pct: Mapped[float | None] = mapped_column(Float)
    fact_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    facts: Mapped[list[AuthorizationPackageFact]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[AuthorizationPackageArtifact]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )


class AuthorizationPackageFact(Base):
    """One normalized fact a package section was generated from."""

    __tablename__ = "authorization_package_facts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    package_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE"), index=True
    )
    # ksi|control|evidence|dependency|risk|poam|readiness
    fact_type: Mapped[str] = mapped_column(String(24))
    fact_key: Mapped[str] = mapped_column(String(255))
    value: Mapped[str | None] = mapped_column(Text)
    digest: Mapped[str | None] = mapped_column(String(64))
    fact_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, default=dict)

    package: Mapped[AuthorizationPackage] = relationship(back_populates="facts")


class AuthorizationPackageArtifact(Base):
    """A rendered artifact (json/oscal/docx/…) belonging to a package."""

    __tablename__ = "authorization_package_artifacts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    package_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE"), index=True
    )
    artifact_kind: Mapped[str] = mapped_column(String(24))
    sha256: Mapped[str | None] = mapped_column(String(64))
    media_type: Mapped[str | None] = mapped_column(String(128))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    storage_ref: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    package: Mapped[AuthorizationPackage] = relationship(back_populates="artifacts")


class AuthorizationPackageDiff(Base):
    """A stored diff between two authorization packages."""

    __tablename__ = "authorization_package_diffs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    from_package_id: Mapped[int | None] = mapped_column(BigInteger)
    to_package_id: Mapped[int | None] = mapped_column(BigInteger)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    changes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthorizationPackageReplayRun(Base):
    """A replay of a package's facts against the current database."""

    __tablename__ = "authorization_package_replay_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    package_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE"), index=True
    )
    # reproducible|drifted|missing
    status: Mapped[str] = mapped_column(String(16), default="reproducible")
    drift: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthorizationDeltaMemo(Base):
    """An assessor-facing memo summarizing what changed between packages."""

    __tablename__ = "authorization_delta_memos"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="CASCADE"))
    from_package_id: Mapped[int | None] = mapped_column(BigInteger)
    to_package_id: Mapped[int | None] = mapped_column(BigInteger)
    since: Mapped[date | None] = mapped_column(Date)
    body: Mapped[str] = mapped_column(Text)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
