"""Evidence repository models — versioned objects, reviews, retention, access.

An :class:`EvidenceObject` is the logical artifact (owner, tags, freshness, review
status, immutable lock); each :class:`EvidenceVersion` is an immutable,
content-addressed snapshot; :class:`EvidenceReview` records the approve/reject
decisions; :class:`EvidenceRetentionPolicy` and :class:`EvidenceAccessEvent`
support retention windows and access auditing. Kept in a dedicated module
(imported by the evidence-repository routes) so the layer is easy to review.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base

# draft → submitted → approved|rejected ; approved/expired are terminal-ish.
EVIDENCE_STATES = ("draft", "submitted", "approved", "rejected", "expired")


class EvidenceObject(Base):
    """A logical evidence artifact with versions, review state, and freshness."""

    __tablename__ = "evidence_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="SET NULL"))
    control_id: Mapped[str | None] = mapped_column(String(64))  # tag (e.g. AC-2)
    framework: Mapped[str | None] = mapped_column(String(64))  # tag (e.g. FEDRAMP)
    owner: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="draft")
    current_version_id: Mapped[int | None] = mapped_column(BigInteger)
    expires_on: Mapped[date | None] = mapped_column(Date)
    immutable_lock: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    versions: Mapped[list[EvidenceVersion]] = relationship(
        back_populates="evidence_object",
        cascade="all, delete-orphan",
        order_by="EvidenceVersion.version",
    )
    reviews: Mapped[list[EvidenceReview]] = relationship(
        back_populates="evidence_object", cascade="all, delete-orphan"
    )


class EvidenceVersion(Base):
    """An immutable, content-addressed snapshot of an :class:`EvidenceObject`."""

    __tablename__ = "evidence_versions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    media_type: Mapped[str | None] = mapped_column(String(128))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    filename: Mapped[str | None] = mapped_column(String(512))
    storage_backend: Mapped[str] = mapped_column(String(16), default="local")
    storage_ref: Mapped[str] = mapped_column(Text)
    uploaded_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    evidence_object: Mapped[EvidenceObject] = relationship(back_populates="versions")


class EvidenceReview(Base):
    """One approve/reject decision on a version of an :class:`EvidenceObject`."""

    __tablename__ = "evidence_reviews"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), index=True
    )
    version_id: Mapped[int | None] = mapped_column(BigInteger)
    reviewer: Mapped[str | None] = mapped_column(String(255))
    decision: Mapped[str] = mapped_column(String(16))  # approved|rejected
    note: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    evidence_object: Mapped[EvidenceObject] = relationship(back_populates="reviews")


class EvidenceRetentionPolicy(Base):
    """A retention window (days) applied to evidence, optionally by framework."""

    __tablename__ = "evidence_retention_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    retain_days: Mapped[int] = mapped_column(Integer, default=365)
    applies_to_framework: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidenceAccessEvent(Base):
    """An append-only record of who viewed/downloaded an evidence version."""

    __tablename__ = "evidence_access_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE"), index=True
    )
    version_id: Mapped[int | None] = mapped_column(BigInteger)
    actor: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(16), default="download")  # view|download
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
