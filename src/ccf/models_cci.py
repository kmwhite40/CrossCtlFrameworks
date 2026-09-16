"""DISA CCI reference data.

Authority-published and identical for every tenant, so these three tables
carry no ``organization_id`` and no RLS policy -- they belong on
``GLOBAL_TABLES`` beside ``controls`` and ``catalog_revisions``. Per-tenant
CCI divergence would make the reverse index incoherent.
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class CciItemRow(Base):
    """One CCI as DISA publishes it."""

    __tablename__ = "cci_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cci: Mapped[str] = mapped_column(String(16), unique=True)
    status: Mapped[str] = mapped_column(String(16))
    type: Mapped[str] = mapped_column(String(32))
    contributor: Mapped[str | None] = mapped_column(String(128))
    published_date: Mapped[date | None] = mapped_column(Date)
    definition: Mapped[str] = mapped_column(Text)
    #: The published list version, e.g. "2026-07-14".
    source_version: Mapped[str] = mapped_column(String(32))
    #: Content address of the file this row was read from.
    source_sha256: Mapped[str] = mapped_column(String(64))
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    references: Mapped[list[CciControlRef]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )
    overlay: Mapped[list[CciAssessmentOverlay]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )


class CciControlRef(Base):
    """One reference from a CCI to a control item, in one revision.

    ``oscal_part_id`` is nullable on purpose: DISA's reference can name an item
    the current catalog no longer has (CCI-005020 -> SI-18 b 1). Dropping such
    a reference would make a real STIG finding unroutable, so the control is
    kept and the part is left null.

    ``resolution_status`` records how much to trust ``canonical_control`` /
    ``oscal_control_id``: the platform holds exactly one OSCAL catalog (Rev.
    5), so a reference naming any other revision is matched against a
    catalog that isn't its own. ``"resolved"`` is verified for a Rev. 5
    reference and a best-effort cross-revision match for any other;
    ``"base_control_fallback"`` means the reference named an enhancement the
    absorption loop could not confirm, so only the base control is recorded;
    ``"withdrawn"``/``"unparseable"`` are the two ways ``canonical_control``
    ends up null. See ``ccf.cci.resolve.ResolutionStatus``.
    """

    __tablename__ = "cci_control_refs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cci_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.cci_items.id", ondelete="CASCADE"), index=True
    )
    revision: Mapped[str] = mapped_column(String(64))
    raw_index: Mapped[str] = mapped_column(String(128))
    canonical_control: Mapped[str | None] = mapped_column(String(32))
    oscal_control_id: Mapped[str | None] = mapped_column(String(32))
    oscal_part_id: Mapped[str | None] = mapped_column(String(64))
    resolution_status: Mapped[str] = mapped_column(String(32), default="resolved")

    item: Mapped[CciItemRow] = relationship(back_populates="references")

    __table_args__ = (
        UniqueConstraint("cci_id", "revision", "raw_index", name="uq_cci_ref"),
        # The reverse lookup: which CCIs cover this control.
        Index("ix_cci_ref_canonical_control", "canonical_control"),
    )


class CciAssessmentOverlay(Base):
    """Derived Rev. 5 assessment metadata for a CCI.

    Not DISA-published. ``source`` names the file it came from so no reader can
    mistake it for the authority.
    """

    __tablename__ = "cci_assessment_overlay"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cci_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.cci_items.id", ondelete="CASCADE"), index=True
    )
    ap_acronym: Mapped[str | None] = mapped_column(String(64))
    emass_identifier: Mapped[str | None] = mapped_column(String(64))
    assessment_procedure: Mapped[str | None] = mapped_column(Text)
    assessment_methods: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(128))

    item: Mapped[CciItemRow] = relationship(back_populates="overlay")

    __table_args__ = (UniqueConstraint("cci_id", "ap_acronym", name="uq_cci_overlay"),)
