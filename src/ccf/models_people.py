"""Personnel & Access models — workforce security lifecycle.

The people layer maps the NIST control families a compliance-automation platform
is expected to operationalize: **PS** (position risk designation PS-2, screening
PS-3, termination/transfer PS-4/PS-5), **AT** (security awareness AT-2 and
role-based training AT-3), and **AC-2** (account/access reviews). Kept in a
dedicated module (imported by the personnel routes) so this net-new layer is easy
to review and doesn't churn the core ORM file. All tables live in the ``ccf``
schema via the shared :class:`Base` and reference core tables by string FKs.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
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


class Person(Base):
    """A workforce member (employee/contractor) — distinct from an app ``User``.

    Tracks the personnel-security posture: position risk designation (PS-2),
    background screening (PS-3), and employment lifecycle (PS-4/PS-5).
    """

    __tablename__ = "people"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    full_name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320), index=True)
    # employee|contractor
    employment_type: Mapped[str] = mapped_column(String(16), default="employee")
    position: Mapped[str | None] = mapped_column(String(255))
    department: Mapped[str | None] = mapped_column(String(255))
    manager: Mapped[str | None] = mapped_column(String(255))
    # prospective|active|offboarded
    status: Mapped[str] = mapped_column(String(16), default="active")
    start_date: Mapped[date | None] = mapped_column(Date)
    end_date: Mapped[date | None] = mapped_column(Date)
    # PS-2 position sensitivity / risk designation.
    risk_designation: Mapped[str] = mapped_column(String(16), default="low")  # low|moderate|high
    # PS-3 personnel screening.
    background_check_status: Mapped[str] = mapped_column(
        String(16), default="not_started"
    )  # not_started|initiated|in_progress|completed|waived
    background_check_completed_on: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    training: Mapped[list[TrainingRecord]] = relationship(
        back_populates="person", cascade="all, delete-orphan"
    )


class TrainingRecord(Base):
    """A security-training assignment/completion for a person (AT-2 / AT-3)."""

    __tablename__ = "training_records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    person_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.people.id", ondelete="CASCADE"), index=True
    )
    course: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(24), default="awareness")  # awareness|role_based
    control_ref: Mapped[str | None] = mapped_column(String(32))  # e.g. AT-2, AT-3
    assigned_on: Mapped[date | None] = mapped_column(Date)
    due_on: Mapped[date | None] = mapped_column(Date)
    completed_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="assigned")  # assigned|completed|waived
    evidence_ref: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    person: Mapped[Person] = relationship(back_populates="training")


class AccessReview(Base):
    """A periodic access-certification campaign (AC-2 account review)."""

    __tablename__ = "access_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.systems.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(255))
    reviewer: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|in_progress|completed
    started_on: Mapped[date | None] = mapped_column(Date)
    due_on: Mapped[date | None] = mapped_column(Date)
    completed_on: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    items: Mapped[list[AccessReviewItem]] = relationship(
        back_populates="review", cascade="all, delete-orphan"
    )


class AccessReviewItem(Base):
    """One access grant reviewed within an :class:`AccessReview`."""

    __tablename__ = "access_review_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    review_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.access_reviews.id", ondelete="CASCADE"), index=True
    )
    person_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.people.id", ondelete="SET NULL"))
    subject: Mapped[str] = mapped_column(String(255))  # account/identity label (denormalized)
    resource: Mapped[str | None] = mapped_column(String(255))  # system/app/role reviewed
    access_level: Mapped[str | None] = mapped_column(String(128))
    # pending|retain|revoke|modify
    decision: Mapped[str] = mapped_column(String(16), default="pending")
    decided_on: Mapped[date | None] = mapped_column(Date)
    note: Mapped[str | None] = mapped_column(Text)

    review: Mapped[AccessReview] = relationship(back_populates="items")
