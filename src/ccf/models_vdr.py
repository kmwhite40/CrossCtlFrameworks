"""Vulnerability evaluations: the source the CR26 VER deliverables lacked.

A POA&M stays the vulnerability record. An evaluation is a person's judgement
of it under VER-EVA -- PAIN N-rating, internet reachability, likely
exploitability, false positive -- and every 20x VDR timeframe runs from one
(see docs/superpowers/specs/2026-11-05-vdr-engine-design.md).

Append-only: a new judgement is a new row, so the history is the record of
PAIN reductions VER-RPT-VDT asks for. No route deletes a row; the only update
is the one-time confirmation below.

An evaluation that **relaxes** a deadline -- a lower rating, a less exposed
reachability column, a false positive, or a first rating with no timeframe at
all -- takes effect only when someone other than its author confirms it
(``ccf.vdr.timeframes.relaxes``). Until then the engine and the deliverables
ignore it. Tightening needs no second person.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class VulnerabilityEvaluation(Base):
    """One evaluation of one POA&M, as recorded."""

    __tablename__ = "vulnerability_evaluations"
    __table_args__ = (
        CheckConstraint("pain_rating BETWEEN 0 AND 5", name="ck_vuln_eval_pain_rating"),
        CheckConstraint(
            "NOT false_positive OR pain_rating = 0", name="ck_vuln_eval_false_positive_unrated"
        ),
        CheckConstraint("length(btrim(rationale)) > 0", name="ck_vuln_eval_rationale"),
        CheckConstraint(
            "confirmed_at IS NULL OR (requires_confirmation AND confirmed_by IS NOT NULL)",
            name="ck_vuln_eval_confirmation",
        ),
        {"schema": "ccf"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    poam_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.poams.id", ondelete="CASCADE"), index=True
    )
    pain_rating: Mapped[int] = mapped_column(SmallInteger)
    internet_reachable: Mapped[bool] = mapped_column(Boolean)
    likely_exploitable: Mapped[bool] = mapped_column(Boolean)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    rationale: Mapped[str] = mapped_column(Text)
    evaluated_by: Mapped[str | None] = mapped_column(String(255))
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    requires_confirmation: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_by: Mapped[str | None] = mapped_column(String(255))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def effective(self) -> bool:
        """Whether deadlines and deliverables may read this evaluation."""
        return not self.requires_confirmation or self.confirmed_at is not None
