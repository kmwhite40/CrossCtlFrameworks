"""The remediation plan -- the record that a write was considered.

A plan exists before anything is written, carries the reversal data captured at
planning time, and records every transition and every per-step outcome. It is
as much an audit artefact as an execution artefact: after an enforcement
action, "what was changed, by whose approval, and how do we put it back" has
to be answerable from one row.

See ``docs/superpowers/specs/2026-09-15-enforcement-design.md``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base

#: The lifecycle. ``refused`` is terminal and reached at plan time -- the
#: operator is never offered an approval for a plan that cannot be applied.
PLAN_STATUSES = (
    "draft",
    "pending_approval",
    "approved",
    "applied",
    "failed",
    "reversed",
    "refused",
    "rejected",
)


class RemediationPlan(Base):
    """One considered change to an environment, and what became of it."""

    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    #: The posture check whose findings motivated this plan.
    check_key: Mapped[str] = mapped_column(String(128), index=True)
    provider_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="draft", index=True)

    #: The steps as planned, each with its captured ``current_state``. Stored
    #: rather than recomputed: the plan that was approved is the plan that is
    #: applied, and re-planning at apply time would silently approve a
    #: different change.
    steps: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    #: Per-step results, so a partial apply is fully described rather than
    #: inferred from a single status.
    outcomes: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    resource_count: Mapped[int] = mapped_column(Integer, default=0)
    #: Why a plan was refused, in the operator's words rather than a code.
    refusal_reason: Mapped[str | None] = mapped_column(Text)

    requested_by: Mapped[str | None] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reversed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: The result that motivated the plan. ON DELETE SET NULL: retention may
    #: prune a result, and the record of what was *done about it* must outlive
    #: the observation.
    result_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ccf.control_test_results.id", ondelete="SET NULL")
    )
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('draft', 'pending_approval', 'approved', 'applied', "
            "'failed', 'reversed', 'refused', 'rejected')",
            name="ck_remediation_plan_status",
        ),
    )
