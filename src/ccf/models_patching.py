"""Flaw-remediation policy, and the campaigns that organize patching.

A :class:`RemediationPolicy` is the organization's declared SI-2 timeframe, in
days per severity — the parameter that previously existed only as free text in
an SSP template. A :class:`PatchCampaign` groups open scan-derived POA&Ms for
one system into ordered :class:`PatchWave` batches, each with a window.

A wave **records** completion; it does not cause it. Concord has no
endpoint-management provider, so a wave either carries an evidence reference or
points at an enforcement ``RemediationPlan`` when a deployment supplies one.
See ``docs/superpowers/specs/2026-09-15-flaw-remediation-design.md``.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
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
from .patching.sla import FEDRAMP_TIMEFRAMES

#: A campaign's lifecycle. ``cancelled`` is terminal and deliberate -- a
#: campaign abandoned mid-way is a fact worth keeping, not a row to delete.
CAMPAIGN_STATUSES = ("planned", "in_progress", "completed", "cancelled")

#: A wave's lifecycle. ``skipped`` records a deliberate decision not to patch
#: this batch, which is different from never having reached it.
WAVE_STATUSES = ("pending", "completed", "skipped")


class RemediationPolicy(Base):
    """One organization's declared flaw-remediation timeframe.

    Defaults are FedRAMP's, so a deployment that never sets one is still
    measured against the numbers an assessor expects rather than against
    nothing.
    """

    __tablename__ = "remediation_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    critical_days: Mapped[int] = mapped_column(
        Integer, default=FEDRAMP_TIMEFRAMES["critical"]
    )
    high_days: Mapped[int] = mapped_column(Integer, default=FEDRAMP_TIMEFRAMES["high"])
    moderate_days: Mapped[int] = mapped_column(
        Integer, default=FEDRAMP_TIMEFRAMES["moderate"]
    )
    low_days: Mapped[int] = mapped_column(Integer, default=FEDRAMP_TIMEFRAMES["low"])
    #: Where the numbers came from, e.g. "fedramp" or "organization policy 4.2".
    source: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", name="uq_remediation_policy_org"),
        CheckConstraint(
            "critical_days > 0 AND high_days > 0 AND moderate_days > 0 AND low_days > 0",
            name="ck_remediation_policy_positive",
        ),
    )


class PatchCampaign(Base):
    """An organized effort to remediate a system's open flaws, in waves."""

    __tablename__ = "patch_campaigns"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="planned", index=True)
    window_start: Mapped[date] = mapped_column(Date)
    window_end: Mapped[date] = mapped_column(Date)
    created_by: Mapped[str | None] = mapped_column(String(255))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('planned', 'in_progress', 'completed', 'cancelled')",
            name="ck_patch_campaign_status",
        ),
        CheckConstraint("window_end >= window_start", name="ck_patch_campaign_window"),
    )


class PatchWave(Base):
    """One batch within a campaign, and the record of what became of it.

    Deliberately carries no ``organization_id``: it is policied through its
    parent campaign, the same parent-chain shape
    ``control_test_resource_results`` uses. A second source of truth for the
    row's tenant is worth avoiding.
    """

    __tablename__ = "patch_waves"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("ccf.patch_campaigns.id", ondelete="CASCADE"), index=True
    )
    #: 1-based position. Order is the control: wave 1 is a canary, so the blast
    #: radius of a bad patch is bounded by the wave.
    sequence: Mapped[int] = mapped_column(Integer)
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    #: The POA&Ms this wave covers. Stored rather than re-derived: the batch
    #: someone scheduled is the batch they completed, and re-deriving at
    #: completion time would silently change what was claimed.
    poam_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    window_start: Mapped[date | None] = mapped_column(Date)
    window_end: Mapped[date | None] = mapped_column(Date)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_by: Mapped[str | None] = mapped_column(String(255))
    #: How the work was evidenced. Free text by design -- a change ticket, a
    #: screenshot reference, an Intune report id.
    evidence_ref: Mapped[str | None] = mapped_column(String(512))
    #: The enforcement plan that applied it, when a deployment has a provider.
    #: ON DELETE SET NULL: deleting a plan must not delete the record that a
    #: wave ran.
    remediation_plan_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ccf.remediation_plans.id", ondelete="SET NULL")
    )
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("campaign_id", "sequence", name="uq_patch_wave_sequence"),
        CheckConstraint(
            "status IN ('pending', 'completed', 'skipped')", name="ck_patch_wave_status"
        ),
    )
