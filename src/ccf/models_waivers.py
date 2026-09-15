"""Waiver model -- a formally accepted finding.

A :class:`Waiver` records that a failing check has been accepted, so its
*consequence* stops: no fresh notification, no repeated remediation task, no
POA&M churn. It never alters the finding. See
``docs/superpowers/specs/2026-09-15-waivers-design.md``.

Distinct from ``models.KSIException`` on purpose. That is a FedRAMP
*disclosure* -- ``fedramp20x.readiness`` counts open ones as a detractor in the
readiness payload and the authorization package, and it suppresses nothing.
Merging the two would either make a disclosure silence an alert or make an
operational silence vanish from the package; §7 of the spec records what a
later merge would cost.

Tenant-owned and carrying ``organization_id``, nullable, matching
``models_capability`` and ``vendors``/``people``: an unscoped principal writes
a row with no organization, and the RLS policy makes such rows invisible to
every scoped tenant.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class Waiver(Base):
    """One accepted finding: what is accepted, by whom, and until when."""

    __tablename__ = "waivers"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    #: What is accepted. Exactly one of these is set -- a waiver targeting both
    #: a check and a control would have two different scopes, and which one
    #: applied would depend on the order the resolver happened to test them.
    check_key: Mapped[str | None] = mapped_column(String(128), index=True)
    control_id: Mapped[str | None] = mapped_column(String(32), index=True)
    #: Narrows the waiver to one resource. NULL accepts the whole check, and is
    #: the only shape that can cover a result whose resources were never
    #: enumerated (a manual test).
    resource_id: Mapped[str | None] = mapped_column(String(512))
    #: Required: an acceptance with no stated reason is not reviewable.
    rationale: Mapped[str] = mapped_column(Text)
    #: requested | approved | revoked. Only ``approved`` suppresses anything.
    status: Mapped[str] = mapped_column(String(16), default="requested", index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: NULL means indefinite. Permitted -- a permanent architectural acceptance
    #: is real -- but it is a governance smell, so it is reported rather than
    #: forbidden, the posture KSIException takes toward disclosure.
    expires_on: Mapped[date | None] = mapped_column(Date, index=True)
    #: The risk this acceptance is filed under, as KSIException does.
    risk_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.risks.id", ondelete="SET NULL")
    )
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "(check_key IS NOT NULL AND control_id IS NULL) "
            "OR (check_key IS NULL AND control_id IS NOT NULL)",
            name="ck_waiver_one_target",
        ),
        CheckConstraint(
            "status IN ('requested', 'approved', 'revoked')", name="ck_waiver_status"
        ),
    )
