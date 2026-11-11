"""ATO workflow models: who signs for a system, package history, POA&M extensions.

Concord already had the pieces an authorization program decides with --
single-use approvals with separation of duties, gated POA&M closure and risk
acceptance, frozen package fact snapshots, ``System.ato_status`` -- but no
record of *who* the ISSO, ISSM and AO of a system are, no workflow over a
package, and no way to ask for more time on a POA&M except editing its date.
These three tables are only that missing part; everything else extends the
existing models (see docs/superpowers/specs/2026-10-20-ato-workspace-design.md).
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
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from . import models_packages
from .models import Base

#: ``authorization_package_events`` references a table that lives in
#: models_packages; it must be in ``Base.metadata`` before this one is. Bound
#: to a name (not a bare import) so ``ruff --fix`` cannot strip it -- see the
#: same note on ``models.CROSS_MODULE_MODEL_MODULES``.
_FK_TARGET_MODULES = (models_packages,)

#: The system roles that sign for an authorization. The keys are the OSCAL
#: role ids the SSP already uses (``api/routes/oscal.py``), so an assignment
#: and the SSP's named roles talk about the same thing.
SYSTEM_ROLES = ("system_owner", "isso", "issm", "authorizing_official")

#: Package workflow vocabulary. ``draft`` is every package captured before this
#: workflow existed, and every new one: the facts are frozen at capture, so a
#: draft is a sealed snapshot no one has reviewed yet.
PACKAGE_STATUSES = (
    "draft",
    "isso_review",
    "issm_review",
    "ao_review",
    "returned",
    "authorized",
    "conditional",
    "denied",
    "superseded",
    "expired",
)

EXTENSION_STATUSES = ("requested", "approved", "rejected", "withdrawn")


class SystemRoleAssignment(Base):
    """The one user who holds a signing role for a system."""

    __tablename__ = "system_role_assignments"
    __table_args__ = (UniqueConstraint("system_id", "role", name="uq_system_role"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(32))
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.users.id", ondelete="CASCADE"), index=True
    )
    assigned_by: Mapped[str | None] = mapped_column(String(255))
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuthorizationPackageEvent(Base):
    """One transition of a package's workflow -- append-only."""

    __tablename__ = "authorization_package_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    package_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str] = mapped_column(String(24))
    to_status: Mapped[str] = mapped_column(String(24))
    actor: Mapped[str | None] = mapped_column(String(255))
    #: The system role the actor signed as (``admin`` when acting on the
    #: platform floor rather than an assignment); NULL for a system action.
    acted_as: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(Text)
    #: What the actor signed: the package's manifest hash at the time.
    manifest_sha256: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class PoamExtension(Base):
    """A request to move a POA&M's due date later, and its decision."""

    __tablename__ = "poam_extensions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    poam_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.poams.id", ondelete="CASCADE"), index=True
    )
    previous_due_on: Mapped[date | None] = mapped_column(Date)
    requested_due_on: Mapped[date] = mapped_column(Date)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="requested", index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255))
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)
