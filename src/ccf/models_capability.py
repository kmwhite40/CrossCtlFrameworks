"""Capability ontology models.

A :class:`Capability` is what the organization *does* -- authored once at the
organization level and reused everywhere -- and the four edge tables connect it
to canonical controls, the system components that implement it, the risks it
mitigates, and the FedRAMP 20x KSIs it satisfies.

Before this, Concord was control-first: narrative authored per control,
evidence parented to a ``(system, control)`` pair, and a crosswalk that ran
control-to-control. One MFA decision therefore had to be restated in every
dependent control, per project, per framework.

Every table here is tenant-owned and carries ``organization_id``, because the
RLS policy compares ``ccf.current_tenant()`` against that column. Omitting it
would force these onto the ``GLOBAL_TABLES`` allowlist in
``tests/test_rls_registry_no_gap.py``, which is for authority-published
reference data -- using it here would be a tenant-isolation hole.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base

#: Reuses the existing implementation-status enum rather than inventing a
#: parallel vocabulary. create_type=False: the type already exists.
_STATUS = Enum(
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
    name="impl_status",
    schema="ccf",
    create_type=False,
)


class Capability(Base):
    """A reusable security capability -- the unit of implementation.

    Authored once per organization and mapped to many controls across many
    frameworks, so a single decision ("Conditional Access enforces MFA") is
    stated once instead of restated in IA-2, IA-2(1), AC-7, MA-4 and every
    other dependent control, per project, per framework.
    """

    __tablename__ = "capabilities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    #: Stable, addressable slug -- also what a future capability pack installs by.
    key: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    #: The reusable narrative. P4 derives SSP prose from this.
    statement: Mapped[str | None] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(Text)
    responsible_role: Mapped[str | None] = mapped_column(String(128))
    #: Grouping label -- the "Solution" layer as a facet, not a table.
    solution: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(_STATUS, default="not_implemented")
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_capability_org_key"),
        {"schema": "ccf"},
    )


class CapabilityControl(Base):
    """Capability -> canonical 800-53 control id.

    ``control_id`` is the **canonical** string (``AC-2``), not a foreign key.
    The workbook-derived ``controls`` table and the OSCAL catalog genuinely
    differ -- ``catalog/reconcile.py`` exists because of it -- so an FK would
    make capabilities un-mappable to catalog controls the workbook lacks.
    Cross-framework reach resolves via ``canonicalize()`` ->
    ``controls.identifier`` -> ``framework_mappings`` at query time, which
    keeps Concord's crosswalk the single authoritative mapping.
    """

    __tablename__ = "capability_controls"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    control_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "control_id", name="uq_capability_control"),
        {"schema": "ccf"},
    )


class CapabilityComponent(Base):
    """Capability -> the system component that implements it.

    Also how a capability binds to a *system*: there is no separate
    capability-to-system table because ``SystemComponent.type`` already
    includes ``policy`` and ``process``, so a policy- or process-backed
    capability binds through a component of that type. That is the OSCAL-native
    answer and it reuses ``boundary/``.
    """

    __tablename__ = "capability_components"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    component_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.system_components.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "component_id", name="uq_capability_component"),
        {"schema": "ccf"},
    )


class CapabilityRisk(Base):
    """Capability -> the risk it mitigates.

    This is the edge ``Risk`` has always lacked: before this table a risk had
    nothing to point at, so the register was terminal.
    """

    __tablename__ = "capability_risks"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    risk_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.risks.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "risk_id", name="uq_capability_risk"),
        {"schema": "ccf"},
    )


class CapabilityKsi(Base):
    """Capability -> the FedRAMP 20x KSI it satisfies.

    Stores ``KSI.identifier``, not a row id: ``ksis`` is global reference data
    that reseeding can renumber, and the identifier is the stable key. KSIs are
    capability-*shaped requirements*, so they map to capabilities roughly 1:1
    where controls fragment one capability across many.
    """

    __tablename__ = "capability_ksis"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    capability_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.capabilities.id", ondelete="CASCADE"), index=True
    )
    ksi_identifier: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("capability_id", "ksi_identifier", name="uq_capability_ksi"),
        {"schema": "ccf"},
    )


__all__ = [
    "Capability",
    "CapabilityComponent",
    "CapabilityControl",
    "CapabilityKsi",
    "CapabilityRisk",
]
