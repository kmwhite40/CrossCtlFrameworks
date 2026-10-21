"""Two SSP inventories the boundary model lacked: ports/protocols/services and
cryptographic modules.

A FedRAMP SSP tabulates both (the ports, protocols and services table, and
Appendix Q, cryptographic modules), and m365-docs-hub collected them only as a
one-off JSON upload into browser storage. Here they are boundary entities like
components and interconnections -- org- and system-scoped, optionally tied to
the component that uses them.

A cryptographic module's ``validation_status`` is what the organization
asserts; Concord does not look the certificate up. So ``validated`` requires a
CMVP certificate number, and the page links to NIST's record for it rather than
vouching for it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base

PPS_PROTOCOLS = ("tcp", "udp", "icmp", "sctp", "other")
PPS_DIRECTIONS = ("inbound", "outbound", "internal", "bidirectional")
CRYPTO_STATUSES = ("validated", "in_process", "historical", "not_validated")
CRYPTO_USAGES = (
    "data_at_rest", "data_in_transit", "authentication", "digital_signature",
    "key_management", "other",
)

#: NIST's public record for a CMVP certificate number.
CMVP_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{n}"


def _uuid() -> str:
    return str(uuid.uuid4())


class PortProtocolService(Base):
    __tablename__ = "ports_protocols_services"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    component_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ccf.system_components.id", ondelete="SET NULL")
    )
    #: A port ("443") or an inclusive range ("49152-65535"); NULL for ICMP.
    port: Mapped[str | None] = mapped_column(String(16))
    protocol: Mapped[str] = mapped_column(String(8))
    service: Mapped[str] = mapped_column(String(128))
    purpose: Mapped[str | None] = mapped_column(Text)
    direction: Mapped[str] = mapped_column(String(16))
    used_by: Mapped[str | None] = mapped_column(String(255))
    oscal_uuid: Mapped[str] = mapped_column(String(36), default=_uuid, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class CryptoModule(Base):
    __tablename__ = "crypto_modules"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    component_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ccf.system_components.id", ondelete="SET NULL")
    )
    module_name: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(255))
    module_version: Mapped[str | None] = mapped_column(String(128))
    #: CMVP certificate number as entered; required for ``validated``.
    cmvp_certificate: Mapped[str | None] = mapped_column(String(16))
    validation_status: Mapped[str] = mapped_column(String(16))
    #: FIPS 140 security level (1-4) the certificate states, if entered.
    security_level: Mapped[int | None] = mapped_column(Integer)
    usage: Mapped[str] = mapped_column(String(24))
    notes: Mapped[str | None] = mapped_column(Text)
    oscal_uuid: Mapped[str] = mapped_column(String(36), default=_uuid, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
