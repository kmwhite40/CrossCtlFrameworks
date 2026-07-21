"""External collaboration portal models — scoped customer/assessor/vendor access.

External principals never get an internal Concord account. Access is via an
:class:`ExternalAccessGrant` bearer **token** with an expiry and an explicit scope
(the packages/evidence shared into it). Every access is recorded in an immutable
:class:`ExternalPortalAuditEvent`. All tables are tenant-isolated; a grant can only
reference its own tenant's artifacts, so the portal cannot leak across tenants.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class ExternalPrincipal(Base):
    """An external collaborator (customer / assessor / vendor) — not an internal user."""

    __tablename__ = "external_principals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16), default="customer")  # customer|assessor|vendor
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))
    organization_name: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExternalAccessGrant(Base):
    """A scoped, expiring bearer-token grant for an external principal."""

    __tablename__ = "external_access_grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    principal_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.external_principals.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(16), default="customer")
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    # {package_ids, evidence_ids}
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    package_shares: Mapped[list[ExternalPackageShare]] = relationship(
        back_populates="grant", cascade="all, delete-orphan"
    )
    evidence_shares: Mapped[list[ExternalEvidenceShare]] = relationship(
        back_populates="grant", cascade="all, delete-orphan"
    )


class ExternalPackageShare(Base):
    """A package shared into a grant."""

    __tablename__ = "external_package_shares"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    grant_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="CASCADE"), index=True
    )
    package_id: Mapped[int] = mapped_column(Integer)

    grant: Mapped[ExternalAccessGrant] = relationship(back_populates="package_shares")


class ExternalEvidenceShare(Base):
    """An evidence object shared into a grant."""

    __tablename__ = "external_evidence_shares"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    grant_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="CASCADE"), index=True
    )
    evidence_object_id: Mapped[int] = mapped_column(Integer)

    grant: Mapped[ExternalAccessGrant] = relationship(back_populates="evidence_shares")


class ExternalComment(Base):
    """A comment thread entry on shared evidence / a finding / a package."""

    __tablename__ = "external_comments"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    grant_id: Mapped[int | None] = mapped_column(BigInteger)
    target_type: Mapped[str] = mapped_column(String(24))  # evidence|finding|package
    target_id: Mapped[str] = mapped_column(String(64))
    author: Mapped[str | None] = mapped_column(String(255))
    author_kind: Mapped[str] = mapped_column(String(16), default="external")  # external|internal
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExternalQuestionnaireRequest(Base):
    """A questionnaire sent to / answered by an external principal via the portal."""

    __tablename__ = "external_questionnaire_requests"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    grant_id: Mapped[int | None] = mapped_column(BigInteger)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|responded
    response_body: Mapped[str | None] = mapped_column(Text)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExternalPortalAuditEvent(Base):
    """Immutable record of external portal access (view / download / comment / respond)."""

    __tablename__ = "external_portal_audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    grant_id: Mapped[int | None] = mapped_column(BigInteger)
    action: Mapped[str] = mapped_column(String(24))  # view|download|comment|respond|denied
    target_type: Mapped[str | None] = mapped_column(String(24))
    target_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
