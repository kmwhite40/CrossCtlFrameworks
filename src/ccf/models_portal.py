"""External collaboration portal models — scoped customer/assessor/vendor access.

External principals never get an internal Concord account. Access is via an
:class:`ExternalAccessGrant` bearer **token** with an expiry and an explicit scope
(the packages/evidence shared into it). An assessor's grants additionally hang off
an :class:`AssessmentEngagement` -- the relationship (this firm, this system, this
period) that the credential merely carries the authority of. Every access is
recorded in an immutable :class:`ExternalPortalAuditEvent`. All tables are
tenant-isolated; a grant can only reference its own tenant's artifacts, so the
portal cannot leak across tenants.
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

from .auth import hash_token
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


class AssessmentEngagement(Base):
    """A 3PAO assessing one system for one tenant over one period.

    A grant is a *credential*: one token, one expiry. An engagement is the
    *relationship* behind it — this firm assesses this system over this window
    — and it outlives its credentials: a token rotates, a second assessor from
    the same firm joins, and ending the relationship must end all of them at
    once (see ``revoke_engagement``).

    ``system_id`` is NOT NULL and is the point of the table. A grant on its own
    has no system at all — it is a hand-picked list of package and evidence ids
    — so "this firm assesses this system" was not expressible, which is why a
    3PAO could not be modelled without this. An engagement-backed grant's
    contents resolve through this column rather than through a share list.

    ``independence_note`` records what the platform *observed* about the
    assessor's email domain / organization name (see
    ``ccf.portal.service._independence_note``). It never blocks: FedRAMP's
    independence requirement is about ownership, contracts and staffing, none
    of which any field here records, so Concord names a string match and stops
    there.
    """

    __tablename__ = "assessment_engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True, nullable=False
    )
    assessor_principal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.external_principals.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    period_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authorized_by: Mapped[str | None] = mapped_column(String(255))
    independence_note: Mapped[str | None] = mapped_column(Text)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    #: The engagement this credential carries the authority of, if any. Nullable
    #: because every existing customer and vendor grant has none and always
    #: will. ``ON DELETE CASCADE``, deliberately not ``SET NULL``: nulling it
    #: would silently convert a bounded assessment credential into an unbounded
    #: one, which is the opposite of what deleting the engagement means.
    engagement_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.assessment_engagements.id", ondelete="CASCADE"), index=True
    )
    # IA-09: only the one-way hash is persisted — see the ``token`` property
    # below for the plaintext write/read-once path.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
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

    @property
    def token(self) -> str | None:
        """Plaintext grant token — available only in-memory, only on the
        instance that just set it (issuance). Never persisted: the DB holds
        ``token_hash`` only, so a freshly loaded grant always reports
        ``None`` here. Resolve grants via ``token_hash`` instead.
        """
        return getattr(self, "_token_plain", None)

    @token.setter
    def token(self, value: str) -> None:
        self._token_plain = value
        if value:
            self.token_hash = hash_token(value)


class ExternalPackageShare(Base):
    """A package shared into a grant."""

    __tablename__ = "external_package_shares"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    grant_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="CASCADE"), index=True
    )
    package_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.authorization_packages.id", ondelete="CASCADE")
    )

    grant: Mapped[ExternalAccessGrant] = relationship(back_populates="package_shares")


class ExternalEvidenceShare(Base):
    """An evidence object shared into a grant."""

    __tablename__ = "external_evidence_shares"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    grant_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="CASCADE"), index=True
    )
    evidence_object_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.evidence_objects.id", ondelete="CASCADE")
    )

    grant: Mapped[ExternalAccessGrant] = relationship(back_populates="evidence_shares")


class ExternalComment(Base):
    """A comment thread entry on shared evidence / a finding / a package."""

    __tablename__ = "external_comments"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    grant_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="SET NULL")
    )
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
    grant_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="SET NULL")
    )
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
    grant_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.external_access_grants.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(24))  # view|download|comment|respond|denied
    target_type: Mapped[str | None] = mapped_column(String(24))
    target_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
