"""Enterprise identity models — OIDC/SSO federation, JIT, and SCIM provisioning.

Concord's primary OIDC configuration is env-driven (``CCF_OIDC_*``); these tables
add the per-organization metadata a shared deployment needs: registered identity
providers, the external (IdP) identities linked to local users, IdP-group → role
mappings applied at login, and an append-only SCIM provisioning event log. Kept in
a dedicated module (imported by the identity routes) so the layer is easy to review.
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
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class IdentityProvider(Base):
    """A registered OIDC identity provider (metadata + default role for JIT)."""

    __tablename__ = "identity_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(128))
    issuer: Mapped[str] = mapped_column(String(512))
    client_id: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    default_role: Mapped[str] = mapped_column(String(32), default="viewer")
    allowed_domains: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExternalIdentity(Base):
    """Links a local :class:`User` to an external IdP subject (one per provider)."""

    __tablename__ = "external_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("ccf.users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(128), default="oidc")
    subject: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    claims: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("provider", "subject", name="uq_external_identity"),)


class GroupRoleMapping(Base):
    """Maps an IdP group/claim value to a Concord role, applied at login."""

    __tablename__ = "group_role_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    group: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32))  # admin|control_owner|assessor|viewer
    priority: Mapped[int] = mapped_column(Integer, default=100)  # lower wins
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("organization_id", "group", name="uq_group_role_mapping"),)


class ScimProvisioningEvent(Base):
    """Append-only record of a SCIM create/update/deactivate operation."""

    __tablename__ = "scim_provisioning_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    operation: Mapped[str] = mapped_column(String(16))  # create|update|deactivate
    external_id: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("ccf.users.id", ondelete="SET NULL"))
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    note: Mapped[str | None] = mapped_column(Text)


class UserMfaCredential(Base):
    """One user's TOTP authenticator (IA-2(1)).

    Spec: ``docs/superpowers/specs/2026-09-23-mfa-totp-design.md``.

    At most one row per user, enforced by a unique constraint rather than by
    convention: two active authenticators would mean two independent replay
    windows, so ``last_used_step`` would stop meaning what §6 says it means.

    ``activated_at`` is the gate, not the row's existence. Enrolment writes a
    row immediately -- the secret has to survive the round trip to the
    authenticator app -- but a credential that has never produced a correct
    code challenges nobody. Without that split, a user who scans and then loses
    the tab is locked out of their own account by a secret they never proved
    they held.

    ``secret_encrypted`` is an envelope-encrypted blob, never the base32 secret.
    """

    __tablename__ = "user_mfa_credentials"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="CASCADE"), index=True
    )
    secret_encrypted: Mapped[str] = mapped_column(Text)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: The RFC 6238 step most recently spent. Refusing this step and every
    #: earlier one is what makes an observed code useless for the rest of its
    #: window; see ``ccf.mfa.verify``.
    last_used_step: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (UniqueConstraint("user_id", name="uq_user_mfa_credential"),)


class UserMfaRecoveryCode(Base):
    """A single-use code for a user who has lost their authenticator.

    Stored as a SHA-256 digest, deliberately not a PBKDF2 hash -- see
    ``ccf.mfa.hash_recovery_code``, which carries the reasoning.

    ``used_at`` rather than deletion: an administrator asking "did somebody get
    in without their authenticator, and when" is asking an audit question, and
    a deleted row cannot answer it.
    """

    __tablename__ = "user_mfa_recovery_codes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.users.id", ondelete="CASCADE"), index=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
