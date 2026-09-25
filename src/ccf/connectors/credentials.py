"""Per-organization connector credential storage (IA-05).

Config-capture connectors (Microsoft Graph, AWS GovCloud) used to read a
single global env credential set for *every* tenant, so an org's captured
evidence could actually be sourced from a different (e.g. the platform's own)
cloud tenant. This module stores each organization's own connector
credentials on ``ccf.models_grc.ConnectorConfig`` — one row per
(organization_id, connector_type) — as an envelope-encrypted secret bundle,
reusing the Slice-3a cipher (:mod:`ccf.ai.cipher`, the same key-provider
infrastructure as the AI credential vault). Secrets are never stored in
plaintext; only ``key_last4`` is ever surfaced to callers/UI.

Resolution is strictly per-organization: there is no global/env fallback.
``org_id=None`` (no caller identity) and an org with no bound row both resolve
to ``None`` — never a different org's or a shared credential.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ai.cipher import build_cipher, mask
from .credential_spec import IncompleteCredential, missing_fields
from ..config import get_settings
from ..models_grc import ConnectorConfig

# The field within each connector's secret bundle that actually identifies the
# credential, in priority order — used to derive a meaningful ``key_last4``
# instead of masking the tail of the serialized JSON bundle (which mostly
# reflects whichever field happens to sort last and isn't a secret at all).
_SECRET_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "msgraph": ("client_secret",),
    "msgraph_write": ("client_secret",),  # ccf.enforcement's write credential
    "aws_govcloud": ("secret_access_key", "profile"),
    "azure_arm": ("client_secret",),
    # The service-account private key, not the JSON bundle: the bundle's
    # last-sorting field is `type`, which is not a secret at all.
    "gcp": ("private_key",),
    # The API token, not the bundle: a Jira secret also carries base_url and
    # email, and the bundle's last-sorting field is the account email address —
    # not a secret, and showing its last four characters tells an operator
    # nothing about which token is installed.
    "jira": ("api_token",),
    # The api-key, not the user-uid: the uid identifies a person, is not
    # secret, and sorts first in the bundle.
    "emass": ("api_key",),
}


def _secret_display_value(connector_type: str, secret: dict[str, Any]) -> str:
    """The value that should drive ``key_last4`` for this connector's secret."""
    for field in _SECRET_FIELD_CANDIDATES.get(connector_type, ()):
        value = secret.get(field)
        if isinstance(value, str) and value:
            return value
    # Unknown connector type or a bundle missing its known secret field(s):
    # fall back to the whole serialized bundle rather than surfacing nothing.
    return json.dumps(secret, sort_keys=True)


async def set_credential(
    session: AsyncSession,
    org_id: int,
    connector_type: str,
    secret: dict[str, Any],
    *,
    name: str | None = None,
    environment: str | None = None,
    actor: str | None = None,
    config: ConnectorConfig | None = None,
) -> ConnectorConfig:
    """Create/update the organization's stored credential for a connector.

    The plaintext secret bundle is enveloped immediately and never stored or
    logged; only a non-reversible ``key_last4`` identifier is retained for
    display. Raises via :func:`ccf.ai.cipher.build_cipher` (fail-closed) if
    credential storage is not configured (no master key set).
    """
    if org_id is None:
        raise ValueError("a connector credential must be bound to an organization")
    # Refuse a bundle that could never authenticate, rather than storing it and
    # reporting `status = "configured"`. Before this, an empty Microsoft secret
    # was accepted, displayed a key_last4 of `…{}`, marked the connector
    # configured, and surfaced much later as "capture produced nothing" with
    # nothing to indicate why.
    outstanding = missing_fields(connector_type, secret)
    if outstanding:
        raise IncompleteCredential(
            f"{connector_type} credential is missing: {', '.join(outstanding)}"
        )
    # `config` is the row the caller was actually editing. Without it this
    # looked the row up by (organization, connector_type) and took the first
    # match, so with two connectors of one type in an organization a credential
    # entered on the second was silently written to the first: the row you
    # filled in stayed "not configured" and the other one changed under you.
    # Observed in a real deployment.
    if config is not None:
        if config.organization_id != org_id or config.connector_type != connector_type:
            raise ValueError(
                "the connector row does not belong to this organization/type"
            )
        cfg = config
    else:
        cfg = (
            await session.execute(
                select(ConnectorConfig)
                .where(
                    ConnectorConfig.organization_id == org_id,
                    ConnectorConfig.connector_type == connector_type,
                )
                .order_by(ConnectorConfig.id)
            )
        ).scalars().first()
    if cfg is None:
        cfg = ConnectorConfig(
            organization_id=org_id,
            connector_type=connector_type,
            name=name or connector_type,
            environment=environment,
        )
        session.add(cfg)
    cipher = build_cipher(get_settings())  # raises if credential storage unavailable
    payload = json.dumps(secret, sort_keys=True)
    cfg.encrypted_credential = cipher.encrypt(payload)
    cfg.key_last4 = mask(_secret_display_value(connector_type, secret))
    cfg.status = "configured"
    cfg.error_message = None
    if actor is not None:
        cfg.auth_method = cfg.auth_method or "credential"
    await session.flush()
    return cfg


async def resolve_credential(
    session: AsyncSession, org_id: int | None, connector_type: str
) -> dict[str, Any] | None:
    """Return this org's own decrypted credential for a connector, or ``None``.

    ``None`` covers both "no caller identity" (``org_id is None``) and "this
    org has no bound credential" — the caller (a connector's ``is_configured``
    via :class:`ccf.connectors.base.ConfigConnector`) must treat both as "not
    configured", never fall back to another credential.
    """
    if org_id is None:
        return None
    cfg = (
        await session.execute(
            select(ConnectorConfig)
            .where(
                ConnectorConfig.organization_id == org_id,
                ConnectorConfig.connector_type == connector_type,
                ConnectorConfig.encrypted_credential.is_not(None),
            )
            .order_by(ConnectorConfig.id)
        )
    ).scalars().first()
    if cfg is None or not cfg.encrypted_credential:
        return None
    plaintext = build_cipher(get_settings()).decrypt(cfg.encrypted_credential)
    data: Any = json.loads(plaintext)
    return data if isinstance(data, dict) else None


async def orgs_with_bound_credentials(
    session: AsyncSession, connector_type: str | None = None
) -> list[int]:
    """Distinct organization ids with at least one bound connector credential.

    Used by the scheduler's global capture cycle to fan out per-org — it must
    only ever touch organizations that have their own credential, never a
    global/no-identity run.
    """
    stmt = select(ConnectorConfig.organization_id).where(
        ConnectorConfig.organization_id.is_not(None),
        ConnectorConfig.encrypted_credential.is_not(None),
    )
    if connector_type:
        stmt = stmt.where(ConnectorConfig.connector_type == connector_type)
    rows = (await session.execute(stmt.distinct())).scalars().all()
    return sorted({oid for oid in rows if oid is not None})


def masked_view(cfg: ConnectorConfig) -> dict[str, Any]:
    """A safe, credential-free serialization for API/UI (never the token)."""
    return {
        "id": cfg.id,
        "organization_id": cfg.organization_id,
        "connector_type": cfg.connector_type,
        "status": cfg.status,
        "has_credential": bool(cfg.encrypted_credential),
        "key_last4": cfg.key_last4,
    }
