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
from ..config import get_settings
from ..models_grc import ConnectorConfig
from . import aws_identity
from .credential_spec import IncompleteCredential, missing_fields, spec_for

# The field within each connector's secret bundle that actually identifies the
# credential, in priority order — used to derive a meaningful ``key_last4``
# instead of masking the tail of the serialized JSON bundle (which mostly
# reflects whichever field happens to sort last and isn't a secret at all).
_SECRET_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "msgraph": ("client_secret",),
    "msgraph_write": ("client_secret",),  # ccf.enforcement's write credential
    # The access key *id*, never the secret key: a tag showing the last four
    # characters of the secret was a fragment of the secret (m365-docs-hub ADR
    # 0005 shows only a masked key id, for the same reason).
    "aws_govcloud": ("access_key_id", "role_arn", "profile"),
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


#: The AWS authentication methods, by the field that names each one.
_AWS_METHODS = {
    "access_key_id": ("access_key_id", "secret_access_key", "session_token"),
    "role_arn": ("role_arn", "external_id"),
    "profile": ("profile",),
}


def without_other_aws_methods(
    stored: dict[str, Any], posted: dict[str, Any]
) -> dict[str, Any]:
    """``stored`` minus the fields of any AWS method other than the one posted.

    The settings form merges what is posted over what is stored. Posting a
    role ARN over a stored key pair is a switch of method, not a request to
    hold both, so the key pair is dropped here (and vice versa).
    """
    chosen = next((m for m in _AWS_METHODS if str(posted.get(m) or "").strip()), None)
    if chosen is None:
        return stored
    drop = {f for m, fields in _AWS_METHODS.items() if m != chosen for f in fields}
    return {k: v for k, v in stored.items() if k not in drop}


async def _prove_aws(secret: dict[str, Any]) -> dict[str, Any]:
    """Ask AWS before storing: a credential it rejects is never written.

    The account recorded is the one STS reports, and a declared ``account_id``
    must agree with it (m365-docs-hub ADR 0005, control 1). When this host
    cannot ask -- capture disabled, or boto3 absent -- the credential is stored
    unproven and the connector's own verify reports that, which is the state
    before this existed; refusing would make a credential impossible to stage.
    """
    from .aws import AwsGovCloudConnector  # noqa: PLC0415 -- aws imports this package

    connector = AwsGovCloudConnector(secret)
    if not connector.is_configured():
        return secret
    result = await connector.verify()
    if not result.get("connected"):
        raise IncompleteCredential(
            f"AWS did not accept this credential, so it was not stored: {result.get('reason')}"
        )
    declared = str(secret.get("account_id") or "").strip()
    reported = str(result.get("account") or "")
    if declared and reported and declared != reported:
        raise IncompleteCredential(
            "the credential belongs to a different AWS account than the one entered"
        )
    return {**secret, "account_id": reported} if reported else secret


def _prepare_aws_bundle(secret: dict[str, Any], cfg: ConnectorConfig) -> dict[str, Any]:
    """One authentication method per bundle; a role gets this org's External ID.

    Two methods in one bundle left it to reader order which identity Concord
    acted as -- and the settings form merges a new entry over the stored one,
    so switching from keys to a role would otherwise keep both.
    """
    named = [m for m in _AWS_METHODS if str(secret.get(m) or "").strip()]
    if len(named) > 1:
        raise IncompleteCredential(
            "choose one way to authenticate: an access key pair, a role ARN, or a profile"
        )
    if named == ["access_key_id"]:
        key_id = str(secret["access_key_id"]).strip()
        token = str(secret.get("session_token") or "").strip()
        # A temporary (ASIA) key is unusable without its session token, and a
        # token beside a long-lived (AKIA) key would make AWS reject the
        # signature -- both refused here rather than discovered at scan time.
        if key_id.startswith("ASIA") and not token:
            raise IncompleteCredential("a temporary (ASIA...) access key needs its session token")
        if key_id.startswith("AKIA") and token:
            raise IncompleteCredential(
                "a session token goes only with a temporary (ASIA...) key, not an AKIA... key"
            )
    if named != ["role_arn"]:
        return secret
    region = str(secret.get("region") or get_settings().aws_region)
    try:
        aws_identity.validate_role(
            str(secret["role_arn"]), region, account_id=secret.get("account_id")
        )
    except aws_identity.RoleConfigError as exc:
        raise IncompleteCredential(str(exc)) from exc
    config = dict(cfg.config or {})
    external_id = config.get("external_id")
    if not (isinstance(external_id, str) and aws_identity.EXTERNAL_ID_RE.match(external_id)):
        external_id = aws_identity.new_external_id()
        config["external_id"] = external_id
        cfg.config = config
    return {**secret, "external_id": external_id}


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
    prove: bool = False,
) -> ConnectorConfig:
    """Create/update the organization's stored credential for a connector.

    The plaintext secret bundle is enveloped immediately and never stored or
    logged; only a non-reversible ``key_last4`` identifier is retained for
    display. Raises via :func:`ccf.ai.cipher.build_cipher` (fail-closed) if
    credential storage is not configured (no master key set).
    """
    if org_id is None:
        raise ValueError("a connector credential must be bound to an organization")
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
        cfg: ConnectorConfig | None = config
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
    # A value Concord generates is never taken from the request -- for AWS that
    # is the External ID, the confused-deputy guard, which a caller choosing it
    # would defeat. Dropped here, the one place both write paths go through.
    secret = dict(secret)
    spec = spec_for(connector_type)
    for f in spec.fields if spec else ():
        if f.generated:
            secret.pop(f.name, None)
    if connector_type == "aws_govcloud":
        secret = _prepare_aws_bundle(secret, cfg)
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
    if prove and connector_type == "aws_govcloud":
        secret = await _prove_aws(secret)
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
        "readiness_status": cfg.readiness_status,
        "readiness_checked_at": cfg.readiness_checked_at,
        "readiness_detail": cfg.readiness_detail,
    }
