"""Org-admin connector credentials — bind/list/remove a per-org config-capture
connector credential (Microsoft Graph, AWS GovCloud). Mirrors ``ai_settings``:
an admin-gated JSON API, scoped to the caller's organization, that goes
through :mod:`ccf.connectors.credentials` (never touches the cipher or a
connector adapter directly) and never returns the raw secret bundle.

Fixes the IA-05 functional regression where ``credentials.set_credential``
existed but no route ever called it, so no organization could actually bind a
connector credential over HTTP even though the storage + resolution layer
(and the scheduler's automated capture path) were fully wired.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...ai.cipher import CredentialStorageError
from ...auth import Principal
from ...connectors import connector_keys
from ...connectors import credentials as connector_credentials
from ...models_grc import ConnectorConfig
from ..auth_deps import require_role
from ..deps import get_session

router = APIRouter(prefix="/api/connector-settings", tags=["connector-settings"])


def _org_id(principal: Principal) -> int:
    """The org to scope this request to — always the principal's, never client input."""
    if principal.org_id is None:
        raise HTTPException(400, "organization context required")
    return principal.org_id


def _require_known_connector(connector_type: str) -> None:
    if connector_type not in connector_keys():
        raise HTTPException(
            422, f"connector_type must be one of {', '.join(connector_keys())}"
        )


class ConnectorCredentialIn(BaseModel):
    secret: dict[str, Any]
    name: str | None = None
    environment: str | None = None


@router.get("/credentials")
async def list_credentials(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> list[dict[str, Any]]:
    org_id = _org_id(principal)
    stmt = (
        select(ConnectorConfig)
        .where(
            ConnectorConfig.organization_id == org_id,
            ConnectorConfig.connector_type.in_(connector_keys()),
        )
        .order_by(ConnectorConfig.connector_type)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [connector_credentials.masked_view(c) for c in rows]


@router.post("/credentials/{connector_type}")
async def bind_credential(
    connector_type: str,
    body: ConnectorCredentialIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    _require_known_connector(connector_type)
    org_id = _org_id(principal)
    try:
        cfg = await connector_credentials.set_credential(
            session,
            org_id,
            connector_type,
            body.secret,
            name=body.name,
            environment=body.environment,
            actor=principal.email,
        )
    except CredentialStorageError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return connector_credentials.masked_view(cfg)


@router.delete("/credentials/{connector_type}")
async def remove_credential(
    connector_type: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    _require_known_connector(connector_type)
    org_id = _org_id(principal)
    cfg = (
        await session.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.organization_id == org_id,
                ConnectorConfig.connector_type == connector_type,
            )
        )
    ).scalars().first()
    if cfg is None or not cfg.encrypted_credential:
        raise HTTPException(404, "no credential bound for this connector")
    cfg.encrypted_credential = None
    cfg.key_last4 = None
    cfg.status = "not_configured"
    await session.commit()
    return connector_credentials.masked_view(cfg)
