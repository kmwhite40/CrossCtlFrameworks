"""Provider readiness checks for live posture scanning.

``ConfigConnector.verify()`` proves connectivity, but callers used it as a
one-off diagnostic. A live audit needs the verdict persisted and shaped the
same way everywhere: credentials, provider identity, required permissions, and
the checks that will be blocked if readiness fails.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_grc import ConnectorConfig
from ..posture.resolve import resolve_checks
from ..ssp.responsibility import (
    control_domain,
    responsibility_entry_for,
    scan_applicability,
)
from . import get_connector
from .credentials import resolve_credential

_CONNECTOR_PLATFORM = {
    "msgraph": "m365",
    "aws_govcloud": "aws_govcloud",
    "azure_arm": "azure",
    "gcp": "gcp",
}


def _now() -> datetime:
    return datetime.now(UTC)


async def _config_row(
    session: AsyncSession, *, organization_id: int | None, connector_type: str
) -> ConnectorConfig | None:
    if organization_id is None:
        return None
    return (
        await session.execute(
            select(ConnectorConfig)
            .where(
                ConnectorConfig.organization_id == organization_id,
                ConnectorConfig.connector_type == connector_type,
            )
            .order_by(ConnectorConfig.id)
        )
    ).scalars().first()


async def provider_readiness(
    session: AsyncSession,
    *,
    organization_id: int | None,
    connector_key: str,
    persist: bool = True,
) -> dict[str, Any]:
    """Return and optionally persist scan-readiness for one provider.

    Status vocabulary:
    - ``ready``: connector is configured and provider verification succeeded.
    - ``not_configured``: no tenant credential, incomplete credential, or an
      unconfigured connector.
    - ``unavailable``: configured connector failed provider verification.
    - ``unknown_connector``: the connector key is not registered.
    """
    checked_at = _now()
    resolved = await resolve_checks(session, provider=connector_key, org_id=organization_id)
    platform = _CONNECTOR_PLATFORM.get(connector_key, connector_key)

    def _check_descriptor(rc) -> dict[str, Any]:
        domain = control_domain(rc.check.control_ids[0] if rc.check.control_ids else None)
        responsibility = responsibility_entry_for(platform, domain)
        return {
            "check_key": rc.check.key,
            "title": rc.check.title,
            "expected": rc.check.expected,
            "control_ids": list(rc.check.control_ids),
            "resource_type": rc.check.resource_type,
            "source": rc.source,
            "required_permissions": list(rc.check.required_permissions),
            "responsibility": responsibility.to_dict(),
            "scan_applicability": scan_applicability(responsibility.responsibility),
        }

    required_permissions = sorted(
        {
            permission
            for rc in resolved
            for permission in rc.check.required_permissions
            if permission
        }
    )
    checks = [_check_descriptor(rc) for rc in resolved]

    credential = await resolve_credential(session, organization_id, connector_key)
    connector = get_connector(connector_key, credential=credential)
    if connector is None:
        out = {
            "connector": connector_key,
            "status": "unknown_connector",
            "ready": False,
            "configured": False,
            "connected": False,
            "checked_at": checked_at.isoformat(),
            "checks_expected": len(checks),
            "checks": checks,
            "required_permissions": required_permissions,
            "reason": "unknown connector",
        }
    else:
        configured = connector.is_configured()
        verification = await connector.verify()
        connected = bool(verification.get("connected"))
        status = "ready" if configured and connected else (
            "unavailable" if configured else "not_configured"
        )
        reason = (
            None
            if status == "ready"
            else str(verification.get("reason") or "provider verification failed")
        )
        out = {
            "connector": connector.key,
            "status": status,
            "ready": status == "ready",
            "configured": configured,
            "connected": connected,
            "checked_at": checked_at.isoformat(),
            "checks_expected": len(checks),
            "checks": checks,
            "required_permissions": required_permissions,
            "reason": reason,
            **{
                k: v
                for k, v in verification.items()
                if k not in {"connected", "reason"} and v is not None
            },
            "provider": {
                k: v
                for k, v in verification.items()
                if k not in {"connected", "reason"} and v is not None
            },
        }

    if persist and organization_id is not None:
        cfg = await _config_row(
            session, organization_id=organization_id, connector_type=connector_key
        )
        if cfg is not None:
            cfg.readiness_status = str(out["status"])
            cfg.readiness_checked_at = checked_at
            cfg.readiness_detail = out
            if out["ready"]:
                cfg.status = "configured"
                cfg.error_message = None
            elif out["status"] in {"not_configured", "unavailable"}:
                cfg.status = "error" if out["status"] == "unavailable" else "not_configured"
                cfg.error_message = str(out.get("reason") or "")[:2000] or None
            await session.flush()

    return out
