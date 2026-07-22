"""Microsoft Graph config-capture connector (M365 Government / GCC High).

Reads tenant configuration via Microsoft Graph to inform organization-defined
parameters. Uses client-credentials OAuth against the Government login/Graph
endpoints by default (override via ``CCF_GRAPH_*`` settings for commercial).

The tenant/client id + client secret are the calling organization's OWN app
registration — passed in as ``credential`` (see :mod:`ccf.connectors.credentials`)
and resolved per-org, never read from global settings (IA-05). Only the Graph
cloud endpoint (Gov vs. commercial) is deployment-wide configuration.

The OAuth + fetch plumbing is real and works once an app registration with the
appropriate application permissions (e.g. ``Policy.Read.All``) is configured.
The value→ODP mapping is deliberately conservative: we only emit a captured
parameter when the live signal maps cleanly to a requirement, and return ``[]``
on any error. Everything else is advertised in :attr:`PARAMETER_MAP` as intended
coverage for the UI, not asserted.
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from ..config import get_settings
from ..logging import get_logger
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)


class MsGraphConnector(ConfigConnector):
    key = "msgraph"
    label = "Microsoft 365 Government (Graph)"

    # ODP key → the Graph signal it is (or will be) derived from.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "mfa_enforced": "Conditional Access grant requiring multi-factor authentication",
        "inactivity_period": "Conditional Access sign-in frequency (session controls)",
        "session_termination_condition": "Conditional Access sign-in frequency / persistent browser",  # noqa: E501
        "nonlocal_maintenance_mfa": "authenticationMethodsPolicy / Conditional Access MFA grant",
        "audit_retention_period": "Purview Audit (unified audit log) retention policy",
        "password_generations_prohibited": "Entra ID password / authentication methods policy",
    }

    def is_configured(self) -> bool:
        c = self.credential
        return bool(c and c.get("tenant_id") and c.get("client_id") and c.get("client_secret"))

    async def _token(self, client: httpx.AsyncClient) -> str | None:
        s = get_settings()
        c = self.credential or {}
        url = f"{s.graph_login_url}/{c.get('tenant_id')}/oauth2/v2.0/token"
        resp = await client.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": c.get("client_id"),
                "client_secret": c.get("client_secret"),
                "scope": f"{s.graph_base_url}/.default",
            },
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        return token if isinstance(token, str) else None

    async def verify(self) -> dict[str, Any]:
        """Confirm we can obtain a Graph token for this org's Gov tenant."""
        s = get_settings()
        if not self.is_configured():
            return {
                "connected": False,
                "reason": "graph credentials not configured for this organization",
            }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                token = await self._token(client)
            return {
                "connected": bool(token),
                "tenant": (self.credential or {}).get("tenant_id"),
                "graph_endpoint": s.graph_base_url,
            }
        except Exception as e:
            return {"connected": False, "reason": str(e)[:200]}

    async def capture(self) -> list[CapturedParameter]:
        if not self.is_configured():
            return []
        s = get_settings()
        out: list[CapturedParameter] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                token = await self._token(client)
                if not token:
                    return []
                headers = {"Authorization": f"Bearer {token}"}
                # Conditional Access sign-in frequency → session/device lock period.
                r = await client.get(
                    f"{s.graph_base_url}/v1.0/identity/conditionalAccess/policies",
                    headers=headers,
                )
                r.raise_for_status()
                payload = r.json()
                out.extend(self._map_conditional_access(payload))
                out.extend(self._map_mfa(payload))
        except Exception as e:  # best-effort — never break the caller
            log.warning("connector.msgraph.capture_failed", error=str(e)[:200])
            return []
        return out

    def _map_mfa(self, payload: dict[str, Any]) -> list[CapturedParameter]:
        """Detect an enabled Conditional Access policy that grants/requires MFA."""
        for pol in payload.get("value", []) or []:
            if (pol.get("state") or "") != "enabled":
                continue
            grant = (pol.get("grantControls") or {}).get("builtInControls") or []
            if "mfa" in grant:
                return [
                    CapturedParameter(
                        odp_key="mfa_enforced",
                        value="required",
                        nist_id="3.5.3",
                        source=f"Graph: Conditional Access '{pol.get('displayName', '')}'",
                        confidence="high",
                        detail={"policy_id": pol.get("id")},
                    )
                ]
        return []

    def _map_conditional_access(self, payload: dict[str, Any]) -> list[CapturedParameter]:
        """Extract a sign-in frequency, mapped to the session-lock ODP."""
        for pol in payload.get("value", []) or []:
            if (pol.get("state") or "") != "enabled":
                continue
            sf = ((pol.get("sessionControls") or {}).get("signInFrequency")) or {}
            if sf.get("isEnabled") and sf.get("value") and sf.get("type"):
                value = f"{sf['value']} {sf['type']}"  # e.g. "15 minutes" / "1 hours"
                return [
                    CapturedParameter(
                        odp_key="inactivity_period",
                        value=value,
                        nist_id="3.1.10",
                        source=f"Graph: Conditional Access '{pol.get('displayName', '')}'",
                        confidence="medium",
                        detail={"policy_id": pol.get("id")},
                    )
                ]
        return []
