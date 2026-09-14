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

from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from ..config import get_settings
from ..logging import get_logger
from ..posture.providers import m365
from ..posture.types import CheckOutcome, PostureCheck, ResourceFinding
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)


class MsGraphConnector(ConfigConnector):
    key = "msgraph"
    label = "Microsoft 365 Government (Graph)"

    #: Hard cap on pages followed, so a pathological or self-referential
    #: ``@odata.nextLink`` cannot spin forever.
    _MAX_PAGES: ClassVar[int] = 50

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

    async def _get_all(
        self, client: httpx.AsyncClient, url: str, headers: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Every page of a Graph collection, following ``@odata.nextLink``.

        Posture scanning needs this where :meth:`capture` does not: capture
        reads Conditional Access policies, of which there are few, but a fleet
        check that stopped at page one would report ``pass`` while three
        non-compliant users sat on page four. Raises on a non-2xx status so
        :meth:`scan` can tell "could not look" from "nothing to see".
        """
        rows: list[dict[str, Any]] = []
        next_url: str | None = url
        for _ in range(self._MAX_PAGES):
            if not next_url:
                break
            resp = await client.get(next_url, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            rows.extend(payload.get("value") or [])
            nxt = payload.get("@odata.nextLink")
            next_url = nxt if isinstance(nxt, str) else None
        return rows

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

    async def scan(self) -> list[CheckOutcome]:
        """Assess this tenant against the registered M365 posture checks.

        Never raises: an unconfigured org, a failed token, or a provider error
        all produce results (or none) rather than an exception, because
        ``ConfigConnector.scan``'s contract says so and ``scan_for_system``
        does not expect one.
        """
        if not self.is_configured():
            return []
        s = get_settings()
        tenant_id = str((self.credential or {}).get("tenant_id") or "unknown")
        outcomes: list[CheckOutcome] = []
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                token = await self._token(client)
                if not token:
                    return []
                headers = {"Authorization": f"Bearer {token}"}
                now = datetime.now(UTC)
                for check in m365.CHECKS:
                    # Per-check isolation: one permission gap must not discard
                    # the checks that did run, matching capture()'s
                    # per-sub-capture try and the scheduler's per-tenant
                    # savepoint.
                    try:
                        rows = await self._get_all(
                            client, f"{s.graph_base_url}{m365.ENDPOINTS[check.key]}", headers
                        )
                    except Exception as e:
                        outcomes.append(self._unrunnable(check, e))
                        continue
                    outcomes.append(self._evaluate(check, rows, tenant_id=tenant_id, now=now))
        except Exception as e:  # token/transport failure -- nothing to report
            log.warning("connector.msgraph.scan_failed", error=str(e)[:200])
            return []
        return outcomes

    def _evaluate(
        self,
        check: PostureCheck,
        rows: list[dict[str, Any]],
        *,
        tenant_id: str,
        now: datetime,
    ) -> CheckOutcome:
        """Dispatch one check's rows to its evaluator.

        The evaluators take different keyword arguments -- the tenant check
        needs the tenant id, the staleness check needs a clock -- so each is
        called with what it declares rather than forcing a uniform signature
        that most checks would ignore.
        """
        evaluator = m365.EVALUATORS[check.key]
        if check.key == m365.LEGACY_AUTH_BLOCKED.key:
            findings = evaluator(rows, tenant_id=tenant_id)
        elif check.key == m365.STALE_ACCOUNTS.key:
            findings = evaluator(rows, now=now)
        else:
            findings = evaluator(rows)
        return CheckOutcome.from_findings(check, tuple(findings))

    def _unrunnable(self, check: PostureCheck, error: Exception) -> CheckOutcome:
        """A check that could not run -- never a clean fleet.

        P2a's rollup maps zero findings to ``not_applicable``, so returning
        nothing here would hide a missing app permission behind a
        benign-looking verdict. Instead one finding carries
        ``manual_review_required`` and names the status and the permission the
        check needs, which puts the reason in the resource list where an
        operator looks.
        """
        status = ""
        if isinstance(error, httpx.HTTPStatusError):
            status = f"{error.response.status_code} "
        needed = ", ".join(check.required_permissions) or "unknown permissions"
        log.warning(
            "connector.msgraph.check_unrunnable", check=check.key, error=str(error)[:200]
        )
        return CheckOutcome.from_findings(
            check,
            (
                ResourceFinding(
                    resource_id=(self.credential or {}).get("tenant_id") or "unknown",
                    resource_type=check.resource_type,
                    verdict="manual_review_required",
                    observed=f"{status}could not read Graph; requires {needed}",
                    detail={"error": str(error)[:300]},
                ),
            ),
        )

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
