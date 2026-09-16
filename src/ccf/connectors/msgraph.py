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
from ..posture.declared import evaluate_declared
from ..posture.providers import m365
from ..posture.resolve import ResolvedCheck, resolve_checks_from_registry
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

    def _safe_url(self, base: httpx.URL, target: str) -> httpx.URL:
        """Resolve ``target`` against ``base`` and refuse anything off-host.

        This is the last of three defensive layers against a tenant-declared
        (Form B pack) ``endpoint`` -- or a hostile/compromised
        ``@odata.nextLink`` -- redirecting the org's Graph bearer token to an
        attacker's host (``packs.catalog`` validates at install,
        ``posture.resolve`` re-validates at resolve; this is the layer that
        must hold even if both are bypassed, because it runs immediately
        before the token-bearing request is sent).

        ``httpx.URL(base).join(target)`` resolves ``target`` as an RFC 3986
        relative reference rather than by string concatenation, which is what
        makes it safe: naive concatenation of ``graph_base_url`` (no trailing
        slash) with a tenant-supplied ``".attacker.example/v1.0/users"``
        produces the single string
        ``"https://graph.microsoft.us.attacker.example/v1.0/users"`` --
        a different, attacker-owned host -- and with
        ``"@attacker.example/x"`` produces
        ``"https://graph.microsoft.us@attacker.example/x"``, where the
        pre-``@`` text becomes URL userinfo and ``attacker.example`` becomes
        the actual host. A proper relative-reference join treats both as
        plain path segments under ``base``'s own host. The explicit host
        check below is still required on top of that: it is what rejects a
        ``target`` that is itself absolute (a scheme-relative or fully
        qualified URL) -- including one supplied via a hostile
        ``@odata.nextLink`` response body.
        """
        resolved = base.join(target)
        if resolved.host != base.host:
            raise ValueError(
                f"refusing off-host Graph request: {target!r} resolved to "
                f"host {resolved.host!r}, expected {base.host!r}"
            )
        return resolved

    async def _get_all(
        self, client: httpx.AsyncClient, url: str, headers: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Every page of a Graph collection, following ``@odata.nextLink``.

        Posture scanning needs this where :meth:`capture` does not: capture
        reads Conditional Access policies, of which there are few, but a fleet
        check that stopped at page one would report ``pass`` while three
        non-compliant users sat on page four. Raises on a non-2xx status so
        :meth:`scan` can tell "could not look" from "nothing to see".

        Every page -- the first (``url``, a caller-supplied path or absolute
        URL that may originate from a tenant's declared check) and every
        subsequent one (``@odata.nextLink``, which comes from the response
        body a Graph call returned) -- is resolved through :meth:`_safe_url`
        against the deployment's *configured* ``graph_base_url`` before the
        request goes out. A hostile or compromised response could otherwise
        redirect a paginated, token-bearing fetch off-host on page two just
        as easily as a malicious ``endpoint`` could on page one.
        """
        s = get_settings()
        base = httpx.URL(s.graph_base_url)
        rows: list[dict[str, Any]] = []
        next_target: str | None = url
        for _ in range(self._MAX_PAGES):
            if not next_target:
                break
            resp = await client.get(self._safe_url(base, next_target), headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            rows.extend(payload.get("value") or [])
            nxt = payload.get("@odata.nextLink")
            next_target = nxt if isinstance(nxt, str) else None
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

    async def scan(
        self, checks: tuple[ResolvedCheck, ...] | None = None
    ) -> list[CheckOutcome]:
        """Assess this tenant against its resolved posture checks.

        ``checks`` is ``None`` for a caller that predates declared checks, in
        which case the platform registry is used and behaviour is unchanged.
        An empty tuple scans nothing -- see ``ConfigConnector.scan``.

        Never raises: an unconfigured org, a failed token, or a provider error
        all produce results (or none) rather than an exception, because
        ``ConfigConnector.scan``'s contract says so and ``scan_for_system``
        does not expect one.
        """
        if not self.is_configured():
            return []
        resolved = resolve_checks_from_registry(self.key) if checks is None else checks
        if not resolved:
            return []
        tenant_id = str((self.credential or {}).get("tenant_id") or "unknown")
        outcomes: list[CheckOutcome] = []
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                token = await self._token(client)
                if not token:
                    return []
                headers = {"Authorization": f"Bearer {token}"}
                now = datetime.now(UTC)
                for rc in resolved:
                    # Per-check isolation: one permission gap -- or one pack's
                    # malformed rule -- must not discard the checks that did
                    # run, matching capture()'s per-sub-capture try and the
                    # scheduler's per-tenant savepoint.
                    try:
                        # rc.endpoint may be tenant-declared (a Form B pack
                        # rule); it is passed through as-is and resolved
                        # safely inside _get_all rather than concatenated
                        # onto the host here -- see _safe_url.
                        rows = await self._get_all(client, rc.endpoint, headers)
                    except Exception as e:
                        outcomes.append(self._unrunnable(rc.check, e))
                        continue
                    try:
                        outcomes.append(
                            self._evaluate(rc, rows, tenant_id=tenant_id, now=now)
                        )
                    except Exception as e:
                        # Evaluation itself failed -- a declared spec that
                        # validation would have refused. It must report rather
                        # than vanish: a check that silently stops producing
                        # results is indistinguishable from one that passes.
                        outcomes.append(self._unrunnable(rc.check, e))
        except Exception as e:  # token/transport failure -- nothing to report
            log.warning("connector.msgraph.scan_failed", error=str(e)[:200])
            return []
        return outcomes

    def _evaluate(
        self,
        rc: ResolvedCheck,
        rows: list[dict[str, Any]],
        *,
        tenant_id: str,
        now: datetime,
    ) -> CheckOutcome:
        """Judge one check's rows -- declaratively, or via its evaluator.

        A declared check (Form B) carries its own predicate. A platform check,
        or a pack that parameterized one (Form A), dispatches to the evaluator
        by ``evaluator_key`` rather than by the check's own key, because a
        parameterized check runs under the pack's key while still using the
        platform's logic.

        The evaluators take different keyword arguments -- the tenant check
        needs the tenant id, the staleness check needs a clock -- so each is
        called with what it declares rather than forcing a uniform signature
        that most checks would ignore. Declared parameters are merged on top.
        """
        if rc.spec is not None:
            findings = evaluate_declared(rc.spec, rows, resource_id=tenant_id)
            return CheckOutcome.from_findings(rc.check, tuple(findings))

        evaluator = m365.EVALUATORS[rc.evaluator_key or rc.check.key]
        kwargs: dict[str, Any] = dict(rc.parameters or {})
        if (rc.evaluator_key or rc.check.key) == m365.LEGACY_AUTH_BLOCKED.key:
            kwargs["tenant_id"] = tenant_id
        elif (rc.evaluator_key or rc.check.key) == m365.STALE_ACCOUNTS.key:
            kwargs["now"] = now
        findings = evaluator(rows, **kwargs)
        return CheckOutcome.from_findings(rc.check, tuple(findings))

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
