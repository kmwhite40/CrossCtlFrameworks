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
on any error.

``PARAMETER_MAP`` describes what this connector captures — not what it might
------------------------------------------------------------------------------
``connectors/base.py`` defines ``PARAMETER_MAP`` as what a connector *would*
pull once credentials are configured, and ``api/routes/ssp.py`` returns it for
an unconfigured connector so the UI can show exactly that. It is a claim made
to an operator about the product, so it may not carry an aspiration.

This map used to advertise six keys while ``capture()`` emitted two.
``session_termination_condition``, ``nonlocal_maintenance_mfa``,
``audit_retention_period`` and ``password_generations_prohibited`` were
"intended coverage for the UI" — which is indistinguishable, to the operator
reading the screen, from coverage. They are removed rather than implemented:
each needs a Graph source this connector does not read (the authentication
methods policy, the Purview unified-audit retention policy), and adding four
integrations is not a parity fix. Re-adding a key means adding the sub-capture
in the same change, because ``tests/test_connector_capture_parity.py`` drives
``capture()`` against a stubbed transport and asserts the emitted keys equal
this map's keys.

Both emitted ids are 800-171 (``3.5.3``, ``3.1.10``), which is the namespace an
``m365`` project's entries actually carry — measured: 8 projects, 880 entries,
all ``3.x.y``, zero 800-53. ``nist_id`` is the join key
``governance/automation.py`` matches against ``SSPControlEntry.nist_id``, so a
capture in the other namespace would be stored and silently never rendered.
"""

from __future__ import annotations

import asyncio
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


class GraphPaginationTruncatedError(RuntimeError):
    """Raised when ``_get_all`` hits the page cap with a page still pending.

    A fleet check evaluated on a partial page set is worse than one that did
    not run at all -- it can roll up to ``pass`` while the unread pages hide
    the non-compliant rows. This is never swallowed silently.
    """


class MsGraphConnector(ConfigConnector):
    key = "msgraph"
    label = "Microsoft 365 Government (Graph)"

    #: Hard cap on pages followed, so a pathological or self-referential
    #: ``@odata.nextLink`` cannot spin forever.
    _MAX_PAGES: ClassVar[int] = 50

    # ODP key → the Graph signal it IS derived from. Every key here is one
    # ``capture()`` actually emits; see the module docstring on why this map
    # may not carry an aspiration.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "mfa_enforced": "Conditional Access grant requiring multi-factor authentication",
        "inactivity_period": "Conditional Access sign-in frequency (session controls)",
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

        Hitting :attr:`_MAX_PAGES` with a ``nextLink`` still outstanding is
        the same danger relocated to page 51: it raises
        :class:`GraphPaginationTruncatedError` rather than returning a partial
        fleet that would roll up to a false ``pass``.
        """
        s = get_settings()
        base = httpx.URL(s.graph_base_url)
        rows: list[dict[str, Any]] = []
        next_target: str | None = url
        for _ in range(self._MAX_PAGES):
            if not next_target:
                return rows
            resp = await self._get_with_retry(
                client, self._safe_url(base, next_target), headers
            )
            resp.raise_for_status()
            payload = resp.json()
            rows.extend(payload.get("value") or [])
            nxt = payload.get("@odata.nextLink")
            next_target = nxt if isinstance(nxt, str) else None
        if next_target:
            raise GraphPaginationTruncatedError(
                f"stopped after {self._MAX_PAGES} pages with more pages remaining "
                "-- refusing to evaluate a partial fleet"
            )
        return rows

    async def _get_with_retry(
        self, client: httpx.AsyncClient, url: httpx.URL | str, headers: dict[str, Any]
    ) -> httpx.Response:
        """One bounded retry on HTTP 429, honoring ``Retry-After``.

        Graph throttles ``/users`` and the reports endpoints hard, so a
        multi-page fleet scan of a real tenant will hit it. A single retry
        keeps the check usable without turning this into an unbounded
        backoff loop -- a second consecutive 429 is surfaced like any other
        transport failure.
        """
        resp = await client.get(url, headers=headers)
        if resp.status_code == 429:
            await asyncio.sleep(self._retry_after_seconds(resp.headers.get("Retry-After")))
            resp = await client.get(url, headers=headers)
        return resp

    @staticmethod
    def _retry_after_seconds(value: str | None) -> float:
        """Seconds to wait, from a ``Retry-After`` header. Bounded and safe.

        Graph sends a plain integer-seconds value here (never the HTTP-date
        form), but a missing or unparseable header must not raise, and a
        pathological value must not stall the scan.
        """
        if value is None:
            return 1.0
        try:
            seconds = float(value)
        except ValueError:
            return 1.0
        return min(max(seconds, 0.0), 30.0)

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
                    # Per-check isolation: one permission gap -- or one
                    # pack's malformed rule, or an evaluator failure on an
                    # unexpected Graph shape -- must not discard the checks
                    # that did run, matching capture()'s per-sub-capture try
                    # and the scheduler's per-tenant savepoint. Fetch and
                    # evaluation each have their own try below, so an
                    # exception from either (e.g. a naive datetime from a
                    # timestamp Graph returned without an offset) produces
                    # _unrunnable for THIS check, not escape to the outer
                    # except and discard every outcome collected so far.
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
        ``manual_review_required`` and names the reason, which puts it in the
        resource list where an operator looks. The verdict is the same in
        every case; only the message differs, and only a 401/403 blames a
        missing permission -- a 429, a 500, a timeout, a truncated fleet, or a
        malformed payload are described by what they actually are, so an
        operator is never told to grant a permission that was never the
        problem.
        """
        observed = self._describe_failure(check, error)
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
                    observed=observed,
                    detail={"error": str(error)[:300]},
                ),
            ),
        )

    @staticmethod
    def _describe_failure(check: PostureCheck, error: Exception) -> str:
        """A human-readable reason a check could not run.

        Only 401/403 name the required permission -- every other failure
        class (throttling, a server error, a timeout, a dropped connection, a
        truncated fleet, an unparseable payload) is described by what it
        actually is instead.
        """
        if isinstance(error, httpx.HTTPStatusError):
            code = error.response.status_code
            if code in (401, 403):
                needed = ", ".join(check.required_permissions) or "unknown permissions"
                return f"{code} could not read Graph; requires {needed}"
            return f"Graph returned {code}; could not evaluate this check"
        if isinstance(error, GraphPaginationTruncatedError):
            return f"could not evaluate this check: {error}"
        if isinstance(error, httpx.TimeoutException):
            return "Graph request timed out; could not evaluate this check"
        if isinstance(error, httpx.RequestError):
            return f"could not reach Graph ({type(error).__name__}); could not evaluate this check"
        return f"could not evaluate this check ({type(error).__name__})"

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
