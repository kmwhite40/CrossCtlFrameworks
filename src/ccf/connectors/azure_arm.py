"""Azure Government config-capture connector (Azure Resource Manager).

Reads a subscription's **infrastructure** configuration through ARM to inform
organization-defined parameters. The transport is the same hand-rolled OAuth2
client-credentials flow ``connectors/msgraph.py`` uses -- ``httpx`` only, no
Azure SDK -- with ARM's own scope (``{arm_base_url}/.default``) and base URL
(``https://management.usgovcloudapi.net`` for Azure Government). The tenant,
client id, client secret and subscription id are the calling organization's OWN
service principal, resolved per-org by :mod:`ccf.connectors.credentials`; there
is no global/env fallback (IA-05).

Scope boundary: ARM is infrastructure, NOT identity
---------------------------------------------------
Entra ID identity for an Azure Government tenant is already
``connectors/msgraph.py``'s territory, and an organization running Azure Gov is
usually the *same* Microsoft tenant Graph authenticates against. Two connectors
emitting the same ODP key for one organization would write two
``CaptureSnapshot`` rows competing for the same ``(organization_id, connector,
odp_key)`` space and put two different answers for one blank into one SSP.

So every ODP key Graph claims is deliberately left to Graph, and this connector
claims none of them:

``mfa_enforced``, ``inactivity_period``, ``session_termination_condition``,
``nonlocal_maintenance_mfa``, ``audit_retention_period`` and
``password_generations_prohibited`` are all identity/Purview signals
(Conditional Access grants and session controls, the authentication methods
policy, the unified audit log retention policy). None of them is readable from
ARM, and all of them are already captured under ``msgraph``.

``audit_retention_period`` is the one worth naming explicitly, because ARM *can*
answer something adjacent: a Log Analytics workspace's ``retentionInDays``. That
is not the same fact -- it is how long *infrastructure* telemetry is kept, not
how long the tenant's unified audit log is -- so it is emitted under its own key
``log_retention_period`` rather than overwriting Graph's answer with a different
measurement of a different thing. ``tests/test_azure_arm_connector.py`` asserts
the two ``PARAMETER_MAP``s are disjoint, so the boundary is enforced rather than
merely intended.

Which ``nist_id`` namespace, and how that was decided
-----------------------------------------------------
``CapturedParameter.nist_id`` is the join key that decides whether a capture
ever reaches a narrative: ``governance/automation.py`` keys ``caps_by_nist`` on
it and matches it against ``SSPControlEntry.nist_id``, so a snapshot with
``nist_id = None`` -- or one in the wrong namespace -- is stored and never read.
The two existing connectors disagree: ``msgraph`` emits 800-171 ids ("3.3.1"),
``aws`` emits 800-53 ("SC-28").

Measured rather than guessed, against the real database, grouping every
``SSPControlEntry`` by its project's platform and the namespace of its
``nist_id``:

* ``platform = "azure"``: 110 entries, **all** 800-171 (``3.x.y``), zero 800-53.
* Every project on the ``nist-800-53r5`` framework (1231 entries, the
  ``seed_80053_project`` path) carries ``platform = "none"`` -- a platform with
  no ``PLATFORM_CONNECTOR_KEYS`` entry at all, so no Azure capture could reach
  one of those narratives even if the namespace matched.
* The handful of 800-53 ids found on CMMC projects were hand-built test
  fixtures, not seeder output.

Both namespaces therefore exist in the product, but only one of them exists on
an Azure project: an Azure project is seeded by ``ssp/seed.py`` from
``ScoringControl.nist_id``, which is 800-171 throughout. **This connector emits
800-171 ids.** For the 800-53 case, each captured parameter also carries its
800-53r5 control id in ``detail["nist_80053_id"]`` -- carried, not emitted as
``nist_id``, so it cannot silently become a second competing answer, and a
future 800-53 join has a documented value to read instead of a re-derivation.

Conservative by construction, like the Graph connector: a value is emitted only
when the ARM response maps cleanly onto a requirement, each sub-capture is
isolated so one missing RBAC role does not discard the rest, and ``capture()``
returns ``[]`` rather than raising on any failure.
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from ..config import get_settings
from ..logging import get_logger
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)

# ARM api-versions, pinned. An unpinned ARM call is a 400, and a floating one
# is a silent shape change on someone else's release schedule.
_API_STORAGE = "2023-01-01"
_API_WORKSPACES = "2022-10-01"
_API_POLICY_ASSIGNMENTS = "2022-06-01"
_API_SECURITY_PRICINGS = "2023-01-01"


class ArmPaginationTruncatedError(RuntimeError):
    """``_get_all`` hit the page cap with a ``nextLink`` still pending.

    A partial resource set is worse than none: "every storage account encrypts
    at rest" read off page one of four is a claim about a quarter of the
    subscription rendered as a claim about all of it.
    """


class AzureArmConnector(ConfigConnector):
    """Azure Government infrastructure capture over Azure Resource Manager."""

    key = "azure_arm"
    label = "Microsoft Azure Government (Resource Manager)"

    #: Hard cap on pages followed, so a pathological or self-referential
    #: ``nextLink`` cannot spin forever. ARM paginates with ``nextLink``,
    #: NOT Graph's ``@odata.nextLink`` -- the two payload shapes are similar
    #: enough to copy by mistake and different enough to silently truncate.
    _MAX_PAGES: ClassVar[int] = 50

    # ODP key → the ARM signal it is derived from. Every key here is
    # infrastructure; see the module docstring for what is left to msgraph.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "encryption_at_rest": (
            "Microsoft.Storage/storageAccounts encryption (service encryption + "
            "requireInfrastructureEncryption)"
        ),
        "transmission_confidentiality": (
            "Microsoft.Storage/storageAccounts supportsHttpsTrafficOnly and minimumTlsVersion"
        ),
        "log_retention_period": (
            "Microsoft.OperationalInsights/workspaces retentionInDays (Log Analytics)"
        ),
        "configuration_baseline_enforcement": (
            "Microsoft.Authorization/policyAssignments in effect on the subscription"
        ),
        "malicious_code_protection": (
            "Microsoft.Security/pricings — Defender for Cloud plans on the Standard tier"
        ),
    }

    # ODP key → the 800-53r5 control the same signal informs. Carried in each
    # capture's ``detail`` (never as ``nist_id``); see the module docstring.
    _NIST_80053: ClassVar[dict[str, str]] = {
        "encryption_at_rest": "SC-28",
        "transmission_confidentiality": "SC-8",
        "log_retention_period": "AU-11",
        "configuration_baseline_enforcement": "CM-2",
        "malicious_code_protection": "SI-3",
    }

    # ── credentials ──────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """True only with this org's own full ARM service-principal bundle.

        ``subscription_id`` is required alongside the OAuth triple because
        every ARM read below is scoped to a subscription: a credential without
        one authenticates fine and can read nothing, which would report
        "configured" and capture zero.
        """
        c = self.credential
        return bool(
            c
            and c.get("tenant_id")
            and c.get("client_id")
            and c.get("client_secret")
            and c.get("subscription_id")
        )

    async def _token(self, client: httpx.AsyncClient) -> str | None:
        """An ARM access token via OAuth2 client credentials.

        Identical flow to Graph's, different scope and audience: the token is
        requested for ``{arm_base_url}/.default``, so a Graph token cannot be
        reused here and an ARM token cannot be replayed against Graph.
        """
        s = get_settings()
        c = self.credential or {}
        url = f"{s.arm_login_url}/{c.get('tenant_id')}/oauth2/v2.0/token"
        resp = await client.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": c.get("client_id"),
                "client_secret": c.get("client_secret"),
                "scope": f"{s.arm_base_url}/.default",
            },
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        return token if isinstance(token, str) else None

    # ── transport ────────────────────────────────────────────────────────────

    def _safe_url(self, base: httpx.URL, target: str) -> httpx.URL:
        """Resolve ``target`` against ``base`` and refuse anything off-host.

        The same guard ``connectors/msgraph.py`` documents at length, needed
        here for the same reason: ``nextLink`` arrives in a *response body*, and
        following it carries the organization's ARM bearer token. An RFC 3986
        relative-reference join (rather than string concatenation) keeps a
        crafted ``".attacker.example/..."`` or ``"@attacker.example/x"`` a path
        segment under ``base``'s host, and the explicit host comparison rejects
        a ``target`` that is itself absolute.
        """
        resolved = base.join(target)
        if resolved.host != base.host:
            raise ValueError(
                f"refusing off-host ARM request: {target!r} resolved to "
                f"host {resolved.host!r}, expected {base.host!r}"
            )
        return resolved

    async def _get_all(
        self, client: httpx.AsyncClient, path: str, headers: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Every page of an ARM collection, following ``nextLink``.

        ARM's continuation key is ``nextLink`` — Graph's is ``@odata.nextLink``.
        Reading the wrong one returns page one and reports it as the whole
        subscription, which is exactly the false-clean-fleet failure the page
        cap below also guards against, so it is spelled out rather than shared
        with the Graph helper.

        Raises on a non-2xx status so a caller can tell "could not look" from
        "nothing to see", and raises :class:`ArmPaginationTruncatedError` rather
        than returning a partial resource set.
        """
        base = httpx.URL(get_settings().arm_base_url)
        rows: list[dict[str, Any]] = []
        next_target: str | None = path
        for _ in range(self._MAX_PAGES):
            if not next_target:
                return rows
            resp = await client.get(self._safe_url(base, next_target), headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            value = payload.get("value")
            if isinstance(value, list):
                rows.extend(row for row in value if isinstance(row, dict))
            nxt = payload.get("nextLink")
            next_target = nxt if isinstance(nxt, str) else None
        if next_target:
            raise ArmPaginationTruncatedError(
                f"stopped after {self._MAX_PAGES} pages with more pages remaining "
                "-- refusing to evaluate a partial subscription"
            )
        return rows

    def _sub_path(self, provider_path: str, api_version: str) -> str:
        c = self.credential or {}
        return (
            f"/subscriptions/{c.get('subscription_id')}/{provider_path}"
            f"?api-version={api_version}"
        )

    # ── verify ───────────────────────────────────────────────────────────────

    async def verify(self) -> dict[str, Any]:
        """Confirm an ARM token can be obtained for this org's subscription."""
        s = get_settings()
        if not self.is_configured():
            return {
                "connected": False,
                "reason": "Azure ARM credentials not configured for this organization",
            }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                token = await self._token(client)
            return {
                "connected": bool(token),
                "tenant": (self.credential or {}).get("tenant_id"),
                "subscription": (self.credential or {}).get("subscription_id"),
                "arm_endpoint": s.arm_base_url,
            }
        except Exception as e:
            return {"connected": False, "reason": str(e)[:200]}

    # ── capture ──────────────────────────────────────────────────────────────

    async def capture(self) -> list[CapturedParameter]:
        """Read ARM and return captured parameters. Never raises (base contract).

        Each sub-capture has its own ``try``: a service principal with Reader on
        storage but not on ``Microsoft.Security`` must still contribute its
        encryption finding rather than lose the whole run, which is the same
        per-check isolation ``msgraph.scan`` applies. A token failure or a
        transport failure that escapes an individual read yields ``[]``.
        """
        if not self.is_configured():
            return []
        out: list[CapturedParameter] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                token = await self._token(client)
                if not token:
                    return []
                headers = {"Authorization": f"Bearer {token}"}
                for label, path, mapper in (
                    (
                        "storage",
                        self._sub_path("providers/Microsoft.Storage/storageAccounts", _API_STORAGE),
                        self._map_storage,
                    ),
                    (
                        "workspaces",
                        self._sub_path(
                            "providers/Microsoft.OperationalInsights/workspaces", _API_WORKSPACES
                        ),
                        self._map_log_retention,
                    ),
                    (
                        "policy",
                        self._sub_path(
                            "providers/Microsoft.Authorization/policyAssignments",
                            _API_POLICY_ASSIGNMENTS,
                        ),
                        self._map_policy_assignments,
                    ),
                    (
                        "defender",
                        self._sub_path(
                            "providers/Microsoft.Security/pricings", _API_SECURITY_PRICINGS
                        ),
                        self._map_defender_plans,
                    ),
                ):
                    try:
                        rows = await self._get_all(client, path, headers)
                        out.extend(mapper(rows))
                    except Exception as e:  # one gap must not discard the rest
                        log.warning(
                            "connector.azure_arm.subcapture_failed",
                            source=label,
                            error=str(e)[:200],
                        )
        except Exception as e:  # token/transport failure — best-effort contract
            log.warning("connector.azure_arm.capture_failed", error=str(e)[:200])
            return []
        return out

    # ── mappers (pure; testable against recorded ARM shapes) ────────────────

    @staticmethod
    def _props(row: dict[str, Any]) -> dict[str, Any]:
        """A resource's ``properties`` bag, or ``{}``.

        ARM nests every setting under ``properties``, and a resource can come
        back without it (a partial projection, a preview api-version). One
        accessor so no mapper has to re-derive "absent means empty".
        """
        props = row.get("properties")
        return props if isinstance(props, dict) else {}

    def _captured(
        self, odp_key: str, value: str, nist_id: str, source: str, *, confidence: str = "medium",
        detail: dict[str, Any] | None = None,
    ) -> CapturedParameter:
        """One capture, with the 800-53 equivalent carried in ``detail``.

        Built through here rather than at each call site so no mapper can ship a
        capture without its ``nist_id`` or without the 800-53 cross-reference —
        the two fields that decide whether it ever reaches a narrative.
        """
        return CapturedParameter(
            odp_key=odp_key,
            value=value,
            nist_id=nist_id,
            source=source,
            confidence=confidence,
            detail={**(detail or {}), "nist_80053_id": self._NIST_80053[odp_key]},
        )

    def _map_storage(self, rows: list[dict[str, Any]]) -> list[CapturedParameter]:
        """Encryption at rest and in transit, across every storage account.

        Reported as a fleet fact ("N of M"), never as "encrypted" off the first
        account: a subscription with one unencrypted account is not one that
        encrypts CUI at rest, and a capture that said so would be a false claim
        an assessor reads as verified.
        """
        if not rows:
            return []
        total = len(rows)
        encrypted = 0
        https_only = 0
        tls_versions: set[str] = set()
        for row in rows:
            props = self._props(row)
            encryption = props.get("encryption")
            services = (encryption or {}).get("services") if isinstance(encryption, dict) else None
            services = services if isinstance(services, dict) else {}
            blob = services.get("blob")
            file_svc = services.get("file")
            # BOTH services, not either: a storage account that encrypts blobs
            # and not files does not protect CUI at rest, and counting it would
            # overstate the fleet number this capture reports as fact.
            if (
                isinstance(blob, dict)
                and blob.get("enabled")
                and isinstance(file_svc, dict)
                and file_svc.get("enabled")
            ):
                encrypted += 1
            if props.get("supportsHttpsTrafficOnly"):
                https_only += 1
            tls = props.get("minimumTlsVersion")
            if isinstance(tls, str) and tls:
                tls_versions.add(tls)
        out = [
            self._captured(
                "encryption_at_rest",
                f"{encrypted} of {total} storage accounts encrypt blob and file data at rest",
                "3.13.16",
                "Azure ARM: Microsoft.Storage/storageAccounts encryption",
                confidence="high" if encrypted == total else "medium",
                detail={"accounts": total, "encrypted": encrypted},
            )
        ]
        tls_text = (
            f"; minimum TLS {'/'.join(sorted(tls_versions))}" if tls_versions else ""
        )
        out.append(
            self._captured(
                "transmission_confidentiality",
                f"{https_only} of {total} storage accounts require HTTPS{tls_text}",
                "3.13.8",
                "Azure ARM: Microsoft.Storage/storageAccounts supportsHttpsTrafficOnly",
                confidence="high" if https_only == total else "medium",
                detail={
                    "accounts": total,
                    "https_only": https_only,
                    "minimum_tls_versions": sorted(tls_versions),
                },
            )
        )
        return out

    def _map_log_retention(self, rows: list[dict[str, Any]]) -> list[CapturedParameter]:
        """The shortest Log Analytics retention in the subscription.

        The *shortest*, deliberately: retention is only as good as the
        workspace that keeps records for the least time, and reporting the
        longest would let one archive workspace vouch for a 30-day one.
        """
        retentions = [
            days
            for row in rows
            if isinstance(days := self._props(row).get("retentionInDays"), int) and days > 0
        ]
        if not retentions:
            return []
        shortest = min(retentions)
        return [
            self._captured(
                "log_retention_period",
                f"{shortest} days",
                "3.3.1",
                "Azure ARM: Microsoft.OperationalInsights/workspaces retentionInDays",
                confidence="high" if len(retentions) == 1 else "medium",
                detail={"workspaces": len(retentions), "shortest_days": shortest},
            )
        ]

    def _map_policy_assignments(self, rows: list[dict[str, Any]]) -> list[CapturedParameter]:
        """Azure Policy assignments actually in effect on the subscription.

        Assignments whose ``enforcementMode`` is ``DoNotEnforce`` are audit-only
        and are excluded from the count: they observe drift, they do not
        maintain a baseline, and counting them would overstate CM-2/3.4.1.
        """
        enforcing = [
            row
            for row in rows
            if str(self._props(row).get("enforcementMode") or "Default").lower() != "donotenforce"
        ]
        if not enforcing:
            return []
        named = sorted(
            name
            for row in enforcing
            if (name := str(self._props(row).get("displayName") or row.get("name") or ""))
        )
        return [
            self._captured(
                "configuration_baseline_enforcement",
                f"{len(enforcing)} enforcing Azure Policy assignment(s)"
                + (f": {', '.join(named[:5])}" if named else ""),
                "3.4.1",
                "Azure ARM: Microsoft.Authorization/policyAssignments",
                detail={"enforcing": len(enforcing), "audit_only": len(rows) - len(enforcing)},
            )
        ]

    def _map_defender_plans(self, rows: list[dict[str, Any]]) -> list[CapturedParameter]:
        """Defender for Cloud plans on the Standard tier.

        ``Free`` is the tier that runs no workload protection, so only
        ``Standard`` plans are named. No plan on Standard emits nothing rather
        than "malicious code protection: none" — an absence this connector
        observed is reported by staying silent and letting the statement keep
        its manual-evidence obligation, not by asserting a negative control
        state Concord did not verify at the endpoint.
        """
        standard = sorted(
            str(row.get("name") or "")
            for row in rows
            if str(self._props(row).get("pricingTier") or "").lower() == "standard"
            and row.get("name")
        )
        if not standard:
            return []
        return [
            self._captured(
                "malicious_code_protection",
                "Microsoft Defender for Cloud enabled for " + ", ".join(standard),
                "3.14.2",
                "Azure ARM: Microsoft.Security/pricings",
                confidence="high",
                detail={"standard_plans": standard},
            )
        ]
