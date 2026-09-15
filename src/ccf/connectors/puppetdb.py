"""PuppetDB connector -- read the fleet, and whether its state is enforced.

Read-only by design and by scope: the directive asked for an inventory
*source*. Nothing here compiles a catalog, triggers an agent run, or enforces a
resource. Concord's enforcement capability writes through its own gated
provider protocol, and adding Puppet to that is a separate decision.

Two things are worth reading. ``/pdb/query/v4/nodes`` carries each node's
``report_timestamp`` and ``latest_report_status``, which together answer
"is this node managed, and is its declared configuration actually being
applied" -- see :mod:`ccf.posture.providers.puppetdb`. And node facts populate
``InventoryItem``, which CM-8 requires and which a configuration-management
database is usually the most authoritative source for.

``capture()`` returns ``[]`` deliberately. Puppet facts describe the machine
(``os``, ``kernel``, ``ipaddress``), not the policy values Concord's ODPs track
-- session-lock periods, MFA enforcement, audit retention. Inventing a mapping
from ``kernel`` to an ODP would be worse than returning nothing, and
``ConfigConnector.capture``'s contract already says empty is a legitimate
answer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..boundary import service as boundary
from ..logging import get_logger
from ..models import InventoryItem
from ..posture.providers import puppetdb as checks
from ..posture.types import CheckOutcome, PostureCheck, ResourceFinding
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)

#: Facts worth pulling onto an inventory row. Deliberately a short list: a
#: PuppetDB fact set runs to hundreds of keys, and copying all of them into
#: ``props`` would turn an inventory record into a data dump nobody reads.
INVENTORY_FACTS = (
    "os",
    "osfamily",
    "operatingsystem",
    "operatingsystemrelease",
    "kernel",
    "kernelrelease",
    "fqdn",
    "ipaddress",
    "virtual",
    "is_virtual",
    "serialnumber",
    "manufacturer",
    "productname",
)


class PuppetDbConnector(ConfigConnector):
    key = "puppetdb"
    label = "PuppetDB (configuration management)"

    #: Hard cap on nodes pulled in one sync, so a pathological fleet size
    #: cannot turn an inventory refresh into an unbounded read.
    MAX_NODES: ClassVar[int] = 5000

    PARAMETER_MAP: ClassVar[dict[str, str]] = {}

    def is_configured(self) -> bool:
        """A base URL is enough.

        A token is optional because many PuppetDB deployments sit behind mTLS
        or a private network rather than bearer auth. An unauthorized response
        is reported as a finding naming the problem, the same way the Graph
        connector reports a 403 -- which is more useful than refusing to try.
        """
        c = self.credential
        return bool(c and c.get("base_url"))

    def _headers(self) -> dict[str, str]:
        token = (self.credential or {}).get("token")
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Authentication"] = str(token)
        return headers

    def _url(self, path: str) -> str:
        base = str((self.credential or {}).get("base_url", "")).rstrip("/")
        return f"{base}{path}"

    async def _get(
        self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """One PuppetDB query. Raises on a non-2xx so the caller can distinguish
        "could not look" from "nothing to see"."""
        resp = await client.get(self._url(path), headers=self._headers(), params=params)
        resp.raise_for_status()
        payload = resp.json()
        return payload if isinstance(payload, list) else []

    async def verify(self) -> dict[str, Any]:
        """Confirm the query API answers, and say how many nodes it knows."""
        if not self.is_configured():
            return {
                "connected": False,
                "reason": "puppetdb base_url not configured for this organization",
            }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                nodes = await self._get(
                    client, "/pdb/query/v4/nodes", {"limit": self.MAX_NODES}
                )
            return {
                "connected": True,
                "endpoint": self._url(""),
                "nodes": len(nodes),
            }
        except Exception as e:
            return {"connected": False, "reason": str(e)[:200]}

    async def capture(self) -> list[CapturedParameter]:
        """Always empty -- see the module docstring."""
        return []

    async def scan(self, checks_: Any = None) -> list[CheckOutcome]:
        """Assess the fleet against the registered PuppetDB checks.

        Never raises: an unconfigured org or a transport failure produces no
        outcomes rather than an exception, matching ``ConfigConnector.scan``'s
        contract. One query serves both checks, because PuppetDB returns the
        run status and the report timestamp on the same node record.
        """
        if not self.is_configured():
            return []
        resolved = tuple(checks.CHECKS) if checks_ is None else tuple(checks_)
        if not resolved:
            return []
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                nodes = await self._get(
                    client, "/pdb/query/v4/nodes", {"limit": self.MAX_NODES}
                )
        except Exception as e:
            log.warning("connector.puppetdb.scan_failed", error=str(e)[:200])
            return [self._unrunnable(self._check_of(rc), e) for rc in resolved]

        now = datetime.now(UTC)
        outcomes: list[CheckOutcome] = []
        for rc in resolved:
            check = self._check_of(rc)
            try:
                outcomes.append(self._evaluate(check, nodes, now=now))
            except Exception as e:
                # A check that silently stops producing results is
                # indistinguishable from one that passes.
                outcomes.append(self._unrunnable(check, e))
        return outcomes

    @staticmethod
    def _check_of(rc: Any) -> PostureCheck:
        """Accept either a bare check or a resolved one, as msgraph does."""
        check = getattr(rc, "check", rc)
        if not isinstance(check, PostureCheck):
            raise TypeError(f"not a posture check: {type(check).__name__}")
        return check

    def _evaluate(
        self, check: PostureCheck, nodes: list[dict[str, Any]], *, now: datetime
    ) -> CheckOutcome:
        evaluator = checks.EVALUATORS[check.key]
        if check.key == checks.NODE_REPORTING.key:
            findings = evaluator(nodes, now=now)
        else:
            findings = evaluator(nodes)
        return CheckOutcome.from_findings(check, tuple(findings))

    def _unrunnable(self, check: PostureCheck, error: Exception) -> CheckOutcome:
        """A check that could not run -- never a clean fleet.

        Zero findings roll up to ``not_applicable``, so returning nothing here
        would hide an unreachable or unauthorized PuppetDB behind a
        benign-looking verdict.
        """
        status = ""
        if isinstance(error, httpx.HTTPStatusError):
            status = f"{error.response.status_code} "
        needed = ", ".join(check.required_permissions) or "query access"
        log.warning(
            "connector.puppetdb.check_unrunnable", check=check.key, error=str(error)[:200]
        )
        return CheckOutcome.from_findings(
            check,
            (
                ResourceFinding(
                    resource_id=str((self.credential or {}).get("base_url") or "unknown"),
                    resource_type=check.resource_type,
                    verdict="manual_review_required",
                    observed=f"{status}could not query PuppetDB; requires {needed}",
                    detail={"error": str(error)[:300]},
                ),
            ),
        )

    async def nodes_with_facts(self) -> list[dict[str, Any]]:
        """Every node, with the subset of facts an inventory row needs.

        Facts are fetched once for the whole fleet and grouped in memory rather
        than per node: a thousand nodes would otherwise be a thousand round
        trips, and PuppetDB's fact query already supports returning them all.
        """
        if not self.is_configured():
            return []
        async with httpx.AsyncClient(timeout=120.0) as client:
            nodes = await self._get(
                client, "/pdb/query/v4/nodes", {"limit": self.MAX_NODES}
            )
            facts = await self._get(
                client, "/pdb/query/v4/facts", {"limit": self.MAX_NODES * 20}
            )
        by_node: dict[str, dict[str, Any]] = {}
        for fact in facts:
            name = fact.get("name")
            if name not in INVENTORY_FACTS:
                continue
            certname = fact.get("certname")
            if isinstance(certname, str) and certname:
                by_node.setdefault(certname, {})[str(name)] = fact.get("value")
        return [
            {**node, "facts": by_node.get(str(node.get("certname")), {})}
            for node in nodes
        ]


#: Puppet's ``virtual`` fact names the hypervisor for a guest and reports
#: ``physical`` for bare metal, so "is it virtual" is "is it anything else".
_PHYSICAL_VIRTUAL_FACTS = frozenset({"physical", "", "none"})

#: Facts mapped onto first-class inventory columns rather than left in ``props``.
#: Everything else stays in ``props`` so the columns keep their meaning.
_COLUMN_FACTS = {
    "ipaddress": "ip_address",
    "operatingsystemrelease": "version",
    "serialnumber": "serial_number",
    "manufacturer": "vendor_name",
    "productname": "model",
}


def _inventory_fields(node: dict[str, Any]) -> dict[str, Any]:
    """The machine-observed half of an inventory row for one node.

    Deliberately excludes ``description`` and ``asset_type`` beyond a default:
    those are a human's characterisation of the asset, and a sync that
    overwrote them every run would make the inventory unusable for the people
    maintaining it.
    """
    certname = str(node.get("certname") or "")
    facts: dict[str, Any] = dict(node.get("facts") or {})
    fields: dict[str, Any] = {
        "hostname": certname,
        "props": facts,
        "last_seen_at": datetime.now(UTC),
    }
    for fact, column in _COLUMN_FACTS.items():
        value = facts.get(fact)
        if value not in (None, ""):
            fields[column] = str(value)
    virtual = facts.get("virtual", facts.get("is_virtual"))
    if virtual is not None:
        if isinstance(virtual, bool):
            fields["virtual"] = virtual
        else:
            fields["virtual"] = str(virtual).lower() not in _PHYSICAL_VIRTUAL_FACTS
    return fields


async def sync_inventory(
    session: AsyncSession,
    connector: PuppetDbConnector,
    *,
    system_id: int,
    org_id: int,
) -> dict[str, int]:
    """Reconcile PuppetDB nodes into this system's ``InventoryItem`` rows.

    **Additive and idempotent, and it never deletes.** A node missing from a
    query was decommissioned, moved out of the queried scope, *or the query
    silently truncated* -- and the third case is indistinguishable from the
    first two at the API boundary. So a vanished node keeps its row and its
    ``last_seen_at`` goes cold, which is the signal; deleting the row would
    destroy it. This is the same distinction drawn for a ``disappeared``
    resource in posture drift.

    Writes go through :mod:`ccf.boundary.service`, which sets
    ``organization_id`` and ``system_id`` server-side -- the property worth
    reusing rather than writing ``InventoryItem`` directly.

    A human's ``source`` and ``description`` survive a sync. Machine-observed
    facts are refreshed; a person's characterisation of the asset is not
    overwritten, the same discipline ``_upsert_generated_test`` applies to
    human-edited control-test fields.
    """
    result = {"seen": 0, "created": 0, "updated": 0}
    if not connector.is_configured():
        return result

    nodes = await connector.nodes_with_facts()
    existing = {
        row.asset_id: row
        for row in (
            await session.execute(
                select(InventoryItem).where(InventoryItem.system_id == system_id)
            )
        )
        .scalars()
        .all()
    }

    for node in nodes:
        certname = str(node.get("certname") or "")
        if not certname:
            # A row keyed on nothing cannot be matched on a later sync, so it
            # would duplicate on every run.
            log.warning("connector.puppetdb.node_without_certname")
            continue
        result["seen"] += 1
        fields = _inventory_fields(node)
        row = existing.get(certname)
        if row is None:
            await boundary.create_inventory_item(
                session,
                system_id=system_id,
                org_id=org_id,
                data={
                    "asset_id": certname,
                    "asset_type": "hardware",
                    "source": connector.key,
                    **fields,
                },
            )
            result["created"] += 1
            continue
        await boundary.update_inventory_item(session, item_id=row.id, data=fields)
        result["updated"] += 1

    log.info("connector.puppetdb.inventory_synced", system_id=system_id, **result)
    return result
