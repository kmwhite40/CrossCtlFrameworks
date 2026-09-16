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

``sync_inventory`` has **no production caller yet, deliberately.** ``scan()``
and ``capture()`` are both org-scoped the same way every connector is:
``resolve_credential`` returns one credential per (org, connector) pair, and
the existing driving routes/scheduler steps (``POST /systems/{id}/scan``,
``governance.collection.collect_for_org``) either take the target system as
an explicit argument or don't need one at all. ``sync_inventory`` additionally
needs a *system*, and nothing in the current data model says which of an
org's systems a bound PuppetDB credential's nodes belong to -- an org with
several systems has no existing signal for that mapping, and guessing (e.g.
"the org's first system") would silently mis-file every node for an org with
more than one. Wiring this properly is a real, separable decision (a
connector-to-system binding, most likely) rather than a bug fix, so it is
left unwired here rather than picking an answer under this fix's scope. The
function itself, and its tests, are exercised directly.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..boundary import service as boundary
from ..logging import get_logger
from ..models import InventoryItem
from ..posture.providers import puppetdb as pdb_checks
from ..posture.types import CheckOutcome, PostureCheck, ResourceFinding
from .base import CapturedParameter, ConfigConnector

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..posture.resolve import ResolvedCheck

log = get_logger(__name__)


class PuppetDbTruncatedError(RuntimeError):
    """Raised when PuppetDB reports more rows exist than a bounded read got.

    ``MAX_NODES`` (and the derived fact-row cap) bound the work one call does,
    but a fleet -- or fact set -- larger than that bound must never be
    silently short-read: the unread rows could be exactly the non-compliant
    ones, or the facts that would have populated an inventory row correctly.
    Mirrors the judgement ``GraphPaginationTruncatedError`` makes for the
    msgraph connector's page cap.
    """


class PuppetDbConfigError(RuntimeError):
    """Raised when the tenant-supplied ``base_url`` is not safe to send a
    request -- let alone the ``X-Authentication`` token -- to."""


def _validate_base_url(url: str) -> None:
    """Require ``https://`` and a bare host, no path/query/fragment.

    Reuses the shape of ``ccf.packs.sync.validate_pack_source_url`` (scheme
    check, no-host check) -- deliberately NOT its RFC1918 rule. That pack
    check exists because a pack source is expected to be a public catalog
    endpoint; PuppetDB is normally an *internal* service reached by hostname
    or a private address, so banning RFC1918/link-local here would reject
    exactly the deployments this connector exists to talk to. What still
    matters regardless of network position: the scheme, so the auth token
    this connector attaches to every request never travels over cleartext
    HTTP, and the absence of a path/query/fragment, so a tenant-supplied
    ``base_url`` cannot smuggle extra path segments or query parameters into
    every request built from it.
    """
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise PuppetDbConfigError(
            f"puppetdb base_url must use https; got {parsed.scheme or '(none)'!r}"
        )
    if not parsed.hostname:
        raise PuppetDbConfigError(f"puppetdb base_url has no host: {url!r}")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise PuppetDbConfigError(
            f"puppetdb base_url must not carry a path, query, or fragment: {url!r}"
        )

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
        """Validated on every call -- see :func:`_validate_base_url` -- so an
        invalid ``base_url`` is refused before ``httpx`` ever builds a request
        from it (and, since this runs before :meth:`_headers` in every caller
        below, before the auth token is ever attached to one)."""
        base = str((self.credential or {}).get("base_url", "")).rstrip("/")
        _validate_base_url(base)
        return f"{base}{path}"

    async def _request(
        self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None
    ) -> tuple[list[dict[str, Any]], httpx.Headers]:
        """One PuppetDB query. Raises on a non-2xx status, or on a 200 whose
        body is not a JSON array.

        PuppetDB returns a JSON error object with a 200 status for some
        malformed queries; treating that as ``[]`` would read as "no fleet"
        rather than "could not look" -- the same distinction a non-2xx status
        already gets via ``raise_for_status``.
        """
        resp = await client.get(self._url(path), headers=self._headers(), params=params)
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, list):
            raise ValueError(
                f"PuppetDB returned a non-list payload for {path}: "
                f"{type(payload).__name__}"
            )
        return payload, resp.headers

    async def _get(
        self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """One PuppetDB query, without a truncation check. See
        :meth:`_get_bounded` for a query that must not silently short-read."""
        payload, _headers = await self._request(client, path, params)
        return payload

    async def _get_bounded(
        self,
        client: httpx.AsyncClient,
        path: str,
        *,
        limit: int,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Every row up to ``limit``, refusing a result larger than that.

        Passes ``include_total=true`` so PuppetDB reports the queryable row
        count on the ``X-Records`` response header; when that count exceeds
        what was actually read, raises :class:`PuppetDbTruncatedError` instead
        of handing the caller a partial fleet that could roll up to a verdict
        the unread rows would have contradicted.

        ``X-Records`` is best-effort: an older PuppetDB build, or a proxy that
        drops the header, leaves the total unknown and the bounded read
        proceeds -- the same posture this connector had before the check
        existed, not worse.
        """
        query = dict(params or {})
        query["limit"] = limit
        query["include_total"] = "true"
        payload, headers = await self._request(client, path, query)
        total_raw = headers.get("X-Records")
        if total_raw is not None:
            try:
                total = int(total_raw)
            except ValueError:
                total = None
            if total is not None and total > len(payload):
                raise PuppetDbTruncatedError(
                    f"{path} returned {len(payload)} of {total} row(s) at "
                    f"limit={limit}; refusing to evaluate a truncated fleet"
                )
        return payload

    async def verify(self) -> dict[str, Any]:
        """Confirm the query API answers, and say how many nodes it knows."""
        if not self.is_configured():
            return {
                "connected": False,
                "reason": "puppetdb base_url not configured for this organization",
            }
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
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

    async def scan(
        self, checks: tuple[ResolvedCheck, ...] | None = None
    ) -> list[CheckOutcome]:
        """Assess the fleet against the registered PuppetDB checks.

        Never raises: an unconfigured org or a transport failure produces no
        outcomes rather than an exception, matching ``ConfigConnector.scan``'s
        contract. One query serves both checks, because PuppetDB returns the
        run status and the report timestamp on the same node record.

        The parameter is named ``checks`` (not ``checks_``) to match
        :meth:`ConfigConnector.scan` -- the base signature is the contract the
        sole production caller (``posture.scan.scan_for_system``) calls
        against, by keyword.
        """
        if not self.is_configured():
            return []
        resolved = tuple(pdb_checks.CHECKS) if checks is None else tuple(checks)
        if not resolved:
            return []
        try:
            async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
                nodes = await self._get_bounded(
                    client, "/pdb/query/v4/nodes", limit=self.MAX_NODES
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
        evaluator = pdb_checks.EVALUATORS[check.key]
        if check.key == pdb_checks.NODE_REPORTING.key:
            findings = evaluator(nodes, now=now)
        else:
            findings = evaluator(nodes)
        return CheckOutcome.from_findings(check, tuple(findings))

    def _unrunnable(self, check: PostureCheck, error: Exception) -> CheckOutcome:
        """A check that could not run -- never a clean fleet.

        Zero findings roll up to ``not_applicable``, so returning nothing here
        would hide an unreachable or unauthorized PuppetDB behind a
        benign-looking verdict. A truncated read (:class:`PuppetDbTruncatedError`)
        gets its own message naming the truncation rather than being described
        as a permissions problem.
        """
        log.warning(
            "connector.puppetdb.check_unrunnable", check=check.key, error=str(error)[:200]
        )
        if isinstance(error, PuppetDbTruncatedError):
            observed = f"fleet larger than could be safely read: {error}"[:400]
        else:
            status = ""
            if isinstance(error, httpx.HTTPStatusError):
                status = f"{error.response.status_code} "
            needed = ", ".join(check.required_permissions) or "query access"
            observed = f"{status}could not query PuppetDB; requires {needed}"
        return CheckOutcome.from_findings(
            check,
            (
                ResourceFinding(
                    resource_id=str((self.credential or {}).get("base_url") or "unknown"),
                    resource_type=check.resource_type,
                    verdict="manual_review_required",
                    observed=observed,
                    detail={"error": str(error)[:300]},
                ),
            ),
        )

    async def nodes_with_facts(self) -> list[dict[str, Any]]:
        """Every node, with the subset of facts an inventory row needs.

        Facts are fetched once for the whole fleet and grouped in memory rather
        than per node: a thousand nodes would otherwise be a thousand round
        trips, and PuppetDB's fact query already supports returning them all.

        The facts query is filtered server-side to :data:`INVENTORY_FACTS` --
        a real node carries 200-500 facts, and pulling all of them just to
        discard everything but ~13 known names in Python is what let the row
        cap (previously ``MAX_NODES * 20``) start truncating around 300
        nodes. Filtered, the theoretical ceiling is one row per node per
        tracked fact, so the same ``MAX_NODES``-derived cap now covers a
        fleet twenty times larger -- and :meth:`_get_bounded` still raises
        rather than silently truncating if even that is exceeded.
        """
        if not self.is_configured():
            return []
        fact_limit = self.MAX_NODES * len(INVENTORY_FACTS)
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=False) as client:
            nodes = await self._get_bounded(
                client, "/pdb/query/v4/nodes", limit=self.MAX_NODES
            )
            facts = await self._get_bounded(
                client,
                "/pdb/query/v4/facts",
                limit=fact_limit,
                params={"query": json.dumps(["in", "name", list(INVENTORY_FACTS)])},
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
        # Merge into props rather than replace it wholesale: a human can add
        # their own keys to an existing row's props (asset tags, a ticket
        # reference, anything this connector doesn't itself track), and a
        # sync that overwrote the whole dict with only the machine-observed
        # facts would silently discard them on the very next run.
        merged_fields = {**fields, "props": {**(row.props or {}), **fields["props"]}}
        await boundary.update_inventory_item(session, item_id=row.id, data=merged_fields)
        result["updated"] += 1

    log.info("connector.puppetdb.inventory_synced", system_id=system_id, **result)
    return result
