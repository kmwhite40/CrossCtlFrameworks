# PuppetDB as a read-only inventory and configuration source (CC&E #9)

**Status:** design, awaiting implementation plan
**Extends:** `connectors/`, `posture/providers/`, `boundary/service.py`
**Explicitly optional** in the directive, and last for a reason: everything it
feeds had to exist first.

## 1. Why this is small

Three things it needs are already here, and one of them was built for it:

- **`ConfigConnector`** (`connectors/base.py`) defines `is_configured` /
  `verify` / `capture` / `scan`, with per-org credentials resolved from the
  encrypted store by `connector_type`.
- **The posture spine** takes a provider's checks through `CHECK_REGISTRY` +
  `ENDPOINT_REGISTRY`, evaluates them, rolls them up and records them through
  `record_result` — including declared checks from packs (#1).
- **`InventoryItem` was designed for a connector.** It already carries
  `source` (defaulting to `"manual"`), `last_seen_at`, and a `props` JSONB;
  and `boundary/service.py`'s docstring says its `create_*` functions take a
  structured dict *"so a future connector mapper can call the same
  functions"*. This is that mapper.

So no new tables, no new migration, no new abstraction.

## 2. What PuppetDB is good for here, and what it is not

PuppetDB's query API exposes nodes, facts, resources and run reports. Two of
those answer compliance questions Concord cannot currently answer:

**Node inventory** (`/pdb/query/v4/nodes`, `/pdb/query/v4/facts`) →
`InventoryItem`. CM-8 requires a component inventory, and a
configuration-management database is the most authoritative source most
deployments have for what is actually running.

**Whether desired state is being enforced** (`latest_report_status`,
`report_timestamp`). This is the one worth having and it is not obvious:

- A node whose **last Puppet run failed** is a node where declared
  configuration is *not* being applied. That is a live CM-2/CM-6 finding, and
  nothing in Concord sees it today.
- A node that **stopped reporting** is unmanaged, whatever its last known state
  said. Silence is not compliance.

**What it is not good for:** organization-defined parameters. Puppet facts
describe the machine (`os`, `kernel`, `ipaddress`), not the policy values
Concord's ODPs track — session-lock periods, MFA enforcement, audit retention.
So `capture()` returns `[]`. Inventing a mapping from `kernel` to an ODP would
be worse than returning nothing, and `ConfigConnector.capture`'s contract
already says empty is a legitimate answer.

## 3. Absence is not removal

The inventory sync is **idempotent and additive**. It matches on
`(system_id, asset_id)`, updates what it finds, stamps `last_seen_at`, and
**never deletes a row for a node PuppetDB stopped returning.**

A node missing from a query result was decommissioned, moved out of the
queried scope, *or the query silently truncated* — and the third case is
indistinguishable from the first two at the API boundary. This is exactly the
`disappeared` distinction P2c drew for resource drift, and the same answer
applies: report the staleness, never infer the deletion. `last_seen_at` going
cold is the signal; deleting the row would destroy it.

## 4. Shape

```python
class PuppetDbConnector(ConfigConnector):
    key = "puppetdb"
    async def verify(self) -> dict        # can we query, and how many nodes
    async def capture(self) -> list       # always [] -- see section 2
    async def scan(self, checks=None)     # the two checks below

# posture/providers/puppetdb.py
NODE_REPORTING   # every node reported within the threshold
NODE_LAST_RUN_OK # no node's most recent Puppet run failed

async def sync_inventory(session, connector, *, system_id, org_id) -> dict
```

Credentials: `{"base_url": ..., "token": ...}` in the existing per-org store
under `connector_type="puppetdb"`. A token is optional because many PuppetDB
deployments sit behind mTLS or a private network; `is_configured` requires only
a base URL, and an unauthorized response is reported as
`manual_review_required` naming the permission problem, exactly as the Graph
connector does with a 403.

## 5. What this does NOT do

- **No writes to Puppet.** No catalog compilation, no `puppet agent -t`, no
  resource enforcement. Concord's enforcement capability (#4) writes through
  its own gated provider protocol; adding Puppet to that is a separate
  decision, and the directive asked for an inventory *source*.
- **No node deletion** (§3).
- **No ODP capture** (§2).
- **No new tables.**

## 6. Testing strategy

- Both evaluators are **pure** — nodes in, findings out, `now` injected — and
  tested against recorded PuppetDB node payloads.
- A node with **no `report_timestamp` at all** is `manual_review_required`,
  never `pass`: never having reported is not evidence of health.
- An unparseable timestamp is likewise not a pass.
- `sync_inventory` is tested for idempotence (twice yields one row), for update
  rather than duplicate on a changed fact, and **for not deleting a node that
  vanished** — asserted on the row still existing with its old `last_seen_at`.
- Tenant and system isolation, with two rows wherever a filter is tested.
- A 401/403 is an outcome, not an exception.
- Mutation testing on every guard, with the harness invariants from the
  mutation-testing memory.
