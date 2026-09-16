# GitOps for desired state (CC&E #10)

**Status:** design, awaiting implementation plan
**Extends:** `etl/sources.py`, `packs/`, `governance/scheduler.py`
**Depends on:** P2b (desired state is data), #6 (change impact)

## 1. What is actually missing, and what is not

GitOps means: git holds the desired state, changes arrive as commits reviewed
outside the platform, the platform reconciles toward what git declares, and the
commit is the version identity.

Three of those four already have machinery here:

- **Desired state is data.** P2b made a posture check declarable in a pack
  manifest. Before that there was nothing to put in git.
- **Fetch, hash, change-detect.** `etl/sources.py` polls upstream URLs with
  conditional `If-None-Match`, compares SHA-256 so a server that ignores ETags
  does not produce false positives, and records each check.
- **Commit identity.** `etl/sources.py:parse_commit_url` and
  `resolve_commit_sha` already resolve a GitHub raw URL to the commit that last
  touched that path, best-effort, with a content-addressed fallback.

**So no git client is needed, and none will be added.** A manifest is a file; a
raw URL at a ref plus the resolved commit sha is the whole of what git
contributes. Shelling out to `git` or adding a library would mean SSH
credentials, a working tree, and a clone cache inside a product that runs in
GCC High — cost with no matching benefit.

What is missing is a **tenant-owned** source registry and a reconcile step. And
that is the one thing that must *not* reuse `CatalogSource`: that table is
global reference data (it sits in `GLOBAL_TABLES`), because NIST's catalog is
the same for everyone. A tenant's desired-state repository is its own, so it
needs its own tenant-scoped table. **The functions are reused; the table is
not.**

## 2. The gate: detection is automatic, adoption is not

`CatalogSource.auto_ingest` defaults to off, and `etl/sources.py` says why:
"drift is recorded for a human to review and re-ingest through a gated PR,
which is the safer default for a compliance catalog."

The same reasoning applies with more force here, because a pack rule *executes*
against a customer tenant. So:

- **Polling is automatic** and read-only: fetch, hash, validate, resolve the
  commit, record. It joins the scheduler's per-tenant cycle.
- **Installing is not.** A changed manifest is stored as **pending**, and an
  operator reviews it — with the #6 impact report for exactly this change —
  before adopting.
- `auto_install` exists and defaults to **False**. A tenant that genuinely
  wants continuous reconciliation can opt in per source; nobody gets it by
  accident.

This is deliberately *not* pure GitOps convergence. A compliance platform that
silently changes what it asserts about a system, because someone merged a PR,
is a platform whose SSP no longer describes a reviewed decision.

## 3. Shape

```python
class PackSource(Base):          # tenant-owned, RLS-policied
    organization_id: int | None
    pack_key: str                # which pack this source provides
    url: str                     # raw manifest URL
    ref: str | None              # the branch/tag polled, for display
    enabled: bool = True
    auto_install: bool = False
    etag / last_sha256 / last_commit_sha
    last_status: str | None      # unchanged | pending | installed | invalid | error
    last_error: str | None
    last_checked_at: datetime | None
    pending_manifest: dict       # fetched, validated, awaiting review
    pending_sha256 / pending_commit_sha
```

```python
async def check_pack_source(session, source, *, actor="scheduler") -> dict
async def sync_for_org(session, org_id) -> dict
async def adopt_pending(session, source, *, actor) -> CompliancePack
async def divergence(session, source) -> dict
```

`check_pack_source` has exactly five outcomes, and each is recorded rather than
inferred:

| Outcome | When | Effect |
|---|---|---|
| `unchanged` | 304, or the sha matches what is installed | nothing |
| `pending` | new content, valid manifest, `auto_install` off | stored for review |
| `installed` | new content, valid, `auto_install` on | installed, audited |
| `invalid` | manifest fails `validate_manifest` | error recorded, **nothing installed** |
| `error` | fetch or transport failure | error recorded, previous state kept |

`invalid` is its own outcome and not folded into `error`: a repository whose
manifest does not validate is a *content* problem someone must fix in git,
where a transport failure is transient. Reporting them identically would send
an operator to the wrong place.

## 4. Divergence is the question GitOps exists to answer

"Is what is running what the repository declares?" `divergence` compares the
installed pack's `manifest_sha` against the source's last fetched sha and
reports `in_sync`, `pending_change`, `diverged` (something was installed that
the repository does not contain — a local install bypassing the source), or
`unknown` (never polled).

`diverged` matters most and is the one nobody asks for: it catches a manifest
installed through the API while a source is configured, which is how a
deployment quietly stops matching its own repository.

## 5. What this does NOT do

- **No git client, no clone, no SSH.** §1.
- **No convergence loop.** Polling records; adoption is an act.
- **No new fetch/hash/commit code** — `etl/sources.py`'s are promoted from
  private to public names and reused. Two implementations of conditional
  fetching would drift.
- **No change to `CatalogSource`, `CatalogCheck`, or catalog polling.**
- **No secret storage.** A private repository needs a token, and credentials
  belong in `connectors/credentials.py`'s encrypted per-org store, not in a new
  column. Until that is wired, sources must be reachable unauthenticated —
  stated as a limitation rather than half-built.

## 6. Testing strategy

- Each of the five outcomes, driven by a stubbed fetch — including that an
  invalid manifest installs **nothing** and is reported as `invalid`, not
  `error`.
- `auto_install` off stores pending and installs nothing; on installs and
  audits through `record_event`.
- A second poll of unchanged content is a no-op (idempotence).
- Adopting a pending manifest installs it, clears the pending fields, and
  writes an audit entry naming the commit.
- Divergence: all four states, with `diverged` asserted against a pack
  installed directly.
- Tenant isolation: one org's source is never polled or adopted for another.
- The scheduler step failing must not break the rest of a tenant's cycle.
- Mutation testing on every guard, harness invariants per the mutation-testing
  memory — including a fixture with **two** rows wherever a filter is tested.
