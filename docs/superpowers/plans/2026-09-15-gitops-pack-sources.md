# GitOps Pack Sources Implementation Plan (CC&E #10)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A tenant declares its desired state in a git repository; the platform polls it, reports what adopting the change would do, and installs only when told.

**Architecture:** `etl/sources.py`'s conditional fetch, hashing and commit resolution are promoted to public names and reused. A new tenant-scoped `PackSource` drives `packs/sync.py`, which has five recorded outcomes and stores a changed manifest as *pending* unless `auto_install` is on.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, httpx, pytest. One migration.

**Spec:** `docs/superpowers/specs/2026-09-15-gitops-pack-sources-design.md`

## Global Constraints

- **No git client, no clone, no SSH.** A raw URL and the resolved commit sha
  are the whole of git's contribution.
- **No second implementation of conditional fetch or hashing.** Reuse
  `etl/sources.py`'s, promoted from private names.
- **`CatalogSource` is untouched** and is not reused as the table: it is global
  reference data, and a tenant's repo is not.
- **`auto_install` defaults to False.** Polling is automatic and read-only;
  adoption is an act.
- **An invalid manifest installs nothing** and is reported as `invalid`, never
  as `error`.
- **RLS:** `pack_sources` carries `organization_id`, so
  `EXPECTED_TENANT_ISOLATION_TABLES` gains it and the count goes **132 → 133**.
- **No credential storage.** Sources must be reachable unauthenticated; a
  private repo is a stated limitation, not a half-built feature.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never two pytest sessions at once. App-driving scripts need `CCF_ENV=test`.
- Wherever a query filter is tested, the fixture has **two** rows, one of which
  must be excluded (the lesson from the previous sub-project).
- `ruff check src tests` and `mypy src` clean; `alembic heads` shows one.

---

### Task 1: Promote the fetch and hash helpers

**Files:**
- Modify: `src/ccf/etl/sources.py`
- Test: `tests/test_etl_source_helpers.py`

**Interfaces:**
- Produces: `sha256_bytes(body: bytes) -> str`,
  `fetch_conditional(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]`
  (the private names kept as thin aliases so nothing internal breaks)

- [ ] **Step 1: Write the failing test** — the public names exist, hash a known
  body to a known digest, and a 304 returns `(304, None, etag)`.
- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Rename, keeping `_sha256_bytes = sha256_bytes` and
  `_fetch = fetch_conditional`** so existing call sites and any test that
  reaches for the private name keep working. Say in the docstring that these
  are shared with `packs/sync.py`.
- [ ] **Step 4: Run the catalog-source suites** — all pass unedited.
- [ ] **Step 5: Commit.**

---

### Task 2: `PackSource`, migration 0071, RLS

**Files:**
- Create: `migrations/versions/0071_pack_sources.py`
- Modify: `src/ccf/models_packs.py`, `tests/test_rls_coverage.py`
- Test: `tests/test_pack_source_models.py`

- [ ] **Step 1: Write the failing test** — a source round-trips;
  `auto_install` and `enabled` default correctly (False and True);
  `(organization_id, pack_key, url)` is unique so the same manifest cannot be
  registered twice for one tenant; `pending_manifest` defaults to `{}`.
- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Write the model** in `models_packs.py` beside the other pack
  tables, nullable `organization_id` per the established convention.
- [ ] **Step 4: Write migration 0071**, `down_revision = "0070_waivers"`, with
  the direct `organization_id = ccf.current_tenant()` policy.
- [ ] **Step 5: Update the RLS guard** — add `pack_sources`, count **132 → 133**.
- [ ] **Step 6: `alembic heads`, model tests, `tests/test_rls_coverage.py`.
  Commit.**

---

### Task 3: `check_pack_source` — the five outcomes

**Files:**
- Create: `src/ccf/packs/sync.py`
- Test: `tests/test_packs_sync.py`

**Interfaces:**
- Produces: `check_pack_source`, `sync_for_org`, `adopt_pending`, `divergence`,
  `SYNC_OUTCOMES`

- [ ] **Step 1: Write the failing test**, one per outcome plus the refusals:

```python
async def test_a_new_manifest_is_stored_pending_and_installs_nothing() -> None:
    """auto_install is off by default; adoption is an act."""
    assert out["status"] == "pending"
    assert await _installed(session, org.id) is None


async def test_auto_install_installs_and_audits() -> None:
    assert out["status"] == "installed"
    assert (await _installed(session, org.id)).version == "1.0.0"
    # the commit is named in the audit entry, or provenance is lost
    assert "commit" in audit_diff


async def test_an_invalid_manifest_is_invalid_not_error_and_installs_nothing() -> None:
    """A repository whose manifest does not validate is a content problem
    someone must fix in git; a transport failure is transient. Sending an
    operator to the wrong place is the cost of conflating them."""
    assert out["status"] == "invalid"
    assert source.last_error and "control" in source.last_error


async def test_a_transport_failure_is_error_and_keeps_the_previous_state() -> None:
    assert out["status"] == "error"
    assert source.last_sha256 == previous_sha


async def test_unchanged_content_is_a_no_op_on_the_second_poll() -> None: ...
async def test_a_304_is_unchanged() -> None: ...
async def test_a_disabled_source_is_skipped() -> None: ...
async def test_adopting_pending_installs_it_and_clears_the_pending_fields() -> None: ...
async def test_adopting_with_nothing_pending_is_refused() -> None: ...
async def test_sync_for_org_skips_another_tenants_source() -> None:
    """Two sources, one per org: the filter must exclude, not merely include."""
```

- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Implement**, reusing `fetch_conditional`, `sha256_bytes`,
  `resolve_commit_sha`, `validate_manifest` and `install_pack`. Audit through
  `ccf.api.audit.record_event` — never a hand-built row, which breaks the hash
  chain.
- [ ] **Step 4: Run tests. Commit.**

---

### Task 4: Divergence

**Files:**
- Modify: `src/ccf/packs/sync.py`
- Test: `tests/test_packs_divergence.py`

- [ ] **Step 1: Write the failing test** — all four states:
  `in_sync` (installed sha equals the source's last sha), `pending_change`,
  `diverged` (a pack installed that the source never provided), `unknown`
  (never polled). `diverged` is the one nobody asks for and the one that
  catches a local install bypassing the source.
- [ ] **Step 2: Run it.** Expect `ImportError`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests. Commit.**

---

### Task 5: Scheduler, API and CLI

**Files:**
- Modify: `src/ccf/governance/scheduler.py`, `src/ccf/api/routes/packs.py`,
  `src/ccf/cli.py`
- Test: `tests/test_pack_sources_api.py`

**Interfaces:**
- `POST /api/packs/{pack_key}/sources`, `GET /api/packs/{pack_key}/sources`,
  `POST /api/pack-sources/{id}/sync`, `POST /api/pack-sources/{id}/adopt`,
  `GET /api/pack-sources/{id}/divergence`
- `ccf packs-sync [--org-id N]`

- [ ] **Step 1: Write the failing test** — register, list, sync, adopt and
  divergence through HTTP; `organization_id` comes from the principal;
  another tenant's source id is a 404 (never confirm existence); adopt
  requires an approver role, matching waivers.
- [ ] **Step 2: Run it.** Expect 404s.
- [ ] **Step 3: Add the scheduler step** inside `_run_per_tenant_cycle`, in its
  own `begin_nested()` savepoint with the same warning-log shape as its
  neighbours — the docstring there explains why a bare try/except is not
  enough.
- [ ] **Step 4: Add the routes and the CLI command.**
- [ ] **Step 5: Run tests plus the scheduler suite. Commit.**

---

### Task 6: Verification, mutation testing, demonstration

- [ ] **Step 1:** full suite, `ruff check src tests`, `mypy src`,
  `alembic heads`. Only the known
  `test_dashboard_overview_sla_excludes_no_due_date_from_on_track` failure.
- [ ] **Step 2: Mutate every guard.** At minimum: each of the five outcome
  branches; the `enabled` and `auto_install` checks; the sha-unchanged
  short-circuit; the validate-before-install order; the pending-fields clear;
  the adopt-with-nothing-pending refusal; both `organization_id` filters; each
  divergence state; the scheduler savepoint.
- [ ] **Step 3:** Report every ESCAPED honestly. Ask of each whether the
  fixture could express the bug and whether the guard is redundant.
- [ ] **Step 4: Demonstrate** — a source pointing at a stubbed manifest; poll
  it (pending); print the impact of adopting; adopt; poll again (unchanged);
  change the manifest and poll (pending again); print divergence at each step.
- [ ] **Step 5: Commit** with results recorded here.
