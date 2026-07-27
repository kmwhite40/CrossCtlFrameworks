# System Boundary & Inventory Implementation Plan (Keystone #1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a tenant-scoped system boundary & inventory model (components, inventory items, information types, interconnections), wire it into the OSCAL SSP export and completeness scoring (replacing synthesized placeholders), and auto-generate boundary + data-flow diagrams from the model — with persistent OSCAL UUIDs and discovery/drift hooks seating the SOTA roadmap.

**Architecture:** Four new RLS-protected ORM models FK'd to `systems`; a `src/ccf/boundary/` service package (CRUD + summary + categorization rollup/reconcile + Mermaid diagram generation); OSCAL export rewired to build from the models with an annotated placeholder fallback; a JSON CRUD API + a role-gated HTMX UI page. Advisory/additive — empty boundary preserves today's output.

**Tech Stack:** Python 3.12, async SQLAlchemy/asyncpg, Alembic, FastAPI + HTMX/Jinja, Mermaid (vendored), pytest/pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-07-27-system-boundary-inventory-design.md` (authoritative for field lists).

## Global Constraints

- **Tenant isolation:** all four tables carry `organization_id` (FK `ccf.organizations`) with RLS ENABLE + FORCE + a `tenant_isolation` policy `USING (ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())`. Mirror migration `0039`/`0046` exactly.
- **Stable OSCAL UUIDs:** every entity has `oscal_uuid` generated ONCE on create (`default` = a `uuid4` callable), NEVER regenerated on export.
- **SOTA hook columns on every entity:** `oscal_uuid str(36)`, `source str default 'manual'`, `last_seen_at datetime|null`.
- **Never fabricate:** OSCAL builders fall back to the existing single-placeholder only when the boundary is empty, and annotate the fallback in `remarks`.
- **Reuse the `fips199_level` enum:** `Enum("low","moderate","high", name="fips199_level", schema="ccf", create_type=False)`.
- **Test harness:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`, `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`. NO `db_session` fixture — use `from ccf.db import session_scope` + `async with session_scope() as s:` and `pytestmark = pytest.mark.usefixtures("fresh_engine")`; DB tests copy the module-scoped `_migrate` fixture from `tests/test_ato.py`. The shared DB accumulates rows across tests — `TRUNCATE ccf.<table> CASCADE` at the start of any test asserting exact counts.
- **Style:** `ruff check .` + `mypy src` (strict) clean; line-length 100; no function-level imports (PLC0415). Migrator rebuild after the migration (`docker compose build api migrator`).

---

### Task 1: Four models + migration 0052 + RLS

**Files:**
- Modify: `src/ccf/models.py` (add `SystemComponent`, `InventoryItem`, `InformationType`, `Interconnection`)
- Create: `migrations/versions/0052_system_boundary_inventory.py`
- Test: `tests/test_boundary_models.py`

**Interfaces (produced — later tasks import from `ccf.models`):** the four ORM classes with the fields from the spec's Data-model section. Each has `id` (BigInteger pk), `organization_id`, `system_id`, the entity-specific columns, `props` (JSONB), `oscal_uuid`, `source`, `last_seen_at`, `created_at`, `updated_at`.

- [ ] **Step 1: Add the four models to `src/ccf/models.py`** near `SystemProfile`, following its `Mapped`/`mapped_column` style. Use a module-level `def _uuid() -> str: return str(uuid.uuid4())` (add `import uuid` at top if absent) for `oscal_uuid` defaults. Example for one; replicate the pattern with the spec's exact fields for the other three:

```python
class SystemComponent(Base):
    __tablename__ = "system_components"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    system_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ccf.systems.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="operational")
    purpose: Mapped[str | None] = mapped_column(Text)
    responsible_role: Mapped[str | None] = mapped_column(String(128))
    props: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    oscal_uuid: Mapped[str] = mapped_column(String(36), default=_uuid, unique=True)
    source: Mapped[str] = mapped_column(String(16), default="manual")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
```
For `InformationType`, the three impact columns reuse the shared enum:
`confidentiality_impact: Mapped[str | None] = mapped_column(Enum("low","moderate","high", name="fips199_level", schema="ccf", create_type=False))` (and integrity/availability). Use the spec's exact field list for `InventoryItem`, `InformationType`, `Interconnection` (incl. `component_id` FK on InventoryItem with `ondelete="SET NULL"`, and `agreement_date`/`expires_on` as `Date`).

- [ ] **Step 2: Write the migration `0052_system_boundary_inventory.py`** — `down_revision="0051_catalog_integrity_reports"`. Create the four tables in schema `ccf` with `sa.Column`s matching the models, indexes on `system_id`+`organization_id`, then RLS for each table (mirror `migrations/versions/0039_poam_milestones_org_rls.py`):

```python
_TABLES = ["system_components", "inventory_items", "information_types", "interconnections"]

def _enable_rls(table: str) -> None:
    op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON ccf.{table} "
        f"USING (ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
    )

def upgrade() -> None:
    op.create_table("system_components", ..., schema="ccf")   # columns per model
    op.create_table("inventory_items", ..., schema="ccf")
    op.create_table("information_types", ..., schema="ccf")
    op.create_table("interconnections", ..., schema="ccf")
    for t in _TABLES:
        _enable_rls(t)

def downgrade() -> None:
    for t in _TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{t}")
        op.execute(f"ALTER TABLE ccf.{t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{t} DISABLE ROW LEVEL SECURITY")
    for t in reversed(_TABLES):
        op.drop_table(t, schema="ccf")
```
For the `fips199_level` enum columns in `information_types`, reference the existing type without recreating it: `sa.Column("confidentiality_impact", postgresql.ENUM(name="fips199_level", schema="ccf", create_type=False))`.
Run `PYTHONPATH=src alembic upgrade head` and confirm `alembic heads` shows a single head `0052_system_boundary_inventory`.

- [ ] **Step 3: Write failing tests** `tests/test_boundary_models.py` (mirror `test_ato.py` setup; use `session_scope()` + `fresh_engine` + module `_migrate`):

```python
async def test_create_and_read_boundary_entities():
    async with session_scope() as s:
        org = Organization(name="Boundary Org A")
        s.add(org); await s.flush()
        sysrow = System(organization_id=org.id, name="Sys A"); s.add(sysrow); await s.flush()
        comp = SystemComponent(organization_id=org.id, system_id=sysrow.id,
                               type="software", title="Web App")
        s.add(comp); await s.flush()
        assert comp.oscal_uuid and len(comp.oscal_uuid) == 36
        assert comp.source == "manual"

async def test_rls_isolates_boundary_across_tenants():
    # create under org A, set session tenant to org B, confirm not visible
    ...  # mirror tests/test_rls_coverage.py set_session_tenant usage
```
Include an RLS isolation test using `set_session_tenant` (import from `ccf.db`) exactly as `test_rls_coverage.py` does.

- [ ] **Step 4-5:** Run tests (fail → pass). `ruff`/`mypy` clean. **Commit:** `feat(boundary): boundary/inventory models + migration 0052 + RLS`.

---

### Task 2: Boundary service — CRUD, summary, categorization rollup/reconcile

**Files:**
- Create: `src/ccf/boundary/__init__.py`, `src/ccf/boundary/service.py`, `src/ccf/boundary/summary.py`
- Test: `tests/test_boundary_service.py`

**Interfaces (produced):**
- `service.py`: `async def create_component(session, system_id, org_id, data: dict) -> SystemComponent` (+ `update_/delete_/list_components`), and the analogous quartet for inventory items, information types, interconnections. Each accepts a **structured dict** (import-ready) and returns the ORM row.
- `summary.py`:
  - `@dataclass class BoundarySummary: components: list[SystemComponent]; inventory: list[InventoryItem]; info_types: list[InformationType]; interconnections: list[Interconnection]`.
  - `async def system_boundary_summary(session, system_id) -> BoundarySummary`.
  - `def categorization_rollup(info_types: list[InformationType]) -> dict` → `{"confidentiality": hi, "integrity": hi, "availability": hi}` (high-water-mark; `None` if no types).
  - `def reconcile_categorization(system, info_types) -> list[dict]` → findings where the rollup disagrees with `System.fips199_*` (e.g. `{"level":"confidentiality","rollup":"high","system":"moderate","kind":"under_categorized"}`). Never mutates the system.

- [ ] **Step 1: Write failing tests** covering: create-then-list roundtrip per entity; `categorization_rollup` returns the max across types (low<moderate<high); `reconcile_categorization` flags a mismatch when rollup=high but system=moderate, and returns `[]` when they agree.

```python
def test_categorization_rollup_high_water_mark():
    its = [_it(conf="moderate"), _it(conf="high"), _it(conf="low")]
    assert categorization_rollup(its)["confidentiality"] == "high"

def test_reconcile_flags_under_categorization():
    sysrow = System(fips199_confidentiality="moderate")
    findings = reconcile_categorization(sysrow, [_it(conf="high")])
    assert any(f["level"]=="confidentiality" and f["kind"]=="under_categorized" for f in findings)
```
(`_it`/`_comp` are small local builders constructing unsaved ORM objects.)

- [ ] **Step 2: Implement** `service.py` (thin async CRUD; set `organization_id`/`system_id` server-side, never from the client dict) and `summary.py`. Rollup uses an order map `{"low":0,"moderate":1,"high":2}`; reconcile compares rollup vs the system's triad and classifies `under_categorized` (rollup > system) / `over_categorized` (rollup < system).

- [ ] **Step 3-4:** Tests pass; ruff/mypy clean. **Commit:** `feat(boundary): CRUD service + categorization rollup/reconcile`.

---

### Task 3: Diagram generation (Mermaid, pure functions)

**Files:**
- Create: `src/ccf/boundary/diagram.py`
- Test: `tests/test_boundary_diagram.py`

**Interfaces (produced):**
- `def boundary_mermaid(summary: BoundarySummary, system_name: str) -> str` — Mermaid `flowchart TD` source: a `subgraph` for the boundary containing component nodes (id = sanitized `oscal_uuid`/index, label = `title` + type), inventory items optionally listed under their component, and interconnections as edges to external nodes labeled `direction`/`agreement_type`.
- `def data_flow_mermaid(summary: BoundarySummary, system_name: str) -> str` — flows between components and across interconnections labeled with information-type titles / `data_description`.
- Both return a safe minimal diagram (a single boundary node) when the summary is empty.

- [ ] **Step 1: Write failing tests** — assert structural substrings, not exact layout:

```python
def test_boundary_mermaid_has_components_and_interconnections():
    summary = BoundarySummary(components=[_comp("Web App")], inventory=[],
                              info_types=[], interconnections=[_ic("Agency IdP","incoming")])
    out = boundary_mermaid(summary, "Sys A")
    assert out.startswith("flowchart")
    assert "Web App" in out
    assert "subgraph" in out and "Agency IdP" in out

def test_empty_boundary_is_safe():
    out = boundary_mermaid(BoundarySummary([],[],[],[]), "Sys A")
    assert "flowchart" in out and "Sys A" in out  # no crash, minimal node
```

- [ ] **Step 2: Implement** `diagram.py`. Sanitize node ids to `[A-Za-z0-9_]` (Mermaid-safe), escape quotes in labels, cap label length. Deterministic ordering (sort by title) so output is stable/testable.

- [ ] **Step 3-4:** Tests pass; ruff/mypy clean. **Commit:** `feat(boundary): Mermaid boundary + data-flow diagram generators`.

---

### Task 4: OSCAL system-implementation + information-types from the model

**Files:**
- Modify: `src/ccf/api/routes/oscal.py` (`_oscal_system_implementation`, `_oscal_information_types`, thread the boundary summary through `ssp_export`)
- Test: `tests/test_boundary_oscal.py` (+ update `tests/test_oscal_validation.py` expectations if needed)

**Interfaces (consumes):** `system_boundary_summary` (Task 2), the models (Task 1). **Produces:** OSCAL `system-implementation` with `components` (from `SystemComponent` + interconnections as `type=interconnection`), `inventory-items` (from `InventoryItem`, each with `implemented-components` → its component `oscal_uuid`), and `information-types` (per `InformationType`).

- [ ] **Step 1: Write failing tests** — populate a boundary for a system that has an `SSPProject`, call the SSP export (or the builders directly with a fetched summary), assert:
  - `system-implementation.components` contains a node with the component's `oscal_uuid` and title (not a fabricated one).
  - an `inventory-item` references that component uuid under `implemented-components`.
  - `information-types` has one entry per info type with `confidentiality-impact.base` = the type's level.
  - **stable UUID:** export twice, assert the component uuid is identical both times (equals the DB `oscal_uuid`).
  - **empty fallback:** a system with no boundary still exports the single annotated placeholder component (assert `remarks` notes the fallback) and OSCAL still validates.

- [ ] **Step 2: Implement.** Make `_oscal_system_implementation` and `_oscal_information_types` accept the `BoundarySummary` (thread a fetched summary from `ssp_export`; keep signatures internal). Build components/inventory/info-types from real rows using their persisted `oscal_uuid` (do NOT call `uuid.uuid4()` for these). Preserve users-from-roles. When a collection is empty, emit the existing placeholder with an added `remarks` note (reuse the `_placeholder` helper). Keep `_oscal_status`/`_meta_str` usage.

- [ ] **Step 3-4:** Run `tests/test_boundary_oscal.py` + `tests/test_oscal_validation.py`; both pass. ruff/mypy clean. **Commit:** `feat(boundary): OSCAL system-implementation + information-types from real inventory`.

---

### Task 5: SSP completeness boundary section

**Files:**
- Modify: `src/ccf/ssp/completeness.py` (add `boundary` arg to `assess`)
- Modify: the caller that invokes `assess` (find via `grep -rn "assess(" src/ccf`) to pass a boundary summary dict
- Test: `tests/test_boundary_completeness.py`

**Interfaces:** `assess(project_metadata, entries, boundary=None)` — `boundary` is a small dict `{"components": n, "info_types": n, "categorization_reconciles": bool, "interconnections_with_agreements": (k, total)}`. Backward compatible (None ⇒ current behavior).

- [ ] **Step 1: Write failing tests** — `assess(meta, entries, boundary={...complete...})` scores higher and lists no boundary gaps; `boundary={components:0,...}` adds a "No boundary components defined" gap; a categorization mismatch adds a gap.

- [ ] **Step 2: Implement** — add a boundary sub-score to the section score; append boundary gaps to the report's missing list. Keep control weight dominant (adjust the section blend, documented in the docstring). Compute the boundary dict in the caller from `system_boundary_summary` + `reconcile_categorization`.

- [ ] **Step 3-4:** Tests pass; ruff/mypy clean; run `tests/test_ssp_completeness.py` for no regression. **Commit:** `feat(boundary): boundary completeness section in SSP scoring`.

---

### Task 6: JSON CRUD API

**Files:**
- Create: `src/ccf/api/routes/boundary.py` (router prefix `/api/systems/{system_id}/boundary`)
- Modify: `src/ccf/api/main.py` (register the router)
- Test: `tests/test_boundary_api.py`

**Interfaces:** GET/POST/PATCH/DELETE for each of components, inventory, information-types, interconnections, all scoped via `require_system_in_scope` (`systems.py:46`) and `require_role("admin","assessor")`. Reuses Task 2 service functions.

- [ ] **Step 1: Write failing tests** (mirror `test_audit_rbac.py` auth-enabled harness: `_mk_user`, `_auth`, unique org/email names): a viewer POST → 403; an admin POST creates a component and GET lists it; a component under org A is not visible to org B's admin (cross-tenant 404/empty).

- [ ] **Step 2: Implement** the router with Pydantic request models (or typed dicts validated inline), delegating to `ccf.boundary.service`. Set `organization_id` from the principal/system, never the body.

- [ ] **Step 3-4:** Tests pass; ruff/mypy clean. **Commit:** `feat(boundary): JSON CRUD API for boundary entities`.

---

### Task 7: UI page + diagram render + SSP summary

**Files:**
- Create: `src/ccf/api/routes/ui_boundary.py` (or add to `ui.py`) — `GET /systems/{system_id}/boundary`
- Create: `src/ccf/api/templates/system_boundary.html`
- Modify: `src/ccf/api/templates/base.html` (nav link under the system/authorization group)
- Add: `src/ccf/api/static/vendor/mermaid.min.js` (download; network available for setup)
- Modify: the SSP view template to embed the read-only boundary summary + diagram
- Test: `tests/test_boundary_ui.py`

- [ ] **Step 1: Vendor Mermaid** — download `mermaid.min.js` (pin a version, e.g. v10) into `static/vendor/`. Confirmed absent today (only alpine/htmx/lucide vendored).
- [ ] **Step 2: Write failing tests** (auth-enabled): non-admin → 403; admin GET `/systems/{id}/boundary` → 200 and page contains the boundary sections + a `<pre class="mermaid">` (or `id="boundary-diagram"`) block.
- [ ] **Step 3: Implement** the route (fetch `system_boundary_summary` + `boundary_mermaid`/`data_flow_mermaid`, pass Mermaid source to the template), the template (HTMX/Alpine CRUD forms hitting the Task-6 API, a `<pre class="mermaid">{{ diagram }}</pre>` rendered by the vendored mermaid.min.js `mermaid.initialize({startOnLoad:true})`), the nav link, and the SSP-view summary embed. Follow `systems.html`/`system_detail.html` conventions.
- [ ] **Step 4-5:** Tests pass; `tests/test_ui_grc_pages.py` no regression; ruff/mypy clean. **Commit:** `feat(boundary): role-gated boundary UI + Mermaid diagrams + SSP summary`.

---

### Task 8: Golden end-to-end + full-suite verification

**Files:**
- Test: `tests/test_boundary_golden.py`

- [ ] **Step 1: Write the golden test** — `TRUNCATE ccf.system_components, ccf.inventory_items, ccf.information_types, ccf.interconnections CASCADE` for isolation; create a system + a full boundary (2 components, 2 inventory items linked to components, 2 information types incl. one that under-categorizes the system, 1 interconnection with an ISA); then assert end-to-end:
  - `system_boundary_summary` returns all rows;
  - `reconcile_categorization` flags the under-categorization;
  - the OSCAL export's `system-implementation` contains the real component uuids + inventory `implemented-components` + per-type information-types (no placeholder);
  - `boundary_mermaid` output contains both components and the interconnection;
  - `assess(..., boundary=...)` reflects a populated boundary.
- [ ] **Step 2: Run the full boundary suite + a broad regression:**
```bash
PYTHONPATH=src pytest tests/test_boundary_models.py tests/test_boundary_service.py \
  tests/test_boundary_diagram.py tests/test_boundary_oscal.py tests/test_boundary_completeness.py \
  tests/test_boundary_api.py tests/test_boundary_ui.py tests/test_boundary_golden.py \
  tests/test_oscal_validation.py tests/test_ssp_completeness.py -q
```
- [ ] **Step 3: Commit:** `test(boundary): golden e2e boundary→OSCAL→completeness→diagram`.

---

## Final verification (after all tasks)
- [ ] `PYTHONPATH=src ruff check .` clean; `PYTHONPATH=src mypy src` clean.
- [ ] Full suite green: `pytest -q` (baseline 599 + ~30 new).
- [ ] `alembic heads` → single head `0052`; rebuild `docker compose build api migrator`.
- [ ] Manual: populate a boundary via the UI, export OSCAL, confirm real `system-implementation`; diagram renders.

## Self-Review
**Spec coverage:** 4 models+RLS ✔(T1); service+rollup/reconcile ✔(T2); diagrams ✔(T3); OSCAL from model + stable UUID + fallback ✔(T4); completeness ✔(T5); API ✔(T6); UI+diagram+SSP summary ✔(T7); golden e2e ✔(T8); SOTA hook columns ✔(T1, spec §SOTA). **Placeholder scan:** field lists reference the spec (single source) rather than re-listing 4× — intentional, not a gap. **Type consistency:** `BoundarySummary`/`system_boundary_summary`/`categorization_rollup`/`reconcile_categorization` names consistent T2→T4→T5→T8; `boundary_mermaid`/`data_flow_mermaid` T3→T7→T8; `oscal_uuid` persisted (T1) and reused in OSCAL (T4), not regenerated.
