# Compliance Graph (System-Posture Layer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Draw each system's assurance graph on a new `/graph` page. Every edge names its source, and no edge is guessed or inferred.

**Architecture:** Concord already builds a per-tenant graph (`ccf/assurance/builder.py` → `assurance_nodes` / `assurance_edges`) that nothing draws. This plan:
- gives every edge a stored `source` and removes the invented `confidence`;
- removes the guessed edges;
- folds catalog rows into real controls;
- adds sourced edges for capabilities, KSIs, control tests and connectors;
- adds a "this system only" subgraph scope;
- renders the result with a vendored Cytoscape.js and server-rendered tables.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2 async, Alembic, Postgres (test DB on port 5434), Jinja2, Cytoscape.js 3.30.2 (vendored), pytest.

**Spec:** `docs/superpowers/specs/2026-10-15-compliance-graph-design.md`

## Global Constraints

- **Edges:** only edges with a named source are stored. No transitive edges, and no confidence numbers.
- **`assurance_edges.source`:** `String(96)`, NOT NULL. The API exposes it as `provenance`, because `source`/`target` already mean node ids in `impact.subgraph` output.
- **Control nodes:** one per canonical control per system, with entity id `"<system_id>:<canonical>"`.
- **Worst-first status order:** `not_implemented`, `planned`, `partial`, `inherited`, `implemented`, `not_applicable`.
- **Connector → control test edges** are drawn only when the org has exactly one connector of that `connector_type`.
- **Renderer:** Cytoscape.js `3.30.2`, MIT-licensed, vendored at `src/ccf/api/static/vendor/cytoscape.min.js` and recorded in `src/ccf/api/static/vendor/VENDOR.json`. The CSP stays unchanged.
- **Size limit:** the page draws at most 3,000 nodes; above that it asks for a filter.
- **Colour means status only** (README / `docs/DESIGN.md`). Owners are shown by fading the other nodes, never by hue.
- **Untrusted text:** labels are tenant-entered. Jinja autoescapes them, the graph data is embedded with `|tojson`, and the script writes them with `textContent` only.
- **Testing:** never run two pytest sessions at once, because the shared test DB fakes failures in unrelated modules. Wait for a pytest summary with `grep -E "[0-9]+ (passed|failed)"`.

## Review Focus

1. **Markup in labels.** A capability or POA&M title containing markup (`<img src=x onerror=alert(1)>`) must show as text in the table, panel and canvas, and never execute. Test: Task 6, `test_a_title_with_markup_is_shown_as_text`.
2. **Another tenant's system, or a deleted one.** A user of org A opening `/graph?system_id=<org B's system or a deleted system>` gets a 404 and sees none of its data. Tests: Task 6, `test_compliance_graph_page_tenancy.py`, and `test_a_deleted_system_is_not_drawn`.
3. **Control ids written differently.** `ac-02` in `capability_controls`, `AC-2` in `nist_refs` and `AC-02` in the catalog must land on one node. Test: Task 3, `test_control_ids_written_differently_meet_on_one_node`.
4. **A capability bound across tenants.** A capability from org B bound by id to a component of org A must not appear in org A's graph. Test: Task 3, `test_a_capability_from_another_tenant_is_not_drawn`.
5. **A system added after the last build.** It must say "not in the graph yet; rebuild", not show an empty canvas. Test: Task 6, `test_a_system_added_after_the_build_says_so`.

---

## File map

| File | Change | Responsibility |
|---|---|---|
| `migrations/versions/0098_assurance_edge_source.py` | create | Add `source`, label old rows, drop `confidence` |
| `src/ccf/models_assurance.py` | modify | `AssuranceEdge.source` replaces `confidence` |
| `src/ccf/assurance/builder.py` | modify | Sourced edges, savepoints, failed contributors, canonical controls, new contributors |
| `src/ccf/assurance/impact.py` | modify | `provenance` on edges, node metadata, `within_system` scope, `system_view` |
| `src/ccf/capability/derive.py` | modify | Expose `bound_capability_ids` (the binding plus its tenant predicate) |
| `src/ccf/api/routes/assurance.py` | modify | `scope` param and build fields, via `system_view` |
| `src/ccf/api/routes/ui_grc.py` | modify | `/graph` page; rebuild can return to it |
| `src/ccf/api/templates/graph.html` | create | Page, states, tables, embedded data |
| `src/ccf/api/templates/assurance.html` | modify | "Open graph" link |
| `src/ccf/api/templates/base.html` | modify | Nav entry |
| `src/ccf/api/static/js/graph.js` | create | Cytoscape rendering, filters, owner picker, panel |
| `src/ccf/api/static/vendor/cytoscape.min.js` | create | Vendored renderer |
| `src/ccf/api/static/vendor/VENDOR.json` | create | Version, licence, origin and sha256 per vendored file it covers |
| `tests/test_compliance_graph.py` | create | Builder, impact, API and page tests |
| `tests/test_compliance_graph_page_tenancy.py` | create | Page tenancy with auth enabled |
| `tests/test_vendored_assets.py` | create | Vendored files match `VENDOR.json` |
| `CHANGELOG.md` | modify | Added / Changed / Upgrading |

---

### Task 1: Every edge names its source; guessed edges go

**Files:**
- Create: `migrations/versions/0098_assurance_edge_source.py`
- Modify: `src/ccf/models_assurance.py:62-79` (AssuranceEdge)
- Modify: `src/ccf/assurance/builder.py` (`_Graph`, `_contribute`, every contributor's `g.edge` call, `_connectors`, `_ai_agents`, `rebuild_org`)
- Modify: `src/ccf/assurance/impact.py` (`subgraph` kept_edges)
- Create: `tests/test_compliance_graph.py`

**Interfaces:**
- Produces:
  - `_Graph.edge(src: NodeKey, tgt: NodeKey, rel: str, source: str) -> None`, which raises `ValueError` on an empty source.
  - `AssuranceEdge.source: str`.
  - `AssuranceGraphBuildRun.status` in `{"ok", "partial"}`.
  - `run.detail == {"sources": {name: int}, "failed": {name: "ExcClass: message"}}`.
  - Subgraph edges: `{"source": int, "target": int, "relationship_type": str, "provenance": str}`.

- [ ] **Step 1: Create the test module with its helpers and the failing tests**

Create `tests/test_compliance_graph.py`:

```python
"""Compliance graph: the assurance graph stores and draws only sourced edges.

Spec: docs/superpowers/specs/2026-10-15-compliance-graph-design.md.
"""

from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.assurance import builder, impact
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Control, ControlImplementation, Evidence, Organization, System
from ccf.models_assurance import AssuranceEdge, AssuranceNode
from ccf.models_grc import ConnectorConfig, ControlTest

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org_and_system() -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"Graph Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"Graph Sys {next(_SEQ)}", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def _system(org_id: int) -> int:
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name=f"Graph Sys {next(_SEQ)}", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _control(s: Any, identifier: str, sequence_control: str | None = None) -> Control:
    c = (
        await s.execute(select(Control).where(Control.identifier == identifier))
    ).scalar_one_or_none()
    if c is None:
        c = Control(
            identifier=identifier, control_name=identifier, sequence_control=sequence_control
        )
        s.add(c)
        await s.flush()
    return c


async def _implement(
    system_id: int,
    identifier: str,
    status: str = "implemented",
    *,
    sequence_control: str | None = None,
    owner_user_id: int | None = None,
    evidence_title: str | None = None,
) -> int:
    async with session_scope() as s:
        c = await _control(s, identifier, sequence_control)
        impl = ControlImplementation(
            system_id=system_id, control_id=c.id, status=status, owner_user_id=owner_user_id
        )
        s.add(impl)
        await s.flush()
        if evidence_title:
            s.add(Evidence(implementation_id=impl.id, kind="document", title=evidence_title))
        return impl.id


async def _build(org_id: int) -> tuple[str, dict[str, Any]]:
    async with session_scope() as s:
        run = await builder.rebuild_org(s, org_id)
        return run.status, dict(run.detail)


async def _nodes(org_id: int) -> dict[str, dict[str, Any]]:
    """``{"type:entity_id": {"label", "status", "metadata"}}`` for one org."""
    async with session_scope() as s:
        return {
            f"{n.entity_type}:{n.entity_id}": {
                "label": n.label, "status": n.status, "metadata": dict(n.node_metadata or {}),
            }
            for n in (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars()
        }


async def _edges(org_id: int) -> list[tuple[str, str, str, str]]:
    """``(from "type:id", to "type:id", relationship, source)`` for one org."""
    async with session_scope() as s:
        keys = {
            n.id: f"{n.entity_type}:{n.entity_id}"
            for n in (
                await s.execute(
                    select(AssuranceNode).where(AssuranceNode.organization_id == org_id)
                )
            ).scalars()
        }
        return [
            (keys[e.source_node_id], keys[e.target_node_id], e.relationship_type, e.source)
            for e in (
                await s.execute(
                    select(AssuranceEdge).where(AssuranceEdge.organization_id == org_id)
                )
            ).scalars()
        ]


# ── Task 1: every edge names its source ──────────────────────────────────────


async def test_every_stored_edge_names_a_source() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-2", evidence_title="AC-2 screenshot")
    async with session_scope() as s:
        s.add(POAM(system_id=sid, title="Fix logging", severity="high", status="open"))
    status, _ = await _build(org)
    edges = await _edges(org)
    assert status == "ok"
    assert edges and all(src for *_, src in edges)
    assert {src for *_, src in edges} >= {"control_implementations", "evidence", "poams"}


async def test_the_database_refuses_an_edge_without_a_source() -> None:
    org, _sid = await _org_and_system()
    await _build(org)
    async with session_scope() as s:
        node_id = (
            await s.execute(
                select(AssuranceNode.id).where(AssuranceNode.organization_id == org)
            )
        ).scalars().first()
        s.add(
            AssuranceEdge(
                organization_id=org, source_node_id=node_id, target_node_id=node_id,
                relationship_type="self",
            )
        )
        with pytest.raises(IntegrityError):
            await s.flush()
        await s.rollback()


def test_the_builder_refuses_an_edge_without_a_source() -> None:
    g = builder._Graph()
    a = g.node("system", 1, "s")
    b = g.node("poam", 2, "p")
    with pytest.raises(ValueError, match="no source"):
        g.edge(a, b, "has_poam", "")


async def test_the_subgraph_returns_provenance_and_no_confidence() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-2")
    await _build(org)
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid))
    assert g["edges"] and all(e["provenance"] for e in g["edges"])
    assert not any("confidence" in e for e in g["edges"])


async def test_a_failed_contributor_is_recorded_and_the_rest_still_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        await session.execute(text("SELECT * FROM ccf.no_such_table"))

    monkeypatch.setattr(builder, "_poams", broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-2")
    async with session_scope() as s:
        s.add(
            ControlTest(
                organization_id=org, system_id=sid, control_id="AC-2", name="MFA on",
                method="automated",
            )
        )
    status, detail = await _build(org)
    assert status == "partial"
    assert detail["failed"]["poams"].startswith("ProgrammingError")
    # control_tests runs after poams: without a savepoint the failed SQL would
    # have aborted the transaction and this slice would be missing too.
    assert any(k.startswith("control_test:") for k in await _nodes(org))


async def test_a_connector_is_not_linked_to_systems_it_does_not_feed() -> None:
    org, _sid = await _org_and_system()
    async with session_scope() as s:
        s.add(ConnectorConfig(organization_id=org, name="AWS prod", connector_type="aws"))
    await _build(org)
    assert not [e for e in await _edges(org) if "connector:" in e[0] + e[1]]


def _load_0098() -> Any:
    path = Path(__file__).parents[1] / "migrations/versions/0098_assurance_edge_source.py"
    spec = importlib.util.spec_from_file_location("m0098", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_0098_labels_old_edges_then_drops_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``op`` is faked: this never touches the shared test database."""
    mod = _load_0098()
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        mod.op, "add_column",
        lambda table, col, **k: calls.append(("add", col.name, col.nullable)), raising=False,
    )
    monkeypatch.setattr(mod.op, "execute", lambda sql: calls.append(("sql", str(sql))), raising=False)
    monkeypatch.setattr(
        mod.op, "alter_column",
        lambda table, col, **k: calls.append(("alter", col, k.get("nullable"))), raising=False,
    )
    monkeypatch.setattr(
        mod.op, "drop_column", lambda table, col, **k: calls.append(("drop", col)), raising=False
    )
    mod.upgrade()
    assert [c[0] for c in calls] == ["add", "sql", "alter", "drop"]
    assert calls[0][1:] == ("source", True)
    assert "unsourced:pre-0098" in calls[1][1]
    assert calls[2] == ("alter", "source", False)
    assert calls[3] == ("drop", "confidence")
    calls.clear()
    mod.downgrade()
    assert [c[:2] for c in calls] == [("add", "confidence"), ("drop", "source")]
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py -q 2>&1 | tail -15`

Expected: failures. The migration file is missing, and `AssuranceEdge` has no `source`.

- [ ] **Step 3: Write the migration**

Create `migrations/versions/0098_assurance_edge_source.py`:

```python
"""Assurance edges name their source; the invented confidence is dropped.

Spec: docs/superpowers/specs/2026-10-15-compliance-graph-design.md §1.

Every edge the builder writes now carries ``source``: a table, a dataset at a
version, or a check source. ``confidence`` held fixed guesses (0.6 for
"connector feeds every system", 0.7 for agent links) that measured nothing.
Rows written before this migration have no provenance; they are labelled
``unsourced:pre-0098`` rather than given one, and the next rebuild replaces
them.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0098_assurance_edge_source"
down_revision = "0097_orgless_digest_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assurance_edges", sa.Column("source", sa.String(96), nullable=True), schema="ccf"
    )
    op.execute(
        "UPDATE ccf.assurance_edges SET source = 'unsourced:pre-0098' WHERE source IS NULL"
    )
    op.alter_column("assurance_edges", "source", nullable=False, schema="ccf")
    op.drop_column("assurance_edges", "confidence", schema="ccf")


def downgrade() -> None:
    op.add_column(
        "assurance_edges",
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
        schema="ccf",
    )
    op.drop_column("assurance_edges", "source", schema="ccf")
```

- [ ] **Step 4: Replace `confidence` with `source` on the model**

In `src/ccf/models_assurance.py`, replace the `confidence` line in `AssuranceEdge`:

```python
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
```

with:

```python
    #: Where this edge comes from: a table (``poams``), a dataset at a version
    #: (``fedramp-rules@2026.10.13.01``) or a check source
    #: (``crosswalk:securescore``). An edge with no source is not stored.
    source: Mapped[str] = mapped_column(String(96))
```

If `Float` is now unused in that module, remove it from the `sqlalchemy` import; ruff reports it as F401.

- [ ] **Step 5: Make `_Graph.edge` require a source, and give each contributor run its own savepoint**

In `src/ccf/assurance/builder.py`, replace the `_Graph` class and `_contribute`:

```python
class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[NodeKey, dict[str, Any]] = {}
        self.edges: list[tuple[NodeKey, NodeKey, str, str]] = []

    def node(
        self, entity_type: str, entity_id: Any, label: str,
        status: str | None = None, **meta: Any,
    ) -> NodeKey:
        key = (entity_type, str(entity_id))
        self.nodes[key] = {
            "entity_type": entity_type, "entity_id": str(entity_id),
            "label": label[:512], "status": status, "metadata": meta,
        }
        return key

    def edge(self, src: NodeKey, tgt: NodeKey, rel: str, source: str) -> None:
        """Record a sourced edge between two nodes already in the graph.

        Both endpoints must exist when this is called, so contributor order in
        :func:`_contribute` matters: an edge to a node added later is dropped.
        """
        if not source:
            raise ValueError(f"edge {src} -> {tgt} ({rel}) has no source")
        if src in self.nodes and tgt in self.nodes:
            self.edges.append((src, tgt, rel, source))


async def _contribute(
    session: AsyncSession, org_id: int, g: _Graph
) -> tuple[dict[str, int], dict[str, str]]:
    """Populate ``g`` from every source: ``(node counts, failed contributors)``.

    Each contributor runs in its own savepoint. A failed statement aborts a
    Postgres transaction, so without one, every contributor after the first
    failure would fail too, and the rebuild's own deletes with them.
    """
    stats: dict[str, int] = {}
    failed: dict[str, str] = {}

    async def run(name: str, contributor: Any) -> None:
        before = len(g.nodes)
        try:
            async with session.begin_nested():
                await contributor(session, org_id, g)
            stats[name] = len(g.nodes) - before
        except Exception as exc:  # recorded and shown, never silent
            log.warning("assurance.source_failed", source=name, error=str(exc)[:200])
            stats[name] = 0
            failed[name] = f"{type(exc).__name__}: {str(exc)[:200]}"

    await run("systems", _systems)
    await run("controls", _controls)
    await run("ksis", _ksis)
    await run("poams", _poams)
    await run("risks", _risks)
    await run("vendors", _vendors)
    await run("scans", _scans)
    await run("control_tests", _control_tests)
    await run("connectors", _connectors)
    await run("evidence_objects", _evidence_objects)
    await run("ai_agents", _ai_agents)
    return stats, failed
```

`run` now takes the contributor function, not a coroutine. That way the monkeypatched `builder._poams` in the test is looked up when `run` is called. `connectors` now runs after `control_tests`, because Task 3 links connectors to tests.

- [ ] **Step 6: Give every existing `g.edge` call its source, and remove the guessed edges**

Make these edits in `builder.py`, one per call:

| Contributor | Call | New last argument |
|---|---|---|
| `_controls` | `g.edge(("system", ...), ck, "has_control")` | `"control_implementations"` |
| `_controls` | `g.edge(ck, ek, "supported_by")` | `"evidence"` |
| `_ksis` | `g.edge(("system", ...), kk, "assessed_by")` | `"ksi_states"` |
| `_poams` | `g.edge(..., pk, "has_poam")` | `"poams"` |
| `_risks` | `g.edge(rk, ..., "threatens")` | `"risks"` |
| `_scans` | `g.edge(sk, ..., "scanned")` | `"scan_ingestions"` |
| `_control_tests` | `g.edge(tk, ..., "tests")` | `"control_tests"` |
| `_evidence_objects` | `g.edge(..., ek, "documented_by")` | `"evidence_objects"` |

Replace `_connectors` with a version that draws no edges (Task 3 adds the sourced ones):

```python
async def _connectors(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_grc import ConnectorConfig  # noqa: PLC0415

    for c in (
        await session.execute(
            select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
        )
    ).scalars().all():
        g.node("connector", c.id, c.name, c.status, connector_type=c.connector_type)
```

In `_ai_agents`, replace the confidence arguments with the agent record as the source:

```python
        if a.system_id is not None:
            g.edge(ak, ("system", str(a.system_id)), "accesses", "ai_agents")
        for ttype, ids, rel in targets:
            for tid in ids:
                # Only connect to nodes the builder already created this run.
                g.edge(ak, (ttype, str(tid)), rel, "ai_agents")
        for rid in list(a.risk_ids or []):
            g.edge(ak, ("risk", str(rid)), "introduces_risk", "ai_agents")
```

- [ ] **Step 7: Persist the source and the failures in `rebuild_org`**

In `rebuild_org`, change `stats = await _contribute(session, org_id, g)` to:

```python
    stats, failed = await _contribute(session, org_id, g)
```

Change the edge loop:

```python
    for src, tgt, rel, source in g.edges:
        sid, tid = key_to_id.get(src), key_to_id.get(tgt)
        if sid is None or tid is None or (sid, tid, rel) in seen:
            continue
        seen.add((sid, tid, rel))
        session.add(
            AssuranceEdge(
                organization_id=org_id, source_node_id=sid, target_node_id=tid,
                relationship_type=rel, source=source,
            )
        )
        edge_count += 1
```

Change the end of the function:

```python
    run.node_count = len(g.nodes)
    run.edge_count = edge_count
    # "partial", not "ok": a slice is missing, and the page says which.
    run.status = "partial" if failed else "ok"
    run.finished_at = datetime.now(UTC)
    run.detail = {"sources": stats, "failed": failed}
```

- [ ] **Step 8: Return `provenance` from the subgraph**

In `src/ccf/assurance/impact.py`, in `subgraph`, replace the `kept_edges` comprehension:

```python
    kept_edges = [
        {"source": e.source_node_id, "target": e.target_node_id,
         "relationship_type": e.relationship_type, "provenance": e.source}
        for e in edges
        if e.source_node_id in seen and e.target_node_id in seen
    ]
```

- [ ] **Step 9: Run the new tests and the existing assurance tests**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py tests/test_assurance_graph.py tests/test_assurance_graph_stays_current.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)|FAILED"`

Expected: all pass. If an existing test asserts `confidence`, update that assertion to `provenance`; the field was removed by design.

- [ ] **Step 10: Mutation-check the guards**

For each mutation, copy the file to the scratchpad, make the edit, run the named test and confirm it FAILS, then copy the original back:
- Delete the `if not source: raise` lines in `_Graph.edge`. → `test_the_builder_refuses_an_edge_without_a_source` must fail.
- Replace `async with session.begin_nested():` with `if True:`. → `test_a_failed_contributor_is_recorded_and_the_rest_still_build` must fail.
- Change `"partial" if failed else "ok"` to `"ok"`. → the same test must fail.

- [ ] **Step 11: Lint, type-check, commit**

```bash
.venv/bin/ruff check src tests && .venv/bin/mypy src | tail -1
git add migrations/versions/0098_assurance_edge_source.py src/ccf/models_assurance.py src/ccf/assurance/builder.py src/ccf/assurance/impact.py tests/test_compliance_graph.py
git commit -m "feat(assurance): every graph edge names its source; guessed edges removed

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Control nodes are real controls

**Files:**
- Modify: `src/ccf/assurance/builder.py` (`_Graph.__init__`, new `fold_control`, `_worst`, `_controls`, `_ai_agents`)
- Test: `tests/test_compliance_graph.py`

**Interfaces:**
- Consumes: `_Graph.edge(..., source)` from Task 1.
- Produces:
  - `builder.fold_control(identifier: str, sequence_control: str | None) -> tuple[str, bool]`, returning (node id part, placed).
  - `builder.STATUS_ORDER: tuple[str, ...]`.
  - Control node key `("control", f"{system_id}:{canonical}")`, with metadata `system_id`, `owners: list[str]`, `rows: int` and `placed: bool`.
  - `_Graph.impl_index: dict[str, NodeKey]`, mapping an implementation row id to its control node.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_compliance_graph.py`:

```python
# ── Task 2: control nodes are real controls ──────────────────────────────────


def test_fold_control_places_rows_on_the_control_they_decompose() -> None:
    assert builder.fold_control("AC-02", None) == ("AC-2", True)
    assert builder.fold_control("AC-02(01)", None) == ("AC-2(1)", True)
    assert builder.fold_control("AC-02a.[01]", "AC-02") == ("AC-2", True)
    assert builder.fold_control("AC-02_ODP[01]", "AC-02") == ("AC-2", True)
    # Neither names a control: shown as recorded, never dropped or guessed.
    assert builder.fold_control("AC-06(01).b", "AC-06(01).b") == ("AC-06(01).b", False)


async def test_objective_rows_fold_into_one_node_and_the_worst_status_wins() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02", "implemented")
    await _implement(sid, f"AC-02a.[0{next(_SEQ) % 9 + 1}]x{next(_SEQ)}", "planned",
                     sequence_control="AC-02")
    await _build(org)
    nodes = await _nodes(org)
    controls = {k: v for k, v in nodes.items() if k.startswith("control:")}
    assert list(controls) == [f"control:{sid}:AC-2"]
    node = controls[f"control:{sid}:AC-2"]
    assert node["status"] == "planned" and node["metadata"]["rows"] == 2
    assert node["metadata"]["placed"] is True


async def test_a_row_that_names_no_control_is_shown_unplaced() -> None:
    org, sid = await _org_and_system()
    ident = f"ZZ-weird-{next(_SEQ)}"
    await _implement(sid, ident, "partial")
    await _build(org)
    node = (await _nodes(org))[f"control:{sid}:{ident}"]
    assert node["metadata"]["placed"] is False


async def test_owners_of_every_folded_row_are_listed() -> None:
    from ccf.models import User  # noqa: PLC0415

    org, sid = await _org_and_system()
    async with session_scope() as s:
        a = User(email=f"a{next(_SEQ)}@g.test", full_name="Ana Owner", organization_id=org)
        b = User(email=f"b{next(_SEQ)}@g.test", full_name=None, organization_id=org)
        s.add_all([a, b])
        await s.flush()
        a_id, b_id, b_email = a.id, b.id, b.email
    await _implement(sid, "AC-03", owner_user_id=a_id)
    await _implement(sid, f"AC-03b.x{next(_SEQ)}", sequence_control="AC-03", owner_user_id=b_id)
    await _build(org)
    owners = (await _nodes(org))[f"control:{sid}:AC-3"]["metadata"]["owners"]
    assert owners == sorted(["Ana Owner", b_email])


async def test_evidence_still_reaches_its_system_through_the_folded_control() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02", evidence_title="screenshot")
    await _build(org)
    edges = await _edges(org)
    assert (f"system:{sid}", f"control:{sid}:AC-2", "has_control", "control_implementations") in edges
    assert any(
        e[0] == f"control:{sid}:AC-2" and e[1].startswith("evidence:") for e in edges
    )


async def test_an_agent_reaches_a_control_by_row_id_or_by_canonical_id() -> None:
    from ccf.models_ai_agents import AiAgent  # noqa: PLC0415

    org, sid = await _org_and_system()
    impl_id = await _implement(sid, "AC-02")
    await _implement(sid, "AU-02")
    async with session_scope() as s:
        s.add(AiAgent(organization_id=org, name="Triage bot", system_id=sid,
                      control_ids=[impl_id, "au-2"]))
    await _build(org)
    edges = {(e[0].split(":")[0], e[1], e[3]) for e in await _edges(org)}
    assert ("ai_agent", f"control:{sid}:AC-2", "ai_agents") in edges
    assert ("ai_agent", f"control:{sid}:AU-2", "ai_agents") in edges
```

Note: `User` may require other non-null columns, such as `role`, which has a default. If the flush fails, add `role="control_owner"`, matching `tests/test_viewer_is_read_only.py:_token`.

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py -q -k "fold or folded or unplaced or owners or agent_reaches" 2>&1 | tail -5`

Expected: FAIL, because `fold_control` is not defined.

- [ ] **Step 3: Implement folding, worst status and owners**

In `builder.py`, add the import `from ..catalog.canonical import canonicalize` at the top. Add `self.impl_index: dict[str, NodeKey] = {}` to `_Graph.__init__`. Then add, above `_controls`:

```python
#: Worst first. A control is only as implemented as its least-implemented row.
STATUS_ORDER: tuple[str, ...] = (
    "not_implemented", "planned", "partial", "inherited", "implemented", "not_applicable",
)


def _worst(statuses: Any) -> str | None:
    ranked = [s for s in statuses if s in STATUS_ORDER]
    return min(ranked, key=STATUS_ORDER.index) if ranked else None


def fold_control(identifier: str, sequence_control: str | None) -> tuple[str, bool]:
    """The control a catalog row belongs to: ``(id, placed)``.

    ``controls`` holds assessment objectives and ODP rows as well as controls,
    so one node per row overstates the graph about fourfold. A row is the
    control it names; otherwise it attaches through ``sequence_control`` (the
    same rule as ``catalog/baseline_delta.py``); otherwise it is shown as
    recorded with ``placed=False`` -- reported, never guessed or dropped.
    """
    for raw in (identifier, sequence_control):
        c = canonicalize(raw)
        if c is not None:
            return c.value, True
    return identifier, False
```

Replace `_controls`:

```python
async def _controls(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from sqlalchemy.orm import selectinload  # noqa: PLC0415

    from ..models import Control, ControlImplementation, System, User  # noqa: PLC0415

    rows = (
        await session.execute(
            select(ControlImplementation, Control.identifier, Control.sequence_control)
            .join(Control, Control.id == ControlImplementation.control_id)
            .join(System, System.id == ControlImplementation.system_id)
            .where(System.organization_id == org_id)
            .options(selectinload(ControlImplementation.evidence))
        )
    ).all()
    owner_ids = {r[0].owner_user_id for r in rows if r[0].owner_user_id is not None}
    owners: dict[int, str] = {}
    if owner_ids:
        for u in (
            await session.execute(select(User).where(User.id.in_(owner_ids)))
        ).scalars():
            owners[u.id] = u.full_name or u.email

    grouped: dict[tuple[int, str], list[Any]] = {}
    placed: dict[tuple[int, str], bool] = {}
    for impl, identifier, sequence_control in rows:
        cid, ok = fold_control(identifier, sequence_control)
        grouped.setdefault((impl.system_id, cid), []).append(impl)
        placed[(impl.system_id, cid)] = ok

    for (sid, cid), impls in grouped.items():
        ck = g.node(
            "control", f"{sid}:{cid}", cid, _worst(i.status for i in impls),
            system_id=sid, rows=len(impls), placed=placed[(sid, cid)],
            owners=sorted({owners[i.owner_user_id] for i in impls
                           if i.owner_user_id in owners}),
        )
        g.edge(("system", str(sid)), ck, "has_control", "control_implementations")
        for impl in impls:
            g.impl_index[str(impl.id)] = ck
            for ev in impl.evidence or []:
                ek = g.node("evidence", ev.id, ev.title or f"evidence-{ev.id}", ev.kind)
                g.edge(ck, ek, "supported_by", "evidence")
```

- [ ] **Step 4: Resolve AI-agent control references to the new node ids**

In `_ai_agents`, remove the `("control", list(a.control_ids or []), "governed_by")` entry from `targets`, and add this after the `targets` loop:

```python
        # control_ids is free-form: an implementation row id (what the graph
        # keyed controls by before) or a control id. Neither is guessed past.
        agent_systems = {str(s) for s in [a.system_id, *(a.system_ids or [])] if s is not None}
        for tid in a.control_ids or []:
            key = g.impl_index.get(str(tid))
            if key is not None:
                g.edge(ak, key, "governed_by", "ai_agents")
                continue
            c = canonicalize(str(tid))
            for sid in agent_systems if c is not None else ():
                g.edge(ak, ("control", f"{sid}:{c.value}"), "governed_by", "ai_agents")
```

- [ ] **Step 5: Run the module and the existing assurance tests**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py tests/test_assurance_graph.py tests/test_assurance_graph_stays_current.py tests/test_ai_agents*.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)|FAILED"`

Expected: all pass. If an AI-agent test asserted an edge to `("control", "<impl id>")`, it now resolves through `impl_index` to the folded node. Update the expected key to `control:<sid>:<canonical>`.

- [ ] **Step 6: Mutation-check**

- Swap `min` for `max` in `_worst`. → `test_objective_rows_fold_into_one_node_and_the_worst_status_wins` must fail.
- Change `for raw in (identifier, sequence_control)` to `for raw in (identifier,)`. → the same test and `test_fold_control_places_rows_on_the_control_they_decompose` must fail.
- Delete the `g.impl_index[...] = ck` line. → `test_an_agent_reaches_a_control_by_row_id_or_by_canonical_id` must fail.

- [ ] **Step 7: Lint, type-check, commit**

```bash
.venv/bin/ruff check src tests && .venv/bin/mypy src | tail -1
git add src/ccf/assurance/builder.py tests/test_compliance_graph.py
git commit -m "feat(assurance): one graph node per real control, worst status, every owner

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Sourced edges for capabilities, KSIs, control tests and connectors

**Files:**
- Modify: `src/ccf/capability/derive.py:38-69` (extract `bound_capability_ids`)
- Modify: `src/ccf/assurance/builder.py` (`_ksis`, new `_capabilities`, `_control_tests`, `_connectors`, `_contribute` order)
- Test: `tests/test_compliance_graph.py`

**Interfaces:**
- Consumes: control node key `("control", f"{sid}:{canonical}")` from Task 2.
- Produces:
  - `ccf.capability.derive.bound_capability_ids(system_id: int) -> Select[tuple[int]]`.
  - Capability node `("capability", f"{sid}:{cap_id}")`.
  - KSI node label = `KSI.identifier`. Its key is unchanged: `("ksi", f"{sid}:{ksi_row_id}")`.
  - Edge sources: `capability_controls`, `capability_ksis`, `fedramp-rules@<version>`, the test's `check_source` (else `control_tests`), and `control_tests` for connector → test.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_compliance_graph.py`:

```python
# ── Task 3: capabilities, KSIs, tests and connectors ─────────────────────────


async def _capability(org_id: int, system_id: int, *, controls: list[str],
                      ksis: tuple[str, ...] = (), title: str = "MFA") -> int:
    from ccf.models import SystemComponent  # noqa: PLC0415
    from ccf.models_capability import (  # noqa: PLC0415
        Capability, CapabilityComponent, CapabilityControl, CapabilityKsi,
    )

    async with session_scope() as s:
        cap = Capability(organization_id=org_id, key=f"cap-{next(_SEQ)}", title=title,
                         status="implemented")
        comp = SystemComponent(organization_id=org_id, system_id=system_id, type="software",
                               title=f"IdP {next(_SEQ)}")
        s.add_all([cap, comp])
        await s.flush()
        s.add(CapabilityComponent(organization_id=org_id, capability_id=cap.id,
                                  component_id=comp.id))
        s.add_all([CapabilityControl(organization_id=org_id, capability_id=cap.id,
                                     control_id=c) for c in controls])
        s.add_all([CapabilityKsi(organization_id=org_id, capability_id=cap.id,
                                 ksi_identifier=k) for k in ksis])
        await s.flush()
        return cap.id


async def _seeded_ksi_with_a_control() -> tuple[int, str, str]:
    """``(ksi row id, identifier, canonical control)`` for a current KSI."""
    from ccf.catalog.canonical import canonicalize  # noqa: PLC0415
    from ccf.fedramp20x import catalog  # noqa: PLC0415

    async with session_scope() as s:
        await catalog.seed_ksis(s)
    async with session_scope() as s:
        for k in (await s.execute(catalog.current_ksis())).scalars():
            for ref in k.nist_refs or []:
                c = canonicalize(str(ref))
                if c is not None:
                    return k.id, k.identifier, c.value
    raise AssertionError("no current KSI names an 800-53 control")


async def test_a_capability_links_to_the_controls_and_ksis_it_claims() -> None:
    from ccf.models import KSIState  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    cap = await _capability(org, sid, controls=[control], ksis=[ksi_ident])
    await _build(org)
    edges = await _edges(org)
    assert (f"capability:{sid}:{cap}", f"control:{sid}:{control}", "implements",
            "capability_controls") in edges
    assert (f"capability:{sid}:{cap}", f"ksi:{sid}:{ksi_id}", "satisfies",
            "capability_ksis") in edges


async def test_a_ksi_links_to_the_controls_the_system_implements_only() -> None:
    from ccf.fedramp20x import rules  # noqa: PLC0415
    from ccf.models import KSIState  # noqa: PLC0415

    ksi_id, ksi_ident, control = await _seeded_ksi_with_a_control()
    org, sid = await _org_and_system()
    await _implement(sid, control)
    async with session_scope() as s:
        s.add(KSIState(system_id=sid, ksi_id=ksi_id, status="pass"))
    await _build(org)
    nodes = await _nodes(org)
    assert nodes[f"ksi:{sid}:{ksi_id}"]["label"] == ksi_ident
    ksi_edges = [e for e in await _edges(org) if e[0] == f"ksi:{sid}:{ksi_id}"]
    assert ksi_edges == [(f"ksi:{sid}:{ksi_id}", f"control:{sid}:{control}", "maps_to",
                          f"fedramp-rules@{rules.load_rules().version}")]


async def test_control_ids_written_differently_meet_on_one_node() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "IA-02")  # catalog spelling
    cap = await _capability(org, sid, controls=["ia-2"])  # capability spelling
    await _build(org)
    assert (f"capability:{sid}:{cap}", f"control:{sid}:IA-2", "implements",
            "capability_controls") in await _edges(org)


async def test_a_capability_from_another_tenant_is_not_drawn() -> None:
    """Bound by id to org A's component, owned by org B: not in A's graph."""
    from ccf.models import SystemComponent  # noqa: PLC0415
    from ccf.models_capability import (  # noqa: PLC0415
        Capability, CapabilityComponent, CapabilityControl,
    )

    org_a, sid_a = await _org_and_system()
    org_b, _sid_b = await _org_and_system()
    await _implement(sid_a, "IA-02")
    async with session_scope() as s:  # unscoped: RLS cannot make this pass
        comp = SystemComponent(organization_id=org_a, system_id=sid_a, type="software",
                               title="A's IdP")
        cap = Capability(organization_id=org_b, key=f"b-{next(_SEQ)}", title="B's MFA",
                         status="implemented")
        s.add_all([comp, cap])
        await s.flush()
        s.add(CapabilityComponent(organization_id=org_b, capability_id=cap.id,
                                  component_id=comp.id))
        s.add(CapabilityControl(organization_id=org_b, capability_id=cap.id,
                                control_id="IA-2"))
    await _build(org_a)
    assert not [k for k in await _nodes(org_a) if k.startswith("capability:")]


async def test_a_test_evidences_every_control_it_declares_with_its_check_source() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "IA-02")
    await _implement(sid, "IA-05")
    async with session_scope() as s:
        t = ControlTest(organization_id=org, system_id=sid, control_id="IA-2",
                        control_ids=["IA-2", "IA-5"], name="Secure Score: MFA",
                        method="automated", check_source="crosswalk:securescore")
        s.add(t)
        await s.flush()
        tid = t.id
    await _build(org)
    edges = await _edges(org)
    for control in ("IA-2", "IA-5"):
        assert (f"control_test:{tid}", f"control:{sid}:{control}", "evidences",
                "crosswalk:securescore") in edges


async def _connector_test(org: int, sid: int, ctype: str) -> int:
    async with session_scope() as s:
        t = ControlTest(organization_id=org, system_id=sid, control_id="AC-2",
                        name=f"{ctype} check", method="connector", connector_type=ctype)
        s.add(t)
        await s.flush()
        return t.id


async def test_a_connector_reaches_a_system_only_through_its_tests() -> None:
    org, sid = await _org_and_system()
    other = await _system(org)
    tid = await _connector_test(org, sid, "aws")
    async with session_scope() as s:
        c = ConnectorConfig(organization_id=org, name="AWS prod", connector_type="aws")
        s.add(c)
        await s.flush()
        cid = c.id
    await _build(org)
    edges = await _edges(org)
    assert (f"connector:{cid}", f"control_test:{tid}", "produced", "control_tests") in edges
    assert not [e for e in edges if e[0] == f"connector:{cid}" and e[1] == f"system:{other}"]


async def test_two_connectors_of_one_type_are_not_guessed_between() -> None:
    org, sid = await _org_and_system()
    await _connector_test(org, sid, "m365")
    async with session_scope() as s:
        s.add_all([ConnectorConfig(organization_id=org, name=f"Tenant {n}",
                                   connector_type="m365") for n in (1, 2)])
    await _build(org)
    assert not [e for e in await _edges(org) if e[0].startswith("connector:")]
    reasons = [v["metadata"].get("unlinked_reason") for k, v in (await _nodes(org)).items()
               if k.startswith("connector:")]
    assert all(r and "2 m365 connectors" in r for r in reasons)
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py -q -k "capability or ksi_links or written_differently or evidences_every or connector_reaches or two_connectors" 2>&1 | tail -5`

Expected: FAIL. There are no capability nodes and no `maps_to` edges yet.

- [ ] **Step 3: Extract the capability binding in `derive.py`**

In `src/ccf/capability/derive.py`, add `from sqlalchemy import Select` next to `select`. Add this above `_capabilities_for_system`, and move the binding docstring onto it:

```python
def bound_capability_ids(system_id: int) -> Select[tuple[int]]:
    """Ids of the capabilities bound to a system: capability -> component -> system.

    Binding runs capability -> component -> system, which is also how a
    policy- or process-backed capability attaches: ``SystemComponent.type``
    already includes ``policy`` and ``process``.

    Filtered on ``Capability.organization_id == System.organization_id`` -- an
    edge's FK check does not consult RLS, so without this predicate a
    capability from one tenant bound (by id) to another tenant's component
    would count as the other tenant's. This is the only defense for the
    CLI/scheduler paths, which run through ``session_scope()`` unscoped.
    """
    return (
        select(Capability.id)
        .join(CapabilityComponent, CapabilityComponent.capability_id == Capability.id)
        .join(SystemComponent, SystemComponent.id == CapabilityComponent.component_id)
        .join(System, System.id == SystemComponent.system_id)
        .where(
            SystemComponent.system_id == system_id,
            Capability.organization_id == System.organization_id,
        )
    )


async def _capabilities_for_system(
    session: AsyncSession, *, system_id: int
) -> list[tuple[Capability, str]]:
    """``(capability, raw_control_id)`` pairs bound to this system (see
    :func:`bound_capability_ids` for the binding and its tenant predicate)."""
    rows = (
        await session.execute(
            select(Capability, CapabilityControl.control_id)
            .join(CapabilityControl, CapabilityControl.capability_id == Capability.id)
            .where(Capability.id.in_(bound_capability_ids(system_id)))
        )
    ).all()
    return [(r[0], r[1]) for r in rows]
```

Run: `.venv/bin/python -m pytest tests/test_capability_derive.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)"`

Expected: all pass. This is a refactor only, and line 294's cross-tenant test still guards the binding.

- [ ] **Step 4: KSI labels and KSI → control edges**

Replace `_ksis` in `builder.py`:

```python
async def _ksis(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..fedramp20x import rules  # noqa: PLC0415
    from ..fedramp20x.catalog import current_ksi_ids  # noqa: PLC0415
    from ..models import KSI, KSIState, System  # noqa: PLC0415

    source = f"fedramp-rules@{rules.load_rules().version}"
    rows = (
        await session.execute(
            select(KSIState, KSI)
            .join(KSI, KSI.id == KSIState.ksi_id)
            .join(System, System.id == KSIState.system_id)
            .where(System.organization_id == org_id, KSIState.ksi_id.in_(current_ksi_ids()))
        )
    ).all()
    for st, ksi in rows:
        kk = g.node("ksi", f"{st.system_id}:{st.ksi_id}", ksi.identifier, st.status,
                    system_id=st.system_id)
        g.edge(("system", str(st.system_id)), kk, "assessed_by", "ksi_states")
        for ref in ksi.nist_refs or []:
            c = canonicalize(str(ref))
            if c is not None:  # drawn only if the system implements it (node exists)
                g.edge(kk, ("control", f"{st.system_id}:{c.value}"), "maps_to", source)
```

- [ ] **Step 5: The capability contributor**

Add to `builder.py`, after `_ksis`:

```python
async def _capabilities(session: AsyncSession, org_id: int, g: _Graph) -> None:
    """Capability nodes per system they are bound to, linked to what they claim."""
    from ..capability.derive import bound_capability_ids  # noqa: PLC0415
    from ..fedramp20x.catalog import current_ksis  # noqa: PLC0415
    from ..models import System  # noqa: PLC0415
    from ..models_capability import Capability, CapabilityControl, CapabilityKsi  # noqa: PLC0415

    ksi_ids = {k.identifier: k.id for k in (await session.execute(current_ksis())).scalars()}
    sys_ids = (
        await session.execute(select(System.id).where(System.organization_id == org_id))
    ).scalars().all()
    for sid in sys_ids:
        caps = (
            await session.execute(
                select(Capability).where(Capability.id.in_(bound_capability_ids(sid)))
            )
        ).scalars().all()
        if not caps:
            continue
        cap_ids = [c.id for c in caps]
        for cap in caps:
            g.node("capability", f"{sid}:{cap.id}", cap.title, cap.status,
                   system_id=sid, key=cap.key, responsible_role=cap.responsible_role)
        for cap_id, raw in (
            await session.execute(
                select(CapabilityControl.capability_id, CapabilityControl.control_id)
                .where(CapabilityControl.capability_id.in_(cap_ids))
            )
        ).all():
            c = canonicalize(raw)
            if c is not None:
                g.edge(("capability", f"{sid}:{cap_id}"), ("control", f"{sid}:{c.value}"),
                       "implements", "capability_controls")
        for cap_id, ident in (
            await session.execute(
                select(CapabilityKsi.capability_id, CapabilityKsi.ksi_identifier)
                .where(CapabilityKsi.capability_id.in_(cap_ids))
            )
        ).all():
            kid = ksi_ids.get(ident)
            if kid is not None:  # a retired or unknown KSI is not drawn
                g.edge(("capability", f"{sid}:{cap_id}"), ("ksi", f"{sid}:{kid}"),
                       "satisfies", "capability_ksis")
```

In `_contribute`, add `await run("capabilities", _capabilities)` immediately after `await run("ksis", _ksis)`.

- [ ] **Step 6: Control test → control, and connector → test**

Replace `_control_tests`:

```python
async def _control_tests(session: AsyncSession, org_id: int, g: _Graph) -> None:
    from ..models_grc import ControlTest  # noqa: PLC0415
    from ..posture.evidence import evidenced_controls  # noqa: PLC0415

    for t in (
        await session.execute(select(ControlTest).where(ControlTest.organization_id == org_id))
    ).scalars().all():
        tk = g.node("control_test", t.id, t.name, t.last_status, control_id=t.control_id,
                    system_id=t.system_id)
        if t.system_id is None:
            continue
        g.edge(tk, ("system", str(t.system_id)), "tests", "control_tests")
        for raw in evidenced_controls(t.control_id, t.control_ids):
            c = canonicalize(raw)
            if c is not None:
                g.edge(tk, ("control", f"{t.system_id}:{c.value}"), "evidences",
                       t.check_source or "control_tests")
```

Replace `_connectors`:

```python
async def _connectors(session: AsyncSession, org_id: int, g: _Graph) -> None:
    """Connector -> the connector tests it produced; never connector -> system.

    A test records its ``connector_type``, not which connector produced it. With
    exactly one connector of that type in the org the link is a fact; with two,
    it would be a guess, so neither is linked and the node says why.
    """
    from ..models_grc import ConnectorConfig, ControlTest  # noqa: PLC0415

    conns = (
        await session.execute(
            select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
        )
    ).scalars().all()
    per_type: dict[str, int] = {}
    for c in conns:
        per_type[c.connector_type] = per_type.get(c.connector_type, 0) + 1
    tests: dict[str, list[int]] = {}
    for tid, ctype in (
        await session.execute(
            select(ControlTest.id, ControlTest.connector_type).where(
                ControlTest.organization_id == org_id, ControlTest.method == "connector"
            )
        )
    ).all():
        if ctype:
            tests.setdefault(ctype, []).append(tid)
    for c in conns:
        n = per_type[c.connector_type]
        reason = None
        if n > 1 and tests.get(c.connector_type):
            reason = (
                f"{n} {c.connector_type} connectors are configured and a test does not "
                "record which one produced it, so none is linked."
            )
        ck = g.node("connector", c.id, c.name, c.status, connector_type=c.connector_type,
                    unlinked_reason=reason)
        if n == 1:
            for tid in tests.get(c.connector_type, []):
                g.edge(ck, ("control_test", str(tid)), "produced", "control_tests")
```

- [ ] **Step 7: Run the module and its neighbours**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py tests/test_assurance_graph.py tests/test_assurance_graph_stays_current.py tests/test_capability_derive.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)|FAILED"`

Expected: all pass.

- [ ] **Step 8: Mutation-check**

- Delete `Capability.organization_id == System.organization_id` in `bound_capability_ids`. → `test_a_capability_from_another_tenant_is_not_drawn` must fail.
- Change `if n == 1:` to `if n >= 1:`. → `test_two_connectors_of_one_type_are_not_guessed_between` must fail.
- In `_capabilities`, replace `c = canonicalize(raw)` with a raw compare: `c = type("C", (), {"value": raw})()`. → `test_control_ids_written_differently_meet_on_one_node` must fail.
- Change `t.check_source or "control_tests"` to `"control_tests"`. → `test_a_test_evidences_every_control_it_declares_with_its_check_source` must fail.

- [ ] **Step 9: Lint, type-check, commit**

```bash
.venv/bin/ruff check src tests && .venv/bin/mypy src | tail -1
git add src/ccf/capability/derive.py src/ccf/assurance/builder.py tests/test_compliance_graph.py
git commit -m "feat(assurance): sourced edges for capabilities, KSIs, tests and connectors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: A system-scoped subgraph and one view builder for page and API

**Files:**
- Modify: `src/ccf/assurance/impact.py` (`_node_out`, `subgraph`, new `system_view`)
- Modify: `src/ccf/api/routes/assurance.py:32-49` (`system_graph`)
- Test: `tests/test_compliance_graph.py`

**Interfaces:**
- Consumes: node metadata `system_id`, from Tasks 2 and 3.
- Produces:
  - `impact.subgraph(..., within_system: int | None = None)`.
  - `impact.system_view(session, *, system: System, hops: int = 6, within_system: bool = True) -> dict`, with keys `root`, `nodes`, `edges`, `built_at` (ISO str | None), `build_status` (str | None) and `failed_contributors` (dict[str, str]).
  - Node dicts gain `"metadata"`.
  - API: `GET /api/assurance/graph/systems/{id}?hops=&scope=connected|system`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_compliance_graph.py`:

```python
# ── Task 4: system scope and the shared view ─────────────────────────────────


async def _two_systems_sharing_a_connector() -> tuple[int, int, int]:
    org, sid = await _org_and_system()
    other = await _system(org)
    await _implement(sid, "AC-02")
    await _implement(other, "AU-02")
    await _connector_test(org, sid, "aws")
    await _connector_test(org, other, "aws")
    async with session_scope() as s:
        s.add(ConnectorConfig(organization_id=org, name="AWS", connector_type="aws"))
    await _build(org)
    return org, sid, other


async def test_connected_scope_reaches_other_systems_through_shared_nodes() -> None:
    org, sid, other = await _two_systems_sharing_a_connector()
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid),
                                  max_hops=6)
    assert any(n["entity_id"] == f"{other}:AU-2" for n in g["nodes"])


async def test_system_scope_stops_at_another_systems_nodes() -> None:
    org, sid, other = await _two_systems_sharing_a_connector()
    async with session_scope() as s:
        g = await impact.subgraph(s, org_id=org, entity_type="system", entity_id=str(sid),
                                  max_hops=6, within_system=sid)
    ids = {(n["entity_type"], n["entity_id"]) for n in g["nodes"]}
    assert ("control", f"{sid}:AC-2") in ids
    assert ("control", f"{other}:AU-2") not in ids
    assert not [n for n in g["nodes"] if n["entity_type"] == "control_test"
                and n["metadata"].get("system_id") == other]


async def test_system_view_carries_the_build_and_its_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("risk register offline")

    monkeypatch.setattr(builder, "_risks", broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _build(org)
    async with session_scope() as s:
        sysm = await s.get(System, sid)
        v = await impact.system_view(s, system=sysm)
    assert v["build_status"] == "partial" and v["built_at"]
    assert v["failed_contributors"] == {"risks": "RuntimeError: risk register offline"}


async def test_the_api_returns_the_same_view_with_scope() -> None:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    org, sid, other = await _two_systems_sharing_a_connector()
    async with AsyncClient(transport=ASGITransport(app=create_app()),
                           base_url="http://t") as c:
        body = (await c.get(f"/api/assurance/graph/systems/{sid}?scope=system")).json()
        bad = await c.get(f"/api/assurance/graph/systems/{sid}?scope=everything")
    assert body["build_status"] == "ok" and body["failed_contributors"] == {}
    assert all(e["provenance"] for e in body["edges"])
    assert not any(n["entity_id"] == f"{other}:AU-2" for n in body["nodes"])
    assert bad.status_code == 422
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py -q -k "scope or system_view or same_view" 2>&1 | tail -5`

Expected: FAIL. `within_system` and `system_view` don't exist yet.

- [ ] **Step 3: Implement the scope and the view**

In `impact.py`, change `_node_out` to include metadata:

```python
def _node_out(n: AssuranceNode) -> dict[str, Any]:
    return {
        "id": n.id,
        "entity_type": n.entity_type,
        "entity_id": n.entity_id,
        "label": n.label,
        "status": n.status,
        "metadata": dict(n.node_metadata or {}),
    }
```

Replace `subgraph`'s signature and its BFS:

```python
async def subgraph(
    session: AsyncSession,
    *,
    org_id: int | None,
    entity_type: str,
    entity_id: str,
    max_hops: int = 5,
    within_system: int | None = None,
) -> dict[str, Any]:
    """Return the connected subgraph (nodes + edges) around a root entity.

    ``within_system`` keeps the walk inside one system. Capabilities,
    connectors and agents join systems together, so an unscoped walk from one
    system reaches another's controls and tests. Scoped, a node belonging to
    another system (``metadata.system_id``) is not returned, and another
    system's own node is returned as a boundary but not walked past.
    """
    root_stmt = select(AssuranceNode).where(
        AssuranceNode.entity_type == entity_type, AssuranceNode.entity_id == str(entity_id)
    )
    if org_id is not None:
        root_stmt = root_stmt.where(AssuranceNode.organization_id == org_id)
    root = (await session.execute(root_stmt)).scalars().first()
    if root is None:
        return {"root": None, "nodes": [], "edges": []}

    edge_stmt = select(AssuranceEdge).where(
        AssuranceEdge.organization_id == root.organization_id
    )
    edges = (await session.execute(edge_stmt)).scalars().all()
    adj: dict[int, list[int]] = {}
    for e in edges:
        adj.setdefault(e.source_node_id, []).append(e.target_node_id)
        adj.setdefault(e.target_node_id, []).append(e.source_node_id)

    foreign: set[int] = set()
    boundary: set[int] = set()
    if within_system is not None:
        for nid, etype, eid, meta in (
            await session.execute(
                select(AssuranceNode.id, AssuranceNode.entity_type, AssuranceNode.entity_id,
                       AssuranceNode.node_metadata)
                .where(AssuranceNode.organization_id == root.organization_id)
            )
        ).all():
            owner = (meta or {}).get("system_id")
            if etype == "system" and eid != str(within_system):
                boundary.add(nid)
            elif owner is not None and int(owner) != within_system:
                foreign.add(nid)

    seen: set[int] = {root.id}
    queue: deque[tuple[int, int]] = deque([(root.id, 0)])
    while queue:
        nid, depth = queue.popleft()
        if depth >= max_hops:
            continue
        for neighbor in adj.get(nid, []):
            if neighbor in seen or neighbor in foreign:
                continue
            seen.add(neighbor)
            if neighbor not in boundary:
                queue.append((neighbor, depth + 1))
```

Keep the rest of `subgraph`: the `nodes` query, `kept_edges` with `provenance` from Task 1, and the return. Scoping edges to `root.organization_id` replaces the `if org_id is not None` filter. It is the same set for a scoped principal and correct for a global one.

Add after `subgraph`:

```python
async def system_view(
    session: AsyncSession, *, system: Any, hops: int = 6, within_system: bool = True
) -> dict[str, Any]:
    """One system's graph plus the build it came from. The page and the API
    both call this, so their nodes, edges and states cannot disagree."""
    graph = await subgraph(
        session, org_id=system.organization_id, entity_type="system",
        entity_id=str(system.id), max_hops=hops,
        within_system=system.id if within_system else None,
    )
    run = await latest_build(session, system.organization_id)
    graph["built_at"] = run.finished_at.isoformat() if run and run.finished_at else None
    graph["build_status"] = run.status if run else None
    graph["failed_contributors"] = dict((run.detail or {}).get("failed") or {}) if run else {}
    return graph
```

- [ ] **Step 4: Route the API through `system_view`**

In `src/ccf/api/routes/assurance.py`, add `from typing import Literal` and `from fastapi import Query` (merge with the existing imports), then replace `system_graph`:

```python
@router.get("/graph/systems/{system_id}")
async def system_graph(
    system_id: int,
    hops: int = Query(5, ge=1, le=10),
    scope: Literal["connected", "system"] = "connected",
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """The subgraph around a system, with the build it came from.

    ``scope=system`` keeps it to this system's own nodes (what /graph draws);
    ``connected`` (the default) follows every edge, as impact analysis does.
    """
    # Validated before the graph query, which is keyed on the entity id and has
    # no notion of whether that system still exists. Without this a deleted
    # system returned its whole subgraph, and a system in another tenant
    # returned an empty one with a 200 -- the only endpoint of thirty-one that
    # answered anything at all for a foreign id.
    sysm = await require_system_in_scope(session, system_id, principal)
    return await impact.system_view(
        session, system=sysm, hops=hops, within_system=scope == "system"
    )
```

- [ ] **Step 5: Run the module, the deleted-system sweep and the assurance tests**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py tests/test_assurance_graph.py tests/test_deleted_systems_are_not_readable.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)|FAILED"`

Expected: all pass.

- [ ] **Step 6: Mutation-check**

- Delete `or neighbor in foreign` from the BFS. → `test_system_scope_stops_at_another_systems_nodes` must fail.
- Delete the `if neighbor not in boundary:` guard, so boundary nodes are always queued. → the same test must fail.

- [ ] **Step 7: Lint, type-check, commit**

```bash
.venv/bin/ruff check src tests && .venv/bin/mypy src | tail -1
git add src/ccf/assurance/impact.py src/ccf/api/routes/assurance.py tests/test_compliance_graph.py
git commit -m "feat(assurance): a system-scoped subgraph, and one view for page and API

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Vendor Cytoscape.js with a recorded hash

**Files:**
- Create: `src/ccf/api/static/vendor/cytoscape.min.js`
- Create: `src/ccf/api/static/vendor/VENDOR.json`
- Create: `tests/test_vendored_assets.py`

**Interfaces:**
- Produces:
  - The script `/static/vendor/cytoscape.min.js`, which defines `window.cytoscape`.
  - The `VENDOR.json` shape `{"<file>": {"package", "version", "license", "source", "sha256"}}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_vendored_assets.py`:

```python
"""Vendored front-end files are exactly what VENDOR.json says they are."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

VENDOR = Path(__file__).parents[1] / "src/ccf/api/static/vendor"


def test_every_recorded_file_matches_its_hash() -> None:
    manifest = json.loads((VENDOR / "VENDOR.json").read_text(encoding="utf-8"))
    assert "cytoscape.min.js" in manifest
    for name, entry in manifest.items():
        assert set(entry) == {"package", "version", "license", "source", "sha256"}, name
        digest = hashlib.sha256((VENDOR / name).read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"{name} differs from the recorded hash"


def test_the_renderer_is_the_pinned_mit_release() -> None:
    entry = json.loads((VENDOR / "VENDOR.json").read_text(encoding="utf-8"))["cytoscape.min.js"]
    assert entry["version"] == "3.30.2" and entry["license"] == "MIT"
    assert entry["version"] in entry["source"]
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `.venv/bin/python -m pytest tests/test_vendored_assets.py -q 2>&1 | tail -3`

Expected: FAIL, because `VENDOR.json` does not exist.

- [ ] **Step 3: Download the pinned release and record its hash**

```bash
curl -sSfL https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js \
  -o src/ccf/api/static/vendor/cytoscape.min.js
head -c 200 src/ccf/api/static/vendor/cytoscape.min.js; echo
shasum -a 256 src/ccf/api/static/vendor/cytoscape.min.js
```

The first line should be Cytoscape's licence banner, naming the MIT licence. If there is no banner, also save `https://raw.githubusercontent.com/cytoscape/cytoscape.js/v3.30.2/LICENSE` as `src/ccf/api/static/vendor/cytoscape.LICENSE`.

Create `src/ccf/api/static/vendor/VENDOR.json`, putting the 64-hex digest printed by `shasum` in place of `<sha256 from shasum>`:

```json
{
  "cytoscape.min.js": {
    "package": "cytoscape",
    "version": "3.30.2",
    "license": "MIT",
    "source": "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js",
    "sha256": "<sha256 from shasum>"
  }
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `.venv/bin/python -m pytest tests/test_vendored_assets.py tests/test_package_data_is_complete.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)"`

Expected: PASS. The package-data test already covers `static/**/*`.

- [ ] **Step 5: Mutation-check, then commit**

Append one byte to a copy of `cytoscape.min.js` in place (`printf ' ' >> …`). `test_every_recorded_file_matches_its_hash` must fail. Restore the file from the copy.

```bash
git add src/ccf/api/static/vendor/cytoscape.min.js src/ccf/api/static/vendor/VENDOR.json tests/test_vendored_assets.py
git commit -m "build(ui): vendor Cytoscape.js 3.30.2 (MIT) with a recorded sha256

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: The `/graph` page

**Files:**
- Modify: `src/ccf/api/routes/ui_grc.py` (new `graph_page`; `assurance_rebuild` gains `return_to`)
- Create: `src/ccf/api/templates/graph.html`
- Create: `src/ccf/api/static/js/graph.js`
- Modify: `src/ccf/api/templates/base.html:63-68` (nav)
- Modify: `src/ccf/api/templates/assurance.html` (link)
- Test: `tests/test_compliance_graph.py`
- Create: `tests/test_compliance_graph_page_tenancy.py`

**Interfaces:**
- Consumes: `impact.system_view` (Task 4) and `/static/vendor/cytoscape.min.js` (Task 5).
- Produces:
  - `GET /graph?system_id=` returns HTML, or 404 for a system that is unknown, foreign or deleted.
  - `POST /assurance/rebuild` accepts form fields `return_to` (`assurance` | `graph`) and `system_id`.

- [ ] **Step 1: Write the failing page tests**

Append to `tests/test_compliance_graph.py`:

```python
# ── Task 6: the /graph page ──────────────────────────────────────────────────


async def _page(path: str) -> Any:
    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415

    from ccf.api.main import create_app  # noqa: PLC0415

    async with AsyncClient(transport=ASGITransport(app=create_app()),
                           base_url="http://t") as c:
        return await c.get(path)


async def test_the_page_draws_a_built_system_with_tables_matching_the_view() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02", evidence_title="screenshot")
    await _build(org)
    r = await _page(f"/graph?system_id={sid}")
    assert r.status_code == 200
    async with session_scope() as s:
        v = await impact.system_view(s, system=await s.get(System, sid))
    html = r.text
    assert html.count('data-graph-node-row') == len(v["nodes"])
    assert html.count('data-graph-edge-row') == len(v["edges"])
    assert "control_implementations" in html  # provenance is shown, not hidden
    assert '/static/vendor/cytoscape.min.js' in html and 'id="graph-data"' in html


async def test_the_page_says_not_built_rather_than_drawing_nothing() -> None:
    _org, sid = await _org_and_system()
    r = await _page(f"/graph?system_id={sid}")
    assert "Not built yet" in r.text and 'name="return_to" value="graph"' in r.text


async def test_a_system_added_after_the_build_says_so() -> None:
    org, _sid = await _org_and_system()
    await _build(org)
    late = await _system(org)
    r = await _page(f"/graph?system_id={late}")
    assert "not in the graph yet" in r.text


async def test_a_system_with_no_relationships_says_so() -> None:
    org, sid = await _org_and_system()
    await _build(org)
    assert "No recorded relationships" in (await _page(f"/graph?system_id={sid}")).text


async def test_a_failed_contributor_is_named_on_the_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken(session: Any, org_id: int, g: Any) -> None:
        raise RuntimeError("risk register offline")

    monkeypatch.setattr(builder, "_risks", broken)
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _build(org)
    html = (await _page(f"/graph?system_id={sid}")).text
    assert "risks" in html and "risk register offline" in html


async def test_a_title_with_markup_is_shown_as_text() -> None:
    org, sid = await _org_and_system()
    await _implement(sid, "AC-02")
    await _capability(org, sid, controls=["AC-2"], title='<img src=x onerror="alert(1)">')
    await _build(org)
    html = (await _page(f"/graph?system_id={sid}")).text
    assert '<img src=x onerror="alert(1)">' not in html
    assert "&lt;img src=x" in html  # the table shows it as text
    assert "\\u003cimg" in html  # the embedded data escapes it too


async def test_a_deleted_system_is_not_drawn() -> None:
    from datetime import UTC, datetime  # noqa: PLC0415

    org, sid = await _org_and_system()
    await _build(org)
    async with session_scope() as s:
        (await s.get(System, sid)).deleted_at = datetime.now(UTC)
    r = await _page(f"/graph?system_id={sid}")
    assert r.status_code == 404


async def test_the_nav_and_the_assurance_page_link_to_the_graph() -> None:
    org, sid = await _org_and_system()
    html = (await _page("/assurance")).text
    assert 'href="/graph"' in html and f'href="/graph?system_id={sid}"' in html
```

Create `tests/test_compliance_graph_page_tenancy.py`:

```python
"""/graph serves only the caller's own systems (auth enabled)."""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.assurance import builder
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")
_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _tenant() -> tuple[str, int, str]:
    """``(api token, system id, system name)`` for a fresh org with a built graph."""
    async with session_scope() as s:
        org = Organization(name=f"Graph Tenant {next(_SEQ)}")
        s.add(org)
        await s.flush()
        name = f"Secret System {next(_SEQ)}"
        sysm = System(organization_id=org.id, name=name)
        user = User(email=f"u{next(_SEQ)}@graph.test", organization_id=org.id,
                    role="control_owner", active=True, password_hash=hash_password("pw"),
                    api_token=new_api_token())
        s.add_all([sysm, user])
        await s.flush()
        await builder.rebuild_org(s, org.id)
        return user.api_token, sysm.id, name


async def test_another_tenants_system_is_a_404_and_is_not_listed() -> None:
    token_a, _sid_a, _name_a = await _tenant()
    _token_b, sid_b, name_b = await _tenant()
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t",
                           headers={"Authorization": f"Bearer {token_a}"}) as c:
        foreign = await c.get(f"/graph?system_id={sid_b}")
        own_page = await c.get("/graph")
    assert foreign.status_code == 404 and name_b not in foreign.text
    assert name_b not in own_page.text
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py tests/test_compliance_graph_page_tenancy.py -q -k "page or built or relationships or markup or deleted or nav or tenant" 2>&1 | tail -5`

Expected: FAIL with 404 on `/graph`.

- [ ] **Step 3: The route, and the rebuild redirect**

In `src/ccf/api/routes/ui_grc.py`, add after `assurance_page`:

```python
#: The page draws at most this many nodes; above it, it asks for a filter.
_GRAPH_NODE_LIMIT = 3000


@router.get("/graph", response_class=HTMLResponse)
async def graph_page(
    request: Request,
    system_id: int | None = None,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    """One system's assurance graph: every edge sourced, nothing inferred."""
    from ...assurance import impact as assurance_impact  # noqa: PLC0415

    org = _principal_org(request)
    # Deleted systems are excluded as everywhere else (DATA-04); a foreign or
    # deleted id is a 404, never an empty graph that implies "no relationships".
    sys_stmt = select(System).where(System.deleted_at.is_(None)).order_by(System.name)
    if org is not None:
        sys_stmt = sys_stmt.where(System.organization_id == org)
    systems = (await session.execute(sys_stmt)).scalars().all()
    selected = next((s for s in systems if s.id == system_id), None)
    if system_id is not None and selected is None:
        raise HTTPException(404, "System not found")
    view = await assurance_impact.system_view(session, system=selected) if selected else None
    labels = {n["id"]: n["label"] for n in view["nodes"]} if view else {}
    node_types = sorted({n["entity_type"] for n in view["nodes"]}) if view else []
    return templates.TemplateResponse(
        request,
        "graph.html",
        {
            "active": "graph",
            "systems": systems,
            "selected": selected,
            "view": view,
            "labels": labels,
            "node_types": node_types,
            "node_limit": _GRAPH_NODE_LIMIT,
        },
    )
```

Replace `assurance_rebuild`:

```python
@router.post("/assurance/rebuild")
async def assurance_rebuild(
    request: Request,
    return_to: str = Form("assurance"),
    system_id: int | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    from ...assurance import builder as assurance_builder  # noqa: PLC0415

    await assurance_builder.rebuild(session, org_id=_principal_org(request))
    await session.commit()
    # Only two fixed destinations: a free-form return URL would be an open redirect.
    if return_to == "graph" and system_id is not None:
        return RedirectResponse(f"/graph?system_id={int(system_id)}", status_code=303)
    return RedirectResponse("/assurance", status_code=303)
```

- [ ] **Step 4: The template**

Create `src/ccf/api/templates/graph.html`:

```html
{% extends "base.html" %}
{% block title %}Compliance graph · Concord{% endblock %}
{% block heading %}Compliance graph{% endblock %}
{% block subtitle %}<p class="page__subtitle">One system's controls and what is linked to them. Every link names where it comes from; nothing is inferred.</p>{% endblock %}
{% block content %}

<nav class="row" aria-label="Graph layer" style="gap:8px;margin-bottom:12px">
  <span class="chip chip--ok" aria-current="page">System posture</span>
</nav>

<form method="get" action="/graph" class="row" style="gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:16px">
  <label for="graph-system">System</label>
  <select id="graph-system" name="system_id">
    <option value="">Choose a system</option>
    {% for s in systems %}<option value="{{ s.id }}" {% if selected and s.id == selected.id %}selected{% endif %}>{{ s.name }}</option>{% endfor %}
  </select>
  <button class="btn btn--sm" type="submit">Show</button>
</form>

{% macro rebuild_form(label) %}
<form method="post" action="/assurance/rebuild">
  <input type="hidden" name="return_to" value="graph">
  <input type="hidden" name="system_id" value="{{ selected.id }}">
  <button class="btn btn--primary btn--sm" type="submit"><i data-lucide="refresh-cw"></i> {{ label }}</button>
</form>
{% endmacro %}

{% if not systems %}
<section class="card"><div class="card__body dim" style="text-align:center;padding:32px">No systems yet.</div></section>
{% elif not selected %}
<section class="card"><div class="card__body dim" style="text-align:center;padding:32px">Choose a system to draw its graph.</div></section>
{% elif view.build_status is none %}
<section class="card"><div class="card__body" style="text-align:center;padding:32px">
  <p><strong>Not built yet.</strong> The graph is built from Concord's records; nothing has been built for this organization.</p>
  {{ rebuild_form("Build graph") }}
</div></section>
{% else %}

{% if view.failed_contributors %}
<section class="card" role="alert" style="margin-bottom:16px;border-color:var(--warning)">
  <div class="card__header"><div class="card__title">Part of the graph could not be built</div></div>
  <div class="card__body">
    <p>These parts are missing from the graph below. Missing is not the same as having no relationships.</p>
    <ul>{% for name, err in view.failed_contributors.items() %}<li><strong>{{ name }}</strong>: {{ err }}</li>{% endfor %}</ul>
  </div>
</section>
{% endif %}

<div class="row" style="gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
  <span class="dim">{% if view.built_at %}Built {{ view.built_at[:16]|replace('T', ' ') }} UTC{% else %}Build {{ view.build_status }}, not finished{% endif %}</span>
  <span style="flex:1"></span>
  {{ rebuild_form("Rebuild") }}
</div>

{% if view.root is none %}
<section class="card"><div class="card__body" style="text-align:center;padding:32px">
  <p>This system is not in the graph yet: it was added after the last build.</p>
</div></section>
{% elif not view.edges %}
<section class="card"><div class="card__body dim" style="text-align:center;padding:32px">No recorded relationships for this system.</div></section>
{% else %}

<div class="row" style="gap:16px;flex-wrap:wrap;align-items:flex-start;margin-bottom:8px">
  <fieldset style="border:0;padding:0">
    <legend class="dim">Show</legend>
    {% for t in node_types %}<label style="margin-right:8px"><input type="checkbox" data-graph-type value="{{ t }}" checked> {{ t|replace('_', ' ') }}</label>{% endfor %}
  </fieldset>
  <label>Owner
    <select id="graph-owner"><option value="">Everyone</option></select>
  </label>
  <label>Find control <input type="search" id="graph-search" placeholder="AC-2" autocomplete="off"></label>
  <button type="button" class="btn btn--ghost btn--sm" id="graph-table-toggle" aria-controls="graph-tables" aria-expanded="false">Table</button>
</div>
<p id="graph-notice" class="dim" role="status" hidden></p>
<div class="row" style="gap:12px;align-items:stretch;flex-wrap:wrap">
  <div id="graph-canvas" role="img" aria-label="Graph of {{ selected.name }}; the same data is in the table." style="flex:1 1 480px;min-height:560px;border:1px solid var(--shell-border);border-radius:8px"></div>
  <aside id="graph-panel" class="card" style="flex:0 1 300px;padding:12px" hidden></aside>
</div>
<p class="dim" style="margin-top:8px">Colour is status: implemented, partial or planned, not implemented, inherited, not applicable. Shapes: square = system, diamond = capability, hexagon = KSI, circle = everything else.</p>

<section id="graph-tables" hidden style="margin-top:16px">
  <div class="card" style="margin-bottom:16px">
    <div class="card__header"><div class="card__title">Nodes</div><span class="dim">{{ view.nodes|length }}</span></div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>Type</th><th>Name</th><th>Status</th><th>Owners</th></tr></thead>
      <tbody>{% for n in view.nodes %}<tr data-graph-node-row>
        <td>{{ n.entity_type|replace('_', ' ') }}</td><td>{{ n.label }}</td><td>{{ n.status or '—' }}</td>
        <td>{{ (n.metadata.owners or [])|join(', ') or '—' }}</td>
      </tr>{% endfor %}</tbody>
    </table></div>
  </div>
  <div class="card">
    <div class="card__header"><div class="card__title">Links</div><span class="dim">{{ view.edges|length }}</span></div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Source</th></tr></thead>
      <tbody>{% for e in view.edges %}<tr data-graph-edge-row>
        <td>{{ labels[e.source] }}</td><td>{{ e.relationship_type|replace('_', ' ') }}</td>
        <td>{{ labels[e.target] }}</td><td><code>{{ e.provenance }}</code></td>
      </tr>{% endfor %}</tbody>
    </table></div>
  </div>
</section>

<script type="application/json" id="graph-data" data-limit="{{ node_limit }}">{{ view|tojson }}</script>
<script src="/static/vendor/cytoscape.min.js"></script>
<script src="/static/js/graph.js?v={{ asset_v }}"></script>
{% endif %}
{% endif %}
<script>if(window.lucide)lucide.createIcons();</script>
{% endblock %}
```

- [ ] **Step 5: The script**

Create `src/ccf/api/static/js/graph.js`:

```javascript
// Compliance graph: draws the system view embedded in #graph-data.
// Labels are tenant-entered text: they reach the DOM through textContent only.
(function () {
  "use strict";
  var dataEl = document.getElementById("graph-data");
  if (!dataEl || !window.cytoscape) return;
  var view = JSON.parse(dataEl.textContent);
  var limit = Number(dataEl.getAttribute("data-limit"));
  var canvas = document.getElementById("graph-canvas");
  var notice = document.getElementById("graph-notice");
  var panel = document.getElementById("graph-panel");
  var ownerSelect = document.getElementById("graph-owner");
  var byId = {};
  view.nodes.forEach(function (n) { byId[n.id] = n; });
  var cy = null;

  function token(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }
  // Colour is status only (docs/DESIGN.md).
  var STATUS = {
    implemented: token("--success", "#2e7d32"), pass: token("--success", "#2e7d32"),
    partial: token("--warning", "#b26a00"), planned: token("--warning", "#b26a00"),
    warn: token("--warning", "#b26a00"),
    not_implemented: token("--danger", "#c62828"), fail: token("--danger", "#c62828"),
    open: token("--danger", "#c62828"),
    inherited: token("--accent", "#3b6fd8"),
    not_applicable: token("--text-muted", "#8a8f98")
  };
  var NEUTRAL = token("--text-secondary", "#6b7280");

  function owners(n) { return (n.metadata && n.metadata.owners) || []; }

  // Owner picker: every owner named on any node, alphabetical.
  var allOwners = {};
  view.nodes.forEach(function (n) { owners(n).forEach(function (o) { allOwners[o] = true; }); });
  Object.keys(allOwners).sort().forEach(function (o) {
    var opt = document.createElement("option");
    opt.value = o;
    opt.textContent = o;
    ownerSelect.appendChild(opt);
  });

  function visibleTypes() {
    var out = {};
    document.querySelectorAll("[data-graph-type]").forEach(function (el) {
      if (el.checked) out[el.value] = true;
    });
    return out;
  }

  function draw() {
    var types = visibleTypes();
    var nodes = view.nodes.filter(function (n) {
      return n.id === view.root.id || types[n.entity_type];
    });
    if (cy) { cy.destroy(); cy = null; }
    if (nodes.length > limit) {
      notice.textContent = nodes.length + " nodes match these filters; the graph draws at most " +
        limit + ". Untick a node type to draw it, or open the table.";
      notice.hidden = false;
      return;
    }
    notice.hidden = true;
    var shown = {};
    nodes.forEach(function (n) { shown[n.id] = true; });
    var elements = nodes.map(function (n) {
      return { data: { id: "n" + n.id, nid: n.id, label: n.label, type: n.entity_type,
                       colour: STATUS[n.status] || NEUTRAL } };
    });
    view.edges.forEach(function (e, i) {
      if (shown[e.source] && shown[e.target]) {
        elements.push({ data: { id: "e" + i, source: "n" + e.source, target: "n" + e.target,
                                rel: e.relationship_type, provenance: e.provenance } });
      }
    });
    var line = token("--shell-border", "#9aa4b2");
    cy = window.cytoscape({
      container: canvas,
      elements: elements,
      layout: { name: "cose", animate: false },
      style: [
        { selector: "node", style: { "background-color": "data(colour)", label: "data(label)",
          "font-size": 9, color: token("--text", "#222"), "text-valign": "bottom",
          "text-margin-y": 2, width: 14, height: 14 } },
        { selector: 'node[type = "system"]', style: { shape: "round-rectangle", width: 26, height: 26 } },
        { selector: 'node[type = "capability"]', style: { shape: "diamond" } },
        { selector: 'node[type = "ksi"]', style: { shape: "hexagon" } },
        { selector: "edge", style: { width: 1, "line-color": line, "curve-style": "bezier",
          "target-arrow-shape": "triangle", "target-arrow-color": line, "arrow-scale": 0.6 } },
        { selector: ".faded", style: { opacity: 0.15 } },
        { selector: ":selected", style: { "border-width": 3, "border-color": token("--text", "#222") } }
      ]
    });
    cy.on("tap", "node", function (evt) { showPanel(byId[evt.target.data("nid")]); });
    cy.on("mouseover", "edge", function (evt) {
      canvas.title = evt.target.data("rel").replace(/_/g, " ") + " (source: " +
        evt.target.data("provenance") + ")";
    });
    cy.on("mouseout", "edge", function () { canvas.title = ""; });
    applyOwner();
  }

  function applyOwner() {
    if (!cy) return;
    var who = ownerSelect.value;
    cy.nodes().forEach(function (node) {
      var n = byId[node.data("nid")];
      var keep = !who || owners(n).indexOf(who) !== -1 || n.id === view.root.id;
      node.toggleClass("faded", !keep);
    });
  }

  function row(label, value) {
    var p = document.createElement("p");
    var b = document.createElement("strong");
    b.textContent = label + ": ";
    p.appendChild(b);
    p.appendChild(document.createTextNode(value));
    panel.appendChild(p);
  }

  function showPanel(n) {
    panel.replaceChildren();
    var h = document.createElement("h3");
    h.textContent = n.label;
    panel.appendChild(h);
    var meta = n.metadata || {};
    row("Type", n.entity_type.replace(/_/g, " "));
    row("Status", n.status || "—");
    if (owners(n).length) row("Owners", owners(n).join(", "));
    if (meta.rows > 1) row("Catalog rows", String(meta.rows));
    if (meta.placed === false) {
      row("Catalog", "This row names no control and has no sequence control; it is shown as recorded.");
    }
    if (meta.unlinked_reason) row("Not linked", meta.unlinked_reason);
    var list = document.createElement("ul");
    view.edges.forEach(function (e) {
      if (e.source !== n.id && e.target !== n.id) return;
      var other = byId[e.source === n.id ? e.target : e.source];
      if (!other) return;
      var li = document.createElement("li");
      li.textContent = (e.source === n.id ? "" : "← ") + e.relationship_type.replace(/_/g, " ") +
        " " + other.label + " (" + e.provenance + ")";
      list.appendChild(li);
    });
    if (list.children.length) panel.appendChild(list);
    var href = recordLink(n);
    if (href) {
      var a = document.createElement("a");
      a.href = href;
      a.textContent = "Open record";
      panel.appendChild(a);
    }
    panel.hidden = false;
  }

  // Only routes that exist in ui*.py; a type with no record page gets no link.
  function recordLink(n) {
    var meta = n.metadata || {};
    switch (n.entity_type) {
      case "system": return "/systems/" + encodeURIComponent(n.entity_id);
      case "connector": return "/connectors/" + encodeURIComponent(n.entity_id);
      case "control_test": return "/control-tests/" + encodeURIComponent(n.entity_id);
      case "ksi": return meta.system_id ? "/fedramp20x?system_id=" + encodeURIComponent(meta.system_id) : null;
      case "poam": return "/poams";
      case "risk": return "/risks";
      case "evidence_object": return "/evidence";
      case "ai_agent": return "/ai-agents";
      default: return null;
    }
  }

  document.querySelectorAll("[data-graph-type]").forEach(function (el) {
    el.addEventListener("change", draw);
  });
  ownerSelect.addEventListener("change", applyOwner);
  document.getElementById("graph-search").addEventListener("change", function (evt) {
    var q = evt.target.value.trim().toUpperCase();
    if (!cy || !q) return;
    var hit = cy.nodes().filter(function (node) {
      return node.data("type") === "control" && String(node.data("label")).toUpperCase() === q;
    });
    if (hit.length) {
      cy.elements().unselect();
      hit.select();
      cy.animate({ center: { eles: hit }, zoom: 1.5 });
      showPanel(byId[hit[0].data("nid")]);
    } else {
      notice.textContent = "No control " + q + " in this system's graph.";
      notice.hidden = false;
    }
  });
  var toggle = document.getElementById("graph-table-toggle");
  toggle.addEventListener("click", function () {
    var tables = document.getElementById("graph-tables");
    tables.hidden = !tables.hidden;
    toggle.setAttribute("aria-expanded", String(!tables.hidden));
  });
  draw();
})();
```

- [ ] **Step 6: Nav entry and the assurance link**

In `src/ccf/api/templates/base.html`, in the `authorization` group:
- add `'graph'` to its `members` list, after `'assurance'`;
- add this link after the `assurance` link:

```
     {'key':'graph','label':'Compliance graph','href':'/graph','desc':'One system drawn as a graph: every link sourced, nothing inferred.'}]},
```

Move the `]},` that closed the `assurance` link onto this new line.

In `src/ccf/api/templates/assurance.html`, replace the "Subgraph JSON" anchor:

```html
        <td><a class="btn btn--ghost btn--sm" href="/graph?system_id={{ s.id }}"><i data-lucide="share-2"></i> Open graph</a></td>
```

- [ ] **Step 7: Run the page tests, the UI shell and the viewer gate**

Run: `.venv/bin/python -m pytest tests/test_compliance_graph.py tests/test_compliance_graph_page_tenancy.py tests/test_ui_shell.py tests/test_viewer_is_read_only.py tests/test_deleted_systems_are_not_listed.py -q 2>&1 | grep -E "[0-9]+ (passed|failed)|FAILED"`

Expected: all pass. `/graph` is a GET, so the viewer gate needs no change. If `test_deleted_systems_are_not_listed` keeps an inventory of system pickers, add `/graph` to it.

- [ ] **Step 8: Mutation-check**

- Delete `if system_id is not None and selected is None: raise HTTPException(404, ...)`. → `test_a_deleted_system_is_not_drawn` and `test_another_tenants_system_is_a_404_and_is_not_listed` must fail.
- Change `{{ view|tojson }}` to `{{ view.nodes|map(attribute='label')|join(',')|safe }}`. → `test_a_title_with_markup_is_shown_as_text` must fail.
- In the table, change `{{ n.label }}` to `{{ n.label|safe }}`. → the same test must fail.
- Delete the `{% if view.failed_contributors %}` block. → `test_a_failed_contributor_is_named_on_the_page` must fail.

- [ ] **Step 9: Check the page by hand in a browser**

No automated test runs the JavaScript. Start the app against the dev database (`docker compose up api`, or the README's run command). Open `/graph`, pick a system with controls, and check each of these:
- the canvas draws, and nodes are coloured by status;
- unticking a type redraws without it;
- the owner picker fades the other owners' nodes;
- searching `AC-2` centres on it and opens the panel, and "Open record" goes to the right page;
- hovering an edge shows its source;
- the Table button shows the tables;
- at a 375px-wide viewport there is no horizontal page scroll.

Record what you checked in the commit message. If no dev data is available, say so in the commit message instead of claiming the check.

- [ ] **Step 10: Lint, type-check, commit**

```bash
.venv/bin/ruff check src tests && .venv/bin/mypy src | tail -1
git add src/ccf/api/routes/ui_grc.py src/ccf/api/templates/graph.html src/ccf/api/static/js/graph.js src/ccf/api/templates/base.html src/ccf/api/templates/assurance.html tests/test_compliance_graph.py tests/test_compliance_graph_page_tenancy.py
git commit -m "feat(ui): /graph draws one system's sourced assurance graph

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Changelog, full verification, independent review

**Files:**
- Modify: `CHANGELOG.md` (`[Unreleased]`)

- [ ] **Step 1: Write the changelog entries**

Under `## [Unreleased]`, add a step to the existing `### Upgrading — operator steps` list, after the migrator step:

```markdown
   - `0098`: `assurance_edges.source` replaces `confidence`. Existing edges are
     labelled `unsourced:pre-0098` until the graph is rebuilt; run
     `ccf assurance graph-rebuild` (or press Rebuild on `/assurance` or `/graph`)
     after migrating.
```

Then add a section:

```markdown
### Added — a compliance graph drawn from Concord's own records
- **`/graph`** draws one system: its controls, and the capabilities, KSIs,
  tests, POA&Ms, evidence and connectors linked to them, coloured by status.
  A table view shows the same nodes and links for screen readers and audit.
- **Every link names its source** (`poams`, `capability_controls`,
  `fedramp-rules@<version>`, `crosswalk:securescore`, ...), shown on hover, in
  the node panel and in the table. Nothing is inferred: frameworks that meet
  only through an 800-53 control are shown as a path through it.
- Inspired by myctrl.tools/graph; none of its data is used (its crosswalks are
  97% bridge-inferred and carry no provenance).

### Changed — the assurance graph no longer guesses
- Connectors were linked to every system in the organization at "confidence
  0.6". A connector is now linked to the connector tests it produced, and
  only when it is the organization's one connector of that type.
- `confidence` is removed from the graph and its API; edges carry
  `provenance` instead.
- A control is one node per system, not one per catalog row: assessment
  objectives and ODP rows fold into the control they decompose, and the node
  takes the worst status among them.
- A part of the graph that fails to build is recorded and named on the page;
  the build is `partial`, not `ok`. Each part now runs in its own savepoint,
  so one failure no longer takes the rest of the build down with it.
- `GET /api/assurance/graph/systems/{id}` gains `scope=system`, `built_at`,
  `build_status` and `failed_contributors`.
```

- [ ] **Step 2: Full verification (one pytest session only)**

```bash
.venv/bin/ruff check src tests && .venv/bin/mypy src | tail -1 && .venv/bin/bandit -r src -ll -x tests -q >/dev/null; echo "bandit exit $?"
.venv/bin/python -m pytest -q -p no:cacheprovider 2>&1 | tail -3 | grep -E "[0-9]+ (passed|failed)"
```

Expected: ruff "All checks passed!", mypy "Success", bandit exit 0, and pytest with 0 failed. If anything fails, fix it before continuing. Never commit over a red suite.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog for the compliance graph

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Independent whole-branch review**

Dispatch a fresh reviewer, on the most capable model, over `git diff feat/fedramp-consolidated-rules..HEAD`, with this spec and plan. Ask it specifically to look for:
- an edge stored without a true source;
- any place a guessed or inferred link survives;
- tenant leakage in `_capabilities`, `subgraph` or `/graph`;
- label injection;
- a page state that shows an empty canvas where it should say something.

Fix every confirmed finding with a test, then re-run Step 2.
