# Compliance graph: sub-project 1, the system-posture layer

Date: 2026-10-15. Status: approved in conversation; this document is for review.

## Purpose

This adds an interactive graph view to Concord, of the kind myctrl.tools offers at `/graph/`. Every edge comes from Concord's own records and names its source.

myctrl's graph cannot be imported. Its edges come from its crosswalk data, and 97% of that is inferred through a bridge framework with no provenance. The *view* is worth having; the data is not.

The work is three sub-projects that share one base. Each gets its own spec, plan and build:

1. **The system-posture layer** (this document). It shows one system's controls, the capabilities, KSIs, tests, POA&Ms and evidence linked to them, and each control's status and owner.
2. **The cross-framework reach layer.** It starts from a control and shows what it reaches in KSIs, CMMC, CCI and capabilities. It reads the global catalog.
3. **The catalog overview layer.** This is the framework-level "galaxy", over the frameworks Concord holds.

## Edge policy (applies to all three)

- **Only edges with a named source are drawn.** The source can be a dataset at a version (FedRAMP rules, DISA CCI), a Concord-authored crosswalk (`crosswalk:securescore`), or a tenant record.
- **A path is shown, never shortened.** Two frameworks that meet only through 800-53 are shown as a path through the shared control. For example, KSI → AC-2 ← CMMC is never drawn as a direct KSI–CMMC edge.
- **Nothing is inferred.** No transitive edge is drawn, and no edge carries a confidence number.

## Approach

Concord already builds a per-tenant graph (`assurance_nodes` / `assurance_edges`, `assurance/builder.py`) that nothing draws. This project fixes that graph and draws it. It does not add a second graph mechanism.

The reach and catalog layers read the global catalog directly, because catalog relationships are not tenant data. They are out of scope here.

## 1. Data: what the assurance graph becomes

### Every edge names its source; confidence is removed

- **New column `assurance_edges.source`,** `String(96)`, NOT NULL. It is a short provenance label:
  - a table name (`capability_controls`, `poams`);
  - a dataset at a version (`fedramp-rules@2026.10.13.01`);
  - or a check source (`crosswalk:securescore`).
- **`assurance_edges.confidence` is dropped.** Under the edge policy an edge is either sourced or not stored, so the number would measure nothing.
- `impact.py` is its only reader, and it stops returning the field.
- The migration labels existing rows `unsourced:pre-0098` before setting NOT NULL. A relationship type is not a source, so the migration doesn't pretend it is. The next rebuild replaces those rows.
- The downgrade re-adds `confidence` with value 1.0.

### Guessed edges are removed

- **Connector → system.** Today every connector is linked to every system in the org at 0.6 (`builder.py:204-205`). This edge is replaced by connector → control test, with source `control_tests`, so the system is reached through the test's own `system_id`.
  - The edge is drawn for each `control_tests` row with `method = "connector"` whose `connector_type` matches the connector's.
  - It is drawn only when the org has **exactly one** connector of that type. With two (e.g. two Microsoft 365 tenants), the test doesn't record which connector produced it, so no edge is drawn and the node's detail panel says why.
  - A connector with no such tests is an unlinked node.
- **AI agent edges are kept and get a real source.** They come from the agent's recorded `system_id`, `system_ids`, `vendor_ids`, `control_ids` and `risk_ids`, so their source is `ai_agents`. The invented 0.7 and 0.9 values are removed.

### New contributors

| Edge | From | Source label |
|---|---|---|
| capability → control | `capability_controls` (per tenant) | `capability_controls` |
| capability → KSI | `capability_ksis` (per tenant) | `capability_ksis` |
| KSI → 800-53 control | `ksis.nist_refs`, current KSIs only | `fedramp-rules@<version>` |
| control test → control | every control the test declares (`control_ids`, else `control_id`), via `ccf.posture.evidence.evidenced_controls` | the test's `check_source`, e.g. `crosswalk:securescore`, else `control_tests` |

Two rules for these edges:
- **No placeholder nodes.** A KSI → control edge is drawn only when that control is already a node for that system. An 800-53 reference with no implementation on the system creates no edge.
- **Secure Score needs no contributor of its own.** Its results are already `control_tests` rows with `check_source = "crosswalk:securescore"`.

### Control nodes are real controls

Today there is one node per `control_implementations` row. Those rows include objective and ODP rows, which would overstate the graph about fourfold.

Instead, each node is one canonical control per system:
- **Identity:** rows are grouped by `canonicalize(identifier)`. Rows that don't canonicalize are attached to their control through `sequence_control`, as `catalog/baseline_delta.py` does.
- **Entity id:** `"<system_id>:<canonical>"`.
- **Status:** the worst status among its rows, in this order: not_implemented, planned, partial, inherited, implemented, then not_applicable.
- **Owner:** taken from `owner_user_id`. If the rows name different owners, the node lists all of them.

### Freshness

- Nothing changes in how the graph is rebuilt: the scheduler still rebuilds it each cycle, and `POST /api/assurance/graph/rebuild` still triggers a rebuild on demand.
- **Failed contributors are recorded.** The build run records which contributors failed and why. Today `_contribute` catches the error and logs it, so that slice of the graph silently goes missing.

## 2. Endpoint, renderer and page

### Endpoint

There is no new endpoint. `GET /api/assurance/graph/systems/{id}?hops=` already exists, is scoped by `require_system_in_scope`, and is allowed by the viewer gate because it is a GET. Its response gains:
- `provenance` on every edge (the stored `source` column). `source` and `target` already mean node ids in this response, so they keep that meaning;
- `owner` on control nodes;
- `built_at`, `build_status` and `failed_contributors` from the latest build run.
- A `scope` parameter, `connected` (the default, today's behaviour) or `system`.
  - Capabilities, connectors and AI agents connect systems to each other. So following edges outward from one system reaches other systems' controls and tests.
  - With `scope=system`, a node that belongs to another system is not returned. Another system's own node is returned as a boundary and not expanded. The page always uses `system`.
- The page and the API build this response with the same function (`impact.system_view`). The page's tables and the API therefore can't disagree.

### Renderer

**Cytoscape.js** is vendored at an exact version into `src/ccf/api/static/vendor/`. Its version, licence, origin URL and sha256 are recorded in a new `static/vendor/VENDOR.json`; until now no vendored file had such a record.
- It is MIT-licensed, a single file with no dependencies, and it handles a few thousand nodes.
- It uses the built-in `cose` layout, so no layout plugins are needed.
- The CSP (`script-src 'self'`) needs no change.
- It loads only on the graph page.

### Page: `/graph`

- **A layer switcher** whose only layer for now is "System posture". Later layers are added when built, never shown as disabled placeholders.
- **A system picker.**
- **Colour shows status only,** using the app's status tokens. `docs/DESIGN.md` reserves colour for status, so owners are not given colours. Instead an **owner picker** keeps the chosen owner's nodes at full strength and fades the rest.
- **Node-type filters:** control, capability, KSI, control test, POA&M, risk, evidence, connector, AI agent.
- **A control search** that centres the graph on the matching control.
- **Node click** opens a side panel with the node's details and a link to its record page.
- **Edge hover** shows the relationship and the source.
- **A "Table" toggle** shows the same nodes and edges as tables, because a canvas is invisible to screen readers. The server renders the tables (Jinja autoescaped), and tests assert against them. The graph data is embedded with `tojson`, and the script writes labels with `textContent` only, so a capability or POA&M title can't inject markup.
- **A size limit:** above 3,000 nodes the page asks for a filter before it draws.
- **Link-in:** the "Subgraph JSON" link on `/assurance` becomes "Open graph".

## 3. Errors and testing

### States the page shows in words

- **Never built:** "Not built yet", with a Rebuild button.
- **A contributor failed:** each one is named with its error. A missing slice must not read as "no relationships".
- **The system has no relationships:** stated in words. An empty canvas can't tell a failed load apart from no data.

### Tests

Each guard is mutation-checked: I delete the guard and confirm a test fails.

- Each contributor stores an edge only when its source record exists.
- No edge is stored without a source. The NOT NULL constraint enforces this in the database, and a test confirms it.
- **Regression:** a connector reaches a system only through a connector test for that system. With two connectors of the same type, neither gets the edge.
- Objective and ODP rows collapse into one control node, and the worst status wins.
- KSI → control edges appear only for controls the system implements, and only for current KSIs.
- **Tenant isolation** is checked on an unscoped session, so RLS can't make the test pass vacuously.
- `impact.py` output has no `confidence`. The migration's upgrade and downgrade are both tested.
- The page's table view matches the API's node and edge counts. The owner picker's data is tested, as is the over-3,000-nodes message.
- The vendored file's sha256 matches the manifest, and the package-data test covers it.

## Out of scope

- The reach and catalog layers (sub-projects 2 and 3).
- Control-to-control crosswalks between non-NIST frameworks. Concord has none with a source: `framework_mappings` stores free-text workbook cells, not links to controls. The graph will be sparser than myctrl's, and that sparseness is accurate.
