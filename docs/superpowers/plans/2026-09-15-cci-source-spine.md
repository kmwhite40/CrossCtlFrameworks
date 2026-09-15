# DISA CCI Source Spine Implementation Plan (P0″a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load DISA's published CCI list as authority-published reference data with a queryable CCI → control reverse index, so a scanner finding that names only a CCI can reach a control.

**Architecture:** A new `ccf/cci/` package with one job per module — an HTML reader that is the only code knowing the file format, a pure resolver that turns a reference string into a control and an OSCAL statement part id, a derived overlay reader for the .ods, and a service that loads and queries. Three global reference tables (no tenant dimension). Nothing existing is mutated: the workbook keeps loading its CCI columns, and a separate advisory report says where the two disagree.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, Alembic, Typer, pytest. Parsing uses stdlib `html.parser` and `zipfile` plus `defusedxml` (already a dependency). **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-15-cci-source-spine-design.md`

## Global Constraints

- **Source files** live at `data/cci/CCI List.html` and `data/cci/All Rev. 5 CCIs.ods` (committed, `4bb396f`). `data/` is **not** in the Docker image (`Dockerfile` copies only `src`, `migrations`, `alembic.ini`), so `ccf cci load` is an admin/ETL step run with the data directory available — the same operational shape as `ccf ingest`.
- **No new dependencies.** Use `defusedxml.ElementTree` for the .ods `content.xml`, stdlib `html.parser` for the HTML.
- **Three new tables carry no `organization_id`** and must be added to `GLOBAL_TABLES` in `tests/test_rls_registry_no_gap.py` with the reason "authority-published reference data". They must **not** be added to `EXPECTED_TENANT_ISOLATION_TABLES` in `tests/test_rls_coverage.py`, and its hardcoded count must **not** change.
- **Migration is `0074_cci_source_spine`, `down_revision = "0073_flaw_remediation"`.** It carries the `pg_roles` GRANT guard exactly as `0071_pack_sources.py:95-98` does. It creates **no** RLS policy (global tables have none).
- **`load_oscal_catalog` stays DB-free.** A test greps the module for database imports; do not add any.
- **Never construct `AuditLog` directly** — use `ccf.api.audit.record_event`. (No task here writes audit rows; this constraint exists so no one adds one casually.)
- **Shared test database.** `session_scope` commits and the schema is migrated once per session, so tests must not assume an empty database, must use unique values for unique columns, and must clean up rows other modules count.
- **Measured constants that tests assert** (from the committed files, verified during design):

  | Quantity | Value |
  |---|---|
  | CCI items | 5,149 |
  | …`status = "deprecated"` | 91 |
  | References, all revisions | 10,216 |
  | …Rev. 5 | 3,849 (across 3,847 CCIs) |
  | …Rev. 5 resolving to an OSCAL part id | 3,848 |
  | The single unresolved Rev. 5 reference | CCI-005020 → `SI-18 b 1` |
  | .ods rows | 3,626 (2,616 Rev. 5 spelling, 1,010 Rev. 4) |

- Commands: `pytest -q` (all), `make lint` (ruff), `make typecheck` (mypy strict). Every task ends green on all three.

---

### Task 1: Addressable statement parts in the OSCAL catalog

`OscalControl` flattens the statement into one string, so there is nothing for a CCI reference to resolve against. This adds the part tree as a flat map, reusing the walk the loader already performs.

**Files:**
- Modify: `src/ccf/catalog/oscal.py` (the `OscalControl` dataclass ~line 35, and `_parse_control` ~line 205)
- Test: `tests/test_catalog_statement_parts.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `OscalControl.statement_parts: dict[str, str]` — OSCAL part id (`"ac-1_smt.a.1.a"`) → that part's prose, prefixed with its label exactly as `_collect_prose` formats it. Empty dict for a control with no statement part.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_catalog_statement_parts.py
"""OscalControl exposes its statement parts by id.

CCI references address a control *item* ("AC-1 a 1 (a)"), not a control, so
resolution needs the part ids the catalog actually defines.
"""
from ccf.catalog.oscal import load_oscal_catalog


def test_statement_parts_are_addressable_by_oscal_part_id() -> None:
    cat = load_oscal_catalog()
    ac1 = cat.get("AC-1")
    assert ac1 is not None
    # The nesting DISA references: a -> 1 -> (a)
    assert "ac-1_smt.a" in ac1.statement_parts
    assert "ac-1_smt.a.1" in ac1.statement_parts
    assert "ac-1_smt.a.1.a" in ac1.statement_parts
    assert "Addresses purpose, scope, roles" in ac1.statement_parts["ac-1_smt.a.1.a"]


def test_statement_parts_absent_where_the_control_has_none() -> None:
    cat = load_oscal_catalog()
    si18 = cat.get("SI-18")
    assert si18 is not None
    # SI-18 b has no sub-items in Rev 5 -- this is the CCI-005020 case.
    assert "si-18_smt.b" in si18.statement_parts
    assert "si-18_smt.b.1" not in si18.statement_parts
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_catalog_statement_parts.py -v`
Expected: FAIL — `AttributeError: 'OscalControl' object has no attribute 'statement_parts'`

- [ ] **Step 3: Write minimal implementation**

In `src/ccf/catalog/oscal.py`, add the field to the frozen dataclass (additive, with a default so every existing constructor keeps working):

```python
@dataclass(frozen=True)
class OscalControl:
    canonical_id: str
    title: str
    statement: str
    guidance: str
    withdrawn: bool
    incorporated_into: list[str]
    param_ids: list[str]
    params: list[OscalParam]
    #: OSCAL part id -> that part's labeled prose, e.g. "ac-1_smt.a.1.a".
    #: DISA's CCI references address control *items*, so resolution needs the
    #: ids the catalog defines rather than the flattened ``statement`` string.
    statement_parts: dict[str, str] = field(default_factory=dict)
```

Add the collector beside `_statement_prose`:

```python
def _collect_statement_parts(control: dict[str, Any], acc: dict[str, str]) -> None:
    """Flatten the statement tree into {part id: labeled prose}.

    Pure dict-walking, like every other helper here -- ``load_oscal_catalog``
    must stay database-free.
    """
    for part in control.get("parts", []):
        if part.get("name") != "statement":
            continue
        _walk_statement_part(part, acc)


def _walk_statement_part(part: dict[str, Any], acc: dict[str, str]) -> None:
    pid = part.get("id")
    if pid:
        label = _part_label(part)
        prose = part.get("prose") or ""
        acc[str(pid)] = f"{label} {prose}".strip() if label else prose
    for sub in part.get("parts", []) or []:
        _walk_statement_part(sub, acc)
```

In `_parse_control`, build it and pass it:

```python
    parts_index: dict[str, str] = {}
    _collect_statement_parts(c, parts_index)
    return OscalControl(
        ...,
        params=[...],
        statement_parts=parts_index,
    )
```

`field` must be in the existing `from dataclasses import ...` line — it already is, `OscalCatalog` uses `field(default_factory=dict)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_catalog_statement_parts.py tests/test_catalog_golden.py tests/test_catalog_manifest.py -v`
Expected: PASS. The golden/manifest tests confirm the additive field broke no existing consumer.

Run: `pytest tests/ -q -k "oscal or catalog"` — expected: PASS.
Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/catalog/oscal.py tests/test_catalog_statement_parts.py
git commit -m "feat(catalog): expose OSCAL statement parts by id

A CCI reference addresses a control item (\"AC-1 a 1 (a)\"), and the loader
flattened the statement into one string, so there was nothing to resolve
against. statement_parts is built by the same walk _collect_prose already
performs, stays pure, and gives P4's evidence citation an addressable target
it did not have."
```

---

### Task 2: The CCI HTML reader

The only module that knows DISA's file format. An XML reader later returns the same types.

**Files:**
- Create: `src/ccf/cci/__init__.py`, `src/ccf/cci/reader.py`
- Test: `tests/test_cci_reader.py`

**Interfaces:**
- Consumes: `ccf.etl.sources.sha256_bytes(body: bytes) -> str`.
- Produces:
  - `CciReference(revision: str, raw_index: str)` — frozen dataclass.
  - `CciItem(cci: str, status: str, type: str, contributor: str | None, published_date: date | None, definition: str, references: tuple[CciReference, ...])` — frozen dataclass.
  - `CciList(version: str, source_sha256: str, items: tuple[CciItem, ...])` — frozen dataclass.
  - `read_cci_html(path: Path) -> CciList`
  - `DEFAULT_CCI_HTML: Path`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_reader.py
"""Parse DISA's published CCI List.

Asserted against the real committed file, not an invented fixture: a fixture
I wrote would encode my assumptions about the format rather than DISA's.
"""
from datetime import date

import pytest

from ccf.cci.reader import DEFAULT_CCI_HTML, read_cci_html


@pytest.fixture(scope="module")
def cci_list():
    return read_cci_html(DEFAULT_CCI_HTML)


def test_reads_every_cci_with_its_version(cci_list) -> None:
    assert cci_list.version == "2026-07-14"
    assert len(cci_list.items) == 5149
    assert len(cci_list.source_sha256) == 64


def test_first_item_carries_every_field(cci_list) -> None:
    item = next(i for i in cci_list.items if i.cci == "CCI-000002")
    assert item.status == "draft"
    assert item.type == "policy"
    assert item.contributor == "DISA FSO"
    assert item.published_date == date(2009, 9, 14)
    assert item.definition.startswith("Disseminate the organization-level")


def test_references_carry_revision_and_verbatim_index(cci_list) -> None:
    item = next(i for i in cci_list.items if i.cci == "CCI-000002")
    by_rev = {r.revision: r.raw_index for r in item.references}
    assert by_rev["5"] == "AC-1 a 1 (a)"
    assert by_rev["4"] == "AC-1 a 1"
    assert by_rev["3"] == "AC-1 a"
    assert by_rev["800-53A"] == "AC-1.1 (iii)"


def test_reference_totals_match_the_published_list(cci_list) -> None:
    refs = [r for i in cci_list.items for r in i.references]
    assert len(refs) == 10216
    assert sum(1 for r in refs if r.revision == "5") == 3849
    assert len({i.cci for i in cci_list.items if any(r.revision == "5" for r in i.references)}) == 3847


def test_deprecated_status_is_preserved(cci_list) -> None:
    # 91 deprecated CCIs must survive the load: a STIG in the field may still
    # cite one, and silently dropping it would make that finding unroutable.
    assert sum(1 for i in cci_list.items if i.status == "deprecated") == 91
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_reader.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.cci'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccf/cci/__init__.py
"""DISA Control Correlation Identifiers as authority-published reference data.

``reader`` knows the file format, ``resolve`` maps a reference onto the OSCAL
catalog, ``overlay`` reads the derived Rev. 5 workbook, and ``service`` loads
and queries. Nothing here mutates workbook-sourced tables.
"""
```

```python
# src/ccf/cci/reader.py
"""Read DISA's published CCI List.

The published artifact is XML; this is DISA's HTML rendering of it, which is
what we hold. The parse is deliberately sealed behind :func:`read_cci_html`
returning typed records, so an ``U_CCI_List.xml`` reader can be added later
without any downstream change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from html.parser import HTMLParser
from pathlib import Path

from ..etl.sources import sha256_bytes
from ..logging import get_logger

log = get_logger(__name__)

DEFAULT_CCI_HTML = Path(__file__).resolve().parents[3] / "data" / "cci" / "CCI List.html"

#: Reference titles DISA publishes -> the short revision code we store. An
#: unrecognised title is stored verbatim rather than dropped: losing an
#: authority's reference silently is worse than carrying an unexpected string.
_REVISIONS: dict[str, str] = {
    "NIST SP 800-53 (v3)": "3",
    "NIST SP 800-53 Revision 4 (v4)": "4",
    "NIST SP 800-53 Revision 5 (v5)": "5",
    "NIST SP 800-53A (v1)": "800-53A",
}

_VERSION_RE = re.compile(r"Version\s+(\d{4}-\d{2}-\d{2})")
_CCI_RE = re.compile(r"^CCI-\d{6}$")


@dataclass(frozen=True)
class CciReference:
    revision: str
    raw_index: str


@dataclass(frozen=True)
class CciItem:
    cci: str
    status: str
    type: str
    contributor: str | None
    published_date: date | None
    definition: str
    references: tuple[CciReference, ...]


@dataclass(frozen=True)
class CciList:
    version: str
    source_sha256: str
    items: tuple[CciItem, ...]


@dataclass
class _Cell:
    text: str = ""
    links: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.links is None:
            self.links = []


class _TableParser(HTMLParser):
    """Collect every <table> as rows of cells, keeping anchor text per cell.

    Anchor text is kept separately because a reference cell reads
    ``NIST:  <a>NIST SP 800-53 Revision 5 (v5)</a>:  AC-1 a 1 (a)`` -- the
    title and the index are only separable if we know where the anchor ended.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[_Cell]]] = []
        self.preamble: str = ""
        self._table: list[list[_Cell]] | None = None
        self._row: list[_Cell] | None = None
        self._cell: _Cell | None = None
        self._in_anchor = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag == "td" and self._row is not None:
            self._cell = _Cell()
        elif tag == "a" and self._cell is not None:
            self._in_anchor = True
            self._cell.links.append("")

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._in_anchor = False
        elif tag == "td" and self._cell is not None and self._row is not None:
            self._row.append(self._cell)
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None

    def handle_data(self, data: str) -> None:
        if self._cell is None:
            if self._table is None:
                self.preamble += data
            return
        self._cell.text += data
        if self._in_anchor and self._cell.links:
            self._cell.links[-1] += data


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _parse_date(raw: str) -> date | None:
    try:
        return date.fromisoformat(_clean(raw))
    except ValueError:
        return None


def _reference(cell: _Cell) -> CciReference | None:
    """A reference cell: an anchor naming the publication, then ': index'."""
    if not cell.links:
        return None
    title = _clean(cell.links[0])
    tail = cell.text.split(cell.links[0], 1)[-1]
    index = _clean(tail.lstrip(": "))
    if not index:
        return None
    revision = _REVISIONS.get(title)
    if revision is None:
        revision = title[:64]
        log.warning("cci.unknown_reference_title", title=title)
    return CciReference(revision=revision, raw_index=index)


def _item(table: list[list[_Cell]]) -> CciItem | None:
    fields: dict[str, str] = {}
    references: list[CciReference] = []
    cci = ""
    for row in table:
        if not row:
            continue
        label = _clean(row[0].text).rstrip(":").lower()
        if label == "cci" and len(row) > 1:
            cci = _clean(row[1].text)
            if len(row) > 3:
                fields[_clean(row[2].text).rstrip(":").lower()] = _clean(row[3].text)
            continue
        if label in {"contributor", "published date"} and len(row) > 1:
            fields[label] = _clean(row[1].text)
            if len(row) > 3:
                fields[_clean(row[2].text).rstrip(":").lower()] = _clean(row[3].text)
            continue
        if label in {"definition", "type"} and len(row) > 1:
            fields[label] = _clean(row[1].text)
            continue
        ref = _reference(row[-1]) if row else None
        if ref is not None:
            references.append(ref)
    if not _CCI_RE.match(cci):
        return None
    return CciItem(
        cci=cci,
        status=fields.get("status", ""),
        type=fields.get("type", ""),
        contributor=fields.get("contributor") or None,
        published_date=_parse_date(fields.get("published date", "")),
        definition=fields.get("definition", ""),
        references=tuple(references),
    )


def read_cci_html(path: Path) -> CciList:
    """Parse DISA's CCI List HTML into typed records."""
    body = path.read_bytes()
    parser = _TableParser()
    parser.feed(body.decode("utf-8", errors="replace"))
    m = _VERSION_RE.search(parser.preamble)
    items = tuple(i for i in (_item(t) for t in parser.tables) if i is not None)
    if not items:
        raise ValueError(f"no CCI entries parsed from {path}")
    return CciList(
        version=m.group(1) if m else "",
        source_sha256=sha256_bytes(body),
        items=items,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cci_reader.py -v`
Expected: PASS — all five.

If a count is off by a small number, **do not adjust the assertion.** Print the diff and find the entry the parser mishandled; the numbers in Global Constraints were measured from this exact file.

Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/cci/__init__.py src/ccf/cci/reader.py tests/test_cci_reader.py
git commit -m "feat(cci): read DISA's published CCI list

5,149 CCIs and 10,216 references, each reference keeping the revision it
decomposes and its index verbatim. Sealed behind typed records so an
U_CCI_List.xml reader drops in later without a downstream change. An
unrecognised reference title is stored verbatim and logged rather than
dropped."
```

---

### Task 3: The resolver

Pure. Turns `"AC-1 a 1 (a)"` into a canonical control, an OSCAL control id, and — where the catalog agrees — a part id.

**Files:**
- Create: `src/ccf/cci/resolve.py`
- Test: `tests/test_cci_resolve.py`

**Interfaces:**
- Consumes: `ccf.catalog.canonical.canonicalize`, `ccf.catalog.canonical.canonical_to_oscal_id`, `OscalControl.statement_parts` (Task 1).
- Produces:
  - `ResolvedReference(canonical_control: str | None, oscal_control_id: str | None, oscal_part_id: str | None)` — frozen dataclass.
  - `resolve_reference(raw_index: str, *, control_ids: frozenset[str], part_ids: frozenset[str]) -> ResolvedReference`
  - `catalog_index(catalog: OscalCatalog) -> tuple[frozenset[str], frozenset[str]]` — the two id sets, built once per load.

The resolver takes id **sets**, not a catalog object or a session: it stays pure and testable without fixtures, and the caller decides which catalog it resolves against.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_resolve.py
"""Resolve a DISA reference onto the OSCAL catalog.

The one rule worth a test of its own: a leading "(n)" is a control
*enhancement*, not a statement item.
"""
from ccf.catalog.oscal import load_oscal_catalog
from ccf.cci.resolve import catalog_index, resolve_reference

CONTROLS, PARTS = catalog_index(load_oscal_catalog())


def _r(raw: str):
    return resolve_reference(raw, control_ids=CONTROLS, part_ids=PARTS)


def test_item_path_resolves_to_a_statement_part() -> None:
    r = _r("AC-1 a 1 (a)")
    assert r.canonical_control == "AC-1"
    assert r.oscal_control_id == "ac-1"
    assert r.oscal_part_id == "ac-1_smt.a.1.a"


def test_leading_parenthetical_is_an_enhancement_not_an_item() -> None:
    r = _r("AC-2 (1)")
    assert r.canonical_control == "AC-2(1)"
    assert r.oscal_control_id == "ac-2.1"
    # The bug this guards: reading (1) as an item yields ac-2_smt.1, which
    # silently mis-maps 1,860 of 3,849 references.
    assert r.oscal_part_id != "ac-2_smt.1"


def test_enhancement_then_item_path() -> None:
    r = _r("AC-2 (1) a")
    assert r.oscal_control_id == "ac-2.1"
    assert r.oscal_part_id == "ac-2.1_smt.a"


def test_control_with_no_item_path_resolves_to_the_statement_root() -> None:
    r = _r("AC-1")
    assert r.canonical_control == "AC-1"
    assert r.oscal_part_id == "ac-1_smt"


def test_unresolvable_item_keeps_its_control() -> None:
    # CCI-005020 cites SI-18 b 1, but SI-18 b has no sub-items in Rev 5.
    r = _r("SI-18 b 1")
    assert r.canonical_control == "SI-18"
    assert r.oscal_control_id == "si-18"
    assert r.oscal_part_id is None


def test_non_80053_reference_resolves_to_nothing_rather_than_guessing() -> None:
    r = _r("AC-1.1 (iii)")
    assert r.canonical_control is None
    assert r.oscal_control_id is None
    assert r.oscal_part_id is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_resolve.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.cci.resolve'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccf/cci/resolve.py
"""Map a DISA reference index onto the OSCAL catalog.

Pure: reference string plus the catalog's id sets in, a resolution out. No
database, no file access, no catalog object -- so the caller decides which
catalog a reference is resolved against, and the rule below is testable on its
own.

**The rule that is easy to get wrong.** A leading parenthesized integer is a
control *enhancement*, not a statement item: ``AC-2 (1)`` is ``ac-2.1``, not
``ac-2_smt.1``. Leading ``(n)`` tokens are absorbed into the control id while
the enhanced control actually exists in the catalog; whatever remains is the
item path. Reading them as items mis-maps 1,860 of the list's 3,849 Rev. 5
references.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..catalog.canonical import canonical_to_oscal_id, canonicalize
from ..catalog.oscal import OscalCatalog

_ENH_TOKEN = re.compile(r"^\(\s*(\d{1,3})\s*\)$")


@dataclass(frozen=True)
class ResolvedReference:
    canonical_control: str | None
    oscal_control_id: str | None
    oscal_part_id: str | None


NOTHING = ResolvedReference(None, None, None)


def catalog_index(catalog: OscalCatalog) -> tuple[frozenset[str], frozenset[str]]:
    """The catalog's control ids and statement part ids, as OSCAL spells them."""
    controls: set[str] = set()
    parts: set[str] = set()
    for canonical, control in catalog.controls.items():
        controls.add(canonical_to_oscal_id(canonical))
        parts.update(control.statement_parts)
    return frozenset(controls), frozenset(parts)


def resolve_reference(
    raw_index: str,
    *,
    control_ids: frozenset[str],
    part_ids: frozenset[str],
) -> ResolvedReference:
    tokens = raw_index.split()
    if not tokens:
        return NOTHING
    base = canonicalize(tokens[0])
    if base is None:
        return NOTHING
    canonical = base.value
    oscal_id = canonical_to_oscal_id(canonical)
    if oscal_id not in control_ids:
        return NOTHING

    i = 1
    while i < len(tokens):
        m = _ENH_TOKEN.match(tokens[i])
        if not m:
            break
        candidate_canonical = f"{canonical}({int(m.group(1))})"
        candidate_oscal = canonical_to_oscal_id(candidate_canonical)
        if candidate_oscal not in control_ids:
            break
        canonical, oscal_id = candidate_canonical, candidate_oscal
        i += 1

    segments = [t.strip("()").lower() for t in tokens[i:]]
    part_id = f"{oscal_id}_smt" + ("." + ".".join(segments) if segments else "")
    return ResolvedReference(
        canonical_control=canonical,
        oscal_control_id=oscal_id,
        oscal_part_id=part_id if part_id in part_ids else None,
    )
```

Note `"ac-1_smt"` itself is in `part_ids`, because Task 1 records every part carrying an id including the statement root — which is what makes `test_control_with_no_item_path_resolves_to_the_statement_root` pass without a special case.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cci_resolve.py -v`
Expected: PASS — all six.

- [ ] **Step 5: Add the whole-list resolution test**

```python
# append to tests/test_cci_resolve.py
from ccf.cci.reader import DEFAULT_CCI_HTML, read_cci_html


def test_every_rev5_reference_but_one_resolves_to_a_part() -> None:
    """The measured rate. A regression here means the rule or the catalog moved."""
    items = read_cci_html(DEFAULT_CCI_HTML).items
    rev5 = [(i.cci, r.raw_index) for i in items for r in i.references if r.revision == "5"]
    assert len(rev5) == 3849
    unresolved = [
        (cci, raw) for cci, raw in rev5 if _r(raw).oscal_part_id is None
    ]
    assert unresolved == [("CCI-005020", "SI-18 b 1")]
```

Run: `pytest tests/test_cci_resolve.py -v` — expected: PASS.
Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cci/resolve.py tests/test_cci_resolve.py
git commit -m "feat(cci): resolve a DISA reference onto the OSCAL catalog

3,848 of 3,849 Rev. 5 references resolve to an exact statement part id. The
one that does not -- CCI-005020 citing SI-18 b 1 against a control with no
b.1 -- is why resolution is opportunistic: the control is always kept, the
raw index is always kept, the part id is kept when the catalog agrees.

A leading (n) is an enhancement, not an item. Reading it the other way costs
1,860 references, so it has its own test."
```

---

### Task 4: Models, migration, and the RLS registry

**Files:**
- Create: `src/ccf/models_cci.py`, `migrations/versions/0074_cci_source_spine.py`
- Modify: `src/ccf/models.py` (the bottom import block and `CROSS_MODULE_MODEL_MODULES`), `tests/test_rls_registry_no_gap.py` (`GLOBAL_TABLES`)
- Test: `tests/test_cci_models.py`

**Interfaces:**
- Produces: `CciItemRow`, `CciControlRef`, `CciAssessmentOverlay` (SQLAlchemy models, tables `cci_items`, `cci_control_refs`, `cci_assessment_overlay`).

The model class is `CciItemRow`, not `CciItem` — `CciItem` is the reader's frozen dataclass and two things with one name in one package is how a later import picks the wrong one.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_models.py
"""The CCI tables exist, are global, and enforce their keys."""
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models_cci import CciControlRef, CciItemRow

pytestmark = pytest.mark.asyncio


async def test_an_item_and_its_references_round_trip(clean_migrated_db) -> None:
    async with session_scope() as s:
        item = CciItemRow(
            cci="CCI-999001",
            status="draft",
            type="technical",
            definition="test-only row",
            source_version="test",
            source_sha256="0" * 64,
        )
        s.add(item)
        await s.flush()
        s.add(
            CciControlRef(
                cci_id=item.id,
                revision="5",
                raw_index="AC-1 a 1 (a)",
                canonical_control="AC-1",
                oscal_control_id="ac-1",
                oscal_part_id="ac-1_smt.a.1.a",
            )
        )
    async with session_scope() as s:
        got = (
            await s.execute(select(CciControlRef).where(CciControlRef.canonical_control == "AC-1"))
        ).scalars().all()
        assert any(r.raw_index == "AC-1 a 1 (a)" for r in got)
        # cleanup: other modules count rows in shared tables
        for r in got:
            if r.raw_index == "AC-1 a 1 (a)":
                await s.delete(r)
        stale = (
            await s.execute(select(CciItemRow).where(CciItemRow.cci == "CCI-999001"))
        ).scalars().all()
        for row in stale:
            await s.delete(row)


async def test_cci_is_unique(clean_migrated_db) -> None:
    async with session_scope() as s:
        s.add(
            CciItemRow(
                cci="CCI-999002", status="draft", type="policy",
                definition="a", source_version="test", source_sha256="0" * 64,
            )
        )
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                CciItemRow(
                    cci="CCI-999002", status="draft", type="policy",
                    definition="b", source_version="test", source_sha256="0" * 64,
                )
            )
    async with session_scope() as s:
        rows = (
            await s.execute(select(CciItemRow).where(CciItemRow.cci == "CCI-999002"))
        ).scalars().all()
        for row in rows:
            await s.delete(row)
```

Check `tests/conftest.py` for the exact fixture name providing a migrated database and use it; `clean_migrated_db` is the name used by the existing suite.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.models_cci'`

- [ ] **Step 3: Write the models**

```python
# src/ccf/models_cci.py
"""DISA CCI reference data.

Authority-published and identical for every tenant, so these three tables
carry no ``organization_id`` and no RLS policy -- they belong on
``GLOBAL_TABLES`` beside ``controls`` and ``catalog_revisions``. Per-tenant
CCI divergence would make the reverse index incoherent.
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger, Date, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .models import Base


class CciItemRow(Base):
    """One CCI as DISA publishes it."""

    __tablename__ = "cci_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cci: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16))
    type: Mapped[str] = mapped_column(String(32))
    contributor: Mapped[str | None] = mapped_column(String(128))
    published_date: Mapped[date | None] = mapped_column(Date)
    definition: Mapped[str] = mapped_column(Text)
    #: The published list version, e.g. "2026-07-14".
    source_version: Mapped[str] = mapped_column(String(32))
    #: Content address of the file this row was read from.
    source_sha256: Mapped[str] = mapped_column(String(64))
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    references: Mapped[list["CciControlRef"]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )
    overlay: Mapped[list["CciAssessmentOverlay"]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )


class CciControlRef(Base):
    """One reference from a CCI to a control item, in one revision.

    ``oscal_part_id`` is nullable on purpose: DISA's reference can name an item
    the current catalog no longer has (CCI-005020 -> SI-18 b 1). Dropping such
    a reference would make a real STIG finding unroutable, so the control is
    kept and the part is left null.
    """

    __tablename__ = "cci_control_refs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cci_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.cci_items.id", ondelete="CASCADE"), index=True
    )
    revision: Mapped[str] = mapped_column(String(64))
    raw_index: Mapped[str] = mapped_column(String(128))
    canonical_control: Mapped[str | None] = mapped_column(String(32))
    oscal_control_id: Mapped[str | None] = mapped_column(String(32))
    oscal_part_id: Mapped[str | None] = mapped_column(String(64))

    item: Mapped[CciItemRow] = relationship(back_populates="references")

    __table_args__ = (
        UniqueConstraint("cci_id", "revision", "raw_index", name="uq_cci_ref"),
        # The reverse lookup: which CCIs cover this control.
        Index("ix_cci_ref_canonical_control", "canonical_control"),
    )


class CciAssessmentOverlay(Base):
    """Derived Rev. 5 assessment metadata for a CCI.

    Not DISA-published. ``source`` names the file it came from so no reader can
    mistake it for the authority.
    """

    __tablename__ = "cci_assessment_overlay"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    cci_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.cci_items.id", ondelete="CASCADE"), index=True
    )
    ap_acronym: Mapped[str | None] = mapped_column(String(64))
    emass_identifier: Mapped[str | None] = mapped_column(String(64))
    assessment_procedure: Mapped[str | None] = mapped_column(Text)
    assessment_methods: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(128))

    item: Mapped[CciItemRow] = relationship(back_populates="overlay")

    __table_args__ = (UniqueConstraint("cci_id", "ap_acronym", name="uq_cci_overlay"),)
```

Register the module in `src/ccf/models.py`'s bottom block — both the import and the tuple, in alphabetical position:

```python
from . import (  # noqa: E402
    models_capability,
    models_cci,
    models_enforcement,
    models_grc,
    models_patching,
    models_waivers,
)

CROSS_MODULE_MODEL_MODULES = (
    models_capability,
    models_cci,
    models_enforcement,
    models_grc,
    models_patching,
    models_waivers,
)
```

- [ ] **Step 4: Write the migration**

```python
# migrations/versions/0074_cci_source_spine.py
"""DISA CCI reference data -- items, control references, derived overlay.

Three GLOBAL tables. DISA's CCI list is authority-published and identical for
every tenant, exactly like ``controls`` and ``catalog_revisions``, so none of
them carries ``organization_id`` and none gets a tenant_isolation policy. They
join ``GLOBAL_TABLES`` in ``tests/test_rls_registry_no_gap.py``; they must NOT
join ``EXPECTED_TENANT_ISOLATION_TABLES`` and its hardcoded count does not move.

``cci_control_refs.oscal_part_id`` is nullable because DISA's reference may name
an item the current Rev. 5 catalog does not define.

Revision ID: 0074_cci_source_spine
Revises: 0073_flaw_remediation
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0074_cci_source_spine"
down_revision = "0073_flaw_remediation"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"


def upgrade() -> None:
    op.create_table(
        "cci_items",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("cci", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("contributor", sa.String(length=128), nullable=True),
        sa.Column("published_date", sa.Date(), nullable=True),
        sa.Column("definition", sa.Text(), nullable=False),
        sa.Column("source_version", sa.String(length=32), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "loaded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("cci", name="uq_cci_items_cci"),
        schema=_SCHEMA,
    )
    op.create_index("ix_cci_items_cci", "cci_items", ["cci"], schema=_SCHEMA)

    op.create_table(
        "cci_control_refs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "cci_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.cci_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision", sa.String(length=64), nullable=False),
        sa.Column("raw_index", sa.String(length=128), nullable=False),
        sa.Column("canonical_control", sa.String(length=32), nullable=True),
        sa.Column("oscal_control_id", sa.String(length=32), nullable=True),
        sa.Column("oscal_part_id", sa.String(length=64), nullable=True),
        sa.UniqueConstraint("cci_id", "revision", "raw_index", name="uq_cci_ref"),
        schema=_SCHEMA,
    )
    op.create_index("ix_cci_control_refs_cci_id", "cci_control_refs", ["cci_id"], schema=_SCHEMA)
    op.create_index(
        "ix_cci_ref_canonical_control", "cci_control_refs", ["canonical_control"], schema=_SCHEMA
    )

    op.create_table(
        "cci_assessment_overlay",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "cci_id",
            sa.BigInteger(),
            sa.ForeignKey("ccf.cci_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ap_acronym", sa.String(length=64), nullable=True),
        sa.Column("emass_identifier", sa.String(length=64), nullable=True),
        sa.Column("assessment_procedure", sa.Text(), nullable=True),
        sa.Column("assessment_methods", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.UniqueConstraint("cci_id", "ap_acronym", name="uq_cci_overlay"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_cci_assessment_overlay_cci_id", "cci_assessment_overlay", ["cci_id"], schema=_SCHEMA
    )

    # Standard since 0054: grant only if the role exists, so a developer
    # database without ccf_app migrates cleanly.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    # No RLS: these are global reference tables (see module docstring).


def downgrade() -> None:
    op.drop_table("cci_assessment_overlay", schema=_SCHEMA)
    op.drop_table("cci_control_refs", schema=_SCHEMA)
    op.drop_table("cci_items", schema=_SCHEMA)
```

- [ ] **Step 5: Register the tables as global**

In `tests/test_rls_registry_no_gap.py`, inside `GLOBAL_TABLES`, after `"catalog_integrity_reports"`:

```python
        # DISA's Control Correlation Identifiers. Authority-published reference
        # data, identical for every tenant exactly as the control catalog is:
        # a per-tenant CCI list would make the CCI -> control reverse index
        # incoherent across tenants. Writes are the `ccf cci load` admin path.
        "cci_items",
        "cci_control_refs",
        "cci_assessment_overlay",
```

- [ ] **Step 6: Run the migration and the tests**

```bash
alembic upgrade head
alembic heads      # must print exactly ONE head: 0074_cci_source_spine
```

Run: `pytest tests/test_cci_models.py tests/test_rls_registry_no_gap.py tests/test_rls_coverage.py -v`
Expected: PASS. `test_rls_coverage` must pass **without** changing its hardcoded count — if it fails, a table was given `organization_id` by mistake.

Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/models_cci.py src/ccf/models.py migrations/versions/0074_cci_source_spine.py tests/test_cci_models.py tests/test_rls_registry_no_gap.py
git commit -m "feat(cci): the CCI tables, migration 0074, registered as global

Three tables with no tenant dimension, because DISA's list is the same for
everyone and a per-tenant CCI list would make the reverse index incoherent.
oscal_part_id is nullable by design. The index on canonical_control is the
reverse lookup P5 needs."
```

---

### Task 5: Load the list

**Files:**
- Create: `src/ccf/cci/service.py`
- Test: `tests/test_cci_load.py`

**Interfaces:**
- Consumes: `read_cci_html` (Task 2), `resolve_reference` / `catalog_index` (Task 3), the models (Task 4).
- Produces: `async def load_cci_list(session, *, path: Path | None = None, catalog: OscalCatalog | None = None) -> LoadResult` and `@dataclass(frozen=True) LoadResult(version: str, source_sha256: str, items_created: int, items_updated: int, refs_written: int, refs_unresolved: int, skipped_unchanged: bool)`.

Content-addressed: if every existing row already carries this file's `source_sha256`, the load is a no-op and `skipped_unchanged` is True.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_load.py
"""Loading the real list is idempotent and content-addressed."""
import pytest
from sqlalchemy import func, select

from ccf.cci.service import load_cci_list
from ccf.db import session_scope
from ccf.models_cci import CciControlRef, CciItemRow

pytestmark = pytest.mark.asyncio


async def test_load_writes_every_item_and_reference(clean_migrated_db) -> None:
    async with session_scope() as s:
        result = await load_cci_list(s)
    assert result.version == "2026-07-14"
    assert result.items_created == 5149
    assert result.refs_written == 10216
    assert result.refs_unresolved == 1  # CCI-005020 -> SI-18 b 1
    async with session_scope() as s:
        assert (await s.execute(select(func.count()).select_from(CciItemRow))).scalar() == 5149


async def test_second_load_of_the_same_file_is_a_no_op(clean_migrated_db) -> None:
    async with session_scope() as s:
        await load_cci_list(s)
    async with session_scope() as s:
        again = await load_cci_list(s)
    assert again.skipped_unchanged is True
    assert again.items_created == 0
    assert again.items_updated == 0


async def test_reverse_index_is_populated(clean_migrated_db) -> None:
    async with session_scope() as s:
        await load_cci_list(s)
        # Joined explicitly rather than walking CciControlRef.item: a lazy
        # relationship load outside the awaited query raises MissingGreenlet
        # under async SQLAlchemy, and expire_on_commit=False does not help.
        rows = (
            await s.execute(
                select(CciItemRow.cci, CciControlRef.oscal_part_id)
                .join(CciControlRef, CciControlRef.cci_id == CciItemRow.id)
                .where(
                    CciControlRef.canonical_control == "AC-1",
                    CciControlRef.revision == "5",
                )
            )
        ).all()
    assert {cci for cci, _ in rows} >= {"CCI-000002", "CCI-002107"}
    assert any(part == "ac-1_smt.a.1.a" for _, part in rows)
```

These tests load 5,149 rows. Keep them in one module so the load happens once per module where the fixture allows, and mark the module `@pytest.mark.slow` if the suite has that marker.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_load.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.cci.service'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccf/cci/service.py
"""Load and query DISA CCI reference data."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.oscal import OscalCatalog, load_oscal_catalog
from ..logging import get_logger
from ..models_cci import CciControlRef, CciItemRow
from .reader import DEFAULT_CCI_HTML, read_cci_html
from .resolve import ResolvedReference, catalog_index, resolve_reference

log = get_logger(__name__)


@dataclass(frozen=True)
class LoadResult:
    version: str
    source_sha256: str
    items_created: int
    items_updated: int
    refs_written: int
    refs_unresolved: int
    skipped_unchanged: bool


async def load_cci_list(
    session: AsyncSession,
    *,
    path: Path | None = None,
    catalog: OscalCatalog | None = None,
) -> LoadResult:
    """Upsert the CCI list. Re-loading identical content writes nothing."""
    parsed = read_cci_html(path or DEFAULT_CCI_HTML)
    existing = {
        row.cci: row for row in (await session.execute(select(CciItemRow))).scalars().all()
    }
    if existing and all(r.source_sha256 == parsed.source_sha256 for r in existing.values()):
        return LoadResult(
            version=parsed.version,
            source_sha256=parsed.source_sha256,
            items_created=0,
            items_updated=0,
            refs_written=0,
            refs_unresolved=0,
            skipped_unchanged=True,
        )

    control_ids, part_ids = catalog_index(catalog or load_oscal_catalog())
    created = updated = refs = unresolved = 0

    for item in parsed.items:
        row = existing.get(item.cci)
        if row is None:
            row = CciItemRow(cci=item.cci)
            session.add(row)
            created += 1
        else:
            updated += 1
        row.status = item.status
        row.type = item.type
        row.contributor = item.contributor
        row.published_date = item.published_date
        row.definition = item.definition
        row.source_version = parsed.version
        row.source_sha256 = parsed.source_sha256
        await session.flush()

        # References are replaced wholesale: a revision that drops a reference
        # must not leave the old edge behind, and the set is tiny per CCI.
        await session.execute(delete(CciControlRef).where(CciControlRef.cci_id == row.id))
        for ref in item.references:
            resolved = resolve_reference(
                ref.raw_index, control_ids=control_ids, part_ids=part_ids
            )
            if ref.revision != "5":
                # Only Rev. 5 has a catalog here; null by construction, not failure.
                resolved = ResolvedReference(
                    canonical_control=resolved.canonical_control,
                    oscal_control_id=resolved.oscal_control_id,
                    oscal_part_id=None,
                )
            elif resolved.oscal_part_id is None:
                unresolved += 1
            session.add(
                CciControlRef(
                    cci_id=row.id,
                    revision=ref.revision,
                    raw_index=ref.raw_index,
                    canonical_control=resolved.canonical_control,
                    oscal_control_id=resolved.oscal_control_id,
                    oscal_part_id=resolved.oscal_part_id,
                )
            )
            refs += 1

    await session.flush()
    log.info(
        "cci.loaded",
        version=parsed.version,
        created=created,
        updated=updated,
        refs=refs,
        unresolved=unresolved,
    )
    return LoadResult(
        version=parsed.version,
        source_sha256=parsed.source_sha256,
        items_created=created,
        items_updated=updated,
        refs_written=refs,
        refs_unresolved=unresolved,
        skipped_unchanged=False,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cci_load.py -v`
Expected: PASS.

If `test_load_writes_every_item_and_reference` reports `refs_unresolved` above 1, a Rev. 5 reference stopped resolving — check Task 3's rule before touching the assertion.

Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/cci/service.py tests/test_cci_load.py
git commit -m "feat(cci): load the list, content-addressed and idempotent

Re-loading identical content writes nothing; a changed file rewrites the
items and replaces their references wholesale, so a revision that drops a
reference cannot leave a stale edge behind. Only Rev. 5 references get a part
id, because Rev. 5 is the only catalog held -- null there means 'no catalog',
not 'failed to resolve'."
```

---

### Task 6: The derived .ods overlay

**Files:**
- Create: `src/ccf/cci/overlay.py`
- Modify: `src/ccf/cci/service.py` (add `load_cci_overlay`)
- Test: `tests/test_cci_overlay.py`

**Interfaces:**
- Produces:
  - `OverlayRow(cci: str, control_number: str, ap_acronym: str, emass_identifier: str | None, assessment_procedure: str | None, assessment_methods: str | None)` — frozen dataclass.
  - `read_overlay_ods(path: Path) -> list[OverlayRow]` — **Rev. 5 rows only**.
  - `DEFAULT_CCI_ODS: Path`, `OVERLAY_SOURCE: str = "derived:All Rev. 5 CCIs.ods"`
  - `async def load_cci_overlay(session, *, path: Path | None = None) -> int` in `service.py`, returning rows written.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_overlay.py
"""The .ods is mixed-generation despite its name; only Rev. 5 rows load."""
import pytest

from ccf.cci.overlay import DEFAULT_CCI_ODS, read_overlay_ods


@pytest.fixture(scope="module")
def rows():
    return read_overlay_ods(DEFAULT_CCI_ODS)


def test_only_rev5_spelled_rows_are_returned(rows) -> None:
    # 2,616 of the file's 3,626 rows are Rev. 5 spelling (AC-01); the other
    # 1,010 are Rev. 4 (AC-1) and are a second copy of the same CCIs.
    assert len(rows) == 2616
    assert all(r.control_number[3].isdigit() and r.control_number[2] == "-" for r in rows)


def test_rev4_spelled_control_numbers_are_excluded(rows) -> None:
    assert not any(r.control_number == "AC-1" for r in rows)
    assert any(r.control_number == "AC-01" for r in rows)


def test_a_row_carries_its_emass_identifier_and_procedure(rows) -> None:
    row = next(r for r in rows if r.ap_acronym == "AC-01a")
    assert row.cci.startswith("CCI-")
    assert row.emass_identifier
    assert row.assessment_procedure
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_overlay.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.cci.overlay'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccf/cci/overlay.py
"""The derived Rev. 5 CCI workbook.

Not DISA-published, and its filename lies: 1,010 of its 3,626 rows are in Rev.
4 spelling (``AC-1``, ``AC-1 (a) (1)``), a second copy of CCIs that also appear
in Rev. 5 spelling (``AC-01``, ``AC-01a``). Loading it unfiltered gives two
conflicting rows per CCI, so only the Rev. 5 generation is returned.

Read with stdlib ``zipfile`` plus ``defusedxml`` -- an .ods is a zip of XML and
the project already depends on both, so no spreadsheet dependency is added.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree

DEFAULT_CCI_ODS = Path(__file__).resolve().parents[3] / "data" / "cci" / "All Rev. 5 CCIs.ods"
OVERLAY_SOURCE = "derived:All Rev. 5 CCIs.ods"

_TABLE_NS = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
_REPEAT = f"{{{_TABLE_NS}}}number-columns-repeated"
#: Rev. 5 spelling zero-pads the control number: AC-01, not AC-1.
_REV5_CONTROL = re.compile(r"^[A-Z]{2}-\d{2}")
_CCI = re.compile(r"^CCI-\d{6}$")

# Column order in the published sheet.
_INHERITANCE, _CONTROL, _AP, _CCI_COL, _EMASS, _DEFINITION, _PROCEDURE, _METHODS = range(8)


@dataclass(frozen=True)
class OverlayRow:
    cci: str
    control_number: str
    ap_acronym: str
    emass_identifier: str | None
    assessment_procedure: str | None
    assessment_methods: str | None


def _cell_text(cell) -> str:
    return "".join(cell.itertext()).strip()


def _rows(content: bytes):
    root = ElementTree.fromstring(content)
    for row in root.iter(f"{{{_TABLE_NS}}}table-row"):
        cells: list[str] = []
        for cell in row.findall(f"{{{_TABLE_NS}}}table-cell"):
            text = _cell_text(cell)
            repeat = int(cell.get(_REPEAT, "1"))
            cells.extend([text] * min(repeat, 3))
        yield cells


def read_overlay_ods(path: Path) -> list[OverlayRow]:
    """Rev. 5 rows only. See the module docstring for why filtering is required."""
    with zipfile.ZipFile(path) as z:
        content = z.read("content.xml")

    out: list[OverlayRow] = []
    for cells in _rows(content):
        if len(cells) <= _METHODS:
            continue
        control = cells[_CONTROL].strip()
        cci = cells[_CCI_COL].strip()
        if not _REV5_CONTROL.match(control) or not _CCI.match(cci):
            continue
        out.append(
            OverlayRow(
                cci=cci,
                control_number=control,
                ap_acronym=cells[_AP].strip(),
                emass_identifier=cells[_EMASS].strip() or None,
                assessment_procedure=cells[_PROCEDURE].strip() or None,
                assessment_methods=cells[_METHODS].strip() or None,
            )
        )
    return out
```

Add to `src/ccf/cci/service.py`:

```python
from .overlay import DEFAULT_CCI_ODS, OVERLAY_SOURCE, read_overlay_ods
from ..models_cci import CciAssessmentOverlay


async def load_cci_overlay(session: AsyncSession, *, path: Path | None = None) -> int:
    """Attach derived Rev. 5 assessment metadata to CCIs already loaded.

    A row whose CCI is not in the list is skipped rather than inventing an
    item: the authority decides which CCIs exist.
    """
    ids = {
        cci: pk
        for cci, pk in (
            await session.execute(select(CciItemRow.cci, CciItemRow.id))
        ).all()
    }
    written = 0
    seen: set[tuple[int, str]] = set()
    for row in read_overlay_ods(path or DEFAULT_CCI_ODS):
        pk = ids.get(row.cci)
        if pk is None:
            continue
        key = (pk, row.ap_acronym)
        if key in seen:
            continue
        seen.add(key)
        await session.execute(
            delete(CciAssessmentOverlay).where(
                CciAssessmentOverlay.cci_id == pk,
                CciAssessmentOverlay.ap_acronym == row.ap_acronym,
            )
        )
        session.add(
            CciAssessmentOverlay(
                cci_id=pk,
                ap_acronym=row.ap_acronym,
                emass_identifier=row.emass_identifier,
                assessment_procedure=row.assessment_procedure,
                assessment_methods=row.assessment_methods,
                source=OVERLAY_SOURCE,
            )
        )
        written += 1
    await session.flush()
    return written
```

- [ ] **Step 4: Add the load test**

```python
# append to tests/test_cci_overlay.py
import pytest
from sqlalchemy import select

from ccf.cci.service import load_cci_list, load_cci_overlay
from ccf.db import session_scope
from ccf.models_cci import CciAssessmentOverlay


@pytest.mark.asyncio
async def test_overlay_attaches_only_to_known_ccis_and_names_its_source(
    clean_migrated_db,
) -> None:
    async with session_scope() as s:
        await load_cci_list(s)
    async with session_scope() as s:
        written = await load_cci_overlay(s)
    assert written > 0
    async with session_scope() as s:
        rows = (await s.execute(select(CciAssessmentOverlay).limit(5))).scalars().all()
    assert rows
    assert all(r.source == "derived:All Rev. 5 CCIs.ods" for r in rows)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cci_overlay.py -v`
Expected: PASS.
Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cci/overlay.py src/ccf/cci/service.py tests/test_cci_overlay.py
git commit -m "feat(cci): the derived Rev. 5 overlay, filtered to one generation

'All Rev. 5 CCIs.ods' is not all Rev. 5 -- 1,010 of its 3,626 rows are Rev. 4
spellings of CCIs it also lists under Rev. 5, so loading it unfiltered gives
two conflicting rows per CCI. Only Rev. 5 rows load, they attach to CCIs the
authority already published, and every row names the file it came from."
```

---

### Task 7: The reverse index queries

**Files:**
- Modify: `src/ccf/cci/service.py`
- Test: `tests/test_cci_queries.py`

**Interfaces:**
- Produces:
  - `async def ccis_for_control(session, canonical_control: str, *, revision: str = "5") -> list[CciCoverage]`
  - `async def controls_for_cci(session, cci: str, *, revision: str = "5") -> list[str]`
  - `@dataclass(frozen=True) CciCoverage(cci: str, status: str, type: str, definition: str, raw_index: str, oscal_part_id: str | None)`

`controls_for_cci` is the P5 seam: a scanner finding names a CCI and nothing else.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_queries.py
"""The reverse index -- the reason this sub-project exists."""
import pytest

from ccf.cci.service import ccis_for_control, controls_for_cci, load_cci_list
from ccf.db import session_scope

pytestmark = pytest.mark.asyncio


@pytest.fixture(scope="module", autouse=True)
async def loaded(clean_migrated_db):
    async with session_scope() as s:
        await load_cci_list(s)


async def test_a_cci_resolves_to_its_control() -> None:
    async with session_scope() as s:
        assert await controls_for_cci(s, "CCI-000002") == ["AC-1"]


async def test_the_unresolvable_reference_still_names_its_control() -> None:
    async with session_scope() as s:
        assert await controls_for_cci(s, "CCI-005020") == ["SI-18"]


async def test_a_control_lists_the_ccis_covering_it() -> None:
    async with session_scope() as s:
        cov = await ccis_for_control(s, "AC-1")
    ids = {c.cci for c in cov}
    assert {"CCI-000002", "CCI-002107"} <= ids
    entry = next(c for c in cov if c.cci == "CCI-000002")
    assert entry.oscal_part_id == "ac-1_smt.a.1.a"
    assert entry.type == "policy"


async def test_revision_scopes_the_answer() -> None:
    async with session_scope() as s:
        rev4 = await controls_for_cci(s, "CCI-000002", revision="4")
    assert rev4 == ["AC-1"]


async def test_an_unknown_cci_returns_empty_rather_than_raising() -> None:
    async with session_scope() as s:
        assert await controls_for_cci(s, "CCI-999999") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_queries.py -v`
Expected: FAIL — `ImportError: cannot import name 'ccis_for_control'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/ccf/cci/service.py`:

```python
@dataclass(frozen=True)
class CciCoverage:
    cci: str
    status: str
    type: str
    definition: str
    raw_index: str
    oscal_part_id: str | None


async def ccis_for_control(
    session: AsyncSession, canonical_control: str, *, revision: str = "5"
) -> list[CciCoverage]:
    """Which CCIs decompose this control, in the given revision."""
    rows = (
        await session.execute(
            select(CciItemRow, CciControlRef)
            .join(CciControlRef, CciControlRef.cci_id == CciItemRow.id)
            .where(
                CciControlRef.canonical_control == canonical_control,
                CciControlRef.revision == revision,
            )
            .order_by(CciItemRow.cci, CciControlRef.raw_index)
        )
    ).all()
    return [
        CciCoverage(
            cci=item.cci,
            status=item.status,
            type=item.type,
            definition=item.definition,
            raw_index=ref.raw_index,
            oscal_part_id=ref.oscal_part_id,
        )
        for item, ref in rows
    ]


async def controls_for_cci(
    session: AsyncSession, cci: str, *, revision: str = "5"
) -> list[str]:
    """The P5 seam: a scanner finding names a CCI and nothing else.

    Returns canonical control ids, de-duplicated and ordered. Empty for an
    unknown CCI -- an unrecognised identifier in a scan file is data, not an
    error.
    """
    rows = (
        await session.execute(
            select(CciControlRef.canonical_control)
            .join(CciItemRow, CciControlRef.cci_id == CciItemRow.id)
            .where(
                CciItemRow.cci == cci,
                CciControlRef.revision == revision,
                CciControlRef.canonical_control.is_not(None),
            )
        )
    ).scalars().all()
    return sorted({r for r in rows if r})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cci_queries.py -v`
Expected: PASS.
Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/cci/service.py tests/test_cci_queries.py
git commit -m "feat(cci): the reverse index -- CCI to control, control to CCI

controls_for_cci is the whole P5 seam: a STIG finding names a CCI and nothing
else. An unknown CCI returns empty rather than raising, because an
unrecognised identifier in a scan file is data, not an error."
```

---

### Task 8: Advisory reconciliation against the workbook

**Files:**
- Create: `src/ccf/cci/reconcile.py`
- Test: `tests/test_cci_reconcile.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) Disagreement(control_identifier: str, workbook_only: tuple[str, ...], disa_only: tuple[str, ...])`
  - `def compare_cci_sets(control_identifier: str, workbook: set[str], disa: set[str]) -> Disagreement | None` — pure.
  - `def parse_workbook_cci_value(value: str | None) -> set[str]` — pure; splits on `;`, strips the `*` "automatically compliant" marker.
  - `async def reconcile_cci(session) -> list[Disagreement]`

Reports, never corrects — the `catalog/reconcile.py` posture.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_reconcile.py
"""Report where the workbook and DISA disagree. Never correct either."""
import pytest

from ccf.cci.reconcile import compare_cci_sets, parse_workbook_cci_value


def test_workbook_value_splits_and_strips_the_compliance_marker() -> None:
    got = parse_workbook_cci_value("CCI-003621; CCI-003622; CCI-003615")
    assert got == {"CCI-003621", "CCI-003622", "CCI-003615"}
    # '*' marks "automatically compliant" and is not part of the identifier.
    assert parse_workbook_cci_value("CCI-003624*") == {"CCI-003624"}
    assert parse_workbook_cci_value(None) == set()
    assert parse_workbook_cci_value("  ") == set()


def test_agreement_reports_nothing() -> None:
    assert compare_cci_sets("AC-02a.[01]", {"CCI-1"}, {"CCI-1"}) is None


def test_each_side_reports_what_the_other_lacks() -> None:
    d = compare_cci_sets("AC-02a.[01]", {"CCI-1", "CCI-2"}, {"CCI-2", "CCI-3"})
    assert d is not None
    assert d.workbook_only == ("CCI-1",)
    assert d.disa_only == ("CCI-3",)


def test_an_empty_workbook_cell_is_not_a_disagreement() -> None:
    # Most workbook rows carry no CCI at all; treating absence as conflict
    # would bury the real findings under thousands of empty ones.
    assert compare_cci_sets("AC-02b.", set(), {"CCI-2"}) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_reconcile.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.cci.reconcile'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/ccf/cci/reconcile.py
"""Compare the workbook's CCI columns against DISA's references.

Advisory only, following :mod:`ccf.catalog.reconcile`. The workbook keeps
loading its CCI columns untouched -- the header classifier is deliberately
generic, and special-casing one column would make ``mapping_history``
snapshots differ for reasons unrelated to the workbook. Disagreement is a
finding *about the workbook*, which is useful on its own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..models import Control, Framework, FrameworkMapping
from ..models_cci import CciControlRef, CciItemRow

#: The workbook column carrying Rev. 5 CCIs; '*' means "automatically
#: compliant" and is a workbook annotation, not part of the identifier.
WORKBOOK_COLUMN = 'CCI Rev 5 ("*" are automatically compliant)'
_CCI = re.compile(r"CCI-\d{6}")


@dataclass(frozen=True)
class Disagreement:
    control_identifier: str
    workbook_only: tuple[str, ...]
    disa_only: tuple[str, ...]


def parse_workbook_cci_value(value: str | None) -> set[str]:
    if not value or not value.strip():
        return set()
    return set(_CCI.findall(value))


def compare_cci_sets(
    control_identifier: str, workbook: set[str], disa: set[str]
) -> Disagreement | None:
    """None when they agree, or when the workbook says nothing.

    An empty workbook cell is silence, not contradiction: most rows carry no
    CCI, and reporting each as a conflict would bury the real findings.
    """
    if not workbook:
        return None
    only_wb = tuple(sorted(workbook - disa))
    only_disa = tuple(sorted(disa - workbook))
    if not only_wb and not only_disa:
        return None
    return Disagreement(control_identifier, only_wb, only_disa)


async def reconcile_cci(session: AsyncSession) -> list[Disagreement]:
    """Every control row whose workbook CCI set differs from DISA's."""
    disa: dict[str, set[str]] = {}
    for control, cci in (
        await session.execute(
            select(CciControlRef.canonical_control, CciItemRow.cci)
            .join(CciItemRow, CciControlRef.cci_id == CciItemRow.id)
            .where(CciControlRef.revision == "5", CciControlRef.canonical_control.is_not(None))
        )
    ).all():
        disa.setdefault(str(control), set()).add(cci)

    rows = (
        await session.execute(
            select(Control.identifier, FrameworkMapping.value)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, FrameworkMapping.framework_id == Framework.id)
            .where(FrameworkMapping.column_key == WORKBOOK_COLUMN)
        )
    ).all()

    out: list[Disagreement] = []
    for identifier, value in rows:
        canonical = canonicalize(str(identifier).split("_")[0].rstrip("."))
        if canonical is None:
            continue
        d = compare_cci_sets(
            str(identifier),
            parse_workbook_cci_value(value),
            disa.get(canonical.value, set()),
        )
        if d is not None:
            out.append(d)
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cci_reconcile.py -v`
Expected: PASS — all four pure tests.

- [ ] **Step 5: Confirm `WORKBOOK_COLUMN` matches the real header**

```bash
python -c "
import openpyxl, json
h=json.load(open('src/ccf/etl/headers.v1_1.json'))
wb=openpyxl.load_workbook('data/NIST Cross Mappings Rev. 1.1.xlsx', read_only=True)
hdr=next(wb[h['sheet']].iter_rows(min_row=1,max_row=1,values_only=True))
print(repr(hdr[163]))"
```
Expected: the exact string in `WORKBOOK_COLUMN`. If it differs, fix the constant — an unmatched `column_key` makes `reconcile_cci` silently return `[]`.

Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cci/reconcile.py tests/test_cci_reconcile.py
git commit -m "feat(cci): advisory reconciliation against the workbook's CCI column

Reports where the workbook's CCI sets and DISA's references disagree, and
corrects neither -- the catalog/reconcile.py posture. An empty workbook cell
is silence, not contradiction, or the real findings drown in thousands of
empty ones."
```

---

### Task 9: CLI and source registration

**Files:**
- Modify: `src/ccf/cli.py` (new `cci_app` group beside `catalog_app`, ~line 1686), `src/ccf/etl/sources.py` (`DEFAULT_SOURCES`)
- Test: `tests/test_cci_cli.py`

**Interfaces:**
- Produces: `ccf cci load [--path P] [--overlay/--no-overlay]`, `ccf cci show CCI-000002`, `ccf cci control AC-1`, `ccf cci reconcile`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cci_cli.py
"""The CLI surface. Assertions avoid rendered help text, which is
terminal-width dependent and has broken CI here before."""
from typer.testing import CliRunner

from ccf.cli import app

runner = CliRunner()


def test_cci_group_is_registered() -> None:
    result = runner.invoke(app, ["cci", "--help"])
    assert result.exit_code == 0
    assert "load" in result.stdout
    assert "reconcile" in result.stdout


def test_source_is_registered_disabled_with_a_reason() -> None:
    from ccf.etl.sources import DEFAULT_SOURCES

    spec = next(s for s in DEFAULT_SOURCES if s["key"] == "disa_cci_list")
    assert spec["authority"] == "DISA"
    assert spec["kind"] == "generic"
    # cyber.mil refuses non-browser fetches; an always-erroring source would
    # put a permanent red line in the alert digest that means nothing.
    assert spec["enabled"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cci_cli.py -v`
Expected: FAIL — `cci` is not a command.

- [ ] **Step 3: Register the source**

In `src/ccf/etl/sources.py`, append to `DEFAULT_SOURCES`:

```python
    {
        "key": "disa_cci_list",
        "name": "DISA Control Correlation Identifiers — CCI List",
        "authority": "DISA",
        # Not OSCAL: content-hash only, like the baseline profiles.
        "kind": "generic",
        "url": "https://public.cyber.mil/stigs/cci/",
        "framework_code": "DISA_CCI",
        # Disabled by default. cyber.mil refuses non-browser fetches, so an
        # enabled source could only ever record an error, and a permanently
        # failing source in the alert digest trains people to ignore it.
        # Enable it where egress allows: the poller already records a
        # per-source failure and moves on, and auto_ingest stays False either
        # way, so a detected change is still reviewed by a human.
        "enabled": False,
    },
```

- [ ] **Step 4: Add the CLI group**

In `src/ccf/cli.py`, after the `catalog_app` block:

```python
cci_app = typer.Typer(help="DISA CCIs — load, look up, reconcile.", no_args_is_help=True)
app.add_typer(cci_app, name="cci")


@cci_app.command("load")
def cci_load(
    path: Path = typer.Option(None, help="CCI List HTML (defaults to data/cci/)."),
    overlay: bool = typer.Option(True, help="Also load the derived Rev. 5 overlay."),
) -> None:
    """Load DISA's CCI list. Re-running on unchanged content writes nothing."""

    async def _run() -> None:
        from .cci.service import load_cci_list, load_cci_overlay

        async with session_scope() as s:
            result = await load_cci_list(s, path=path)
            written = await load_cci_overlay(s) if overlay and not result.skipped_unchanged else 0
        if result.skipped_unchanged:
            console.print(f"[dim]unchanged[/dim] version {result.version} — nothing written")
            return
        console.print(
            f"version {result.version}: {result.items_created} created, "
            f"{result.items_updated} updated, {result.refs_written} references "
            f"({result.refs_unresolved} unresolved), {written} overlay rows"
        )

    asyncio.run(_run())


@cci_app.command("show")
def cci_show(cci: str) -> None:
    """Show one CCI and the controls it decomposes."""

    async def _run() -> None:
        from .cci.service import controls_for_cci

        async with session_scope() as s:
            controls = await controls_for_cci(s, cci)
        if not controls:
            console.print(f"[yellow]{cci}: no Rev. 5 control reference[/yellow]")
            return
        console.print(f"{cci}: {', '.join(controls)}")

    asyncio.run(_run())


@cci_app.command("control")
def cci_control(control: str) -> None:
    """List the CCIs covering a control."""

    async def _run() -> None:
        from .cci.service import ccis_for_control

        async with session_scope() as s:
            rows = await ccis_for_control(s, control)
        table = Table(title=f"CCIs covering {control} (Rev. 5)")
        table.add_column("CCI")
        table.add_column("Type")
        table.add_column("Index")
        table.add_column("OSCAL part")
        for r in rows:
            table.add_row(r.cci, r.type, r.raw_index, r.oscal_part_id or "—")
        console.print(table)

    asyncio.run(_run())


@cci_app.command("reconcile")
def cci_reconcile() -> None:
    """Report where the workbook's CCI column and DISA disagree. Advisory."""

    async def _run() -> None:
        from .cci.reconcile import reconcile_cci

        async with session_scope() as s:
            findings = await reconcile_cci(s)
        console.print(f"{len(findings)} control rows disagree")
        for d in findings[:50]:
            console.print(
                f"  {d.control_identifier}: workbook-only={list(d.workbook_only)} "
                f"disa-only={list(d.disa_only)}"
            )

    asyncio.run(_run())
```

Match the surrounding file's existing imports for `asyncio`, `Path`, `console`, `Table`, and `session_scope` rather than adding duplicates.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cci_cli.py -v` — expected: PASS.
Run: `pytest tests/ -q -k "sources or catalog_cli"` — expected: PASS (a new `DEFAULT_SOURCES` entry must not break seeding tests; if one asserts an exact source count, update it and say why in the commit).
Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cli.py src/ccf/etl/sources.py tests/test_cci_cli.py
git commit -m "feat(cci): the cci CLI group and a disabled currency source

ccf cci load / show / control / reconcile. The CatalogSource row registers
DISA as an authority but ships disabled: cyber.mil refuses non-browser
fetches, and a source that can only ever error trains people to ignore the
digest. Enabling it is one field where egress allows; auto_ingest stays False
either way."
```

---

### Task 10: Objective labels prefer the row's own identifier

Independent of the CCI data — see §6 of the spec for the measurements that moved this off the .ods.

**Files:**
- Modify: `src/ccf/assessment/engine/objectives.py` (the label selection at ~line 110, and the module docstring)
- Test: `tests/test_assessment_objectives.py` (extend)

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature change. `Objective.label` now prefers `Control.identifier`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_assessment_objectives.py
@pytest.mark.asyncio
async def test_label_prefers_the_rows_own_identifier(clean_migrated_db) -> None:
    """The workbook's identifier IS the item path (AC-02a.[01]) and is UNIQUE,
    so it beats both the near-empty ap_acronym column (4 populated rows in
    5,435) and an ordinal derived from position."""
    async with session_scope() as s:
        s.add_all(
            [
                Control(
                    identifier="ZZ-01a.[01]", sequence_control="ZZ-01",
                    control_name=None, assessment_objective="first objective",
                    source_row=1,
                ),
                Control(
                    identifier="ZZ-01b.", sequence_control="ZZ-01",
                    control_name=None, assessment_objective="second objective",
                    source_row=2,
                ),
            ]
        )
    async with session_scope() as s:
        got = await objectives_for(s, "ZZ-01")
    assert [o.label for o in got] == ["ZZ-01a.[01]", "ZZ-01b."]
    async with session_scope() as s:
        for ident in ("ZZ-01a.[01]", "ZZ-01b."):
            row = (
                await s.execute(select(Control).where(Control.identifier == ident))
            ).scalar_one()
            await s.delete(row)


@pytest.mark.asyncio
async def test_ordinal_fallback_survives_a_missing_identifier(clean_migrated_db) -> None:
    """identifier is NOT NULL in practice, but the fallback must still run --
    removing it silently would make a future schema change label-less."""
    async with session_scope() as s:
        s.add(
            Control(
                identifier="ZZ-02#row9", sequence_control="ZZ-02",
                control_name=None, assessment_objective="only objective", source_row=1,
            )
        )
    async with session_scope() as s:
        got = await objectives_for(s, "ZZ-02")
    assert got[0].label == "ZZ-02#row9"
    async with session_scope() as s:
        row = (
            await s.execute(select(Control).where(Control.identifier == "ZZ-02#row9"))
        ).scalar_one()
        await s.delete(row)
```

Use the module's existing fixtures and imports; add `select` and `Control` imports only if absent.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_assessment_objectives.py -v -k identifier`
Expected: FAIL — labels come back as `ZZ-01a` / `ZZ-01b` from `_ordinal_label`.

- [ ] **Step 3: Write minimal implementation**

In `objectives_for`, change one line:

```python
        label = row.identifier or row.ap_acronym or _ordinal_label(
            row.sequence_control or canonical, index
        )
```

and update the module docstring's label paragraph:

```
Labels come from the row's own ``identifier``, which in the real workbook *is*
the item path -- ``AC-02a.[01]``, ``AC-02b.``, ``AC-02_ODP[01]`` -- and is
UNIQUE in the schema, so it is unique by construction. ``ap_acronym`` is kept
as a fallback but is populated on 4 of 5,435 catalog rows, and the ordinal
derivation below is the last resort. The duplicate handling further down stays
regardless: uniqueness by construction is a property of the current schema,
not a promise, and ``uq_objective_proposal_label`` is what actually enforces it.
```

Leave both duplicate-label fallbacks exactly as they are.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_assessment_objectives.py -v` — expected: PASS.
Run: `pytest tests/test_assessment_engine_real_catalog.py -v` — expected: PASS. If a test there asserts a derived label like `AC-2a`, update it to the identifier the real catalog row carries and note the change in the commit — the label is now more faithful, not differently wrong.
Run: `make lint && make typecheck` — expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/assessment/engine/objectives.py tests/test_assessment_objectives.py
git commit -m "fix(assessment): label objectives from the row's own identifier

The workbook identifier IS the item path (AC-02a.[01], AC-02b.) and is UNIQUE,
so it is unique by construction -- the exact property the duplicate handling
below it exists to defend. ap_acronym is populated on 4 of 5,435 rows and the
ordinal derivation was carrying almost every label.

Stored proposals keep their stored labels: they are records of what was
proposed, not a cache. Every duplicate and ordinal fallback is retained."
```

---

### Task 11: Mutation-test the guards, then record the result

House practice: delete each guard and confirm a test fails. A guard no test defends is either untested or unnecessary, and both are worth knowing.

**Files:**
- Modify: `docs/superpowers/plans/2026-09-15-cci-source-spine.md` (this file — the results table below), `docs/architecture/forge-capability-inventory.md` (a status section)

- [ ] **Step 1: Mutate each guard and record whether a test caught it**

For each row, make the edit, run the named tests, restore the file. A surviving mutant means a missing test — write it before moving on.

| # | File | Mutation | Expected to fail |
|---|---|---|---|
| 1 | `cci/resolve.py` | Remove the enhancement-absorption `while` loop | `test_leading_parenthetical_is_an_enhancement_not_an_item` |
| 2 | `cci/resolve.py` | Return the part id unconditionally (drop `if part_id in part_ids`) | `test_unresolvable_item_keeps_its_control` |
| 3 | `cci/resolve.py` | Drop the `oscal_id not in control_ids` check | `test_non_80053_reference_resolves_to_nothing_rather_than_guessing` |
| 4 | `cci/reader.py` | Map an unknown reference title to `""` instead of the verbatim title | add a test if none fails |
| 5 | `cci/reader.py` | Drop the `_CCI_RE.match(cci)` guard in `_item` | `test_reads_every_cci_with_its_version` (count moves) |
| 6 | `cci/overlay.py` | Remove the `_REV5_CONTROL` filter | `test_only_rev5_spelled_rows_are_returned` |
| 7 | `cci/service.py` | Drop the `skipped_unchanged` short-circuit | `test_second_load_of_the_same_file_is_a_no_op` |
| 8 | `cci/service.py` | Keep the old refs (remove the `delete` before re-adding) | add a test if none fails |
| 9 | `cci/service.py` | Attach overlay rows to unknown CCIs (remove the `pk is None` skip) | `test_overlay_attaches_only_to_known_ccis_and_names_its_source` |
| 10 | `cci/reconcile.py` | Report empty workbook cells as disagreements | `test_an_empty_workbook_cell_is_not_a_disagreement` |
| 11 | `cci/reconcile.py` | Stop stripping `*` | `test_workbook_value_splits_and_strips_the_compliance_marker` |
| 12 | `objectives.py` | Put `ap_acronym` back ahead of `identifier` | `test_label_prefers_the_rows_own_identifier` |

**Harness invariant:** before trusting any row, confirm the test command actually runs the test and can fail — a harness that cannot fail proves nothing. Run one mutation you expect to be caught and watch it fail first.

- [ ] **Step 2: Record the results in this plan**

Append a `## Mutation results` section: the table above with a caught/escaped column, and a line naming any test written to close an escape.

- [ ] **Step 3: Record status in the capability inventory**

Add a section to `docs/architecture/forge-capability-inventory.md` in the style of §6.2i: what was built, the three or four judgements that are load-bearing (the enhancement rule, nullable `oscal_part_id`, the mixed-generation .ods, the objective-label correction), and the measured numbers. Mark G4's CCI half closed, and state plainly that P5 is unblocked but not built.

- [ ] **Step 4: Full suite, then commit**

```bash
pytest -q && make lint && make typecheck && alembic heads
```
Expected: the suite green except the known pre-existing `test_analytics_residual_and_overdue` failure inherited from `main`; ruff and mypy clean; exactly one alembic head.

```bash
git add docs/superpowers/plans/2026-09-15-cci-source-spine.md docs/architecture/forge-capability-inventory.md
git commit -m "docs(cci): record the mutation results and mark G4's CCI half closed"
```

---

## Notes for the executor

- **Do not adjust a measured assertion to make a test pass.** Every count in Global Constraints came from the committed files. A mismatch means the parser is wrong, not the number.
- **Do not add a dependency.** An .ods is a zip of XML; `zipfile` and `defusedxml` are enough.
- **Do not write to `controls`, `framework_mappings`, or any `*_history` table.** The workbook owns those and the next ingest rebuilds them.
- **Do not build CKL or XCCDF parsing.** That is P5, and `controls_for_cci` is the seam it will use.
- After committing a task, run `git show --stat` and confirm the intended files are actually in the commit. A green suite answers "does the tree work", not "is the tree committed".
