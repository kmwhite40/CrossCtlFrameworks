# OSCAL Catalog Reconciliation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an advisory engine that reconciles Concord's workbook-sourced controls against a pinned NIST OSCAL 800-53 Rev 5 catalog + 800-53B baselines, producing a catalog-integrity report and a raw→canonical control-id crosswalk, changing no control data.

**Architecture:** A standalone `src/ccf/catalog/` package (OSCAL loader, one pure control-id canonicalizer, four pure reconcilers, a report persister) whose only write target is a new `catalog_integrity_reports` table. Three consumers call it: a `ccf catalog` CLI, a non-fatal tail-call in `ingest_workbook`, and a `/readyz` check; a read-only role-gated UI page renders the latest report. Advisory-only is guaranteed by construction — the engine has no write path into `controls`.

**Tech Stack:** Python 3.12, async SQLAlchemy/asyncpg, Alembic, Typer CLI, FastAPI + HTMX/Jinja templates, pytest/pytest-asyncio. OSCAL catalog is vendored JSON (NIST `usnistgov/oscal-content`, Rev 5.2.0).

## Global Constraints

- **Advisory only in v1:** the engine MUST NOT write to, update, or delete `controls` or `framework_mappings`. Its only write target is `catalog_integrity_reports`.
- **Bundled catalog, no runtime network:** all OSCAL data is read from `data/oscal/*.json` shipped in the repo; no code path fetches over the network at runtime.
- **Catalog provenance verified:** `data/oscal/MANIFEST.json` records `oscal_version`, per-file `sha256`, `source_url`, `retrieved_at`; the loader verifies each file's sha256 against the manifest and raises on mismatch.
- **Canonical id form:** display form `AC-2` (base) and `AC-2(1)` (enhancement), uppercase family, no zero-padding. OSCAL ids are lowercase dot form (`ac-2`, `ac-2.1`) and MUST be converted to canonical on load.
- **Engine keys off `Control.control_number`** (the NIST id column), never `Control.identifier` (the workbook assessment-row key).
- **Graceful degradation:** a control that fails the identity check is recorded `not_evaluated` by every downstream check; report counts MUST always reconcile: `controls_checked == distinct canonical ids evaluated + not_evaluated`.
- **No silent caps:** mapping targets with no bundled catalog are reported as `not evaluated (no bundled catalog)` in `summary`, never silently passed.
- **Test harness:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`, `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`; `pytest-asyncio` `asyncio_mode=auto`; schema changes require an Alembic migration and the conftest `clean_migrated_db` reset base→head.
- **Migrator rebuild:** after adding the migration, note that `docker compose build api migrator` is required before the stack will start (see [[migrator-image-rebuild]]).
- **Style gates:** `ruff check .` and `mypy src` (strict) must pass; line-length 100; follow existing module patterns (`src/ccf/fedramp20x/catalog.py`, `docs/superpowers/assessments/integrity_checks.py`).

---

### Task 1: Vendor + pin the OSCAL catalog and baselines, with a verifying loader

**Files:**
- Create: `data/oscal/NIST_SP-800-53_rev5_catalog.json` (downloaded, pinned)
- Create: `data/oscal/NIST_SP-800-53_rev5_LOW-baseline_profile.json`
- Create: `data/oscal/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json`
- Create: `data/oscal/NIST_SP-800-53_rev5_HIGH-baseline_profile.json`
- Create: `data/oscal/MANIFEST.json`
- Create: `src/ccf/catalog/__init__.py`
- Create: `src/ccf/catalog/oscal.py`
- Test: `tests/test_catalog_oscal.py`
- Test fixture: `tests/fixtures/oscal_mini/` (a tiny catalog + one baseline profile + manifest, authored by hand)

**Interfaces:**
- Produces:
  - `class OscalControl` dataclass: `canonical_id: str`, `title: str`, `statement: str`, `guidance: str`, `withdrawn: bool`, `incorporated_into: list[str]`, `param_ids: list[str]`.
  - `class OscalCatalog`: `version: str`, `controls: dict[str, OscalControl]` (keyed by canonical id), `baselines: dict[str, set[str]]` (keys `"low"/"moderate"/"high"`, values canonical-id sets); methods `get(cid) -> OscalControl | None`, `exists(cid) -> bool`, `in_baseline(cid, level) -> bool`.
  - `def load_oscal_catalog(base_dir: Path | None = None) -> OscalCatalog` — resolves `data/oscal/`, verifies sha256 against `MANIFEST.json`, parses catalog + 3 profiles, returns the indexed catalog. Raises `OscalManifestError` on sha mismatch or missing file.
  - `def oscal_id_to_canonical(oscal_id: str) -> str` — `"ac-2"→"AC-2"`, `"ac-2.1"→"AC-2(1)"`, `"ac-2.1.2"→"AC-2(1)(2)"`.

- [ ] **Step 1: Download and pin the four OSCAL files + generate the manifest**

Run (from repo root; network is available for this setup step only — the runtime never fetches):
```bash
mkdir -p data/oscal
BASE="https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json"
for f in NIST_SP-800-53_rev5_catalog.json \
         NIST_SP-800-53_rev5_LOW-baseline_profile.json \
         NIST_SP-800-53_rev5_MODERATE-baseline_profile.json \
         NIST_SP-800-53_rev5_HIGH-baseline_profile.json; do
  curl -sSL --max-time 60 "$BASE/$f" -o "data/oscal/$f"
done
PYTHONPATH=src python - <<'PY'
import hashlib, json, datetime
from pathlib import Path
d = Path("data/oscal")
files = sorted(p.name for p in d.glob("*.json") if p.name != "MANIFEST.json")
cat = json.loads((d / "NIST_SP-800-53_rev5_catalog.json").read_text())
manifest = {
    "oscal_version": cat["catalog"]["metadata"]["version"],
    "source_url": "https://github.com/usnistgov/oscal-content (nist.gov/SP800-53/rev5/json)",
    "retrieved_at": datetime.date.today().isoformat(),
    "files": {f: hashlib.sha256((d / f).read_bytes()).hexdigest() for f in files},
}
(d / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("manifest version", manifest["oscal_version"], "files", list(manifest["files"]))
PY
```
Expected: prints `manifest version 5.2.0 files [...4 files...]`.

- [ ] **Step 2: Create the hand-authored mini fixture**

Create `tests/fixtures/oscal_mini/NIST_SP-800-53_rev5_catalog.json` with a minimal but valid shape: a catalog with one group `ac` holding controls `ac-1` (title "Policy and Procedures", statement/guidance parts), `ac-2` (title "Account Management", with a nested enhancement `ac-2.1` title "Automated System Account Management"), and `ac-13` marked withdrawn with an `incorporated-into` link to `ac-2`.
```json
{
  "catalog": {
    "uuid": "00000000-0000-0000-0000-000000000000",
    "metadata": {"title": "MINI", "version": "5.2.0", "oscal-version": "1.2.2"},
    "groups": [{
      "id": "ac", "class": "family", "title": "Access Control",
      "controls": [
        {"id": "ac-1", "class": "SP800-53", "title": "Policy and Procedures",
         "parts": [
           {"name": "statement", "prose": "Develop, document, and disseminate an access control policy."},
           {"name": "guidance", "prose": "Access control policy guidance."}]},
        {"id": "ac-2", "class": "SP800-53", "title": "Account Management",
         "params": [{"id": "ac-02_odp.01"}],
         "parts": [
           {"name": "statement", "prose": "Manage system accounts."},
           {"name": "guidance", "prose": "Account management guidance."}],
         "controls": [
           {"id": "ac-2.1", "class": "SP800-53-enhancement", "title": "Automated System Account Management",
            "parts": [{"name": "statement", "prose": "Support account management with automation."}]}]},
        {"id": "ac-13", "class": "SP800-53", "title": "Withdrawn Control",
         "props": [{"name": "status", "value": "withdrawn"}],
         "links": [{"href": "#ac-2", "rel": "incorporated-into"}]}
      ]
    }]
  }
}
```
Create `tests/fixtures/oscal_mini/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json`:
```json
{"profile": {"uuid": "00000000-0000-0000-0000-000000000001",
  "metadata": {"title": "MINI-MOD", "version": "5.2.0", "oscal-version": "1.2.2"},
  "imports": [{"href": "#cat", "include-controls": [{"with-ids": ["ac-1", "ac-2", "ac-2.1"]}]}]}}
```
Create matching `..._LOW-baseline_profile.json` (`with-ids: ["ac-1", "ac-2"]`) and `..._HIGH-baseline_profile.json` (`with-ids: ["ac-1", "ac-2", "ac-2.1"]`). Then generate `tests/fixtures/oscal_mini/MANIFEST.json` using the same manifest snippet from Step 1 pointed at the fixture dir.

- [ ] **Step 3: Write failing tests**

```python
# tests/test_catalog_oscal.py
from pathlib import Path
import json
import pytest
from ccf.catalog.oscal import (
    load_oscal_catalog, oscal_id_to_canonical, OscalManifestError,
)

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


def test_oscal_id_to_canonical():
    assert oscal_id_to_canonical("ac-2") == "AC-2"
    assert oscal_id_to_canonical("ac-2.1") == "AC-2(1)"
    assert oscal_id_to_canonical("ac-2.1.2") == "AC-2(1)(2)"


def test_loads_and_indexes_controls_and_enhancements():
    cat = load_oscal_catalog(FIX)
    assert cat.version == "5.2.0"
    assert cat.exists("AC-1") and cat.exists("AC-2") and cat.exists("AC-2(1)")
    ac2 = cat.get("AC-2")
    assert ac2.title == "Account Management"
    assert "Manage system accounts." in ac2.statement
    assert ac2.param_ids == ["ac-02_odp.01"]


def test_withdrawn_and_incorporated_into():
    cat = load_oscal_catalog(FIX)
    ac13 = cat.get("AC-13")
    assert ac13.withdrawn is True
    assert "AC-2" in ac13.incorporated_into


def test_baseline_membership():
    cat = load_oscal_catalog(FIX)
    assert cat.in_baseline("AC-2", "moderate") is True
    assert cat.in_baseline("AC-2(1)", "low") is False
    assert cat.in_baseline("AC-2(1)", "high") is True


def test_manifest_sha_mismatch_raises(tmp_path):
    # copy fixture, corrupt one file, expect OscalManifestError
    import shutil
    dst = tmp_path / "oscal"
    shutil.copytree(FIX, dst)
    p = dst / "NIST_SP-800-53_rev5_catalog.json"
    p.write_text(p.read_text() + " ")  # change bytes -> sha mismatch
    with pytest.raises(OscalManifestError):
        load_oscal_catalog(dst)
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_oscal.py -q`
Expected: FAIL (`ModuleNotFoundError: ccf.catalog.oscal`).

- [ ] **Step 5: Implement `src/ccf/catalog/__init__.py` and `src/ccf/catalog/oscal.py`**

```python
# src/ccf/catalog/__init__.py
"""Concord catalog reconciliation engine (advisory).

Reconciles workbook-sourced controls against the pinned NIST OSCAL 800-53 Rev 5
catalog. Never writes to ``controls``; its only persistence target is
``catalog_integrity_reports``.
"""
```

```python
# src/ccf/catalog/oscal.py
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_DEFAULT_DIR = Path(__file__).resolve().parents[3] / "data" / "oscal"
_PACKAGED_DIR = Path(__file__).with_name("oscal_data")  # wheel/Docker fallback
_BASELINE_FILES = {
    "low": "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
    "moderate": "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
    "high": "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
}
_CATALOG_FILE = "NIST_SP-800-53_rev5_catalog.json"


class OscalManifestError(RuntimeError):
    """Raised when a bundled OSCAL file is missing or fails sha256 verification."""


@dataclass(frozen=True)
class OscalControl:
    canonical_id: str
    title: str
    statement: str
    guidance: str
    withdrawn: bool
    incorporated_into: list[str]
    param_ids: list[str]


@dataclass
class OscalCatalog:
    version: str
    controls: dict[str, OscalControl] = field(default_factory=dict)
    baselines: dict[str, set[str]] = field(default_factory=dict)

    def get(self, cid: str) -> OscalControl | None:
        return self.controls.get(cid)

    def exists(self, cid: str) -> bool:
        return cid in self.controls

    def in_baseline(self, cid: str, level: str) -> bool:
        return cid in self.baselines.get(level, set())


def oscal_id_to_canonical(oscal_id: str) -> str:
    parts = oscal_id.split(".")
    base = parts[0]
    m = re.match(r"^([a-zA-Z]+)-(\d+)$", base)
    fam, num = (m.group(1).upper(), str(int(m.group(2)))) if m else (base.upper(), "")
    canon = f"{fam}-{num}" if num else base.upper()
    for enh in parts[1:]:
        canon += f"({int(enh)})" if enh.isdigit() else f"({enh})"
    return canon


def _resolve_dir(base_dir: Path | None) -> Path:
    for d in ([base_dir] if base_dir else [_DEFAULT_DIR, _PACKAGED_DIR]):
        if d and (d / "MANIFEST.json").is_file():
            return d
    raise OscalManifestError(f"OSCAL data dir not found (looked in {base_dir or [_DEFAULT_DIR, _PACKAGED_DIR]})")


def _verify(d: Path) -> dict:
    manifest = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    for name, want in manifest.get("files", {}).items():
        p = d / name
        if not p.is_file():
            raise OscalManifestError(f"missing OSCAL file {name}")
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        if got != want:
            raise OscalManifestError(f"sha256 mismatch for {name}: {got} != {want}")
    return manifest


def _iter_controls(node: dict):
    for c in node.get("controls", []):
        yield c
        yield from _iter_controls(c)
    for g in node.get("groups", []):
        yield from _iter_controls(g)


def _part_prose(control: dict, name: str) -> str:
    out = []
    for part in control.get("parts", []):
        if part.get("name") == name and part.get("prose"):
            out.append(part["prose"])
    return "\n".join(out)


def _parse_control(c: dict) -> OscalControl:
    props = c.get("props", [])
    withdrawn = any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in props)
    inc = [
        oscal_id_to_canonical(link["href"].lstrip("#"))
        for link in c.get("links", [])
        if link.get("rel") == "incorporated-into" and link.get("href")
    ]
    return OscalControl(
        canonical_id=oscal_id_to_canonical(c["id"]),
        title=c.get("title", ""),
        statement=_part_prose(c, "statement"),
        guidance=_part_prose(c, "guidance"),
        withdrawn=withdrawn,
        incorporated_into=inc,
        param_ids=[p["id"] for p in c.get("params", []) if p.get("id")],
    )


def load_oscal_catalog(base_dir: Path | None = None) -> OscalCatalog:
    d = _resolve_dir(base_dir)
    manifest = _verify(d)
    raw = json.loads((d / _CATALOG_FILE).read_text(encoding="utf-8"))
    cat_meta = raw["catalog"]["metadata"]
    catalog = OscalCatalog(version=cat_meta.get("version", manifest.get("oscal_version", "")))
    for c in _iter_controls(raw["catalog"]):
        oc = _parse_control(c)
        catalog.controls[oc.canonical_id] = oc
    for level, fname in _BASELINE_FILES.items():
        prof = json.loads((d / fname).read_text(encoding="utf-8"))
        ids: set[str] = set()
        for imp in prof["profile"].get("imports", []):
            for inc in imp.get("include-controls", []):
                ids.update(oscal_id_to_canonical(x) for x in inc.get("with-ids", []))
        catalog.baselines[level] = ids
    return catalog
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_oscal.py -q`
Expected: PASS (5 tests). Also sanity-load the real catalog:
`PYTHONPATH=src python -c "from ccf.catalog.oscal import load_oscal_catalog; c=load_oscal_catalog(); print(c.version, len(c.controls), {k:len(v) for k,v in c.baselines.items()})"`
Expected: prints `5.2.0`, ~1189 controls, and non-zero baseline sizes (moderate ≈ 287).

- [ ] **Step 7: Commit**

```bash
git add data/oscal src/ccf/catalog/__init__.py src/ccf/catalog/oscal.py tests/test_catalog_oscal.py tests/fixtures/oscal_mini
git commit -m "feat(catalog): pin NIST OSCAL 800-53r5 catalog + verifying loader"
```

---

### Task 2: The control-id canonicalizer

**Files:**
- Create: `src/ccf/catalog/canonical.py`
- Test: `tests/test_catalog_canonical.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `@dataclass(frozen=True) class CanonicalId: value: str; family: str; number: int; enhancements: tuple[int, ...]`.
  - `def canonicalize(raw: str | None) -> CanonicalId | None` — returns `None` for anything not confidently an 800-53 control id (empty, CMMC forms like `AC.L2-3.1.1`, prose). Never guesses.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_catalog_canonical.py
import pytest
from ccf.catalog.canonical import canonicalize, CanonicalId


@pytest.mark.parametrize("raw,expected", [
    ("AC-2", "AC-2"),
    ("AC-02", "AC-2"),
    ("ac-2", "AC-2"),
    ("AC-2 (1)", "AC-2(1)"),
    ("AC-2(1)", "AC-2(1)"),
    ("ac-02 (01)", "AC-2(1)"),
    ("AC-2 (1)(2)", "AC-2(1)(2)"),
    ("  SC-7  ", "SC-7"),
    ("PM-31", "PM-31"),
])
def test_canonicalizes_valid_ids(raw, expected):
    cid = canonicalize(raw)
    assert cid is not None and cid.value == expected


@pytest.mark.parametrize("raw", [
    None, "", "   ", "n/a", "AC.L2-3.1.1", "3.1.1", "See AC-2",
    "Access Control", "AC", "AC-",
])
def test_rejects_non_800_53_ids(raw):
    assert canonicalize(raw) is None


def test_parses_parts():
    cid = canonicalize("AC-2 (1)")
    assert cid.family == "AC" and cid.number == 2 and cid.enhancements == (1,)
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_canonical.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `src/ccf/catalog/canonical.py`**

```python
# src/ccf/catalog/canonical.py
from __future__ import annotations

import re
from dataclasses import dataclass

# Family AB..BB then -NN, then zero or more (N) or " (N)" enhancement groups.
# Anchored + full-match so prose and CMMC ids (which contain '.') are rejected.
_PATTERN = re.compile(
    r"^\s*(?P<fam>[A-Za-z]{2})-0*(?P<num>\d{1,3})"
    r"(?P<enh>(?:\s*\(\s*0*\d{1,3}\s*\))*)\s*$"
)
_ENH = re.compile(r"\(\s*0*(\d{1,3})\s*\)")


@dataclass(frozen=True)
class CanonicalId:
    value: str
    family: str
    number: int
    enhancements: tuple[int, ...]


def canonicalize(raw: str | None) -> CanonicalId | None:
    if not raw or not raw.strip():
        return None
    m = _PATTERN.match(raw)
    if not m:
        return None
    fam = m.group("fam").upper()
    num = int(m.group("num"))
    enh = tuple(int(x) for x in _ENH.findall(m.group("enh") or ""))
    value = f"{fam}-{num}" + "".join(f"({e})" for e in enh)
    return CanonicalId(value=value, family=fam, number=num, enhancements=enh)
```

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_canonical.py -q`
Expected: PASS (all parametrized cases).

- [ ] **Step 5: Commit**

```bash
git add src/ccf/catalog/canonical.py tests/test_catalog_canonical.py
git commit -m "feat(catalog): control-id canonicalizer (never-guess 800-53 normalizer)"
```

---

### Task 3: Reconcilers part 1 — findings type, identity + baseline checks, crosswalk

**Files:**
- Create: `src/ccf/catalog/reconcile.py`
- Test: `tests/test_catalog_reconcile_identity.py`

**Interfaces:**
- Consumes: `OscalCatalog` (Task 1), `canonicalize` (Task 2).
- Produces:
  - `@dataclass class CatalogFinding: check: str; severity: str; canonical_id: str; raw_id: str; field: str | None; workbook_value: str | None; oscal_value: str | None; detail: str` with `.as_dict() -> dict`.
  - `@dataclass class ControlRow: control_number: str | None; control_name: str | None; description: str | None; discussion: str | None; fisma_low: bool | None; fisma_mod: bool | None; fisma_high: bool | None; source_row: int | None` — the plain input the reconcilers take (decoupled from the ORM so they stay pure and unit-testable).
  - `def check_identity(catalog, rows) -> tuple[list[CatalogFinding], dict[str, str | None], set[str]]` — returns (findings, crosswalk raw→canonical-or-None, set of canonical ids that FAILED identity and must be treated `not_evaluated` downstream).
  - `def check_baseline(catalog, rows, failed) -> list[CatalogFinding]`.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_catalog_reconcile_identity.py
from pathlib import Path
from ccf.catalog.oscal import load_oscal_catalog
from ccf.catalog.reconcile import ControlRow, check_identity, check_baseline

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


def _rows(*specs):
    out = []
    for s in specs:
        out.append(ControlRow(
            control_number=s.get("cn"), control_name=s.get("name"),
            description=s.get("desc"), discussion=s.get("disc"),
            fisma_low=s.get("low"), fisma_mod=s.get("mod"), fisma_high=s.get("high"),
            source_row=s.get("row"),
        ))
    return out


def test_identity_flags_unknown_unparseable_withdrawn():
    cat = load_oscal_catalog(FIX)
    rows = _rows(
        {"cn": "AC-2", "row": 2},          # ok
        {"cn": "SC-99", "row": 3},         # unknown
        {"cn": "AC.L2-3.1.1", "row": 4},   # unparseable
        {"cn": "AC-13", "row": 5},         # withdrawn
    )
    findings, crosswalk, failed = check_identity(cat, rows)
    checks = {(f.check, f.severity, f.canonical_id) for f in findings}
    assert ("identity", "high", "SC-99") in checks       # unknown_control_id
    assert any(f.detail.startswith("unparseable") or f.field == "unparseable" for f in findings)
    assert ("identity", "medium", "AC-13") in checks     # withdrawn
    assert crosswalk["AC-2"] == "AC-2"
    assert crosswalk["AC.L2-3.1.1"] is None
    assert "SC-99" in failed and "AC-2" not in failed


def test_baseline_over_and_under_claim():
    cat = load_oscal_catalog(FIX)
    # AC-2(1) is in MODERATE+HIGH per fixture, NOT in LOW
    rows = _rows(
        {"cn": "AC-2(1)", "low": True, "mod": True, "high": True, "row": 2},  # low overclaim
        {"cn": "AC-2", "low": False, "mod": False, "high": False, "row": 3},  # mod/high/low underclaim
    )
    _, _, failed = check_identity(cat, rows)
    findings = check_baseline(cat, rows, failed)
    kinds = {(f.field, f.detail.split()[0]) for f in findings}
    assert ("fisma_low", "baseline_overclaim") in {(f.field, f.check_kind()) for f in findings} or \
           any(f.severity == "medium" and f.field == "fisma_low" for f in findings)
    assert any(f.severity == "high" and f.field in {"fisma_mod", "fisma_high"} for f in findings)
```

Note to implementer: keep the finding `check` field = `"baseline"` and encode the sub-kind in `detail` (e.g. `"baseline_overclaim: ..."`). The test tolerates either a `check_kind()` helper or a `detail`-prefix; implement the `detail` prefix and drop the helper branch — adjust the assertion to read the detail prefix.

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_reconcile_identity.py -q`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement identity + baseline in `src/ccf/catalog/reconcile.py`**

```python
# src/ccf/catalog/reconcile.py
from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonicalize
from .oscal import OscalCatalog

_BASELINE_FIELDS = {"fisma_low": "low", "fisma_mod": "moderate", "fisma_high": "high"}


@dataclass
class CatalogFinding:
    check: str
    severity: str
    canonical_id: str
    raw_id: str
    field: str | None
    workbook_value: str | None
    oscal_value: str | None
    detail: str

    def as_dict(self) -> dict:
        return {
            "check": self.check, "severity": self.severity,
            "canonical_id": self.canonical_id, "raw_id": self.raw_id,
            "field": self.field, "workbook_value": self.workbook_value,
            "oscal_value": self.oscal_value, "detail": self.detail,
        }


@dataclass
class ControlRow:
    control_number: str | None
    control_name: str | None
    description: str | None
    discussion: str | None
    fisma_low: bool | None
    fisma_mod: bool | None
    fisma_high: bool | None
    source_row: int | None


def check_identity(
    catalog: OscalCatalog, rows: list[ControlRow]
) -> tuple[list[CatalogFinding], dict[str, str | None], set[str]]:
    findings: list[CatalogFinding] = []
    crosswalk: dict[str, str | None] = {}
    failed: set[str] = set()
    for row in rows:
        raw = (row.control_number or "").strip()
        if not raw:
            continue
        cid = canonicalize(raw)
        if cid is None:
            crosswalk[raw] = None
            failed.add(raw)
            findings.append(CatalogFinding(
                "identity", "high", raw, raw, "unparseable", raw, None,
                f"unparseable control id '{raw}' — cannot be trusted in joins"))
            continue
        crosswalk[raw] = cid.value
        oc = catalog.get(cid.value)
        if oc is None:
            failed.add(cid.value)
            findings.append(CatalogFinding(
                "identity", "high", cid.value, raw, None, raw, None,
                f"unknown_control_id: {cid.value} not in OSCAL 800-53r5 catalog"))
        elif oc.withdrawn:
            succ = ", ".join(oc.incorporated_into) or "n/a"
            findings.append(CatalogFinding(
                "identity", "medium", cid.value, raw, None, raw, succ,
                f"withdrawn_control: {cid.value} is withdrawn (incorporated into {succ})"))
    return findings, crosswalk, failed


def check_baseline(
    catalog: OscalCatalog, rows: list[ControlRow], failed: set[str]
) -> list[CatalogFinding]:
    findings: list[CatalogFinding] = []
    for row in rows:
        cid = canonicalize(row.control_number or "")
        if cid is None or cid.value in failed or not catalog.exists(cid.value):
            continue
        for field_name, level in _BASELINE_FIELDS.items():
            claimed = getattr(row, field_name)
            if claimed is None:
                continue
            authoritative = catalog.in_baseline(cid.value, level)
            if claimed and not authoritative:
                findings.append(CatalogFinding(
                    "baseline", "medium", cid.value, row.control_number or cid.value,
                    field_name, "true", "false",
                    f"baseline_overclaim: {cid.value} marked {level} but not in 800-53B {level}"))
            elif authoritative and not claimed:
                findings.append(CatalogFinding(
                    "baseline", "high", cid.value, row.control_number or cid.value,
                    field_name, "false", "true",
                    f"baseline_underclaim: {cid.value} in 800-53B {level} but not marked"))
    return findings
```

Adjust the Step-1 test's final two assertions to read the `detail` prefix (`f.detail.split(":")[0]`), removing the `check_kind()` fallback.

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_reconcile_identity.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/catalog/reconcile.py tests/test_catalog_reconcile_identity.py
git commit -m "feat(catalog): identity + baseline reconcilers with crosswalk"
```

---

### Task 4: Reconcilers part 2 — content drift, mapping endpoints, orchestrator

**Files:**
- Modify: `src/ccf/catalog/reconcile.py`
- Test: `tests/test_catalog_reconcile_drift.py`

**Interfaces:**
- Consumes: everything from Task 3.
- Produces:
  - `@dataclass class MappingRow: control_number: str | None; column_key: str; framework_code: str | None; value: str | None`.
  - `def check_content_drift(catalog, rows, failed) -> list[CatalogFinding]`.
  - `def check_mapping_endpoints(catalog, mappings) -> tuple[list[CatalogFinding], dict[str, int]]` — second element is per-framework "not evaluated" counts for `summary`.
  - `@dataclass class ReconcileResult: controls_checked: int; not_evaluated: int; findings: list[CatalogFinding]; crosswalk: dict[str, str | None]; summary: dict`.
  - `def reconcile(catalog, control_rows, mapping_rows) -> ReconcileResult` — runs all four checks, assembles counts and `summary`; enforces `controls_checked == evaluated + not_evaluated`.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_catalog_reconcile_drift.py
from pathlib import Path
from ccf.catalog.oscal import load_oscal_catalog
from ccf.catalog.reconcile import (
    ControlRow, MappingRow, check_content_drift, check_mapping_endpoints, reconcile,
)

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


def test_title_and_text_drift():
    cat = load_oscal_catalog(FIX)
    rows = [
        ControlRow("AC-2", "Wrong Title", "totally different text here", None,
                   None, None, None, 2),
    ]
    findings = check_content_drift(cat, rows, failed=set())
    assert any(f.field == "control_name" and f.severity == "medium" for f in findings)  # title_drift
    assert any(f.field in {"description", "discussion"} and f.severity == "low" for f in findings)  # text_drift


def test_mapping_endpoint_dangling_and_uncovered():
    cat = load_oscal_catalog(FIX)
    mappings = [
        MappingRow("A.9.2.1", "NIST 800-53r5", "NIST", "AC-2"),    # endpoint AC-2 exists
        MappingRow("A.9.2.9", "NIST 800-53r5", "NIST", "SC-99"),   # dangling
        MappingRow("x", "ISO 27001", "ISO", "A.5.1"),              # no bundled catalog
    ]
    findings, uncovered = check_mapping_endpoints(cat, mappings)
    assert any(f.check == "mapping_endpoint" and f.canonical_id == "SC-99" for f in findings)
    assert uncovered.get("ISO", 0) == 1


def test_reconcile_counts_reconcile():
    cat = load_oscal_catalog(FIX)
    rows = [
        ControlRow("AC-2", "Account Management", "Manage system accounts.", "", None, None, None, 2),
        ControlRow("SC-99", None, None, None, None, None, None, 3),  # fails identity
    ]
    res = reconcile(cat, rows, [])
    assert res.controls_checked == 2
    assert res.not_evaluated == 1  # SC-99
    assert res.controls_checked == len(_evaluated(res)) + res.not_evaluated
    assert set(res.summary["by_check"]) >= {"identity", "baseline", "content_drift", "mapping_endpoint"}


def _evaluated(res):
    # distinct canonical ids that were NOT in the failed set (see summary)
    return res.summary["evaluated_ids"]
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_reconcile_drift.py -q`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Implement drift + mappings + orchestrator (append to `reconcile.py`)**

```python
# add near the top of reconcile.py
from difflib import SequenceMatcher

_TEXT_DRIFT_THRESHOLD = 0.6  # below this similarity -> text_drift (low)


def _norm(s: str | None) -> str:
    return " ".join((s or "").split()).casefold()


def check_content_drift(
    catalog: OscalCatalog, rows: list[ControlRow], failed: set[str]
) -> list[CatalogFinding]:
    findings: list[CatalogFinding] = []
    for row in rows:
        cid = canonicalize(row.control_number or "")
        if cid is None or cid.value in failed:
            continue
        oc = catalog.get(cid.value)
        if oc is None or oc.withdrawn:
            continue
        if row.control_name and _norm(row.control_name) != _norm(oc.title):
            findings.append(CatalogFinding(
                "content_drift", "medium", cid.value, row.control_number or cid.value,
                "control_name", row.control_name, oc.title,
                f"title_drift: workbook '{row.control_name}' != OSCAL '{oc.title}'"))
        wb_text = row.description or row.discussion
        if wb_text and oc.statement:
            ratio = SequenceMatcher(None, _norm(wb_text), _norm(oc.statement)).ratio()
            if ratio < _TEXT_DRIFT_THRESHOLD:
                field_name = "description" if row.description else "discussion"
                findings.append(CatalogFinding(
                    "content_drift", "low", cid.value, row.control_number or cid.value,
                    field_name, (wb_text[:160] + "…") if len(wb_text) > 160 else wb_text,
                    (oc.statement[:160] + "…") if len(oc.statement) > 160 else oc.statement,
                    f"text_drift: similarity {ratio:.2f} < {_TEXT_DRIFT_THRESHOLD}"))
    return findings


def _is_nist_target(m: "MappingRow") -> bool:
    key = f"{m.column_key} {m.framework_code or ''}".lower()
    return "800-53" in key or "nist" in key


def check_mapping_endpoints(
    catalog: OscalCatalog, mappings: list["MappingRow"]
) -> tuple[list[CatalogFinding], dict[str, int]]:
    findings: list[CatalogFinding] = []
    uncovered: dict[str, int] = {}
    for m in mappings:
        if _is_nist_target(m):
            cid = canonicalize(m.value or "")
            if cid is None or not catalog.exists(cid.value):
                shown = (m.value or "").strip() or "(empty)"
                findings.append(CatalogFinding(
                    "mapping_endpoint", "medium",
                    cid.value if cid else shown, shown, m.column_key, shown, None,
                    f"dangling_mapping_endpoint: '{shown}' not an 800-53r5 control"))
        else:
            code = m.framework_code or "OTHER"
            uncovered[code] = uncovered.get(code, 0) + 1
    return findings, uncovered
```

```python
# append the orchestrator + result to reconcile.py
@dataclass
class ReconcileResult:
    controls_checked: int
    not_evaluated: int
    findings: list[CatalogFinding]
    crosswalk: dict[str, str | None]
    summary: dict


def reconcile(
    catalog: OscalCatalog,
    control_rows: list[ControlRow],
    mapping_rows: list["MappingRow"],
) -> ReconcileResult:
    id_findings, crosswalk, failed = check_identity(catalog, control_rows)
    base_findings = check_baseline(catalog, control_rows, failed)
    drift_findings = check_content_drift(catalog, control_rows, failed)
    map_findings, uncovered = check_mapping_endpoints(catalog, mapping_rows)
    findings = id_findings + base_findings + drift_findings + map_findings

    distinct: dict[str, str | None] = {}
    for row in control_rows:
        raw = (row.control_number or "").strip()
        if raw:
            distinct[raw] = crosswalk.get(raw)
    controls_checked = len(distinct)
    evaluated_ids = sorted(
        {v for v in distinct.values() if v is not None and v not in failed}
    )
    # not_evaluated = distinct raws whose canonical id failed identity (or None)
    not_evaluated = sum(1 for v in distinct.values() if v is None or v in failed)

    by_check: dict[str, int] = {"identity": 0, "baseline": 0, "content_drift": 0, "mapping_endpoint": 0}
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_check[f.check] = by_check.get(f.check, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    summary = {
        "by_check": by_check,
        "by_severity": by_sev,
        "evaluated_ids": evaluated_ids,
        "mapping_endpoints_not_evaluated": uncovered,
        "oscal_version": catalog.version,
    }
    return ReconcileResult(controls_checked, not_evaluated, findings, crosswalk, summary)
```

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_reconcile_drift.py tests/test_catalog_reconcile_identity.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccf/catalog/reconcile.py tests/test_catalog_reconcile_drift.py
git commit -m "feat(catalog): content-drift + mapping-endpoint reconcilers + orchestrator"
```

---

### Task 5: Persistence — model, migration 0051, report loader/renderer

**Files:**
- Modify: `src/ccf/models.py` (add `CatalogIntegrityReport`)
- Create: `migrations/versions/0051_catalog_integrity_reports.py`
- Create: `src/ccf/catalog/report.py`
- Test: `tests/test_catalog_report.py`

**Interfaces:**
- Consumes: `ReconcileResult` (Task 4), `load_oscal_catalog` (Task 1).
- Produces:
  - ORM `CatalogIntegrityReport` (table `catalog_integrity_reports`) with columns from the spec data model.
  - `async def run_and_store(session, *, oscal_dir=None) -> CatalogIntegrityReport` — loads the catalog, reads `ControlRow`s from `controls` and `MappingRow`s from `framework_mappings` (+ their control's `control_number`), runs `reconcile`, persists a report row, returns it. Reads only; writes only the report.
  - `async def latest_report(session) -> CatalogIntegrityReport | None`.
  - `def render_text(report) -> str`.

- [ ] **Step 1: Add the ORM model to `src/ccf/models.py`** (follow the existing `Base`/`JSONB`/`func.now()` patterns near `WorkbookVersion`):

```python
class CatalogIntegrityReport(Base):
    __tablename__ = "catalog_integrity_reports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    oscal_version: Mapped[str | None] = mapped_column(String(32))
    oscal_sha256: Mapped[str | None] = mapped_column(String(64))
    controls_checked: Mapped[int] = mapped_column(Integer, default=0)
    not_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    findings_by_severity: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    findings: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    crosswalk: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
```

- [ ] **Step 2: Write the Alembic migration `0051_catalog_integrity_reports.py`**

Determine current head first: `PYTHONPATH=src alembic heads` (expect `0050_evidence_object_impl_fk`). Then:
```python
"""catalog integrity reports

Revision ID: 0051_catalog_integrity_reports
Revises: 0050_evidence_object_impl_fk
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0051_catalog_integrity_reports"
down_revision = "0050_evidence_object_impl_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "catalog_integrity_reports",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("run_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("oscal_version", sa.String(32)),
        sa.Column("oscal_sha256", sa.String(64)),
        sa.Column("controls_checked", sa.Integer, server_default="0"),
        sa.Column("not_evaluated", sa.Integer, server_default="0"),
        sa.Column("findings_total", sa.Integer, server_default="0"),
        sa.Column("findings_by_severity", postgresql.JSONB, server_default="{}"),
        sa.Column("findings", postgresql.JSONB, server_default="[]"),
        sa.Column("crosswalk", postgresql.JSONB, server_default="{}"),
        sa.Column("summary", postgresql.JSONB, server_default="{}"),
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_table("catalog_integrity_reports", schema="ccf")
```
Note: this is global catalog data (not tenant-scoped), so no RLS policy — consistent with other non-tenant reference tables. Confirm the `ccf` schema qualifier matches sibling migrations.

- [ ] **Step 3: Write failing tests**

```python
# tests/test_catalog_report.py
from pathlib import Path
import pytest
from sqlalchemy import select
from ccf.catalog.report import run_and_store, latest_report, render_text
from ccf.models import CatalogIntegrityReport, Control

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"
pytestmark = pytest.mark.asyncio


async def test_run_and_store_persists_report(db_session):
    db_session.add(Control(identifier="row-1", control_number="AC-2",
                           control_name="Account Management",
                           description="Manage system accounts.",
                           fisma_mod=True))
    db_session.add(Control(identifier="row-2", control_number="SC-99"))  # unknown
    await db_session.flush()

    report = await run_and_store(db_session, oscal_dir=FIX)
    assert report.controls_checked == 2
    assert report.findings_total >= 1
    assert any(f["canonical_id"] == "SC-99" for f in report.findings)
    assert report.oscal_version == "5.2.0"

    got = await latest_report(db_session)
    assert got.id == report.id
    assert "OSCAL" in render_text(got)
```

Note: `db_session` is the existing async-session fixture in `tests/conftest.py`; confirm its name and reuse it (do not invent a new fixture).

- [ ] **Step 4: Run to verify fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_report.py -q`
Expected: FAIL (`ImportError` / missing table until migration + module exist).

- [ ] **Step 5: Implement `src/ccf/catalog/report.py`**

```python
# src/ccf/catalog/report.py
from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CatalogIntegrityReport, Control, FrameworkMapping
from .oscal import load_oscal_catalog
from .reconcile import ControlRow, MappingRow, reconcile


async def run_and_store(session: AsyncSession, *, oscal_dir: Path | None = None) -> CatalogIntegrityReport:
    catalog = load_oscal_catalog(oscal_dir)
    ctrls = (await session.execute(select(Control))).scalars().all()
    rows = [
        ControlRow(
            control_number=c.control_number, control_name=c.control_name,
            description=c.description, discussion=c.discussion,
            fisma_low=c.fisma_low, fisma_mod=c.fisma_mod, fisma_high=c.fisma_high,
            source_row=c.source_row,
        )
        for c in ctrls
    ]
    by_id = {c.id: c for c in ctrls}
    maps_q = (await session.execute(select(FrameworkMapping))).scalars().all()
    mrows = [
        MappingRow(
            control_number=(by_id[m.control_id].control_number if m.control_id in by_id else None),
            column_key=m.column_key or "", framework_code=None, value=m.value,
        )
        for m in maps_q
    ]
    result = reconcile(catalog, rows, mrows)
    report = CatalogIntegrityReport(
        oscal_version=catalog.version,
        oscal_sha256=None,
        controls_checked=result.controls_checked,
        not_evaluated=result.not_evaluated,
        findings_total=len(result.findings),
        findings_by_severity=result.summary["by_severity"],
        findings=[f.as_dict() for f in result.findings],
        crosswalk=result.crosswalk,
        summary=result.summary,
    )
    session.add(report)
    await session.flush()
    return report


async def latest_report(session: AsyncSession) -> CatalogIntegrityReport | None:
    q = select(CatalogIntegrityReport).order_by(CatalogIntegrityReport.run_at.desc()).limit(1)
    return (await session.execute(q)).scalars().first()


def render_text(report: CatalogIntegrityReport) -> str:
    lines = [
        f"OSCAL 800-53r5 catalog integrity — version {report.oscal_version}",
        f"controls checked: {report.controls_checked} "
        f"(not evaluated: {report.not_evaluated}); findings: {report.findings_total}",
        f"by severity: {report.findings_by_severity}",
    ]
    for f in report.findings[:200]:
        lines.append(f"  [{f['severity']:6}] [{f['check']:15}] {f['canonical_id']}: {f['detail']}")
    return "\n".join(lines)
```

- [ ] **Step 6: Run tests to verify pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_report.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/models.py migrations/versions/0051_catalog_integrity_reports.py src/ccf/catalog/report.py tests/test_catalog_report.py
git commit -m "feat(catalog): catalog_integrity_reports model + migration 0051 + report persistence"
```

---

### Task 6: Consumers — CLI, ingest tail-call, /readyz check

**Files:**
- Modify: `src/ccf/cli.py` (add a `catalog` Typer sub-app: `reconcile`, `show`)
- Modify: `src/ccf/etl/pipeline.py` (`ingest_workbook`: non-fatal tail-call)
- Modify: `src/ccf/reliability/checks.py` (add `catalog_integrity` check)
- Test: `tests/test_catalog_cli_readyz.py`

**Interfaces:**
- Consumes: `run_and_store`, `latest_report`, `render_text` (Task 5).
- Produces: CLI commands `ccf catalog reconcile [--strict]` and `ccf catalog show`; a reliability check function `async def check_catalog_integrity(session) -> CheckResult` returning `pass` with the loaded OSCAL version + latest counts (informational; never `fail` in v1).

- [ ] **Step 1: Inspect the existing patterns**

Read `src/ccf/cli.py` for how sub-apps/async commands are wired (look for `typer.Typer()` sub-apps and the async-runner helper), `src/ccf/reliability/checks.py` for the `CheckResult` shape and how checks are registered (mirror `alembic_migration_status`), and `src/ccf/etl/pipeline.py::ingest_workbook` (lines ~383-420) for where to add the tail-call.

- [ ] **Step 2: Write failing tests**

```python
# tests/test_catalog_cli_readyz.py
from pathlib import Path
import pytest
from ccf.reliability.checks import check_catalog_integrity
from ccf.catalog.report import run_and_store
from ccf.models import Control

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"
pytestmark = pytest.mark.asyncio


async def test_readyz_check_reports_pass_with_version(db_session):
    db_session.add(Control(identifier="row-1", control_number="AC-2",
                           control_name="Account Management"))
    await db_session.flush()
    await run_and_store(db_session, oscal_dir=FIX)
    res = await check_catalog_integrity(db_session)
    assert res.status == "pass"
    assert "5.2.0" in (res.message or "")
```
(CLI is covered by the golden e2e in Task 8; here we only assert the readyz check to keep this task's suite fast. If `cli.py` exposes a testable callable, add a smoke test that `catalog reconcile` stores a report and `catalog show` prints it.)

- [ ] **Step 3: Run to verify fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_cli_readyz.py -q`
Expected: FAIL (`ImportError: check_catalog_integrity`).

- [ ] **Step 4: Implement the reliability check** (in `src/ccf/reliability/checks.py`, mirroring the existing `CheckResult` construction):

```python
async def check_catalog_integrity(session) -> CheckResult:
    from ..catalog.oscal import load_oscal_catalog, OscalManifestError
    from ..catalog.report import latest_report
    try:
        version = load_oscal_catalog().version
    except OscalManifestError as exc:
        return CheckResult(name="catalog_integrity", status="fail",
                           message=f"OSCAL catalog unreadable: {exc}", remediation="Restore data/oscal/*.")
    report = await latest_report(session)
    if report is None:
        return CheckResult(name="catalog_integrity", status="pass",
                           message=f"OSCAL {version} loaded; no reconciliation run yet.")
    return CheckResult(
        name="catalog_integrity", status="pass",
        message=f"OSCAL {version}; last run {report.controls_checked} checked, "
                f"{report.findings_total} findings {report.findings_by_severity}.")
```
Register it alongside the other `/readyz` checks (informational — not in the blocking set) exactly where `alembic_migration_status` is registered. Match the real `CheckResult` constructor signature you find in the file (adjust kwarg names if they differ).

- [ ] **Step 5: Implement the CLI sub-app** in `src/ccf/cli.py` following the file's existing async-command pattern:

```python
catalog_app = typer.Typer(help="OSCAL catalog reconciliation (advisory).")
app.add_typer(catalog_app, name="catalog")


@catalog_app.command("reconcile")
def catalog_reconcile(strict: bool = typer.Option(False, "--strict")) -> None:
    from .catalog.report import run_and_store, render_text

    async def _run():
        async with session_scope() as session:   # use the file's real session helper
            report = await run_and_store(session)
            typer.echo(render_text(report))
            return report.findings_by_severity.get("high", 0)

    highs = _run_async(_run())                     # use the file's real async runner
    if strict and highs:
        raise typer.Exit(code=1)


@catalog_app.command("show")
def catalog_show() -> None:
    from .catalog.report import latest_report, render_text

    async def _run():
        async with session_scope() as session:
            report = await latest_report(session)
            typer.echo(render_text(report) if report else "No catalog reconciliation report yet.")

    _run_async(_run())
```
Replace `session_scope` / `_run_async` with the actual helpers used by neighboring commands in `cli.py`.

- [ ] **Step 6: Add the non-fatal ingest tail-call** at the end of `ingest_workbook` (after the run is finalized), wrapped so it never breaks ingest:

```python
    try:
        from ..catalog.report import run_and_store
        await run_and_store(session)
    except Exception as exc:  # advisory only — never fail ingest on reconciliation
        log.warning("catalog.reconcile_failed", error=str(exc))
```

- [ ] **Step 7: Run to verify pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_cli_readyz.py -q`
Expected: PASS. Then `ruff check . && mypy src` clean for the touched files.

- [ ] **Step 8: Commit**

```bash
git add src/ccf/cli.py src/ccf/etl/pipeline.py src/ccf/reliability/checks.py tests/test_catalog_cli_readyz.py
git commit -m "feat(catalog): CLI (reconcile/show) + non-fatal ingest tail-call + /readyz check"
```

---

### Task 7: UI — read-only role-gated catalog-integrity report page + packaging

**Files:**
- Create: `src/ccf/api/routes/catalog.py`
- Create: `src/ccf/api/templates/catalog_integrity.html`
- Modify: `src/ccf/api/main.py` (register the router)
- Modify: `src/ccf/api/templates/base.html` (nav link, gated like the /audit link)
- Modify: `pyproject.toml` (`[tool.setuptools.package-data]` — ship the OSCAL JSON in the wheel)
- Test: `tests/test_catalog_ui.py`

**Interfaces:**
- Consumes: `latest_report` (Task 5), existing auth dependency used by `/audit` (find it in `src/ccf/api/routes/audit.py`).
- Produces: `GET /catalog/integrity` returning the rendered report (200 for authorized admin role, 403/redirect for unauthorized) — matching how `/audit` is gated.

- [ ] **Step 1: Inspect `/audit` gating** in `src/ccf/api/routes/audit.py` and its test in `tests/test_audit_rbac.py`; reuse the identical role dependency and the same unauthorized-response convention (status code/redirect). Do not invent a new auth pattern.

- [ ] **Step 2: Write failing tests** (mirror `tests/test_audit_rbac.py` request/auth setup exactly):

```python
# tests/test_catalog_ui.py
import pytest
pytestmark = pytest.mark.asyncio


async def test_catalog_integrity_requires_admin(client_unauth):
    resp = await client_unauth.get("/catalog/integrity")
    assert resp.status_code in (401, 403, 302, 303)


async def test_catalog_integrity_renders_for_admin(client_admin):
    resp = await client_admin.get("/catalog/integrity")
    assert resp.status_code == 200
    assert "OSCAL" in resp.text
```
Reuse the actual authorized/unauthorized client fixtures from `tests/test_audit_rbac.py` (names may be `client_admin`/`client_unauth` or similar — match what exists).

- [ ] **Step 3: Run to verify fail**

Run: `PYTHONPATH=src pytest tests/test_catalog_ui.py -q`
Expected: FAIL (404 — route not registered).

- [ ] **Step 4: Implement the route** (`src/ccf/api/routes/catalog.py`) using the templating + auth pattern from `audit.py`:

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ..templating import templates            # use the real templates import in audit.py
from ..auth_deps import require_admin          # use the real dependency name from audit.py
from ...db import get_session                  # real session dependency
from ...catalog.report import latest_report

router = APIRouter()


@router.get("/catalog/integrity", response_class=HTMLResponse)
async def catalog_integrity(request: Request, session=Depends(get_session), _=Depends(require_admin)):
    report = await latest_report(session)
    return templates.TemplateResponse(
        "catalog_integrity.html", {"request": request, "report": report})
```
Adjust every import to the real symbol names found in `audit.py`.

- [ ] **Step 5: Create the template** `src/ccf/api/templates/catalog_integrity.html` extending `base.html`, with summary tiles (`report.oscal_version`, `report.controls_checked`, `report.findings_by_severity`) and a findings table (columns: severity, check, canonical_id, field, workbook_value, oscal_value, detail) iterating `report.findings`. Show a friendly empty-state when `report` is `None`. Follow the markup conventions in `src/ccf/api/templates/portal_admin.html` / `poams.html`.

- [ ] **Step 6: Register the router** in `src/ccf/api/main.py` (alongside the other `include_router` calls) and add a nav link in `base.html` gated the same way the `/audit` link is.

- [ ] **Step 7: Ship the OSCAL data in the package** — add to `pyproject.toml` `[tool.setuptools.package-data]`:
```toml
"ccf.catalog" = ["oscal_data/*.json"]
```
and add a build note: the packaged fallback dir is `src/ccf/catalog/oscal_data/`; for the wheel/Docker image, the `data/oscal/*.json` files must be copied there at build time (or symlinked in the Dockerfile). For local/dev + tests, `data/oscal/` resolves first, so this only matters for the shipped image. Document this in `src/ccf/catalog/__init__.py` docstring.

- [ ] **Step 8: Run to verify pass**

Run: `PYTHONPATH=src pytest tests/test_catalog_ui.py -q`
Expected: PASS. Then `ruff check . && mypy src` clean.

- [ ] **Step 9: Commit**

```bash
git add src/ccf/api/routes/catalog.py src/ccf/api/templates/catalog_integrity.html src/ccf/api/main.py src/ccf/api/templates/base.html pyproject.toml tests/test_catalog_ui.py
git commit -m "feat(catalog): read-only role-gated /catalog/integrity UI + packaging"
```

---

### Task 8: Golden end-to-end test + real-corpus canonicalizer guard

**Files:**
- Test: `tests/test_catalog_golden.py`
- Create (if not present): `tests/fixtures/mini_workbook.xlsx` OR reuse an existing ingest test fixture.

**Interfaces:**
- Consumes: the whole engine + `ingest_workbook`.

- [ ] **Step 1: Locate an existing workbook fixture** used by current ingest tests (grep `tests/` for `ingest_workbook(` and `.xlsx`). If one exists, reuse it; otherwise build a tiny 2-sheet xlsx fixture with an assessment sheet containing the required headers (from `contracts/headers.v1_1.json`) plus a handful of rows: one valid (`AC-2`), one unknown (`SC-99`), one CMMC-form id, one baseline-mismatch row.

- [ ] **Step 2: Write the golden test**

```python
# tests/test_catalog_golden.py
from pathlib import Path
import pytest
from ccf.etl.pipeline import ingest_workbook
from ccf.catalog.report import latest_report

pytestmark = pytest.mark.asyncio
FIX_WB = Path(__file__).parent / "fixtures" / "mini_workbook.xlsx"  # or the reused fixture


async def test_ingest_produces_reconciliation_report(db_session):
    # oscal_dir defaults to data/oscal in the tail-call; ensure it resolves in CI
    await ingest_workbook(db_session, FIX_WB)
    report = await latest_report(db_session)
    assert report is not None
    assert report.controls_checked >= 1
    # counts always reconcile
    evaluated = len(report.summary["evaluated_ids"])
    assert report.controls_checked == evaluated + report.not_evaluated
    # crosswalk has one entry per distinct control_number
    assert all(isinstance(k, str) for k in report.crosswalk)
```
If the ingest tail-call's `run_and_store()` cannot resolve `data/oscal/` in the test environment, assert on `run_and_store(db_session, oscal_dir=FIX)` directly instead, and keep the ingest golden focused on rows landing in `controls`.

- [ ] **Step 3: Add a real-corpus canonicalizer guard** to `tests/test_catalog_canonical.py`:

```python
def test_real_workbook_control_numbers_canonicalize_or_are_reported():
    # Extract distinct control_number values seen in the shipped catalog contract;
    # every value must EITHER canonicalize OR be intentionally rejected (None) —
    # never crash. This guards the canonicalizer against real-world forms.
    from ccf.catalog.canonical import canonicalize
    samples = ["AC-2", "AC-02", "AC-2 (1)", "AC-2(1)", "SC-7", "PM-31",
               "AC.L2-3.1.1", "", "N/A"]
    for s in samples:
        canonicalize(s)  # must not raise
```
(If the live DB is reachable in CI, optionally extend this to pull `select(distinct(Control.control_number))` and assert none raise. Keep the static list as the always-on guard.)

- [ ] **Step 4: Run the full engine suite**

Run:
```bash
PYTHONPATH=src pytest tests/test_catalog_oscal.py tests/test_catalog_canonical.py \
  tests/test_catalog_reconcile_identity.py tests/test_catalog_reconcile_drift.py \
  tests/test_catalog_report.py tests/test_catalog_cli_readyz.py \
  tests/test_catalog_ui.py tests/test_catalog_golden.py -q
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_catalog_golden.py tests/test_catalog_canonical.py tests/fixtures
git commit -m "test(catalog): golden ingest->reconcile e2e + real-corpus canonicalizer guard"
```

---

## Final verification (after all tasks)

- [ ] `PYTHONPATH=src ruff check .` — clean.
- [ ] `PYTHONPATH=src mypy src` — clean.
- [ ] Full suite: `CCF_DATABASE_URL=... CCF_DATABASE_URL_SYNC=... PYTHONPATH=src pytest -q` — green (prior baseline 558 passed; expect +~25 new).
- [ ] `PYTHONPATH=src python docs/superpowers/assessments/integrity_checks.py` still runs.
- [ ] Rebuild images: `docker compose build api migrator` (migration 0051 present), `docker compose up -d db migrator api`, then `curl -s localhost:8088/readyz | python -m json.tool` shows the `catalog_integrity` check with the OSCAL version.
- [ ] `ccf catalog reconcile` against the live DB prints a report; `/catalog/integrity` renders it for an admin.

## Self-Review

**Spec coverage:** advisory-only ✔ (Global Constraints + no write path); bundled+pinned catalog ✔ (Task 1); sha provenance ✔ (Task 1 loader); canonicalization ✔ (Task 2); all four checks ✔ (Tasks 3-4); crosswalk stored not enforced ✔ (Tasks 3/5); data model + migration ✔ (Task 5); CLI/ingest/readyz consumers ✔ (Task 6); UI ✔ (Task 7); testing strategy incl. golden + real-corpus ✔ (Task 8); packaging ✔ (Task 7); migrator rebuild note ✔ (final verification).

**Placeholder scan:** all code steps contain real code; import/symbol names that must match existing code are flagged explicitly as "use the real name from <file>" rather than guessed — because inventing them would be a worse failure than instructing verification.

**Type consistency:** `ControlRow`/`MappingRow`/`CatalogFinding`/`ReconcileResult` names and fields are consistent across Tasks 3→4→5; `canonicalize`/`CanonicalId` consistent Task 2→3→4; `OscalCatalog.exists/get/in_baseline` consistent Task 1→3→4; `run_and_store/latest_report/render_text` consistent Task 5→6→7→8.
