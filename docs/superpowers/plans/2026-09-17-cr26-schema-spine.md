# CR26 Schema Spine Implementation Plan (P9a-ii, part 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pin FedRAMP's eleven published CR26 JSON schemas as authority-published reference data, and make offline validation against them work — so every later CR26 deliverable is a projection this module validates, and none is a shape we invented.

**Architecture:** Mirror `src/ccf/oscal/` exactly. Vendored schema files plus a sha256 manifest under `src/ccf/cr26/schemas/`; a `cr26/validation.py` in the shape of `oscal/validation.py`; and one `generic` `CatalogSource` row per schema so the existing ETag/sha256 poller detects upstream drift without adopting it. No generators, no rule table, no migration.

**Tech Stack:** Python 3.12, `jsonschema>=4.20,<5` (already a dependency, 4.26.0 installed) and its `referencing` companion, pytest. **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-17-cr26-schema-spine-design.md`

## Global Constraints

- **Concord validates against the published schema and never invents the shape of a FedRAMP deliverable.** Do not hand-edit a vendored schema, ever — not to fix a validation failure, not to "correct" an upstream mistake. A schema that seems wrong is a finding to report, not a file to edit.
- **All eleven schemas**, ruleset revision **`2026-06-24`**, fetched from `https://fedramp.gov/schemas/fedramp-<name>-schema-2026-06-24.json`.
- **Two-level versioning.** The `2026-06-24` in every filename is the *ruleset* revision; each schema separately carries its own `$schemaVersion` (semver), and the spread is live — `certification-package-overview` is 0.1.4 while `assessor-information` is 1.0.1. The manifest records the ruleset date once and `$schemaVersion` per file.
- **`kind="generic"`, `auto_ingest=False`.** Content-hash only: nothing parses a schema into tables. Drift is detected and surfaced for a human, never adopted silently — the same call `etl/sources.py` already records for baseline profiles ("a profile is not a catalog"; a schema is not one either).
- **Offline validation is non-negotiable.** Verified behaviour of `jsonschema` 4.26.0: an unresolvable `$ref` raises `Unresolvable`; it does **not** fetch. Ten of the eleven schemas carry absolute `$ref`s (1–3 each), every one targeting `common-definitions`. Validation must resolve entirely through a `referencing.Registry` built from the vendored files.
- **`$ref` resolution is LAZY, and that is the trap this plan exists to avoid.** A reference resolves only when validation descends into the property carrying it, so a document that fails an earlier `required` check never reaches it. An empty document against the CPO schema returns 12 ordinary errors and never raises. **A "minimal invalid document" fixture passes with no registry at all.** Every reference-resolution test must use a document complete enough to actually reach a `$ref`.
- **Do not copy `_translate_ecma_pattern` from `oscal/validation.py`.** It exists because OSCAL uses ECMA regex constructs Python's `re` rejects. The eleven CR26 schemas contain four patterns (`^CVE-[0-9]{4}-[0-9]{4,}$`, `^\d{6}$`, `^[0-9]{3}-[0-9]{3}-[0-9]{4}$`, and an image-extension pattern), all plain and Python-compatible.
- **Format checking: pass a `FormatChecker`, add no dependency, pin the live set in a test.** Measured on this environment: `date` and `email` are enforced; `date-time` and `uri` are **not** (their optional validators `rfc3339-validator` and `rfc3986-validator` are absent), and a malformed value silently passes. The test records which formats are actually live so the gap is a fact rather than an assumption.
- **Every new test must be able to fail.** This programme has shipped at least seven that could not. Where a task says to prove a guard bites, break it, watch the failure, and revert.
- `ruff check .` and `mypy src` clean. mypy runs with `strict = true`.
- Current head is `0078_cr26_certification`. **No migration is expected** — Task 3 confirms that rather than assuming it. If one turns out to be needed, stop and report.
- Test command — the default `pytest` hits the WRONG database (`.env` points at port 5432, another project's container):

```
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
.venv/bin/python3 -m pytest -q
```

  Use `.venv/bin/` binaries only — the system `python3` is 3.9 and lacks the project. **Never let a pytest call background:** a Bash call past 120s is auto-backgrounded and its completion notification never arrives, which stalled an implementer on the previous plan. Pass an explicit `timeout` (600000 focused, 900000 full suite — the full run takes 110–190s). One pytest session at a time.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/ccf/cr26/__init__.py` | package, re-exporting the validation surface | 2 |
| `src/ccf/cr26/schemas/*.json` | the eleven vendored schemas, byte-for-byte upstream | 1 |
| `src/ccf/cr26/schemas/MANIFEST.json` | ruleset revision, source URL, retrieval date, per-file sha256 + `$schemaVersion` | 1 |
| `tests/test_cr26_schema_manifest.py` | the vendored set matches the manifest and the manifest matches the files | 1 |
| `src/ccf/cr26/validation.py` | kinds, offline registry, `validate_document` | 2 |
| `tests/test_cr26_validation.py` | resolution, offline guarantee, format-checker live set | 2 |
| `src/ccf/etl/sources.py` | eleven `DEFAULT_SOURCES` rows | 3 |
| `tests/test_cr26_sources.py` | the rows seed, and carry the right kind/authority | 3 |

`cr26/` is a sibling of `oscal/` rather than a subpackage of it: they validate different specifications, share no code, and the CR26 module is deliberately simpler (no ECMA pattern translation, no structural fallback — see Task 2).

---

### Task 1: Vendor the eleven schemas

**Files:**
- Create: `src/ccf/cr26/__init__.py` (empty for now; Task 2 fills it), `src/ccf/cr26/schemas/` (11 `.json` + `MANIFEST.json`)
- Test: `tests/test_cr26_schema_manifest.py`

**Interfaces:**
- Produces: the vendored directory and `MANIFEST.json`, whose shape Task 2 reads.

**MANIFEST.json shape** — modelled on `src/ccf/oscal/schemas/MANIFEST.json`, which you should open first:

```json
{
  "ruleset_version": "2026-06-24",
  "source_url": "https://github.com/FedRAMP/schemas",
  "retrieved_at": "2026-09-17",
  "files": {
    "fedramp-common-definitions-schema-2026-06-24.json": {
      "sha256": "<64 hex>",
      "schema_version": "0.3.0",
      "title": "FedRAMP Common Definitions",
      "id": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json"
    }
  }
}
```

Note this differs from the OSCAL manifest, whose `files` maps name → sha256 string. CR26 versions each schema independently, so the value is an object. Say so in a comment or the module docstring.

- [ ] **Step 1: Fetch the eleven schemas**

Keep upstream bytes exactly — do not reformat, re-indent, or re-serialize. The sha256 must be of what FedRAMP served.

```bash
cd /Users/kevinwhite/CrossCtlFrameworks
mkdir -p src/ccf/cr26/schemas
for n in common-definitions certification-package-overview security-decision-record \
         ongoing-certification-report incident-report significant-change-notifications \
         vulnerability-detail-report accepted-vulnerability-info historical-ver-activity \
         advisor-information assessor-information; do
  f="fedramp-${n}-schema-2026-06-24.json"
  curl -sSL --fail -o "src/ccf/cr26/schemas/$f" "https://fedramp.gov/schemas/$f" \
    && echo "ok $f" || echo "FAILED $f"
done
ls -1 src/ccf/cr26/schemas/ | wc -l   # expect 11
```

Cross-check the sizes and `$schemaVersion` against the table in **§2 of the spec** before continuing. If any file's size or version differs from the spec's table, **stop and report** — upstream has published a new ruleset revision and that is a decision, not a detail.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_cr26_schema_manifest.py
"""The vendored CR26 schemas match their manifest, and the manifest matches them.

FedRAMP publishes the CR26 deliverables as JSON schemas at stable URLs. Concord
vendors them so validation works with no network and no configuration, and pins
each by sha256 so a silent substitution is impossible. This file is the pin.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "src" / "ccf" / "cr26" / "schemas"
MANIFEST = SCHEMA_DIR / "MANIFEST.json"
RULESET_VERSION = "2026-06-24"
EXPECTED_COUNT = 11


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_the_manifest_records_the_ruleset_revision() -> None:
    """The date in every filename is the RULESET revision, not a schema version."""
    assert _manifest()["ruleset_version"] == RULESET_VERSION


def test_all_eleven_schemas_are_vendored() -> None:
    """Pinning a subset guarantees a second spine job before the 2026-12-07
    VDR/VER deadline -- see the spec's section 2."""
    on_disk = sorted(p.name for p in SCHEMA_DIR.glob("*.json") if p.name != "MANIFEST.json")
    assert len(on_disk) == EXPECTED_COUNT, on_disk
    assert sorted(_manifest()["files"]) == on_disk


def test_every_vendored_file_matches_its_recorded_hash() -> None:
    """The pin itself. A substituted or hand-edited schema fails here."""
    mismatches = []
    for name, entry in _manifest()["files"].items():
        digest = hashlib.sha256((SCHEMA_DIR / name).read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            mismatches.append(f"{name}: manifest {entry['sha256'][:12]} != file {digest[:12]}")
    assert mismatches == []


def test_every_entry_records_the_schema_s_own_version_and_id() -> None:
    """Two-level versioning: one ruleset date, a separate semver per schema.

    The spread is live -- certification-package-overview is 0.1.4 while
    assessor-information is 1.0.1 -- so a single version field cannot describe
    this set.
    """
    wrong = []
    for name, entry in _manifest()["files"].items():
        doc = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        if entry.get("schema_version") != doc.get("$schemaVersion"):
            wrong.append(f"{name}: manifest {entry.get('schema_version')!r} != file {doc.get('$schemaVersion')!r}")
        if entry.get("id") != doc.get("$id"):
            wrong.append(f"{name}: manifest id != file $id")
    assert wrong == []


def test_the_schema_versions_are_not_all_identical() -> None:
    """Guards the manifest generator against writing one version everywhere --
    which would look right and silently defeat the per-schema pin."""
    versions = {e["schema_version"] for e in _manifest()["files"].values()}
    assert len(versions) > 1, versions


def test_each_filename_carries_the_ruleset_revision() -> None:
    for name in _manifest()["files"]:
        assert name.endswith(f"-schema-{RULESET_VERSION}.json"), name
```

- [ ] **Step 3: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_schema_manifest.py -q` with `timeout: 600000`
Expected: every test errors — `FileNotFoundError` for `MANIFEST.json`, which does not exist yet.

- [ ] **Step 4: Generate the manifest**

Write it with a script rather than by hand — eleven 64-character digests typed by hand is a defect waiting to happen. Run this once and let it write the file:

```bash
.venv/bin/python3 - <<'PY'
import hashlib, json, pathlib, datetime
d = pathlib.Path("src/ccf/cr26/schemas")
files = {}
for p in sorted(d.glob("*.json")):
    if p.name == "MANIFEST.json":
        continue
    raw = p.read_bytes()
    doc = json.loads(raw)
    files[p.name] = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema_version": doc.get("$schemaVersion"),
        "title": doc.get("title"),
        "id": doc.get("$id"),
    }
manifest = {
    "ruleset_version": "2026-06-24",
    "source_url": "https://github.com/FedRAMP/schemas",
    "retrieved_at": datetime.date.today().isoformat(),
    "files": files,
}
(d / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(files)} entries")
PY
```

Also create an empty `src/ccf/cr26/__init__.py` so the package imports.

- [ ] **Step 5: Run to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_schema_manifest.py -q` — expected: 6 passed.

- [ ] **Step 6: Prove the pin bites**

Append a single space to one vendored schema, re-run, and confirm `test_every_vendored_file_matches_its_recorded_hash` FAILS naming that file. **Then restore the file with `git checkout --` or by re-fetching it, and re-run to confirm green.** Paste both outputs in your report. A pin nobody has watched fail is not a pin.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/cr26 tests/test_cr26_schema_manifest.py
git commit -m "feat(cr26): vendor FedRAMP's eleven CR26 schemas, pinned by sha256

FedRAMP publishes the CR26 deliverables as JSON schemas at stable URLs --
eleven of them, ruleset revision 2026-06-24, 45,495 bytes in total. Vendoring
them makes validation work with no network and no configuration, and the
sha256 manifest makes a silent substitution impossible.

All eleven rather than the three with a near-term consumer: the deadline that
binds first is VDR/VER on 2026-12-07, ahead of CPO/SDR maintenance on
2027-01-01, so a partial pin guarantees a second spine job before December.

The manifest carries two levels of version because FedRAMP uses two: the date
in every filename is the ruleset revision, while each schema separately
carries a semver $schemaVersion, and the spread is already live.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Offline validation

The heart of the spine, and where the trap lives.

**Files:**
- Create: `src/ccf/cr26/validation.py`; fill `src/ccf/cr26/__init__.py`
- Test: `tests/test_cr26_validation.py`

**Interfaces:**
- Consumes: Task 1's `MANIFEST.json` and vendored files.
- Produces:
  - `CR26_KINDS: dict[str, tuple[str, str]]` — kind → (schema filename, rule id)
  - `@dataclass ValidationReport` with `kind: str`, `mode: str`, `ok: bool`, `errors: list[str]`, `warnings: list[str]`, and `as_dict()` — the same shape as `oscal.validation.ValidationReport`, so a caller that handles one handles the other
  - `def schema_path(kind: str) -> Path | None`
  - `def validate_document(doc: Any, kind: str) -> ValidationReport`
  - `def enforced_formats() -> tuple[str, ...]` — which `format` values are actually checked in this environment

**Deliberately unlike `oscal/validation.py` in three ways**, each for a reason; do not restore the parallel:

1. **No `detect_kind`.** OSCAL documents self-identify by a root key (`system-security-plan`, …). CR26 documents do not — an SDR's root keys are `certificationPackageOverviewUri` and `fedRampRequirements`, which name no document type. `kind` is therefore a required argument, not inferred. Guessing would be a silent mis-validation.
2. **No structural fallback.** `oscal/validation.py` degrades to hand-written required-children checks when the official schema is missing. Here the schema is vendored in-package and cannot be missing; a fallback would be unreachable code asserting a shape we invented, which is exactly what this module exists to prevent. If `jsonschema` is unavailable, return `mode="none"`, `ok=False` and say so.
3. **No `_translate_ecma_pattern`.** See Global Constraints.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cr26_validation.py
"""CR26 document validation: resolves offline, or not at all.

The load-bearing property is that $ref resolution never touches the network.
Ten of the eleven schemas reference common-definitions by absolute URL, and
jsonschema 4.26 raises Unresolvable rather than fetching -- so without a
registry built from the vendored files, every complete document fails.

The trap this file is shaped around: resolution is LAZY. A document that fails
an earlier `required` check never descends into the $ref, so a "minimal invalid
document" fixture passes with no registry at all. Every test below that claims
something about reference resolution uses a document complete enough to reach
one.
"""

from __future__ import annotations

import socket

import pytest

from ccf.cr26.validation import (
    CR26_KINDS,
    ValidationReport,
    enforced_formats,
    schema_path,
    validate_document,
)


def _valid_sdr() -> dict:
    """An SDR complete enough that validation descends into the $ref'd property.

    certificationPackageOverviewUri is $ref'd to common-definitions, so this
    document -- unlike an empty one -- cannot validate without the registry.
    """
    return {
        "certificationPackageOverviewUri": "https://example.gov/cpo.json",
        "fedRampRequirements": [
            {"frrID": "SDR-CSO-FRR", "frrImplementation": "Implemented as described."}
        ],
    }


class _NoNetwork(socket.socket):
    def __init__(self, *a: object, **k: object) -> None:
        raise AssertionError("validation attempted a network connection")


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block sockets outright. 'It worked on my machine' is not the claim."""
    monkeypatch.setattr(socket, "socket", _NoNetwork)


def test_every_kind_resolves_to_a_vendored_schema() -> None:
    missing = [k for k in CR26_KINDS if schema_path(k) is None]
    assert missing == []


def test_all_eleven_schemas_have_a_kind() -> None:
    assert len(CR26_KINDS) == 11


def test_a_valid_document_validates_with_no_network(no_network: None) -> None:
    """The whole point of vendoring. Sockets are blocked; this must still pass."""
    report = validate_document(_valid_sdr(), "sdr")
    assert report.ok is True, report.errors
    assert report.mode == "official"


def test_the_ref_is_actually_resolved_not_skipped(no_network: None) -> None:
    """Prove the $ref is exercised: a value that violates the $ref'd definition
    must be REJECTED. If resolution were silently skipped this would pass."""
    doc = _valid_sdr()
    doc["certificationPackageOverviewUri"] = 12345  # not a string/uri
    report = validate_document(doc, "sdr")
    assert report.ok is False
    assert any("certificationPackageOverviewUri" in e for e in report.errors), report.errors


def test_a_missing_required_property_is_reported(no_network: None) -> None:
    report = validate_document({"fedRampRequirements": []}, "sdr")
    assert report.ok is False
    assert any("certificationPackageOverviewUri" in e for e in report.errors), report.errors


def test_a_non_object_document_is_reported_not_raised() -> None:
    report = validate_document(["not", "an", "object"], "sdr")
    assert isinstance(report, ValidationReport)
    assert report.ok is False


def test_an_unknown_kind_is_reported_not_raised() -> None:
    report = validate_document({}, "no-such-kind")
    assert report.ok is False
    assert report.mode == "none"


def test_the_cpo_schema_also_validates_offline(no_network: None) -> None:
    """Ten of eleven schemas carry absolute $refs; SDR must not be the only
    one the registry covers."""
    report = validate_document({}, "cpo")
    assert report.ok is False  # empty document, but it must not RAISE
    assert report.mode == "official"


def test_the_enforced_format_set_is_what_this_environment_actually_checks() -> None:
    """jsonschema registers a format checker only when that format's optional
    validator is installed. Here date and email are enforced; date-time and uri
    are NOT -- rfc3339-validator and rfc3986-validator are absent, and a
    malformed value silently passes.

    Pinning the live set makes the gap a recorded fact. Without this, a future
    test written to prove a malformed date-time is caught could never pass, and
    one written to prove a document validates would pass vacuously.
    """
    enforced = enforced_formats()
    assert "date" in enforced
    assert "email" in enforced
    assert "date-time" not in enforced
    assert "uri" not in enforced


def test_an_unenforced_format_lets_a_malformed_value_through(no_network: None) -> None:
    """The honest consequence of the gap above, asserted rather than implied.

    metadata.lastUpdated is declared format: date-time, which this environment
    does NOT enforce, so a plainly malformed value validates. When someone
    later installs rfc3339-validator this test flips -- and it should, loudly,
    because that is a real change in what the spine guarantees.
    """
    doc = _valid_sdr()
    doc["metadata"] = {"version": "1", "lastUpdated": "not-a-date", "updateSource": "x"}
    report = validate_document(doc, "sdr")
    assert report.ok is True, report.errors
```

Verified facts these tests rely on, so you need not re-derive them: `metadata.lastUpdated` is declared `format: date-time` (unenforced here), and `certificationPackageOverviewUri` resolves through the `$ref` to `{"type": "string", "format": "uri"}` — which is why `test_the_ref_is_actually_resolved_not_skipped` discriminates on **type** with an integer rather than on the `uri` format, since `uri` is not enforced and a malformed string would pass.

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_validation.py -q` with `timeout: 600000`
Expected: collection error — `ModuleNotFoundError: No module named 'ccf.cr26.validation'`.

- [ ] **Step 3: Implement**

```python
# src/ccf/cr26/validation.py
"""Validate a document against a vendored FedRAMP CR26 schema.

FedRAMP publishes the CR26 deliverables as JSON schemas. Concord validates
against those schemas and never invents the shape of a FedRAMP artefact -- so
this module resolves every reference through the vendored copies under
``schemas/`` and never reaches the network.

That is not a preference. Ten of the eleven schemas reference
``common-definitions`` by absolute URL, and ``jsonschema`` 4.26 raises
``Unresolvable`` rather than fetching, so without a registry built from the
vendored files every *complete* document fails. Note "complete": ``$ref``
resolution is lazy, so a document that fails an earlier ``required`` check
never descends into the reference and appears to validate fine. That asymmetry
is why the tests here use documents complete enough to reach a ``$ref``.

Unlike :mod:`ccf.oscal.validation` this module has no ``detect_kind`` (CR26
documents do not self-identify by root key), no structural fallback (the schema
is vendored in-package and cannot be missing; a fallback would assert a shape
we invented) and no ECMA pattern translation (CR26's four patterns are all
Python-compatible).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

_SCHEMA_DIR = Path(__file__).with_name("schemas")
_MANIFEST = _SCHEMA_DIR / "MANIFEST.json"

#: Concord document kind -> (vendored filename, FedRAMP rule id).
#:
#: ``kind`` is required rather than inferred: an SDR's root keys are
#: ``certificationPackageOverviewUri`` and ``fedRampRequirements``, which name
#: no document type, so guessing would be a silent mis-validation.
CR26_KINDS: dict[str, tuple[str, str]] = {
    "common": ("fedramp-common-definitions-schema-2026-06-24.json", "-"),
    "cpo": ("fedramp-certification-package-overview-schema-2026-06-24.json", "FRC-CSO-PKG"),
    "sdr": ("fedramp-security-decision-record-schema-2026-06-24.json", "SDR-CSO-FRR"),
    "ocr": ("fedramp-ongoing-certification-report-schema-2026-06-24.json", "CCM-OCR-AVL"),
    "incident": ("fedramp-incident-report-schema-2026-06-24.json", "IEC-CSO-IIR"),
    "scn": ("fedramp-significant-change-notifications-schema-2026-06-24.json", "SCN-CSO-INF"),
    "vdr": ("fedramp-vulnerability-detail-report-schema-2026-06-24.json", "VER-RPT-VDT"),
    "avi": ("fedramp-accepted-vulnerability-info-schema-2026-06-24.json", "VER-RPT-AVI"),
    "ver_history": ("fedramp-historical-ver-activity-schema-2026-06-24.json", "-"),
    "advisor": ("fedramp-advisor-information-schema-2026-06-24.json", "MKT-CAS-WEB"),
    "assessor": ("fedramp-assessor-information-schema-2026-06-24.json", "MKT-IAS-WEB"),
}


@dataclass
class ValidationReport:
    """Outcome of validating one CR26 document.

    Same shape as :class:`ccf.oscal.validation.ValidationReport`, so a caller
    that handles one handles the other.
    """

    kind: str
    mode: str  # official|none
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "mode": self.mode,
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def schema_path(kind: str) -> Path | None:
    """Path to the vendored schema for ``kind``, or ``None`` if unknown."""
    entry = CR26_KINDS.get(kind)
    if entry is None:
        return None
    candidate = _SCHEMA_DIR / entry[0]
    return candidate if candidate.is_file() else None


@lru_cache(maxsize=1)
def _registry() -> Any:
    """Every vendored schema, keyed by its own ``$id``.

    This is what keeps validation offline: references resolve here or not at
    all. Built once -- the files cannot change under a running process.
    """
    from referencing import Registry, Resource  # noqa: PLC0415

    resources = []
    for name, _rule in CR26_KINDS.values():
        path = _SCHEMA_DIR / name
        if not path.is_file():
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = doc.get("$id")
        if uri:
            resources.append((uri, Resource.from_contents(doc)))
    return Registry().with_resources(resources)


@lru_cache(maxsize=1)
def _format_checker() -> Any:
    from jsonschema import FormatChecker  # noqa: PLC0415

    return FormatChecker()


def enforced_formats() -> tuple[str, ...]:
    """Which ``format`` values this environment actually checks.

    ``jsonschema`` registers a checker for a format only when that format's
    optional validator library is installed, so the answer is environmental,
    not a property of the schemas. Reported rather than assumed: a caller that
    needs ``uri`` or ``date-time`` enforced must install
    ``rfc3986-validator`` / ``rfc3339-validator`` and can check here.
    """
    try:
        return tuple(sorted(_format_checker().checkers))
    except Exception:
        return ()


def _jsonschema_available() -> bool:
    try:
        import jsonschema  # noqa: F401,PLC0415
    except Exception:
        return False
    return True


def validate_document(doc: Any, kind: str) -> ValidationReport:
    """Validate ``doc`` against the vendored CR26 schema for ``kind``.

    Returns a report rather than raising: an unknown kind, a non-object
    document, or a missing backend yields a report, never a crash.
    """
    if kind not in CR26_KINDS:
        return ValidationReport(
            kind, "none", ok=False, errors=[f"unknown CR26 document kind: {kind!r}"]
        )
    if not isinstance(doc, dict):
        return ValidationReport(kind, "none", ok=False, errors=["document must be a JSON object"])

    path = schema_path(kind)
    if path is None:
        return ValidationReport(
            kind, "none", ok=False, errors=[f"vendored schema missing for kind {kind!r}"]
        )
    if not _jsonschema_available():
        return ValidationReport(
            kind, "none", ok=False, errors=["jsonschema is not installed"]
        )

    from jsonschema.validators import validator_for  # noqa: PLC0415

    schema = json.loads(path.read_text(encoding="utf-8"))
    # Dialect from the schema itself, never hardcoded.
    cls = validator_for(schema)
    validator = cls(schema, registry=_registry(), format_checker=_format_checker())
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    ]
    return ValidationReport(kind, "official", ok=not errors, errors=errors)
```

And `src/ccf/cr26/__init__.py`:

```python
"""FedRAMP CR26 deliverable schemas, vendored and validated offline."""

from .validation import (
    CR26_KINDS,
    ValidationReport,
    enforced_formats,
    schema_path,
    validate_document,
)

__all__ = [
    "CR26_KINDS",
    "ValidationReport",
    "enforced_formats",
    "schema_path",
    "validate_document",
]
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_validation.py -q` — expected: 10 passed.
Run: `.venv/bin/ruff check . && .venv/bin/mypy src` — expected: clean.

If `mypy --strict` objects to the `Any` returns from `_registry()` / `_format_checker()`, keep them `Any` (the libraries' types are not worth importing at module scope) rather than loosening the annotations on the public surface.

- [ ] **Step 5: Prove the offline guarantee bites**

This is the most important verification in the plan. Temporarily remove `registry=_registry()` from the `cls(...)` call, then:

1. Run `test_a_valid_document_validates_with_no_network` — expected: FAIL with `Unresolvable`.
2. Run `test_a_missing_required_property_is_reported` — expected: **still PASSES**, because that document never descends into the `$ref`.

Paste both outputs. Point 2 is the finding: it demonstrates on live code why a "minimal invalid document" fixture proves nothing. **Then restore the argument and re-run the whole file green.**

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cr26 tests/test_cr26_validation.py
git commit -m "feat(cr26): validate CR26 documents against the vendored schemas, offline

Ten of the eleven schemas reference common-definitions by absolute URL, and
jsonschema 4.26 raises Unresolvable rather than fetching, so validation
resolves every reference through a referencing.Registry built from the
vendored files. Sockets are blocked in the tests that assert this: 'it worked
on my machine' is not the claim.

$ref resolution is lazy, which makes the obvious test useless: a document that
fails an earlier required check never descends into the reference, so a
minimal invalid fixture passes with no registry at all. The tests here use
documents complete enough to reach a $ref, and one asserts a value that
violates the $ref'd definition is actually rejected.

No detect_kind (CR26 documents do not self-identify by root key, so guessing
would be a silent mis-validation), no structural fallback (the schema is
vendored and cannot be missing; a fallback would assert a shape we invented)
and no ECMA pattern translation (CR26's four patterns are Python-compatible).

enforced_formats() reports which formats this environment actually checks --
date and email yes, date-time and uri no -- so the gap is a recorded fact
rather than an assumption.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Watch upstream for drift

**Files:**
- Modify: `src/ccf/etl/sources.py` (`DEFAULT_SOURCES`)
- Test: `tests/test_cr26_sources.py`

**Interfaces:**
- Consumes: `CR26_KINDS` from Task 2, to keep the source rows and the vendored set from drifting apart.
- Produces: eleven `CatalogSource` rows, keys `cr26_schema_<kind>`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cr26_sources.py
"""The eleven CR26 schemas are watched for upstream drift.

kind="generic" is content-hash only, and that is the right call for the same
reason etl/sources.py already records for baseline profiles: a profile is not
a catalog, and a schema is not one either. Nothing parses a schema into tables.
auto_ingest=False means drift is surfaced for a human, never adopted silently
-- a schema that changed under us is exactly the event a person needs to see.
"""

from __future__ import annotations

from ccf.cr26.validation import CR26_KINDS
from ccf.etl.sources import DEFAULT_SOURCES

RULESET_VERSION = "2026-06-24"
_CR26 = [s for s in DEFAULT_SOURCES if s["key"].startswith("cr26_schema_")]


def test_there_is_one_source_row_per_vendored_schema() -> None:
    assert len(_CR26) == len(CR26_KINDS) == 11
    assert {s["key"] for s in _CR26} == {f"cr26_schema_{k}" for k in CR26_KINDS}


def test_each_row_points_at_the_file_that_was_vendored() -> None:
    """Row and vendored file must name the same upstream artefact, or the
    poller watches one thing while validation uses another."""
    by_key = {s["key"]: s for s in _CR26}
    for kind, (filename, _rule) in CR26_KINDS.items():
        assert by_key[f"cr26_schema_{kind}"]["url"].endswith(f"/{filename}")


def test_the_rows_are_content_hash_only_and_never_auto_ingested() -> None:
    for s in _CR26:
        assert s["kind"] == "generic", s["key"]
        assert s.get("auto_ingest", False) is False, s["key"]
        assert s["authority"] == "FedRAMP", s["key"]
        assert s["enabled"] is True, s["key"]


def test_every_url_carries_the_pinned_ruleset_revision() -> None:
    """A row pointing at an unversioned 'latest' URL would silently track
    upstream and defeat the pin."""
    for s in _CR26:
        assert f"-schema-{RULESET_VERSION}.json" in s["url"], s["key"]


def test_the_keys_do_not_collide_with_existing_sources() -> None:
    keys = [s["key"] for s in DEFAULT_SOURCES]
    assert len(keys) == len(set(keys))
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_sources.py -q`
Expected: `assert 0 == 11` — no `cr26_schema_` rows exist yet.

- [ ] **Step 3: Implement**

Append to `DEFAULT_SOURCES` in `src/ccf/etl/sources.py`, generated from `CR26_KINDS` so the two cannot drift apart — do not hand-write eleven near-identical dicts:

```python
# --- FedRAMP CR26 deliverable schemas ---------------------------------------
# Watched, not ingested. ``kind="generic"`` is content-hash only, the same call
# already recorded above for baseline profiles: a profile is not a catalog, and
# a schema is not one either -- nothing here parses a schema into tables.
# ``auto_ingest=False`` because a schema that changed under us is exactly the
# event a person needs to see, never something to adopt silently. The vendored
# copies under ``ccf/cr26/schemas/`` are what validation actually reads; these
# rows exist so upstream drift is detected.
_CR26_SCHEMA_BASE = "https://fedramp.gov/schemas"

DEFAULT_SOURCES += [
    {
        "key": f"cr26_schema_{_kind}",
        "name": f"FedRAMP CR26 — {_rule if _rule != '-' else _kind} schema (2026-06-24)",
        "authority": "FedRAMP",
        "kind": "generic",
        "url": f"{_CR26_SCHEMA_BASE}/{_filename}",
        "framework_code": "FEDRAMP",
        "enabled": True,
        "auto_ingest": False,
    }
    for _kind, (_filename, _rule) in _CR26_KINDS_FOR_SOURCES.items()
]
```

Import the mapping at the top of `sources.py` as `from ..cr26.validation import CR26_KINDS as _CR26_KINDS_FOR_SOURCES`. **If that import creates a cycle** — `cr26.validation` imports nothing from `etl`, so it should not — stop and report rather than duplicating the table. A circular import bit this project once before, in `posture/types.py`.

`CatalogSource.auto_ingest` is a real column (`models.py:1172`, `Boolean, default=False`), so passing it explicitly is redundant but deliberate — it states the intent at the row rather than relying on a default a future change could flip.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_sources.py -q` — expected: 5 passed.

- [ ] **Step 5: Confirm no migration is needed**

```bash
.venv/bin/alembic heads          # FULL output, never piped through tail
```

Expected: exactly one line, `0078_cr26_certification (head)` — unchanged, because this task adds rows to a seed list, not columns to a table. If you believe a migration IS needed, **stop and report** rather than writing one.

Then run the seeding path against the test database to prove the rows insert:
`.venv/bin/python3 -m pytest tests/ -q -k "source or catalog"` with `timeout: 600000`.

- [ ] **Step 6: Full verification and commit**

```bash
.venv/bin/python3 -m pytest -q     # timeout: 900000
.venv/bin/ruff check . && .venv/bin/mypy src
.venv/bin/alembic heads
```

```bash
git add src/ccf/etl/sources.py tests/test_cr26_sources.py
git commit -m "feat(cr26): watch the eleven CR26 schemas for upstream drift

One generic CatalogSource per vendored schema, generated from CR26_KINDS so
the watched set and the validated set cannot drift apart. Content-hash only
and auto_ingest=False: nothing parses a schema into tables, and a schema that
changed under us is an event for a human, not something to adopt.

No migration -- this adds rows to a seed list, not columns to a table.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Notes for the executor

- **Never hand-edit a vendored schema.** Not to fix a validation failure, not to correct an apparent upstream mistake. The sha256 pin exists to make that impossible; if you find yourself wanting to, report it instead.
- **A "minimal invalid document" proves nothing about `$ref` resolution.** Lazy resolution means it never reaches the reference. Every such test uses a complete document.
- **Do not add `rfc3339-validator` or `rfc3986-validator`.** The spec defers them deliberately: this unit ships no generator, so nothing emits a `date-time` or `uri` yet, and the dependencies buy nothing until one does.
- **Do not invent a CR26 rule table.** FedRAMP publishes no machine-readable ruleset — only rule ids in README prose. The `frrID` values in `CR26_KINDS` are labels for humans reading the mapping, not a claim to model the ruleset.
- After committing a task, run `git show --stat` and confirm the intended files are in it. A green suite answers "does the tree work", not "is the tree committed".
