# CR26 SDR Seeder Implementation Plan (P9a-ii, part 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Seed a FedRAMP Security Decision Record from content the platform already holds — control implementations from the SSP, indicator evidence from the KSI subsystem — while refusing to invent the one field it cannot derive.

**Architecture:** Three pieces in `src/ccf/cr26/sdr.py`: a control renderer, a KSI merger keyed by `ksiId`, and `seed_sdr` assembling both and returning a result that names what was omitted. Plus one route beside the CPO's. No migration.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, FastAPI, pytest. **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-17-cr26-sdr-seeder-design.md`

## Global Constraints

- **Never invent `ksiImplementation`.** Not from `KSI.description` (the catalog's org-agnostic description of the *requirement*), not from `ksi_states.notes` (per-system free text not designed as an implementation statement — a provider who used it for a reminder would file that reminder to FedRAMP), not as `[]`.
- **A KSI with no authored `ksiImplementation` is OMITTED from the document entirely** and named in the result. Every required `keySecurityIndicators` field is an array of free text, so `ksiImplementation: []` *satisfies the schema* — a complete-looking entry that says nothing. The CPO's gap fails loudly; this one would be silent.
- **The merge preserves `ksiImplementation` and refreshes the other five.** `ksiImplementationStatus`, `ksiValidation`, `ksiAssessment`, `ksiTests`, `ksiEvidence` are facts about the system that change as scans and reviews run.
- **`parameterValues` drops any parameter whose value is `None`.** `ssp/nist80053.py:71` scaffolds `odp_values` as `{param.id: None}`, so `str(None)` would emit `parameterValue: "None"` — a document that validates while asserting the provider chose the literal string "None". Same failure class as inventing a CPO field.
- **Follow `ssp/nist80053_docx.py`'s joins, do not invent new ones** — line 170 (`" ".join(p["text"])` for narratives) and line 173 (`", ".join(...)` for status) already render these exact fields for the Word SSP.
- **`fedRampRequirements` is `[]` and `certificationPackageOverviewUri` is omitted unless authored.** A seeded SDR is therefore **invalid**, like a seeded CPO, and for the same reason: something is genuinely still owed.
- **No migration.** The head stays `0079_cr26_documents`. If you conclude one is needed, stop and report.
- **Never hand-edit a vendored schema** under `src/ccf/cr26/schemas/`.
- **Every new test must be able to fail.** This programme has shipped at least seven that could not, six in the two preceding CR26 units, every one because the asserted value equalled what the code produces doing nothing. Before trusting an assertion, ask: *what would this be if the code under test were deleted?* An assertion of `[]`, `{}`, `None` or `False` is suspect by default.
- `ruff check .` and `mypy src` clean; mypy `strict = true`. **`ruff format` is NOT enforced** (343 files repo-wide would change; CI runs only `ruff check .`) — do not run it.
- **Stage explicit paths when committing. Never `git add -A`** — it has swept an unrelated file into a commit twice on this programme.
- Test command — the default `pytest` hits the WRONG database (`.env` → port 5432, another project's container):

```
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
.venv/bin/python3 -m pytest -q
```

  Use `.venv/bin/` binaries only. **Never let a pytest call background** — a Bash call past 120s is auto-backgrounded and its notification never arrives; this has stalled three implementers here. Pass `timeout: 600000` focused / `900000` full suite, in the foreground. The suite is hermetic: a conftest guard fails any test opening a connection to :80/:443.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/ccf/cr26/sdr.py` | `_render_controls` + project selection | 1 |
| `src/ccf/cr26/sdr.py` | `_merge_indicators` | 2 |
| `src/ccf/cr26/sdr.py` | `seed_sdr`, `SdrSeedResult` | 3 |
| `src/ccf/api/routes/cr26.py` | the seed route | 3 |
| `tests/test_cr26_sdr_controls.py` | Task 1 |
| `tests/test_cr26_sdr_indicators.py` | Task 2 |
| `tests/test_cr26_sdr_seed.py` | Task 3 |

One module, three tasks: the pieces share the document's shape and splitting them across files would scatter one deliverable's rendering. Read `src/ccf/cr26/cpo.py` first — `seed_sdr` mirrors `seed_cpo`'s structure (load system, read current document, merge, hand to `put_document`).

---

### Task 1: Render the controls

**Files:** modify `src/ccf/cr26/sdr.py` (create); test `tests/test_cr26_sdr_controls.py`

**Interfaces:**
- Produces: `def render_controls(entries: Sequence[SSPControlEntry]) -> list[dict[str, Any]]` and `async def latest_project_id(session, system_id) -> int | None`

- [ ] **Step 1: Read the precedent**

Open `src/ccf/ssp/nist80053_docx.py` lines 165–175. Lines 170 and 173 render `part_narratives` and `implementation_status` for the Word SSP. Your conversions must match them — the SDR is a second profile over the same content, not a second opinion about how to flatten it.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_cr26_sdr_controls.py
"""securityControls: the SSP's content in CR26's shape.

Three of the four fields need a shape conversion rather than a copy -- the SDR
wants strings where the platform holds JSONB -- and the joins are the ones
ssp/nist80053_docx.py already uses, so the Word SSP and the JSON SDR cannot
disagree about the same control.
"""

from __future__ import annotations

from ccf.cr26.sdr import render_controls
from ccf.models import SSPControlEntry


def _entry(**kw: object) -> SSPControlEntry:
    defaults: dict[str, object] = {
        "control_id": "AC-2",
        "implementation_status": ["implemented"],
        "part_narratives": [{"part": "a", "text": "We do the thing."}],
        "odp_values": {},
    }
    return SSPControlEntry(**{**defaults, **kw})  # type: ignore[arg-type]


def test_a_control_renders_every_field() -> None:
    out = render_controls([_entry()])
    assert out == [
        {
            "controlId": "AC-2",
            "controlImplementationStatus": "implemented",
            "controlImplementationDescription": "We do the thing.",
            "parameterValues": [],
        }
    ]


def test_several_narrative_parts_join_with_a_space() -> None:
    """Matching nist80053_docx.py:170 -- not newline, not concatenation."""
    out = render_controls(
        [_entry(part_narratives=[{"text": "First."}, {"text": "Second."}])]
    )
    assert out[0]["controlImplementationDescription"] == "First. Second."


def test_several_statuses_join_with_a_comma() -> None:
    """Matching nist80053_docx.py:173."""
    out = render_controls([_entry(implementation_status=["planned", "partial"])])
    assert out[0]["controlImplementationStatus"] == "planned, partial"


def test_an_answered_parameter_is_rendered() -> None:
    out = render_controls([_entry(odp_values={"ac-2_prm_1": "30 days"})])
    assert out[0]["parameterValues"] == [
        {"parameterId": "ac-2_prm_1", "parameterValue": "30 days"}
    ]


def test_an_UNANSWERED_parameter_is_dropped_not_stringified() -> None:
    """ssp/nist80053.py:71 scaffolds odp_values as {param.id: None} for every
    parameter in the control, so an unanswered ODP is present with a None
    value. str(None) would emit "None" as the provider's chosen parameter --
    a document that validates and is wrong.
    """
    out = render_controls(
        [_entry(odp_values={"answered": "7", "unanswered": None})]
    )
    assert out[0]["parameterValues"] == [
        {"parameterId": "answered", "parameterValue": "7"}
    ]


def test_a_non_string_parameter_value_becomes_a_string() -> None:
    """parameterValue is type: string, so a number or bool must be coerced --
    but coercion must not resurrect None (see the test above)."""
    out = render_controls([_entry(odp_values={"count": 30, "flag": True})])
    values = {p["parameterId"]: p["parameterValue"] for p in out[0]["parameterValues"]}
    assert values == {"count": "30", "flag": "True"}


def test_empty_columns_render_as_empty_not_missing() -> None:
    """Every key must be present even when the source is empty -- a caller
    reading controlImplementationStatus must not have to handle KeyError."""
    out = render_controls(
        [_entry(implementation_status=[], part_narratives=[], odp_values={})]
    )
    assert out[0] == {
        "controlId": "AC-2",
        "controlImplementationStatus": "",
        "controlImplementationDescription": "",
        "parameterValues": [],
    }


def test_controls_keep_their_input_order() -> None:
    out = render_controls([_entry(control_id="AC-1"), _entry(control_id="AU-2")])
    assert [c["controlId"] for c in out] == ["AC-1", "AU-2"]
```

- [ ] **Step 3: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_sdr_controls.py -q` with `timeout: 600000`
Expected: `ModuleNotFoundError: No module named 'ccf.cr26.sdr'`.

- [ ] **Step 4: Implement**

```python
# src/ccf/cr26/sdr.py
"""Seed a FedRAMP Security Decision Record from what the platform holds.

Unlike the CPO -- which is mostly facts about the business that live nowhere
here -- the SDR genuinely IS a second profile over content this platform
already produces. Ten of its eleven mapped fields have real sources.

The eleventh, ``ksiImplementation``, is the provider's narrative of how the
offering meets each indicator, and it exists nowhere per-system.
``KSI.description`` is the catalog's org-agnostic description of the
*requirement*, so rendering it there would describe the obligation while
claiming to describe the implementation.

That gap is more dangerous than the CPO's, because every required
``keySecurityIndicators`` field is an array of free text: ``[]`` satisfies the
schema. A seeder could emit a complete-looking indicator saying nothing at all,
and unlike the CPO the document would still validate. So an indicator with no
authored narrative is **omitted entirely** and named in the result.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SSPControlEntry, SSPProject


def _parameter_values(odp_values: dict[str, Any] | None) -> list[dict[str, str]]:
    """Answered organization-defined parameters, as CR26 wants them.

    Unanswered parameters are DROPPED, not stringified. ``ssp/nist80053.py``
    scaffolds ``odp_values`` as ``{param.id: None}`` for every parameter in the
    control, and ``parameterValue`` is ``type: string`` -- so ``str(None)``
    would emit ``"None"`` as the provider's chosen value, a document that
    validates and is wrong.
    """
    return [
        {"parameterId": str(key), "parameterValue": str(value)}
        for key, value in (odp_values or {}).items()
        if value is not None
    ]


def render_controls(entries: Sequence[SSPControlEntry]) -> list[dict[str, Any]]:
    """The SSP's control content in the SDR's shape.

    The joins match ``ssp/nist80053_docx.py`` lines 170 and 173, which render
    these same two fields into the Word SSP. Two profiles over one body of
    content must not disagree about what a control says.
    """
    return [
        {
            "controlId": entry.control_id,
            "controlImplementationStatus": ", ".join(entry.implementation_status or []),
            "controlImplementationDescription": " ".join(
                str(part.get("text") or "") for part in (entry.part_narratives or [])
            ),
            "parameterValues": _parameter_values(entry.odp_values),
        }
        for entry in entries
    ]


async def latest_project_id(session: AsyncSession, system_id: int) -> int | None:
    """The SSP project this system's SDR renders from, or ``None``.

    ``SSPProject.system_id`` is nullable with no unique constraint, so a system
    may have several. Two precedents disagree -- ``api/routes/oscal.py`` orders
    by ``id.desc()``, ``api/routes/reports.py`` by ``updated_at.desc()``. This
    follows ``reports.py``: it is the closer analogue (rendering a document
    rather than assembling a package), and "most recently worked on" is the
    better answer to "which SSP describes this system today".

    The choice is reported in :class:`SdrSeedResult` rather than left implicit,
    because the ambiguity is real and an operator should never have to guess
    which SSP their SDR came from.
    """
    return (
        await session.execute(
            select(SSPProject.id)
            .where(SSPProject.system_id == system_id)
            .order_by(SSPProject.updated_at.desc())
            .limit(1)
        )
    ).scalars().first()
```

- [ ] **Step 5: Run to verify it passes**

Run the focused file, then `ruff check .` and `mypy src`.

- [ ] **Step 6: Prove the None-drop bites**

Change `if value is not None` to `if True`, run the focused file, and confirm `test_an_UNANSWERED_parameter_is_dropped_not_stringified` FAILS showing `"None"`. **Revert.** Paste both outputs. That rule is the one thing in this task that prevents a document which validates and lies.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/cr26/sdr.py tests/test_cr26_sdr_controls.py
git commit -m "feat(cr26): render SSP control content into the SDR's shape

Three of the four securityControls fields need a shape conversion rather than
a copy -- the SDR wants strings where the platform holds JSONB -- and the joins
are the ones ssp/nist80053_docx.py already uses, so the Word SSP and the JSON
SDR cannot disagree about the same control.

Unanswered parameters are dropped rather than stringified. nist80053.py
scaffolds odp_values as {param.id: None} for every parameter in a control, and
parameterValue is type: string, so str(None) would emit \"None\" as the
provider's chosen value -- a document that validates and is wrong.

Project selection follows reports.py (most recently updated) over oscal.py
(highest id); the two precedents disagree and the chosen id is reported rather
than left implicit.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Merge the indicators

The riskiest piece. This is the first thing in the programme reconciling two sources **inside an array**, and array merges are where silent data loss lives.

**Files:** modify `src/ccf/cr26/sdr.py`; test `tests/test_cr26_sdr_indicators.py`

**Interfaces:**
- Consumes: Task 1's module.
- Produces: `def merge_indicators(authored: Sequence[dict[str, Any]], derived: Mapping[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]` — returns the merged entries and the omitted `ksiId`s.

Keeping the merge a **pure function** over already-loaded data is deliberate: it is the part most likely to be wrong, and a pure function can be tested exhaustively without a database.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cr26_sdr_indicators.py
"""The KSI merge: authored narrative survives, derived facts refresh.

ksiImplementation is the one field the platform cannot derive. Everything else
is a fact about the system that changes as scans and reviews run, so it must be
refreshed on every seed -- and an indicator with no authored narrative is
omitted entirely rather than emitted with an empty array, which would satisfy
the schema while saying nothing.
"""

from __future__ import annotations

from ccf.cr26.sdr import merge_indicators

_DERIVED = {
    "KSI-IAM-01": {
        "ksiImplementationStatus": "implemented",
        "ksiValidation": ["passed 2026-09-17 (scan)"],
        "ksiAssessment": ["accepted by assessor@3pao.example"],
        "ksiTests": ["automated: mfa_registered"],
        "ksiEvidence": [{"evidenceType": "scan", "evidenceDescription": "47 users"}],
    },
    "KSI-CNA-02": {
        "ksiImplementationStatus": "planned",
        "ksiValidation": [],
        "ksiAssessment": [],
        "ksiTests": [],
        "ksiEvidence": [],
    },
}


def test_an_indicator_with_no_authored_narrative_is_omitted() -> None:
    merged, omitted = merge_indicators([], _DERIVED)
    assert merged == []
    assert sorted(omitted) == ["KSI-CNA-02", "KSI-IAM-01"]


def test_an_authored_narrative_is_kept_and_the_derived_fields_refresh() -> None:
    """The central property. Both halves matter: asserting only that the
    narrative survives would pass against a seeder that ignores the database
    entirely and echoes the authored document back."""
    authored = [
        {
            "ksiId": "KSI-IAM-01",
            "ksiImplementation": ["We enforce MFA via Entra Conditional Access."],
            "ksiValidation": ["STALE -- from a previous seed"],
            "ksiTests": ["STALE"],
            "ksiEvidence": [],
            "ksiAssessment": [],
            "ksiImplementationStatus": "planned",
        }
    ]
    merged, omitted = merge_indicators(authored, _DERIVED)

    assert omitted == ["KSI-CNA-02"]
    assert len(merged) == 1
    entry = merged[0]
    assert entry["ksiImplementation"] == [
        "We enforce MFA via Entra Conditional Access."
    ]
    assert entry["ksiValidation"] == ["passed 2026-09-17 (scan)"]
    assert entry["ksiTests"] == ["automated: mfa_registered"]
    assert entry["ksiImplementationStatus"] == "implemented"
    assert entry["ksiEvidence"] == [
        {"evidenceType": "scan", "evidenceDescription": "47 users"}
    ]


def test_an_empty_authored_narrative_does_not_count() -> None:
    """``ksiImplementation: []`` satisfies the schema, which is exactly why it
    must not be treated as authored."""
    merged, omitted = merge_indicators(
        [{"ksiId": "KSI-IAM-01", "ksiImplementation": []}], _DERIVED
    )
    assert merged == []
    assert "KSI-IAM-01" in omitted


def test_an_authored_indicator_the_platform_no_longer_knows_is_kept() -> None:
    """A narrative is human work. If the KSI catalog drops an identifier, the
    entry stays with whatever derived fields it last had, rather than being
    silently deleted -- the merge must never destroy authored text.
    """
    authored = [{"ksiId": "KSI-GONE-99", "ksiImplementation": ["Still true."]}]
    merged, _omitted = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-GONE-99"]
    assert merged[0]["ksiImplementation"] == ["Still true."]


def test_entries_are_ordered_by_ksi_id() -> None:
    """Stable order, so re-seeding produces no spurious document diff."""
    authored = [
        {"ksiId": "KSI-CNA-02", "ksiImplementation": ["b"]},
        {"ksiId": "KSI-IAM-01", "ksiImplementation": ["a"]},
    ]
    merged, _ = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-CNA-02", "KSI-IAM-01"]


def test_an_authored_entry_without_a_ksi_id_is_omitted_not_crashed() -> None:
    merged, omitted = merge_indicators(
        [{"ksiImplementation": ["orphaned"]}], _DERIVED
    )
    assert merged == []
    assert sorted(omitted) == ["KSI-CNA-02", "KSI-IAM-01"]
```

- [ ] **Step 2: Run to verify it fails**

Expected: `ImportError: cannot import name 'merge_indicators'`.

- [ ] **Step 3: Implement**

```python
#: The five ``keySecurityIndicators`` fields the platform derives. Refreshed on
#: every seed, because each is a fact about the system that changes as scans
#: and reviews run. ``ksiImplementation`` is deliberately absent: it is the one
#: field only a human can supply.
DERIVED_INDICATOR_FIELDS: tuple[str, ...] = (
    "ksiImplementationStatus",
    "ksiValidation",
    "ksiAssessment",
    "ksiTests",
    "ksiEvidence",
)


def merge_indicators(
    authored: Sequence[dict[str, Any]],
    derived: Mapping[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Merge authored narrative with derived facts, keyed by ``ksiId``.

    Returns the merged entries and the ids omitted for want of a narrative.

    Three rules, each load-bearing:

    * **An indicator with no authored ``ksiImplementation`` is omitted.**
      Emitting it with an empty array would satisfy the schema while saying
      nothing about how the offering meets the indicator -- and unlike the
      CPO's gaps, the document would still validate, so the omission would be
      invisible.
    * **The five derived fields are overwritten**, because they are facts about
      the system rather than anything a human authored here.
    * **An authored entry the platform no longer recognises is KEPT**, with
      whatever derived fields it last carried. A narrative is human work; a KSI
      catalog revision must not silently delete it.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for entry in authored:
        ksi_id = entry.get("ksiId")
        if isinstance(ksi_id, str) and ksi_id:
            by_id[ksi_id] = dict(entry)

    merged: list[dict[str, Any]] = []
    omitted: list[str] = []
    for ksi_id in sorted(set(by_id) | set(derived)):
        entry = by_id.get(ksi_id)
        narrative = (entry or {}).get("ksiImplementation") or []
        if not narrative:
            omitted.append(ksi_id)
            continue
        out = dict(entry or {})
        out["ksiId"] = ksi_id
        out["ksiImplementation"] = narrative
        for field in DERIVED_INDICATOR_FIELDS:
            if ksi_id in derived:
                out[field] = derived[ksi_id][field]
            else:
                out.setdefault(field, [] if field != "ksiImplementationStatus" else "")
        merged.append(out)
    return merged, omitted
```

Add `Mapping` to the `collections.abc` import.

- [ ] **Step 4: Run to verify it passes**, then `ruff check .` and `mypy src`.

- [ ] **Step 5: Prove the merge bites, three ways**

This is the task's whole point. Run each mutation, capture the failure, revert:

1. Replace the narrative-preserving line with `out["ksiImplementation"] = []` → `test_an_authored_narrative_is_kept_and_the_derived_fields_refresh` must FAIL. (Silent destruction of human work.)
2. Skip the derived overwrite (`continue` before the loop) → the same test must FAIL on `ksiValidation` still reading `"STALE"`. (A seeder that echoes the document back.)
3. Change `if not narrative` to `if entry is None` → `test_an_empty_authored_narrative_does_not_count` must FAIL. (An empty array counted as authored.)

Paste all three. **Restore between each** and confirm green at the end.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/cr26/sdr.py tests/test_cr26_sdr_indicators.py
git commit -m "feat(cr26): merge authored KSI narrative with derived facts

The first thing in this programme reconciling two sources inside an array,
which is where silent data loss lives -- so it is a pure function over loaded
data, tested exhaustively without a database, and each of its three rules is
proven by mutation.

An indicator with no authored ksiImplementation is omitted rather than emitted
empty: every required keySecurityIndicators field is an array of free text, so
[] satisfies the schema and the gap would be invisible. The five derived fields
are overwritten because they are facts about the system. An authored entry the
platform no longer recognises is kept, because a narrative is human work and a
catalog revision must not delete it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Assemble and expose

**Files:** modify `src/ccf/cr26/sdr.py`, `src/ccf/api/routes/cr26.py`; test `tests/test_cr26_sdr_seed.py`

**Interfaces:**
- Consumes: Tasks 1 and 2; `ccf.cr26.store.put_document`; `ccf.cr26.cpo` as the structural precedent.
- Produces: `@dataclass SdrSeedResult` (`document: Cr26Document`, `omitted_ksi_ids: list[str]`, `ssp_project_id: int | None`) and `async def seed_sdr(session, *, system_id) -> SdrSeedResult`; route `POST /api/systems/{id}/cr26-documents/sdr/seed`.

`seed_sdr` returns a result object rather than a bare `Cr26Document` like `seed_cpo` does, because it has something to report that the CPO does not: what was left out, and which SSP it rendered from. That divergence is deliberate.

- [ ] **Step 1: Write the failing test**

Fixtures follow `tests/test_cr26_cpo_seed.py`. The two load-bearing tests in full; the rest are listed after.

```python
# tests/test_cr26_sdr_seed.py
"""Seeding an SDR: render what is known, omit what is owed, preserve what was written."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.cr26.sdr import seed_sdr
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import (
    KSI, KSIValidationResult, Organization, SSPControlEntry, SSPProject, System,
)

_SEQ = itertools.count()


async def _fixture(name: str) -> tuple[int, int, str]:
    """An org, a system with one SSP control entry, and one KSI identifier."""
    ident = f"KSI-{name.upper()}-{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"{name} Provider")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} Service")
        s.add(sysm)
        await s.flush()
        project = SSPProject(
            organization_id=org.id, system_id=sysm.id, customer_name=name,
            platform="aws", framework="NIST_800_53_R5", title=f"{name} SSP", version="1.0",
        )
        s.add(project)
        await s.flush()
        s.add(
            SSPControlEntry(
                project_id=project.id, control_id="AC-2",
                implementation_status=["implemented"],
                part_narratives=[{"part": "a", "text": "We manage accounts."}],
                odp_values={"ac-2_prm_1": "30 days", "ac-2_prm_2": None},
            )
        )
        s.add(KSI(identifier=ident, category="IAM", name=f"{name} indicator",
                  description="The CATALOG description of the requirement.",
                  validation_method="automated"))
        await s.flush()
        return org.id, sysm.id, ident


async def test_a_seeded_sdr_renders_the_ssp_controls_and_is_invalid() -> None:
    """Two claims at once: the controls carry real content (not []), and the
    document is invalid because certificationPackageOverviewUri is owed."""
    _org_id, system_id, _ident = await _fixture("render")
    async with session_scope() as s:
        result = await seed_sdr(s, system_id=system_id)

    doc = result.document.document
    assert doc["securityControls"] == [
        {
            "controlId": "AC-2",
            "controlImplementationStatus": "implemented",
            "controlImplementationDescription": "We manage accounts.",
            # ac-2_prm_2 is unanswered and must NOT appear as "None".
            "parameterValues": [{"parameterId": "ac-2_prm_1", "parameterValue": "30 days"}],
        }
    ]
    assert doc["fedRampRequirements"] == []
    assert "certificationPackageOverviewUri" not in doc
    assert result.document.is_valid is False
    assert any(
        "certificationPackageOverviewUri" in e for e in result.document.validation_errors
    ), result.document.validation_errors
    assert result.ssp_project_id is not None


async def test_seeding_twice_keeps_the_narrative_and_refreshes_the_derived_fields() -> None:
    """The plan's central risk. BOTH halves matter: asserting only that the
    narrative survives would pass against a seeder that ignores the database
    and echoes the stored document back."""
    _org_id, system_id, ident = await _fixture("twice")

    async with session_scope() as s:
        first = await seed_sdr(s, system_id=system_id)
    assert ident in first.omitted_ksi_ids, "no narrative yet, so it must be omitted"

    # A human authors the one field the platform cannot derive.
    async with session_scope() as s:
        doc = dict(first.document.document)
        doc["keySecurityIndicators"] = [
            {"ksiId": ident, "ksiImplementation": ["We enforce MFA via Conditional Access."]}
        ]
        await put_document(s, system_id=system_id, kind="sdr", document=doc)

    async with session_scope() as s:
        second = await seed_sdr(s, system_id=system_id)
    entry = next(
        e for e in second.document.document["keySecurityIndicators"] if e["ksiId"] == ident
    )
    assert entry["ksiImplementation"] == ["We enforce MFA via Conditional Access."]
    assert ident not in second.omitted_ksi_ids
    before = entry["ksiValidation"]

    # A scan runs between seeds -- the derived half must move.
    async with session_scope() as s:
        s.add(
            KSIValidationResult(
                system_id=system_id, ksi_identifier=ident, status="pass",
                source="scan", validated_at=datetime.now(UTC), evidence_refs=["s3://ev/1"],
            )
        )

    async with session_scope() as s:
        third = await seed_sdr(s, system_id=system_id)
    entry = next(
        e for e in third.document.document["keySecurityIndicators"] if e["ksiId"] == ident
    )
    assert entry["ksiImplementation"] == ["We enforce MFA via Conditional Access."], (
        "the authored narrative must survive a re-seed"
    )
    assert entry["ksiValidation"] != before, (
        "the derived fields must actually refresh -- if they never change, this "
        "test would pass against a seeder that only echoes the stored document"
    )
    assert entry["ksiEvidence"], entry
```

Then, in the same file and the same fixture style:

- `test_the_latest_project_is_used` — give the system two `SSPProject` rows with different `updated_at`, assert `result.ssp_project_id` is the newer one's id, and assert the rendered `controlId` comes from that project's entries (an id assertion alone would pass if the renderer read the other project).
- `test_an_unknown_system_raises` and `test_a_soft_deleted_system_raises` — `pytest.raises(ValueError, match="system")`, matching `seed_cpo`.
- `test_the_route_returns_the_document_and_what_was_omitted` — `POST /api/systems/{id}/cr26-documents/sdr/seed` returns 200 with `omitted_ksi_ids` and `ssp_project_id` alongside the document.
- `test_the_seed_route_is_admin_gated` — **try `control_owner`, never `viewer`**: viewer 403s under either gate and so could not tell an admin-only gate from an admin+control_owner one.
- `test_another_tenants_system_is_404` — and note the trap found in the CR26 API work: a 404 test must exercise a path that would otherwise return 200, or it passes from the wrong branch.

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement `seed_sdr`**

Mirror `seed_cpo`: load and check the system (`None` or `deleted_at` → `ValueError`), read the current document, build `derived` from the KSI tables, call `merge_indicators`, render controls from `latest_project_id`'s entries, and hand the whole document to `put_document(kind="sdr")`.

Build `derived` from `ksi_states.status`, `ksi_validation_results` (status, `validated_at`, `source`), `ksi_assessor_reviews` (finding, status, assessor), `KSI.validation_method`/`rule`, and `ksi_validation_results.evidence_refs`. Keep each rendering a small named helper so a wrong one is obvious and separately testable — and **never fall back to `KSI.description`** for any of them.

`certificationPackageOverviewUri` is carried over from the existing document if present and otherwise absent. `fedRampRequirements` is `[]` unless already authored.

- [ ] **Step 4: Add the route**

Beside `seed_cpo_document` in `src/ccf/api/routes/cr26.py`, same `AUTHOR_ROLES` gate and `_owned_system` check, returning `_full(result.document)` plus `omitted_ksi_ids` and `ssp_project_id`.

- [ ] **Step 5: Run focused, then full suite** (`timeout: 900000`, foreground), plus `ruff check .`, `mypy src`, and the FULL `alembic heads` output — **never piped through `tail`**, which hid a second head once and errored 1,992 tests here. Expect `0079_cr26_documents (head)`, unchanged.

- [ ] **Step 6: Prove the seed-twice test bites**

Make `seed_sdr` pass `authored=[]` to `merge_indicators` and confirm the seed-twice test FAILS on the lost narrative. **Revert**, confirm green. That test is the one carrying this plan's central risk.

- [ ] **Step 7: Commit** with a message in the branch's style, staging explicit paths.

---

## Notes for the executor

- **Do not invent `ksiImplementation`** from any source, including `KSI.description` and `ksi_states.notes`.
- **Do not emit an indicator with an empty narrative** to make the document look complete.
- **Do not make the seeded SDR valid.** It is invalid until a published CPO URI exists, and that is the honest state.
- **Do not add a column or a migration.** The document is the authoring surface.
- After committing, run `git show --stat` and confirm only the intended files are in it.
