# CR26 VER Family Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Seed three CR26 deliverables — Vulnerability Detail Report, Accepted
Vulnerability Info, and Historical VER Activity — from the POA&M rows Concord
already holds.

**Architecture:** One `POAM → vulnerabilityDetail` renderer, one single walk
that filters to flaws and partitions accepted from not-accepted, one merge that
preserves authored acceptance rationale, and three thin envelopes. No
migration; the existing `cr26_documents` store and `put_document` are unchanged.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, FastAPI, pytest, jsonschema
4.26 against vendored schemas in `src/ccf/cr26/schemas/`.

**Spec:** `docs/superpowers/specs/2026-09-18-cr26-ver-family-design.md` — read
it before Task 1. This plan argues from it and does not restate its reasoning.

## Global Constraints

- **Database.** Every test run needs `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test`
  and `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`.
  Port **5432 is a different project's database** — do not use it.
- **Bash timeouts.** Any command that could exceed 120 seconds MUST pass
  `timeout: 600000`. Without it the call is auto-backgrounded and its
  completion notification never arrives.
- **Never run the full suite.** Run only the files your task touches. The
  controller runs the full suite.
- **No migration.** `alembic heads` must stay `0079_cr26_documents` throughout.
- **`ruff check .` and `mypy src` must be clean** at the end of every task.
  `ruff format` is NOT enforced in this repo — do not run it.
- **Never `git add -A`.** Stage paths explicitly. An untracked
  `docs/concord-build-level-report-2026-09.html` sits in the working tree and
  must stay untracked.
- **Reuse, never restate.** `FLAW_SOURCES`, `ACCEPTED_WEAKNESS_STATES`,
  `FEDRAMP_TIMEFRAMES`, `RemediationWindow`, `classify`,
  `accepted_weakness_state` and `enforced_formats` all already exist. Import
  them. A second copy of any of these is a review rejection.
- **`format: date-time` is NOT validated in this environment** (spec §4).
  Tests must assert exact rendered strings; `assert report.ok` proves nothing
  about a date-time.

## File Structure

| File | Responsibility |
|---|---|
| `src/ccf/cr26/ver.py` (new) | Everything: blank test, single-POA&M renderer, single walk, merge, three seeders, result type |
| `src/ccf/api/routes/cr26.py` (modify) | Three seed endpoints |
| `tests/test_cr26_ver_render.py` (new) | Pure: `is_blank`, `render_vulnerability` |
| `tests/test_cr26_ver_walk.py` (new) | Pure: `render_all` — flaw filter, partition, counts |
| `tests/test_cr26_ver_merge.py` (new) | Pure: `merge_accepted` |
| `tests/test_cr26_ver_seed.py` (new) | DB + HTTP: three seeders and three routes |

`ver.py` is one module because every piece operates on the same row shape and
they change together. It will land around 600 lines, comparable to `sdr.py`.

---

### Task 1: The single-vulnerability renderer

**Files:**
- Create: `src/ccf/cr26/ver.py`
- Test: `tests/test_cr26_ver_render.py`

**Interfaces:**
- Consumes: `ccf.patching.sla.classify`, `RemediationWindow`; `ccf.models.POAM`
- Produces:
  - `is_blank(value: Any) -> bool`
  - `render_vulnerability(poam: Any, *, today: date, window: RemediationWindow) -> tuple[dict[str, Any] | None, list[str]]`
  - Invariant, relied on by Task 2: **the reason list is non-empty if and
    only if the detail is `None`.**

- [ ] **Step 1: Write the failing tests**

```python
"""The POA&M -> vulnerabilityDetail renderer.

Every assertion here checks what the document CLAIMS, not merely that it
validates: `format: date-time` is unenforced in this environment (spec §4), so
the validator is not a backstop for any date this module writes.
"""

from __future__ import annotations

from datetime import date

import pytest

from ccf.cr26.ver import is_blank, render_vulnerability
from ccf.patching.sla import RemediationWindow

TODAY = date(2026, 9, 18)
WINDOW = RemediationWindow()


class _Poam:
    """A POA&M stand-in. Only the columns the renderer reads."""

    def __init__(self, **kw):
        self.id = kw.get("id", 42)
        self.title = kw.get("title", "Outdated OpenSSL on web tier")
        self.weakness = kw.get("weakness")
        self.severity = kw.get("severity", "high")
        self.status = kw.get("status", "open")
        self.identified_on = kw.get("identified_on", date(2026, 9, 1))
        self.closed_on = kw.get("closed_on")
        self.scanner = kw.get("scanner", "nessus")
        self.source = kw.get("source", "scan")


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, True),
        ("", True),
        ("   ", True),
        ("\t\n", True),
        ("x", False),
        (" x ", False),
        (0, True),
        (["a"], True),
    ],
)
def test_is_blank_is_a_blank_test_not_a_none_test(value, expected) -> None:
    """Five omission rules (spec §7) all ask this one question. A `None` test
    would let `""` and `"   "` through, which is how the SDR shipped a
    whitespace description twice. A non-string is blank: this module never
    reprs a value into a federal document.
    """
    assert is_blank(value) is expected


def test_a_complete_poam_renders_every_sourced_field() -> None:
    detail, reasons = render_vulnerability(_Poam(), today=TODAY, window=WINDOW)
    assert reasons == []
    assert detail == {
        "providerTrackingId": "42",
        "detection": {
            "detectedAt": "2026-09-01T00:00:00Z",
            "detectionSource": "nessus",
        },
        "vulnerabilityDescription": "Outdated OpenSSL on web tier",
        "overdueStatus": {"isOverdue": False},
    }


def test_the_tracking_id_is_a_string_because_the_schema_says_so() -> None:
    """Measured: an integer fails with
    "vulnerabilities/0/providerTrackingId: 42 is not of type 'string'".
    """
    detail, _ = render_vulnerability(_Poam(id=7), today=TODAY, window=WINDOW)
    assert detail["providerTrackingId"] == "7"
    assert isinstance(detail["providerTrackingId"], str)


def test_the_detected_date_is_widened_to_midnight_utc_exactly() -> None:
    """`identified_on` is a DATE; `detectedAt` is a date-time. The widening is
    a DECLARED CONVENTION (spec §3.3), not a measured fact -- and since
    `format: date-time` is unenforced here, this exact-string assertion is the
    only thing standing between a malformed value and the deliverable.
    """
    detail, _ = render_vulnerability(
        _Poam(identified_on=date(2026, 3, 4)), today=TODAY, window=WINDOW
    )
    assert detail["detection"]["detectedAt"] == "2026-03-04T00:00:00Z"


def test_weakness_wins_over_title_when_it_has_content() -> None:
    detail, _ = render_vulnerability(
        _Poam(weakness="CVE-2026-1234 in libssl"), today=TODAY, window=WINDOW
    )
    assert detail["vulnerabilityDescription"] == "CVE-2026-1234 in libssl"


def test_a_blank_weakness_falls_through_to_the_title() -> None:
    """`weakness` is nullable and the UI saves `str(...)` with no strip, so a
    cleared textarea persists as "". Blank is as absent as NULL.
    """
    detail, _ = render_vulnerability(
        _Poam(weakness="   "), today=TODAY, window=WINDOW
    )
    assert detail["vulnerabilityDescription"] == "Outdated OpenSSL on web tier"


def test_the_scanner_wins_over_the_source_for_the_detection_source() -> None:
    detail, _ = render_vulnerability(
        _Poam(scanner="qualys", source="scan"), today=TODAY, window=WINDOW
    )
    assert detail["detection"]["detectionSource"] == "qualys"


def test_a_blank_scanner_falls_through_to_the_source() -> None:
    detail, _ = render_vulnerability(
        _Poam(scanner=None, source="scan"), today=TODAY, window=WINDOW
    )
    assert detail["detection"]["detectionSource"] == "scan"


def test_no_identification_date_omits_the_row_and_names_the_reason() -> None:
    """`detection` is required and `updated_at` is when the ROW changed, not
    when the vulnerability was detected. There is no honest fallback.
    """
    detail, reasons = render_vulnerability(
        _Poam(identified_on=None), today=TODAY, window=WINDOW
    )
    assert detail is None
    assert reasons == ["no identification date"]


def test_no_detection_source_at_all_omits_the_row() -> None:
    detail, reasons = render_vulnerability(
        _Poam(scanner=None, source=None), today=TODAY, window=WINDOW
    )
    assert detail is None
    assert reasons == ["no detection source"]


def test_a_blank_description_on_both_columns_omits_the_row() -> None:
    """`title` is NOT NULL, which guarantees the column exists and says nothing
    about its content.
    """
    detail, reasons = render_vulnerability(
        _Poam(title="  ", weakness=""), today=TODAY, window=WINDOW
    )
    assert detail is None
    assert reasons == ["no description"]


def test_every_reason_that_applies_is_reported_not_just_the_first() -> None:
    """Spec §7. Reporting only the first reason sends an operator to fix one
    field and back again for the next.
    """
    detail, reasons = render_vulnerability(
        _Poam(identified_on=None, scanner=None, source=None, title=" ", weakness=None),
        today=TODAY,
        window=WINDOW,
    )
    assert detail is None
    assert reasons == ["no identification date", "no detection source", "no description"]


def test_a_breached_poam_is_overdue() -> None:
    """high severity -> 30 days. Identified 2026-01-01, today 2026-09-18."""
    detail, _ = render_vulnerability(
        _Poam(identified_on=date(2026, 1, 1), severity="high"),
        today=TODAY,
        window=WINDOW,
    )
    assert detail["overdueStatus"] == {"isOverdue": True}


@pytest.mark.parametrize(
    "kw",
    [
        {"status": "risk_accepted"},
        {"status": "closed", "closed_on": date(2026, 9, 10)},
        {"status": "completed", "closed_on": date(2026, 9, 10)},
    ],
)
def test_a_row_with_no_present_tense_answer_omits_overdue_status(kw) -> None:
    """`isOverdue` asks whether the vulnerability IS overdue. A closed one is
    no longer outstanding and `accepted` short-circuits in `classify` ahead of
    every date check, so no date judgment was ever made. `false` would be the
    FAVOURABLE answer -- the defect this programme keeps shipping.
    """
    detail, reasons = render_vulnerability(_Poam(**kw), today=TODAY, window=WINDOW)
    assert reasons == []
    assert "overdueStatus" not in detail


def test_the_nine_unsourced_fields_are_absent() -> None:
    """Spec §3.4. Emitting any of these would assert something the platform
    cannot defend -- `currentRating` most of all, since `nRating` is 1-5 and
    `severity` has four values on a different scale.
    """
    detail, _ = render_vulnerability(_Poam(), today=TODAY, window=WINDOW)
    for field in (
        "currentRating",
        "painReductionEvents",
        "projectedNextReduction",
        "isInternetReachable",
        "isLikelyExploitable",
        "finalDisposition",
        "potentialAgencyImpact",
        "evaluationCompletedAt",
        "supplementaryRiskInformation",
    ):
        assert field not in detail, field


def test_reasons_are_non_empty_exactly_when_the_detail_is_none() -> None:
    """The invariant Task 2 relies on. Asserted over every fixture shape this
    file uses, so a future branch that returns both or neither fails here.
    """
    cases = [
        _Poam(),
        _Poam(identified_on=None),
        _Poam(scanner=None, source=None),
        _Poam(title=" ", weakness=None),
        _Poam(status="risk_accepted"),
    ]
    for poam in cases:
        detail, reasons = render_vulnerability(poam, today=TODAY, window=WINDOW)
        assert (detail is None) is bool(reasons), (poam.id, detail, reasons)
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
python -m pytest tests/test_cr26_ver_render.py -q
```

Expected: collection error — `No module named 'ccf.cr26.ver'`.

- [ ] **Step 3: Write the implementation**

```python
"""Render Concord's POA&M rows into the CR26 VER family's vulnerability shape.

See docs/superpowers/specs/2026-09-18-cr26-ver-family-design.md.

Two rules govern everything here, and both exist because a JSON Schema
constrains shape rather than honesty:

* A field the platform cannot defend is **omitted**, never approximated. Nine
  optional fields have no source and stay absent (spec §3.4).
* `format: date-time` is **not enforced** in this environment -- see
  :func:`ccf.cr26.validation.enforced_formats` -- so a malformed date reaches
  the deliverable with ``ok: True``. Correctness here is by construction and by
  exact-string test, not by validation.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from ..patching.sla import RemediationWindow, classify

#: `classify` buckets that answer the present-tense question `isOverdue` asks.
#: Every other bucket omits the object rather than claiming `false`, which
#: would be the favourable answer for a row nobody measured (spec §3.2).
_OVERDUE_BY_BUCKET: dict[str, bool] = {"breached": True, "within_sla": False}


def is_blank(value: Any) -> bool:
    """True when ``value`` carries no usable text.

    A blank test, never a ``None`` test: five separate omission rules (spec §7)
    ask this one question, and a column holding ``""`` or ``"   "`` is as
    absent as one holding ``NULL``. The UI saves narrative with ``str(...)``
    and no strip, so a cleared field persists as the empty string.

    A non-string is blank rather than coerced: ``str(["a"])`` would put a repr
    into a federal document.
    """
    return not isinstance(value, str) or not value.strip()


def _first_written(*values: Any) -> str | None:
    """The first value with content, stripped -- or ``None`` if none has any."""
    for value in values:
        if not is_blank(value):
            return str(value).strip()
    return None


def _overdue_status(poam: Any, *, today: date, window: RemediationWindow) -> dict[str, bool] | None:
    """``{"isOverdue": ...}``, or ``None`` when the question has no answer.

    ``allowed_days`` is resolved per severity by :class:`RemediationWindow`,
    which gives an unrecognised severity the *strictest* window rather than the
    most generous.
    """
    bucket = classify(poam, allowed_days=window.days_for(poam.severity), today=today)
    value = _OVERDUE_BY_BUCKET.get(bucket)
    return None if value is None else {"isOverdue": value}


def render_vulnerability(
    poam: Any, *, today: date, window: RemediationWindow
) -> tuple[dict[str, Any] | None, list[str]]:
    """One POA&M as a ``vulnerabilityDetail``, or ``None`` and why not.

    The reason list is non-empty **if and only if** the detail is ``None``, and
    every reason that applies is reported rather than the first: an operator
    told about one missing field would fix it and come straight back for the
    next.
    """
    reasons: list[str] = []

    detected_at = poam.identified_on
    if detected_at is None:
        reasons.append("no identification date")

    source = _first_written(poam.scanner, poam.source)
    if source is None:
        reasons.append("no detection source")

    description = _first_written(poam.weakness, poam.title)
    if description is None:
        reasons.append("no description")

    if reasons:
        return None, reasons

    detail: dict[str, Any] = {
        # `type: string` -- measured. An int fails validation outright.
        "providerTrackingId": str(poam.id),
        "detection": {
            # A DATE widened to a date-time: a DECLARED CONVENTION (spec §3.3),
            # not a measured instant. Stated so no reader mistakes it.
            "detectedAt": f"{detected_at.isoformat()}T00:00:00Z",
            "detectionSource": source,
        },
        "vulnerabilityDescription": description,
    }
    overdue = _overdue_status(poam, today=today, window=window)
    if overdue is not None:
        detail["overdueStatus"] = overdue
    return detail, []
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python -m pytest tests/test_cr26_ver_render.py -q
```

Expected: PASS.

- [ ] **Step 5: Prove the guards are load-bearing**

Perform each mutation, run the file, confirm the named test fails, revert.
Paste all five results into your report.

| # | Mutation | Must fail |
|---|---|---|
| 1 | `is_blank`: `return value is None` | the `is_blank` parametrize, and the blank-fallthrough tests |
| 2 | `detectedAt`: emit `detected_at.isoformat()` with no `T00:00:00Z` | `test_the_detected_date_is_widened_to_midnight_utc_exactly` |
| 3 | `providerTrackingId`: emit `poam.id` unwrapped | `test_the_tracking_id_is_a_string_because_the_schema_says_so` |
| 4 | `_OVERDUE_BY_BUCKET`: add `"accepted": False` | `test_a_row_with_no_present_tense_answer_omits_overdue_status` |
| 5 | `render_vulnerability`: `return None, reasons[:1]` | `test_every_reason_that_applies_is_reported_not_just_the_first` |

Mutation 4 is the one that matters most — it is this programme's signature
defect in its newest hiding place.

- [ ] **Step 6: Lint, type-check, commit**

```bash
ruff check . && mypy src && alembic heads
git add src/ccf/cr26/ver.py tests/test_cr26_ver_render.py
git commit -m "feat(cr26): render a POA&M into the VER family's vulnerability shape"
```

`alembic heads` must print `0079_cr26_documents (head)`.

---

### Task 2: The single walk — flaw filter, partition, counts

**Files:**
- Modify: `src/ccf/cr26/ver.py`
- Test: `tests/test_cr26_ver_walk.py`

**Interfaces:**
- Consumes: `render_vulnerability` and `is_blank` from Task 1;
  `ccf.patching.sla.FLAW_SOURCES`, `accepted_weakness_state`
- Produces:
  - `@dataclass(frozen=True) class VerRendering` with fields
    `active: list[dict[str, Any]]`, `accepted: list[dict[str, Any]]`,
    `omitted: list[tuple[int, str]]`, `counts: dict[str, int]`
  - `render_all(poams: Sequence[Any], *, today: date, window: RemediationWindow) -> VerRendering`

**One walk, not three.** The SDR split this work across two passes over the
same input and spent a review round merging them back; start merged. `active`,
`accepted`, `omitted` and `counts` are produced together or they drift.

- [ ] **Step 1: Write the failing tests**

```python
"""The single walk: which rows are vulnerabilities, and where each one goes."""

from __future__ import annotations

from datetime import date

from ccf.cr26.ver import render_all
from ccf.patching.sla import RemediationWindow

TODAY = date(2026, 9, 18)
WINDOW = RemediationWindow()


class _Poam:
    def __init__(self, **kw):
        self.id = kw.get("id", 1)
        self.title = kw.get("title", "Outdated OpenSSL")
        self.weakness = kw.get("weakness")
        self.severity = kw.get("severity", "high")
        self.status = kw.get("status", "open")
        self.identified_on = kw.get("identified_on", date(2026, 9, 1))
        self.closed_on = kw.get("closed_on")
        self.scanner = kw.get("scanner", "nessus")
        self.source = kw.get("source", "scan")


def test_a_control_deficiency_is_not_a_vulnerability_and_is_not_a_defect() -> None:
    """`FLAW_SOURCES` is ("scan",) because "an assessment finding is a control
    deficiency" (sla.py:60). A VULNERABILITY report that carried one would tell
    a regulator that an assessor's documentation finding has a detection source
    and a remediation clock.

    It is EXCLUDED, not omitted: nothing is wrong with the row, so it must not
    appear in the to-do list an operator works through.
    """
    out = render_all([_Poam(id=9, source="assessment")], today=TODAY, window=WINDOW)
    assert out.active == []
    assert out.accepted == []
    assert out.omitted == []
    assert out.counts["excluded_not_a_flaw"] == 1
    assert out.counts["rendered"] == 0


def test_an_open_flaw_is_active_and_an_accepted_one_is_accepted() -> None:
    rows = [
        _Poam(id=1, status="open"),
        _Poam(id=2, status="risk_accepted"),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW)
    assert [d["providerTrackingId"] for d in out.active] == ["1"]
    assert [d["providerTrackingId"] for d in out.accepted] == ["2"]


def test_an_unmeasurable_row_reaches_neither_document() -> None:
    """`accepted_weakness_state` returns `unknown` for a row that cannot be
    SHOWN to fall outside the window. Putting it in `active` would assert it is
    NOT accepted -- the favourable answer under a rule obliging providers to
    report their accepted weaknesses.

    This row also has no identification date, which is why it is unmeasurable;
    both reasons are reported.
    """
    out = render_all([_Poam(id=5, identified_on=None)], today=TODAY, window=WINDOW)
    assert out.active == []
    assert out.accepted == []
    assert sorted(out.omitted) == [
        (5, "no identification date"),
        (5, "not measurable as accepted or not"),
    ]


def test_the_counts_partition_every_row_considered() -> None:
    """A partition whose parts do not add up is how a row disappears silently."""
    rows = [
        _Poam(id=1, status="open"),
        _Poam(id=2, status="risk_accepted"),
        _Poam(id=3, source="assessment"),
        _Poam(id=4, scanner=None, source="scan", title=" ", weakness=None),
    ]
    out = render_all(rows, today=TODAY, window=WINDOW)
    assert sum(out.counts.values()) == len(rows)
    assert set(out.counts) == {"excluded_not_a_flaw", "rendered", "omitted"}
    assert out.counts["rendered"] == len(out.active) + len(out.accepted)


def test_one_row_with_several_faults_is_counted_once_and_reported_thrice() -> None:
    """`omitted_poam_ids` carries one tuple per (id, reason) pair, so a row
    tripping three rules appears three times -- but `counts["omitted"]` counts
    ROWS, or the sum invariant breaks.
    """
    row = _Poam(id=8, identified_on=None, scanner=None, source="scan", title=" ")
    out = render_all([row], today=TODAY, window=WINDOW)
    assert out.counts["omitted"] == 1
    assert len([pid for pid, _ in out.omitted if pid == 8]) >= 2


def test_an_empty_input_is_an_empty_rendering() -> None:
    out = render_all([], today=TODAY, window=WINDOW)
    assert out.active == [] and out.accepted == [] and out.omitted == []
    assert sum(out.counts.values()) == 0
```

The two reason strings are fixed vocabulary — `"not measurable as accepted or
not"` and the three from Task 1. Task 4's tests assert them verbatim, so do not
reword them.

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_cr26_ver_walk.py -q
```

Expected: `ImportError: cannot import name 'render_all'`.

- [ ] **Step 3: Write the implementation**

Append to `src/ccf/cr26/ver.py`:

```python
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..patching.sla import FLAW_SOURCES, accepted_weakness_state


@dataclass(frozen=True)
class VerRendering:
    """Every candidate row's destination, produced in ONE walk.

    Two passes over the same rows would let `active`, `accepted`, `omitted` and
    `counts` drift apart; the SDR split exactly this work and spent a review
    round merging it back. `counts` partitions the input, and its parts sum to
    the number of rows considered -- a partition that does not add up is how a
    row disappears without anyone noticing.
    """

    active: list[dict[str, Any]] = field(default_factory=list)
    accepted: list[dict[str, Any]] = field(default_factory=list)
    #: One tuple per (id, reason) pair, so a row failing three rules appears
    #: three times. `counts["omitted"]` counts ROWS.
    omitted: list[tuple[int, str]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def render_all(
    poams: Sequence[Any], *, today: date, window: RemediationWindow
) -> VerRendering:
    """Filter to flaws, partition accepted from not-accepted, render each.

    A row that is not scanner-derived is **out of scope**, not omitted: nothing
    is wrong with it, it simply is not a vulnerability (spec §2.1). Collapsing
    that into the omitted list would bury a real data gap among healthy rows.
    """
    out = VerRendering(
        counts={"excluded_not_a_flaw": 0, "rendered": 0, "omitted": 0}
    )
    for poam in poams:
        if (poam.source or "") not in FLAW_SOURCES:
            out.counts["excluded_not_a_flaw"] += 1
            continue

        reasons: list[str] = []
        state = accepted_weakness_state(poam, today=today)
        if state == "unknown":
            # Neither document. `active` means "not accepted", which is the
            # favourable answer for a row nobody can measure.
            reasons.append("not measurable as accepted or not")

        detail, render_reasons = render_vulnerability(poam, today=today, window=window)
        reasons.extend(render_reasons)

        if reasons or detail is None:
            out.counts["omitted"] += 1
            out.omitted.extend((poam.id, reason) for reason in reasons)
            continue

        out.counts["rendered"] += 1
        (out.accepted if state == "accepted" else out.active).append(detail)
    return out
```

- [ ] **Step 4: Run to verify pass**

```bash
python -m pytest tests/test_cr26_ver_walk.py tests/test_cr26_ver_render.py -q
```

- [ ] **Step 5: Prove the guards**

| # | Mutation | Must fail |
|---|---|---|
| 1 | drop the `FLAW_SOURCES` filter | `test_a_control_deficiency_is_not_a_vulnerability_and_is_not_a_defect` |
| 2 | count a non-flaw as `omitted` instead of `excluded_not_a_flaw` | same test |
| 3 | let `unknown` fall through into `active` | `test_an_unmeasurable_row_reaches_neither_document` |
| 4 | `out.counts["omitted"] += len(reasons)` | `test_the_counts_partition_every_row_considered` |

- [ ] **Step 6: Lint, type-check, commit**

```bash
ruff check . && mypy src && alembic heads
git add src/ccf/cr26/ver.py tests/test_cr26_ver_walk.py
git commit -m "feat(cr26): one walk partitioning POA&Ms into the VER family's two halves"
```

---

### Task 3: `merge_accepted` — preserve the authored rationale

**Files:**
- Modify: `src/ccf/cr26/ver.py`
- Test: `tests/test_cr26_ver_merge.py`

**Interfaces:**
- Produces: `merge_accepted(authored: Sequence[dict[str, Any]], derived: Sequence[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[tuple[int, str]]]`

**Read `ccf.cr26.sdr.merge_indicators` before writing this.** It has been
through five review rounds; its aliasing, ordering and self-healing behaviour
are settled. Mirror them rather than rediscovering them.

- [ ] **Step 1: Write the failing tests**

```python
"""Keep the human's acceptance rationale; refresh everything else."""

from __future__ import annotations

from ccf.cr26.ver import merge_accepted


def _detail(pid: str, desc: str = "Outdated OpenSSL") -> dict:
    return {
        "providerTrackingId": pid,
        "detection": {"detectedAt": "2026-09-01T00:00:00Z", "detectionSource": "nessus"},
        "vulnerabilityDescription": desc,
    }


def test_an_authored_rationale_survives_and_the_detail_refreshes() -> None:
    authored = [
        {
            "vulnerabilityDetail": _detail("1", "STALE description"),
            "acceptanceRationale": "Compensating control: WAF rule 91234.",
        }
    ]
    merged, omitted = merge_accepted(authored, [_detail("1", "Outdated OpenSSL")])
    assert omitted == []
    assert merged == [
        {
            "vulnerabilityDetail": _detail("1", "Outdated OpenSSL"),
            "acceptanceRationale": "Compensating control: WAF rule 91234.",
        }
    ]


def test_a_derived_entry_with_no_authored_rationale_is_omitted_and_named() -> None:
    """`acceptanceRationale` is REQUIRED. Emitting "" would be the CPO's
    empty-description defect: a value that validates and asserts the provider
    gave a blank reason for accepting a vulnerability.
    """
    merged, omitted = merge_accepted([], [_detail("7")])
    assert merged == []
    assert omitted == [(7, "no acceptance rationale")]


def test_a_blank_authored_rationale_is_no_rationale() -> None:
    authored = [{"vulnerabilityDetail": _detail("7"), "acceptanceRationale": "   "}]
    merged, omitted = merge_accepted(authored, [_detail("7")])
    assert merged == []
    assert omitted == [(7, "no acceptance rationale")]


def test_entries_are_ordered_by_tracking_id_not_by_input_order() -> None:
    """Input is deliberately REVERSED. Do not "tidy" it to ascending -- that is
    what makes this test able to fail.
    """
    authored = [
        {"vulnerabilityDetail": _detail(p), "acceptanceRationale": f"r{p}"}
        for p in ("30", "4", "200")
    ]
    derived = [_detail(p) for p in ("30", "4", "200")]
    merged, _ = merge_accepted(authored, derived)
    assert [e["vulnerabilityDetail"]["providerTrackingId"] for e in merged] == [
        "4",
        "30",
        "200",
    ]


def test_an_authored_entry_the_scanner_no_longer_reports_is_dropped_and_named() -> None:
    """A vulnerability that is no longer accepted -- remediated, or reopened --
    must leave the accepted list. Keeping it would report a resolved weakness
    as still accepted.
    """
    authored = [{"vulnerabilityDetail": _detail("99"), "acceptanceRationale": "r"}]
    merged, omitted = merge_accepted(authored, [])
    assert merged == []
    assert omitted == [(99, "no longer an accepted vulnerability")]


def test_the_merge_does_not_alias_its_inputs() -> None:
    """Mutating the result must not reach back into the caller's dicts. The SDR
    needed two rounds on exactly this, including the dicts nested inside.
    """
    derived = [_detail("1")]
    authored = [{"vulnerabilityDetail": _detail("1"), "acceptanceRationale": "r"}]
    merged, _ = merge_accepted(authored, derived)
    merged[0]["vulnerabilityDetail"]["detection"]["detectionSource"] = "MUTATED"
    assert derived[0]["detection"]["detectionSource"] == "nessus"
    assert authored[0]["vulnerabilityDetail"]["detection"]["detectionSource"] == "nessus"
```

- [ ] **Step 2: Run to verify failure**

Expected: `ImportError: cannot import name 'merge_accepted'`.

- [ ] **Step 3: Write the implementation**

```python
import copy


def _tracking_id(entry: Any) -> str | None:
    """The id an entry is keyed on, or ``None`` if it has none."""
    if not isinstance(entry, dict):
        return None
    detail = entry.get("vulnerabilityDetail")
    if not isinstance(detail, dict):
        return None
    value = detail.get("providerTrackingId")
    return None if is_blank(value) else str(value).strip()


def merge_accepted(
    authored: Sequence[dict[str, Any]], derived: Sequence[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[tuple[int, str]]]:
    """Refresh each accepted vulnerability, keeping its authored rationale.

    ``acceptanceRationale`` is the one field the platform cannot derive -- no
    POA&M column holds it -- so an admin authors it into the stored document
    and every re-seed preserves it, exactly as the SDR preserves
    ``ksiImplementation``.

    An entry with no rationale is **omitted and named**, never emitted with
    ``""``: the empty string validates while asserting the provider gave a
    blank reason for accepting a vulnerability.

    Entries are ordered by numeric tracking id so a re-seed produces a
    byte-identical document when nothing has changed.
    """
    by_id = {
        tid: entry
        for entry in authored
        if (tid := _tracking_id(entry)) is not None
    }
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []
    omitted: list[tuple[int, str]] = []

    for detail in derived:
        tid = detail.get("providerTrackingId")
        if is_blank(tid):
            continue
        tid = str(tid).strip()
        seen.add(tid)
        rationale = (by_id.get(tid) or {}).get("acceptanceRationale")
        if is_blank(rationale):
            omitted.append((int(tid), "no acceptance rationale"))
            continue
        merged.append(
            {
                "vulnerabilityDetail": copy.deepcopy(detail),
                "acceptanceRationale": str(rationale).strip(),
            }
        )

    for tid in by_id:
        if tid not in seen:
            omitted.append((int(tid), "no longer an accepted vulnerability"))

    merged.sort(key=lambda e: int(e["vulnerabilityDetail"]["providerTrackingId"]))
    omitted.sort()
    return merged, omitted
```

- [ ] **Step 4: Run to verify pass**

- [ ] **Step 5: Prove the guards**

| # | Mutation | Must fail |
|---|---|---|
| 1 | emit `""` instead of omitting when the rationale is blank | both no-rationale tests |
| 2 | `is_blank(rationale)` → `rationale is None` | `test_a_blank_authored_rationale_is_no_rationale` |
| 3 | drop the `sort` | `test_entries_are_ordered_by_tracking_id_not_by_input_order` |
| 4 | `copy.deepcopy(detail)` → `detail` | `test_the_merge_does_not_alias_its_inputs` |
| 5 | drop the no-longer-accepted loop | `test_an_authored_entry_the_scanner_no_longer_reports_is_dropped_and_named` |

- [ ] **Step 6: Lint, type-check, commit**

```bash
ruff check . && mypy src && alembic heads
git add src/ccf/cr26/ver.py tests/test_cr26_ver_merge.py
git commit -m "feat(cr26): preserve the authored acceptance rationale across re-seeds"
```

---

### Task 4: The three seeders

**Files:**
- Modify: `src/ccf/cr26/ver.py`
- Test: `tests/test_cr26_ver_seed.py`

**Interfaces:**
- Consumes: `render_all`, `merge_accepted`; `ccf.cr26.store.put_document`
- Produces:
  - `@dataclass(frozen=True) class VerSeedResult` with
    `document: Cr26Document`, `omitted_poam_ids: list[tuple[int, str]]`,
    `counts: dict[str, int]`
  - `seed_vdr(session, *, system_id, period_from, period_to) -> VerSeedResult`
  - `seed_avi(session, *, system_id, period_from, period_to) -> VerSeedResult`
  - `seed_ver_history(session, *, system_id) -> VerSeedResult`

**The requirement that cost the SDR five review rounds:** assert
`validation_errors` by **exact equality**, on a document containing a **real
entry**. A fixture whose arrays are empty pins nothing.

- [ ] **Step 1: Write the failing tests**

```python
"""The three seeders, end to end against the database and the real validator."""

from __future__ import annotations

from datetime import UTC, date, datetime

from ccf.cr26.store import put_document
from ccf.cr26.ver import seed_avi, seed_vdr, seed_ver_history
from ccf.db import session_scope
from ccf.models import POAM, Organization, System

FROM = datetime(2026, 9, 1, tzinfo=UTC)
TO = datetime(2026, 12, 1, tzinfo=UTC)
ONE_ERROR = ["<root>: 'certificationPackageOverviewUri' is a required property"]


async def _system(name: str) -> tuple[int, int]:
    """``(org_id, system_id)``. The org id is returned because Task 5's route
    tests need it to build a principal, and one helper is better than two."""
    async with session_scope() as s:
        org = Organization(name=f"{name} org")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=name, baseline="moderate")
        s.add(system)
        await s.flush()
        return org.id, system.id


async def _poam(system_id: int, **kw) -> int:
    async with session_scope() as s:
        row = POAM(
            system_id=system_id,
            title=kw.get("title", "Outdated OpenSSL"),
            severity=kw.get("severity", "high"),
            status=kw.get("status", "open"),
            identified_on=kw.get("identified_on", date(2026, 9, 5)),
            scanner=kw.get("scanner", "nessus"),
            source=kw.get("source", "scan"),
        )
        s.add(row)
        await s.flush()
        return row.id


async def test_a_seeded_vdr_is_invalid_for_exactly_one_reason() -> None:
    """The document carries a REAL vulnerability, so every rendered field goes
    through the validator. The SDR asserted this only on empty arrays and its
    whole derived half went unvalidated for three review rounds.
    """
    _org_id, system_id = await _system("vdr-one")
    await _poam(system_id)
    async with session_scope() as s:
        result = await seed_vdr(s, system_id=system_id, period_from=FROM, period_to=TO)
    assert len(result.document.document["vulnerabilities"]) == 1
    assert result.document.validation_errors == ONE_ERROR, result.document.validation_errors
    assert result.document.is_valid is False


async def test_a_vdr_records_the_period_the_caller_asked_for() -> None:
    """Nothing in the platform records what a previous report covered, so
    VER-RPT-PER's chaining is the operator's obligation and the period is an
    argument. The document states the window it actually covered.
    """
    _org_id, system_id = await _system("vdr-period")
    async with session_scope() as s:
        result = await seed_vdr(s, system_id=system_id, period_from=FROM, period_to=TO)
    assert result.document.document["reportPeriod"] == {
        "from": "2026-09-01T00:00:00Z",
        "to": "2026-12-01T00:00:00Z",
    }


async def test_an_accepted_weakness_leaves_the_vdr_and_enters_the_avi() -> None:
    _org_id, system_id = await _system("split")
    open_id = await _poam(system_id, status="open")
    accepted_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        vdr = await seed_vdr(s, system_id=system_id, period_from=FROM, period_to=TO)
    ids = [v["providerTrackingId"] for v in vdr.document.document["vulnerabilities"]]
    assert ids == [str(open_id)]
    assert str(accepted_id) not in ids


async def test_an_avi_omits_a_vulnerability_with_no_authored_rationale() -> None:
    _org_id, system_id = await _system("avi-none")
    poam_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        result = await seed_avi(s, system_id=system_id, period_from=FROM, period_to=TO)
    assert result.document.document["acceptedVulnerabilities"] == []
    assert (poam_id, "no acceptance rationale") in result.omitted_poam_ids


async def test_an_authored_rationale_survives_a_reseed_and_the_document_validates() -> None:
    """The one place the accepted half reaches the validator with content in
    it. Exact equality, not a membership check: the claim is ONE reason.
    """
    _org_id, system_id = await _system("avi-keep")
    poam_id = await _poam(system_id, status="risk_accepted")
    async with session_scope() as s:
        await seed_avi(s, system_id=system_id, period_from=FROM, period_to=TO)

    async with session_scope() as s:
        row = await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "reportPeriod": {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"},
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {
                            "providerTrackingId": str(poam_id),
                            "detection": {
                                "detectedAt": "1999-01-01T00:00:00Z",
                                "detectionSource": "STALE",
                            },
                            "vulnerabilityDescription": "STALE",
                        },
                        "acceptanceRationale": "Compensating control: WAF rule 91234.",
                    }
                ],
            },
        )
        assert row is not None

    async with session_scope() as s:
        result = await seed_avi(s, system_id=system_id, period_from=FROM, period_to=TO)

    entries = result.document.document["acceptedVulnerabilities"]
    assert len(entries) == 1
    assert entries[0]["acceptanceRationale"] == "Compensating control: WAF rule 91234."
    assert entries[0]["vulnerabilityDetail"]["detection"]["detectedAt"] == "2026-09-05T00:00:00Z"
    assert entries[0]["vulnerabilityDetail"]["detection"]["detectionSource"] == "nessus"
    assert result.document.validation_errors == ONE_ERROR, result.document.validation_errors


async def test_ver_history_carries_both_halves_and_a_generated_at() -> None:
    _org_id, system_id = await _system("hist")
    await _poam(system_id, status="open")
    async with session_scope() as s:
        result = await seed_ver_history(s, system_id=system_id)
    body = result.document.document
    assert len(body["activeVulnerabilities"]) == 1
    assert body["acceptedVulnerabilities"] == []
    assert body["generatedAt"].endswith("Z")
    assert "reportPeriod" not in body
    assert result.document.validation_errors == ONE_ERROR


async def test_a_cpo_uri_already_in_the_document_survives_a_reseed() -> None:
    """Never invented, always carried forward -- as in the SDR."""
    _org_id, system_id = await _system("uri")
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system_id,
            kind="vdr",
            document={
                "certificationPackageOverviewUri": "https://example.gov/cpo.json",
                "reportPeriod": {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"},
                "vulnerabilities": [],
            },
        )
    async with session_scope() as s:
        result = await seed_vdr(s, system_id=system_id, period_from=FROM, period_to=TO)
    assert (
        result.document.document["certificationPackageOverviewUri"]
        == "https://example.gov/cpo.json"
    )
    assert result.document.validation_errors == []
    assert result.document.is_valid is True


async def test_counts_partition_every_row_the_seeder_considered() -> None:
    _org_id, system_id = await _system("counts")
    await _poam(system_id, status="open")
    await _poam(system_id, source="assessment")
    await _poam(system_id, identified_on=None)
    async with session_scope() as s:
        result = await seed_vdr(s, system_id=system_id, period_from=FROM, period_to=TO)
    assert sum(result.counts.values()) == 3
    assert result.counts["excluded_not_a_flaw"] == 1


async def test_another_systems_poams_never_reach_this_document() -> None:
    """App-layer scoping is the primary defence: RLS on this table is
    ORG-scoped, so a dropped filter leaks between systems inside one tenant
    regardless, and an unscoped principal bypasses RLS entirely.
    """
    _org_a, a = await _system("tenant-a")
    _org_b, b = await _system("tenant-b")
    mine = await _poam(a, title="MINE")
    await _poam(b, title="THEIRS")
    async with session_scope() as s:
        result = await seed_vdr(s, system_id=a, period_from=FROM, period_to=TO)
    descriptions = [
        v["vulnerabilityDescription"] for v in result.document.document["vulnerabilities"]
    ]
    assert descriptions == ["MINE"]
    assert [v["providerTrackingId"] for v in result.document.document["vulnerabilities"]] == [str(mine)]
```

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Write the implementation**

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM
from ..models_cr26 import Cr26Document
from .store import put_document


def _instant(value: datetime) -> str:
    """A UTC instant in the shape the schemas use.

    `format: date-time` is NOT enforced here (spec §4), so this function is the
    only thing standing between a malformed value and the deliverable.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class VerSeedResult:
    """What one seed produced, and what it could not say.

    `omitted_poam_ids` is the deliverable's own to-do list and is worth more to
    an operator than the document beside it -- nothing in the document says a
    vulnerability was left out.
    """

    document: Cr26Document
    omitted_poam_ids: list[tuple[int, str]]
    counts: dict[str, int]


async def _poam_rows(session: AsyncSession, system_id: int) -> list[POAM]:
    """EVERY POA&M for this system, flaws and control deficiencies alike.

    The flaw filter deliberately lives downstream in :func:`render_all`, not in
    this query: `counts["excluded_not_a_flaw"]` can only be reported by code
    that SEES the excluded rows. Filtering here would make the exclusion
    invisible and the count a lie. Do not "optimise" it into the WHERE clause.
    """
    return list(
        (
            await session.execute(
                select(POAM).where(POAM.system_id == system_id).order_by(POAM.id.asc())
            )
        ).scalars()
    )


async def _current(session: AsyncSession, system_id: int, kind: str) -> dict[str, Any]:
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == kind
            )
        )
    ).scalars().first()
    return dict(row.document) if row is not None and row.document else {}


def _carry_uri(document: dict[str, Any], current: dict[str, Any]) -> None:
    """Keep an authored CPO URI. Never invent one -- the document stays invalid
    until a CPO is published, which is the honest state."""
    uri = current.get("certificationPackageOverviewUri")
    if not is_blank(uri):
        document["certificationPackageOverviewUri"] = str(uri).strip()


async def _seed(
    session: AsyncSession,
    *,
    system_id: int,
    kind: str,
    build: Any,
    today: date | None = None,
) -> VerSeedResult:
    today = today or datetime.now(UTC).date()
    rows = await _poam_rows(session, system_id)
    rendering = render_all(rows, today=today, window=RemediationWindow())
    current = await _current(session, system_id, kind)
    document, extra_omitted = build(rendering, current)
    _carry_uri(document, current)
    stored = await put_document(
        session, system_id=system_id, kind=kind, document=document
    )
    return VerSeedResult(
        document=stored,
        omitted_poam_ids=sorted(rendering.omitted + extra_omitted),
        counts=dict(rendering.counts),
    )


async def seed_vdr(
    session: AsyncSession,
    *,
    system_id: int,
    period_from: datetime,
    period_to: datetime,
) -> VerSeedResult:
    """Non-accepted vulnerabilities for the caller's reporting period."""

    def build(rendering: VerRendering, _current: dict[str, Any]):
        return {
            "reportPeriod": {
                "from": _instant(period_from),
                "to": _instant(period_to),
            },
            "vulnerabilities": rendering.active,
        }, []

    return await _seed(session, system_id=system_id, kind="vdr", build=build)


async def seed_avi(
    session: AsyncSession,
    *,
    system_id: int,
    period_from: datetime,
    period_to: datetime,
) -> VerSeedResult:
    """Accepted vulnerabilities, keeping each authored acceptance rationale."""

    def build(rendering: VerRendering, current: dict[str, Any]):
        authored = current.get("acceptedVulnerabilities")
        merged, omitted = merge_accepted(
            authored if isinstance(authored, list) else [], rendering.accepted
        )
        return {
            "reportPeriod": {
                "from": _instant(period_from),
                "to": _instant(period_to),
            },
            "acceptedVulnerabilities": merged,
        }, omitted

    return await _seed(session, system_id=system_id, kind="avi", build=build)


async def seed_ver_history(
    session: AsyncSession, *, system_id: int
) -> VerSeedResult:
    """Both halves at once. No period -- the schema has none, and carries
    ``generatedAt`` instead."""

    def build(rendering: VerRendering, current: dict[str, Any]):
        authored = current.get("acceptedVulnerabilities")
        merged, omitted = merge_accepted(
            authored if isinstance(authored, list) else [], rendering.accepted
        )
        return {
            "generatedAt": _instant(datetime.now(UTC)),
            "activeVulnerabilities": rendering.active,
            "acceptedVulnerabilities": merged,
        }, omitted

    return await _seed(session, system_id=system_id, kind="ver_history", build=build)
```

Add `from datetime import UTC, datetime` to the module's imports.

- [ ] **Step 4: Run to verify pass**

```bash
python -m pytest tests/test_cr26_ver_seed.py -q
```

- [ ] **Step 5: Prove the guards**

| # | Mutation | Must fail |
|---|---|---|
| 1 | drop `.where(POAM.system_id == system_id)` | `test_another_systems_poams_never_reach_this_document` |
| 2 | `_instant` emits `value.isoformat()` | `test_a_vdr_records_the_period_the_caller_asked_for` |
| 3 | `_carry_uri` becomes a no-op | `test_a_cpo_uri_already_in_the_document_survives_a_reseed` |
| 4 | `seed_avi` passes `[]` as `authored` | `test_an_authored_rationale_survives_a_reseed_and_the_document_validates` |
| 5 | `seed_ver_history` adds a `reportPeriod` key | `test_ver_history_carries_both_halves_and_a_generated_at` |

Mutation 2 is the one that proves spec §4: the mutated value still validates
(`ok: True`), and only the exact-string assertion catches it. **Say so in your
report** — note whether any test other than the named one failed.

- [ ] **Step 6: Lint, type-check, commit**

```bash
ruff check . && mypy src && alembic heads
git add src/ccf/cr26/ver.py tests/test_cr26_ver_seed.py
git commit -m "feat(cr26): seed the VDR, AVI and historical VER documents"
```

---

### Task 5: The three routes

**Files:**
- Modify: `src/ccf/api/routes/cr26.py`
- Test: `tests/test_cr26_ver_seed.py` (append)

**Interfaces:**
- Consumes: `seed_vdr`, `seed_avi`, `seed_ver_history`, `VerSeedResult`

Mirror `seed_sdr_document` in the same file exactly — `require_role(*AUTHOR_ROLES)`,
then `_owned_system`, then the seeder, then `session.commit()` and
`session.refresh(result.document)`.

**Every field of `VerSeedResult` must be asserted in a route test.** On the
SDR, deleting two result fields from the route handler left the entire suite
green, and those fields were the only operator-facing signal that a control was
unwritten.

- [ ] **Step 1: Write the failing tests**

`tests/test_cr26_sdr_seed.py:520-533` already has the harness. **Copy that
`_Session` class into this file** (it is nine lines and the two files are
independent) rather than importing across test modules:

```python
from httpx import ASGITransport, AsyncClient

from ccf.api.app import create_app
from ccf.api.deps import Principal, get_principal


class _Session:
    """A client whose identity and role can change between calls."""

    def __init__(self, *, org_id: int | None = None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email="isso@acme.gov", org_id=self.org_id, role=self.role)

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")
```

Confirm the import paths against `tests/test_cr26_sdr_seed.py`'s own import
block before using them — do not assume `ccf.api.app` / `ccf.api.deps`.

```python
PERIOD = {"from": "2026-09-01T00:00:00Z", "to": "2026-12-01T00:00:00Z"}


async def test_the_vdr_route_reports_every_result_field_to_the_caller() -> None:
    """Both result fields must cross the HTTP boundary. They are the ENTIRE
    operator-facing signal that a vulnerability was left out -- nothing in the
    document says so -- and on the SDR, deleting the equivalent two lines from
    the route left every dataclass-level assertion green.
    """
    org_id, system_id = await _system("route-vdr")
    await _poam(system_id, status="open")
    await _poam(system_id, source="assessment")
    omitted_id = await _poam(system_id, identified_on=None)
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=PERIOD
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kind"] == "vdr"
    assert body["counts"]["excluded_not_a_flaw"] == 1
    assert [omitted_id, "no identification date"] in body["omitted_poam_ids"]
    assert len(body["document"]["vulnerabilities"]) == 1


async def test_an_inverted_period_is_refused() -> None:
    """A report whose window runs backwards states an impossible period."""
    org_id, system_id = await _system("route-inverted")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed",
            json={"from": "2026-12-01T00:00:00Z", "to": "2026-09-01T00:00:00Z"},
        )
    assert resp.status_code == 422, resp.text


async def test_a_non_admin_cannot_seed_a_vdr() -> None:
    """`control_owner` rather than `viewer`, so this distinguishes the write
    gate from the read gate. Authoring a CR26 deliverable is admin only."""
    org_id, system_id = await _system("route-role")
    async with _Session(org_id=org_id, role="control_owner").client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=PERIOD
        )
    assert resp.status_code == 403, resp.text


async def test_another_tenants_system_is_404_not_403() -> None:
    """Seeded as the owner first, so this exercises a path that would otherwise
    return 200 -- a 404 against a system that never existed proves nothing."""
    owner_org, system_id = await _system("route-other")
    other_org, _ = await _system("route-intruder")
    async with _Session(org_id=owner_org).client() as c:
        first = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=PERIOD
        )
    assert first.status_code == 200, first.text

    async with _Session(org_id=other_org).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/vdr/seed", json=PERIOD
        )
    assert resp.status_code == 404, resp.text


async def test_the_ver_history_route_takes_no_period() -> None:
    org_id, system_id = await _system("route-hist")
    await _poam(system_id, status="open")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(
            f"/api/systems/{system_id}/cr26-documents/ver_history/seed"
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "reportPeriod" not in body["document"]
    assert body["document"]["generatedAt"].endswith("Z")
    assert len(body["document"]["activeVulnerabilities"]) == 1
```

Note `[omitted_id, "no identification date"]` is a **list**, not a tuple: JSON
has no tuples, so the round-trip turns each pair into a list. Asserting a tuple
there fails for a reason that has nothing to do with the code.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Write the routes**

```python
class VerPeriod(BaseModel):
    """The reporting window, supplied by the caller.

    Nothing in the platform records what a previous report covered, so
    VER-RPT-PER's "all activity since the previous report" is an obligation on
    the operator. The document records the window it actually covered.
    """

    model_config = ConfigDict(populate_by_name=True)

    period_from: datetime = Field(alias="from")
    period_to: datetime = Field(alias="to")

    @model_validator(mode="after")
    def _ordered(self) -> "VerPeriod":
        if self.period_from >= self.period_to:
            raise ValueError("'from' must be strictly before 'to'")
        return self


def _ver_body(result: VerSeedResult) -> dict[str, Any]:
    return {
        **_full(result.document),
        "omitted_poam_ids": result.omitted_poam_ids,
        "counts": result.counts,
    }


@router.post("/systems/{system_id}/cr26-documents/vdr/seed")
async def seed_vdr_document(
    system_id: int,
    period: VerPeriod,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed this system's Vulnerability Detail Report. Admin only."""
    await _owned_system(session, system_id, principal)
    result = await seed_vdr(
        session,
        system_id=system_id,
        period_from=period.period_from,
        period_to=period.period_to,
    )
    await session.commit()
    await session.refresh(result.document)
    return _ver_body(result)
```

Write `seed_avi_document` and `seed_ver_history_document` the same way.
`seed_ver_history_document` takes **no** body and calls `seed_ver_history`.

`ver_history` keeps its underscore in the path: it is the only kind in
`CR26_KINDS` containing one, and the generic `GET`/`PUT` `/{kind}` routes take
the kind verbatim, so a hyphen would disagree with the read path for the same
document.

- [ ] **Step 4: Run to verify pass**

- [ ] **Step 5: Prove the guards**

| # | Mutation | Must fail |
|---|---|---|
| 1 | delete `"omitted_poam_ids"` from `_ver_body` | the VDR route test |
| 2 | delete `"counts"` from `_ver_body` | the VDR route test |
| 3 | drop the `_ordered` validator | `test_an_inverted_period_is_refused` |
| 4 | `require_role(*AUTHOR_ROLES)` → no role dependency | `test_a_non_admin_cannot_seed_a_vdr` |
| 5 | call the seeder before `_owned_system` | `test_another_tenants_system_is_404_not_403` |

- [ ] **Step 6: Lint, type-check, commit**

```bash
ruff check . && mypy src && alembic heads
git add src/ccf/api/routes/cr26.py tests/test_cr26_ver_seed.py
git commit -m "feat(cr26): expose the three VER-family seed endpoints, admin only"
```

---

## Notes for the executor

- **The renderer is where the risk is.** Task 1 and Task 2 hold every decision
  that can misreport something to a regulator. Tasks 4 and 5 are plumbing.
- **A comment saying "we deliberately do NOT do X" is a claim and needs a
  test.** On the SDR, the rule "a blank part is not a dropped part" was
  documented twice, tested nowhere, and could be *inverted* with the suite
  green. The usual trap is a guard you can delete green; this is its mirror.
- **Do not trust a green suite as evidence that a value is right.** `format:
  date-time` is unenforced here, so a malformed `detectedAt` produces
  `ok: True, errors: []`. Assert the string.
- **If you find the spec wrong, say so and stop.** The SDR spec was corrected
  four times, every time because the implementer measured something the spec
  had asserted from memory. That is the single most valuable thing an
  implementer on this programme does.
