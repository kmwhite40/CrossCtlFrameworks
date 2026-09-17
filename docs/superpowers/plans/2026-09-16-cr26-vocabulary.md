# CR26 Vocabulary Implementation Plan (P9a-i)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach the platform CR26's vocabulary — Certification Class and Path as independent axes on a system, and Accepted Weakness as a derived classification of an existing POA&M — without adding a second record of any fact.

**Architecture:** Two nullable columns on `System`, derived from nothing. One pure function in `patching/sla.py` classifying a POA&M as an Accepted Weakness under the 192-day rule, reusing that module's already-reviewed boundary semantics. One correctness fix where `risk_accepted` currently reads as an SLA breach. No new table, no new dependency, no new service.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async, Alembic, pytest. **No new dependencies.**

**Spec:** `docs/superpowers/specs/2026-09-16-cr26-vocabulary-design.md`

## Global Constraints

- **Nothing may derive `certification_class` from `baseline`, or `baseline` from `certification_class`.** FedRAMP states Classes are not one-for-one replacements for impact levels, and the published adequacy ranges overlap, so any derivation is wrong in both directions.
- **No new table, no second writer.** `POAM` stays the single record of a provider-side weakness. Accepted Weakness is a classification of that row.
- **The two halves of the union are disjoint:** declared is `status == "risk_accepted"` at any age; elapsed is `status in POAM_ACTIVE_STATUSES` past 192 days. `POAM_ACTIVE_STATUSES` excludes `risk_accepted` by design — see the comment block at `src/ccf/constants.py:90-113`, which explains why the two "open" sets must not be collapsed.
- **Reuse `sla.py`'s boundary semantics exactly.** Inclusive at the limit — "an organization that says 30 days means 30, not 29", so 192 means 192. `unknown` for a missing `identified_on`. **A reopened POA&M carrying a stale `closed_on` is never treated as resolved** — shipping that backwards was a Critical in the flaw-remediation work.
- **`ACCEPTED_WEAKNESS_DAYS = 192`**, a module constant, never a literal at a call site.
- **The 192 days run from *evaluation*; the code keys to `identified_on`.** That substitution is an explicit assumption to record in the docstring and confirm against the VER ruleset when it publishes — never a silent equivalence. If they differ, only the key changes.
- Current migration head is `0077_cci_source_spine`. Chain from it, carry the `pg_roles` GRANT guard used since `0054`, and confirm **exactly one head** with the FULL `alembic heads` output — three migrations in this programme forked by chaining off a renamed or duplicate revision, and one of those errored all 1,992 tests.
- **Every new test must be able to fail.** This programme produced at least seven that could not. Where a task says to prove a guard bites, actually break the rule, watch the failure, and revert.
- Test command — the default `pytest` hits the WRONG database (`.env` points at port 5432, another project's container):

```
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
.venv/bin/python3 -m pytest -q
```

  Pass an explicit long timeout (e.g. 900000) on any full-suite run — it takes 110–190s, and a run started without one is auto-backgrounded past the 120s tool timeout and never reports back. Run one pytest session at a time. If every test ERRORs (not fails) with `Can't locate revision` or `Multiple head revisions`, the shared DB is stamped at another branch's migration; recreate it:

```
.venv/bin/python3 -c "import psycopg; c=psycopg.connect('postgresql://ccf:ccf@localhost:5434/postgres', autocommit=True); c.execute(\"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='ccf_test' AND pid<>pg_backend_pid()\"); c.execute('DROP DATABASE IF EXISTS ccf_test'); c.execute('CREATE DATABASE ccf_test OWNER ccf')"
```

- `ruff check .` and `mypy src` clean at the end of every task.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/ccf/patching/sla.py` | gains `ACCEPTED_WEAKNESS_DAYS`, `is_accepted_weakness`; `SLA_BUCKETS` and `classify` gain `accepted` | 1, 2 |
| `tests/test_accepted_weakness.py` | the 192-day rule and the disjoint union | 1 |
| `tests/test_patching_sla.py` | extended: `risk_accepted` is its own bucket | 2 |
| `src/ccf/constants.py` | `CERTIFICATION_CLASSES`, `CERTIFICATION_PATHS` + why they are not impact levels | 3 |
| `src/ccf/models.py` | `System.certification_class`, `System.certification_path` | 3 |
| `migrations/versions/0078_cr26_certification.py` | the two nullable columns | 3 |
| `tests/test_cr26_certification_columns.py` | persistence, nullability, independence from `baseline` | 3 |
| `tests/test_certification_class_is_independent.py` | AST guard: no code derives one axis from the other | 4 |
| `docs/architecture/forge-capability-inventory.md` | records what CR26 support now means | 4 |

`sla.py` is the right home for Task 1 rather than a new module: the 192-day rule is a remediation-window question, it reuses that module's boundary semantics, and Task 2 changes the same function it sits beside. Splitting them across two files would put one rule in two places.

---

### Task 1: Accepted Weakness classification

The deadline-bound piece (VER mandatory 7 December 2026), and pure — no database, no migration.

**Files:**
- Modify: `src/ccf/patching/sla.py`
- Test: `tests/test_accepted_weakness.py` (create)

**Interfaces:**
- Consumes: `ccf.constants.POAM_ACTIVE_STATUSES` (NOT currently imported by `sla.py` — it imports only `POAM_CLOSED_STATUSES`; add it to that same import).
- Produces:
  - `ACCEPTED_WEAKNESS_DAYS: int = 192`
  - `def is_accepted_weakness(poam: Any, *, today: date) -> bool`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_accepted_weakness.py
"""CR26 Accepted Weakness: declared or elapsed.

The rule (Vulnerability Evaluation and Reporting) requires a provider to
categorize any vulnerability that "is not OR WILL NOT BE" fully mitigated or
remediated within 192 days of evaluation as an accepted vulnerability. Both
halves matter: "will not" is a forward-looking decision a provider can make on
day 3, which no elapsed-time arithmetic can represent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from ccf.constants import POAM_ACTIVE_STATUSES
from ccf.patching.sla import ACCEPTED_WEAKNESS_DAYS, is_accepted_weakness

TODAY = date(2026, 9, 16)


@dataclass
class _Poam:
    """Only the fields the classification reads."""

    status: str = "open"
    identified_on: date | None = None
    closed_on: date | None = None


def _aged(days: int, **kw: object) -> _Poam:
    """A POA&M identified exactly ``days`` ago."""
    return _Poam(identified_on=TODAY - timedelta(days=days), **kw)  # type: ignore[arg-type]


def test_the_threshold_is_the_rule_s_number() -> None:
    assert ACCEPTED_WEAKNESS_DAYS == 192


def test_declared_is_accepted_at_any_age() -> None:
    """The "will not be remediated" half: a provider may accept on day 3."""
    assert is_accepted_weakness(_aged(3, status="risk_accepted"), today=TODAY) is True


def test_elapsed_past_the_threshold_is_accepted() -> None:
    assert is_accepted_weakness(_aged(258, status="open"), today=TODAY) is True


def test_the_boundary_is_inclusive_like_classify() -> None:
    """192 means 192 -- sla.classify's stated convention, reused verbatim."""
    assert is_accepted_weakness(_aged(ACCEPTED_WEAKNESS_DAYS), today=TODAY) is False
    assert is_accepted_weakness(_aged(ACCEPTED_WEAKNESS_DAYS + 1), today=TODAY) is True


def test_in_progress_counts_as_backlog() -> None:
    """Work underway past the window is still an accepted weakness -- the rule
    is about elapsed time, not effort."""
    assert is_accepted_weakness(_aged(258, status="in_progress"), today=TODAY) is True


def test_a_closed_weakness_is_not_accepted() -> None:
    done = _aged(600, status="completed", closed_on=date(2025, 3, 1))
    assert is_accepted_weakness(done, today=TODAY) is False


def test_a_stale_closed_on_does_not_make_a_reopened_weakness_look_resolved() -> None:
    """Status is consulted before any closure date.

    Shipping this backwards was a Critical in the flaw-remediation work: a
    reopened POA&M read as closed_on_time and counted toward compliance. Here
    the row is open and 258 days old, so it IS accepted -- by the elapsed rule,
    never dismissed because a stale closed_on made it look resolved.
    """
    reopened = _aged(258, status="open", closed_on=TODAY - timedelta(days=254))
    assert is_accepted_weakness(reopened, today=TODAY) is True


def test_no_identified_on_is_never_accepted_by_elapsed_time() -> None:
    """Never invent a date: unknown age cannot satisfy a 192-day rule."""
    assert is_accepted_weakness(_Poam(status="open"), today=TODAY) is False


def test_but_an_undated_declared_weakness_is_still_accepted() -> None:
    """The declared half does not depend on a date at all."""
    assert is_accepted_weakness(_Poam(status="risk_accepted"), today=TODAY) is True


def test_the_two_halves_are_disjoint() -> None:
    """risk_accepted is excluded from POAM_ACTIVE_STATUSES by design, so an old
    accepted row is reached by the declared half alone."""
    assert "risk_accepted" not in POAM_ACTIVE_STATUSES
    assert is_accepted_weakness(_aged(600, status="risk_accepted"), today=TODAY) is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_accepted_weakness.py -q`
Expected: collection error — `ImportError: cannot import name 'ACCEPTED_WEAKNESS_DAYS' from 'ccf.patching.sla'`

- [ ] **Step 3: Write minimal implementation**

In `src/ccf/patching/sla.py`, widen the existing constants import:

```python
from ..constants import POAM_ACTIVE_STATUSES, POAM_CLOSED_STATUSES
```

Add the constant beside `FEDRAMP_TIMEFRAMES`:

```python
#: CR26 (Vulnerability Evaluation and Reporting): a provider MUST categorize any
#: vulnerability not -- or that will not be -- fully mitigated or remediated
#: within this many days of evaluation as an accepted vulnerability. Mandatory
#: for offerings obtaining or maintaining FedRAMP Certification from 2026-12-07.
ACCEPTED_WEAKNESS_DAYS = 192
```

And the function, after `classify`:

```python
def is_accepted_weakness(poam: Any, *, today: date) -> bool:
    """Is this weakness an Accepted Weakness under CR26?

    Two disjoint halves, because the rule says "is not **or will not be**"
    remediated within the window:

    - **declared** -- ``status == "risk_accepted"``, at any age, dated or not.
      This is the forward-looking half: a provider may accept a weakness on day
      3, and no elapsed-time arithmetic can represent a decision not yet made.
      A projection keyed only to age would report it as open remediation work
      for up to 191 days.
    - **elapsed** -- still in the remediation backlog past the window.

    The elapsed half is scoped to ``POAM_ACTIVE_STATUSES``, which *excludes*
    ``risk_accepted`` by design (see :mod:`ccf.constants`), so the halves cannot
    overlap and a row is reached by exactly one.

    Status is consulted before any closure date, matching :func:`classify`: a
    reopened weakness carrying a stale ``closed_on`` must not read as resolved.
    An unknown ``identified_on`` is never accepted by elapsed time -- this never
    invents a date.

    **Stated assumption:** the 192 days run from *evaluation*, and ``POAM``
    records ``identified_on``. These may not be the same act -- evaluation is
    VER-defined. ``identified_on`` is the closest existing field, and that
    substitution is an explicit assumption to confirm against the VER ruleset
    when it publishes, not a silent equivalence. If they differ, only the key
    changes; the shape of the rule does not.

    ``today`` is injected so the rule is testable at both boundaries, as
    everything else in this module is.
    """
    status = str(poam.status)
    if status == "risk_accepted":
        return True
    if status not in POAM_ACTIVE_STATUSES:
        return False
    if poam.identified_on is None:
        return False
    # Inclusive at the limit, like classify: 192 days means 192, not 191.
    return (today - poam.identified_on).days > ACCEPTED_WEAKNESS_DAYS
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_accepted_weakness.py -q` — expected: 10 passed.
Run: `.venv/bin/ruff check . && .venv/bin/mypy src` — expected: clean.

- [ ] **Step 5: Prove the boundary test bites**

Change `>` to `>=` in the return, re-run — expected: `test_the_boundary_is_inclusive_like_classify` FAILS. **Revert.** Paste both outputs in your report. A boundary test nobody has watched fail is the defect class this programme produced seven times.

Then note for your report: the disjointness is guaranteed by the *constant*, not by a test — swapping `POAM_ACTIVE_STATUSES` for `POAM_UNRESOLVED_STATUSES` here leaves every test green, because overlapping halves are invisible to a boolean return. That is why the constraint is written down rather than merely asserted.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/patching/sla.py tests/test_accepted_weakness.py
git commit -m "feat(cr26): classify a weakness as accepted, declared or elapsed

CR26 eliminates the provider-side POA&M and replaces it with a list of Accepted
Weaknesses. The rule covers a weakness that 'is not OR WILL NOT BE' remediated
within 192 days, so a projection keyed only to age would report an accepted
weakness as open remediation work for up to 191 days.

Declared (risk_accepted, any age) and elapsed (active backlog past 192 days)
are disjoint, because POAM_ACTIVE_STATUSES excludes risk_accepted by design.
No new table: POAM stays the single record and both lanes render from it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: `risk_accepted` stops reading as an SLA breach

A correctness fix the CR26 semantics force, and a divergence from a convention this repo already documents.

**Files:**
- Modify: `src/ccf/patching/sla.py` (`SLA_BUCKETS`, `classify`)
- Test: `tests/test_patching_sla.py` (extend)

**Interfaces:**
- Consumes: nothing from Task 1 — `classify` stays a pure bucket function and does NOT call `is_accepted_weakness`. The two answer different questions: `classify` buckets against an org's own remediation window, `is_accepted_weakness` applies FedRAMP's fixed 192 days. Wiring one through the other would silently bind an org's window to the federal one.
- Produces: `SLA_BUCKETS` gains `"accepted"`. **No `SlaReport` change is needed** — `buckets` is a `dict[str, int]` built with `dict.fromkeys(SLA_BUCKETS, 0)`, and `by_severity` likewise, so a new bucket propagates everywhere by itself, `as_dict()` included.

**Why:** `classify` currently returns `breached` for a `risk_accepted` row past its window and adds it to `breaching_ids`; a *young* accepted row returns `within_sla` and counts as compliant. `src/ccf/constants.py:90-113` states the convention plainly — `POAM_ACTIVE_STATUSES` is the remediation backlog and excludes `risk_accepted` because it is risk leadership has formally accepted rather than work still to do — and `analytics/posture.py` already buckets it separately. `sla.py` diverged. Under CR26 the divergence is not cosmetic: an accepted weakness is the outcome the rule defines, not an SLA failure.

**Two judgements to implement exactly as written, not re-decided:**

1. **The `risk_accepted` branch goes FIRST in `classify`, above the `identified_on is None` guard.** The bucket does not depend on a date, and `is_accepted_weakness` returns True for an undated accepted row; a row those two functions disagree about is precisely the divergence this task exists to end.
2. **`accepted` stays in the `compliance_pct` denominator and out of its numerator.** An accepted weakness was not remediated within the timeframe, so it is not compliant with one — but excluding it from the denominator would let an organization improve its SI-2 score by accepting risk, the gaming the module's own docstring refuses for `unknown`. This follows from `compliant = within_sla + closed_on_time` and needs no code change. **It lowers `compliance_pct` for any org holding young accepted rows** (previously `within_sla`); that is the correction, not a regression.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_patching_sla.py`, and add `is_accepted_weakness` to nothing — this file needs no new imports beyond what it has (`SLA_BUCKETS`, `classify`, `measure`, `_Poam`, `_open`, `_closed`, `TODAY`, `timedelta` are all already there, as is `WINDOW` — the module-level `RemediationWindow(**FEDRAMP_TIMEFRAMES)` at line 47):

```python
def test_risk_accepted_is_its_own_bucket_not_a_breach() -> None:
    """Accepted residual risk is not an SLA failure.

    constants.py states the convention: POAM_ACTIVE_STATUSES excludes
    risk_accepted because it is risk formally accepted rather than work still
    to do, and analytics/posture.py already buckets it separately. sla.py had
    diverged, reporting it as a breach.
    """
    old = _Poam(status="risk_accepted", identified_on=TODAY - timedelta(days=200))
    assert classify(old, allowed_days=30, today=TODAY) == "accepted"


def test_a_young_accepted_weakness_is_not_within_sla_either() -> None:
    """The half that used to pass silently: accepted on day 3 counted as
    compliant with a remediation timeframe it was never remediated within."""
    young = _Poam(status="risk_accepted", identified_on=TODAY - timedelta(days=3))
    assert classify(young, allowed_days=30, today=TODAY) == "accepted"


def test_an_undated_accepted_weakness_is_accepted_not_unknown() -> None:
    """The bucket does not depend on a date, and sla.is_accepted_weakness
    agrees. Two functions disagreeing about one row is the divergence this
    change ends."""
    undated = _Poam(status="risk_accepted", identified_on=None)
    assert classify(undated, allowed_days=30, today=TODAY) == "accepted"


def test_an_accepted_weakness_is_not_listed_as_breaching() -> None:
    accepted = _Poam(
        id=910, status="risk_accepted", identified_on=TODAY - timedelta(days=200)
    )
    report = measure([accepted], window=WINDOW, today=TODAY)
    assert report.buckets["accepted"] == 1
    assert report.buckets["breached"] == 0
    assert report.breaching_ids == []


def test_accepted_stays_in_the_compliance_denominator() -> None:
    """Out of the numerator, in the denominator: an accepted weakness was not
    remediated in time, and excluding it would let an org improve its SI-2
    score by accepting risk."""
    report = measure(
        [
            _Poam(id=1, status="risk_accepted", identified_on=TODAY - timedelta(days=200)),
            _open("high", 5, id=2),
        ],
        window=WINDOW,
        today=TODAY,
    )
    assert report.measured == 2
    assert report.compliance_pct == 50.0


def test_a_closure_predating_identification_is_still_unknown() -> None:
    """Unchanged by this task, asserted because the accepted branch now runs
    ahead of every date check and must not have swallowed this case."""
    corrupt = _Poam(
        id=6,
        status="completed",
        identified_on=TODAY - timedelta(days=40),
        closed_on=TODAY - timedelta(days=60),
    )
    assert classify(corrupt, allowed_days=30, today=TODAY) == "unknown"


def test_the_buckets_still_sum_to_the_measured_count() -> None:
    poams = [
        _open("high", 5, id=1),                                   # within_sla
        _open("high", 200, id=2),                                 # breached
        _Poam(id=3, status="risk_accepted", identified_on=TODAY),  # accepted
        _closed("high", 40, 10),                                  # closed_on_time
        _Poam(id=5, status="open", identified_on=None),           # unknown
    ]
    report = measure(poams, window=WINDOW, today=TODAY)
    assert sum(report.buckets.values()) == report.measured == len(poams)


def test_accepted_is_declared_in_the_bucket_vocabulary() -> None:
    assert "accepted" in SLA_BUCKETS
```

`_open` forwards `**kw` to `_Poam`, so `id=` reaches it; `_closed` does not take `**kw`, which is why the calls above leave its id at the default. Duplicate ids are harmless here — only `breached` rows reach `breaching_ids`. Do not change either helper's signature; other tests depend on them.

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_patching_sla.py -q`
Expected: the first three FAIL with `assert 'breached' == 'accepted'`, `assert 'within_sla' == 'accepted'`, `assert 'unknown' == 'accepted'`; the bucket-vocabulary test fails on the missing key.

- [ ] **Step 3: Implement**

In `src/ccf/patching/sla.py`:

```python
SLA_BUCKETS = (
    "within_sla",
    "breached",
    "accepted",
    "closed_on_time",
    "closed_late",
    "unknown",
)
```

Update that constant's docstring to name `accepted` alongside the others. Then make the FIRST statement in the body of `classify`:

```python
    if str(poam.status) == "risk_accepted":
        # Residual risk formally accepted, not work outstanding. constants.py
        # excludes it from POAM_ACTIVE_STATUSES for exactly this reason, and
        # analytics.posture already buckets it separately; sla.py had diverged,
        # reporting it as an SLA breach when old and as within_sla when young.
        # Under CR26 it is the outcome the rule defines -- see
        # is_accepted_weakness. Checked before the identified_on guard because
        # the bucket does not depend on a date, and is_accepted_weakness agrees.
        # It stays OUT of compliance_pct's numerator: it was not remediated in
        # time. It stays IN the denominator: otherwise accepting risk would
        # improve the score.
        return "accepted"
```

Extend `classify`'s docstring with one sentence recording that `accepted` short-circuits ahead of every date check.

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python3 -m pytest tests/test_patching_sla.py tests/test_accepted_weakness.py -q` — expected: all pass, including the pre-existing `set(report.buckets) == set(SLA_BUCKETS)` assertion, which is derived and needs no edit.

- [ ] **Step 5: Run the full suite**

Run the full suite with an explicit long timeout. `tests/test_patching_api.py` asserts on `breaching_ids` at two places (lines ~130 and ~502); if either fixture uses a `risk_accepted` POA&M, its expectation is now wrong and **that test is what changes** — the behaviour is the fix. Report every test you touch and why.

- [ ] **Step 6: Commit**

```bash
git add src/ccf/patching/sla.py tests/
git commit -m "fix(patching): risk_accepted is its own bucket, not an SLA breach

classify() returned 'breached' for old accepted residual risk and listed it in
breaching_ids, while a young accepted row returned 'within_sla' and counted as
compliant with a timeframe it was never remediated within.

constants.py already states the convention -- risk_accepted is excluded from
the remediation backlog because it is risk formally accepted rather than work
outstanding -- and analytics.posture already buckets it separately. sla.py had
diverged. Under CR26 the divergence is not cosmetic: an accepted weakness is
the outcome the rule defines, so reporting it as an SLA failure misstates
compliance in one direction and as on-time remediation in the other.

'accepted' stays out of compliance_pct's numerator and in its denominator, so
accepting risk cannot improve an SI-2 score.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Certification Class and Path

**Files:**
- Modify: `src/ccf/constants.py`, `src/ccf/models.py` (`System`, around line 355)
- Create: `migrations/versions/0078_cr26_certification.py`
- Test: `tests/test_cr26_certification_columns.py` (create)

**Interfaces:**
- Produces: `CERTIFICATION_CLASSES: tuple[str, ...] = ("A", "B", "C", "D")`, `CERTIFICATION_PATHS: tuple[str, ...] = ("program", "agency")`, and `System.certification_class` / `System.certification_path`, both `Mapped[str | None]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cr26_certification_columns.py
"""Certification Class and Path are independent axes, never derived.

FedRAMP states plainly that a Certification Class is not a replacement for an
impact level: "Agencies should not treat Certification Classes as one-for-one
replacements for Low, Moderate, or High impact levels." The published
definitions are deliberately overlapping adequacy ranges -- Class B is adequate
for most Low and SOME Moderate or High -- so a mapping between the two is wrong
in both directions.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.constants import CERTIFICATION_CLASSES, CERTIFICATION_PATHS
from ccf.db import session_scope
from ccf.models import Organization, System

pytestmark = pytest.mark.asyncio


def test_the_vocabularies_are_what_fedramp_publishes() -> None:
    assert CERTIFICATION_CLASSES == ("A", "B", "C", "D")
    assert CERTIFICATION_PATHS == ("program", "agency")


async def test_a_system_may_hold_a_class_and_a_path() -> None:
    async with session_scope() as s:
        org = Organization(name="cr26-cols-org")
        s.add(org)
        await s.flush()
        sys_ = System(
            organization_id=org.id,
            name="cr26-cols-system",
            baseline="moderate",
            certification_class="B",
            certification_path="program",
        )
        s.add(sys_)
        await s.flush()
        sid = sys_.id

    async with session_scope() as s:
        got = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert got.certification_class == "B"
        assert got.certification_path == "program"
        # The independence that matters: Class B on a moderate baseline is
        # legal, and so is Class B on high. Neither column constrains the other.
        assert got.baseline == "moderate"


async def test_both_columns_default_to_null() -> None:
    """Null means "not CR26-certified" -- correct for every existing row and for
    the whole Rev5 lane. No row may be forced to claim a Class it lacks."""
    async with session_scope() as s:
        org = Organization(name="cr26-null-org")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name="cr26-null-system", baseline="low")
        s.add(sys_)
        await s.flush()
        sid = sys_.id

    async with session_scope() as s:
        got = (await s.execute(select(System).where(System.id == sid))).scalar_one()
        assert got.certification_class is None
        assert got.certification_path is None


async def test_every_class_in_the_vocabulary_is_storable() -> None:
    """A tuple the database rejects is a vocabulary in name only."""
    async with session_scope() as s:
        org = Organization(name="cr26-all-classes-org")
        s.add(org)
        await s.flush()
        for cls in CERTIFICATION_CLASSES:
            s.add(
                System(
                    organization_id=org.id,
                    name=f"cr26-class-{cls}",
                    certification_class=cls,
                )
            )
        await s.flush()
```

`clean_migrated_db` is a session-scoped autouse fixture in `tests/conftest.py`, so it needs no parameter here; the database is already migrated. Follow `tests/test_capability_models.py` for the `Organization`/`session_scope` idiom, and match whatever cleanup convention that file uses — if these tests leave rows behind where the file's neighbours do not, add the same teardown they use.

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python3 -m pytest tests/test_cr26_certification_columns.py -q`
Expected: collection error — `ImportError: cannot import name 'CERTIFICATION_CLASSES' from 'ccf.constants'`

- [ ] **Step 3: Add the vocabularies**

In `src/ccf/constants.py`, after the POA&M block:

```python
# ---------------------------------------------------------------------------
# CR26 Certification vocabulary.
#
# A Certification Class describes the DEPTH, FREQUENCY and QUALITY of the
# assurance data a provider commits to supplying -- not the sensitivity of the
# information a system holds. FedRAMP is explicit that the two are different
# axes:
#   "Agencies should not treat Certification Classes as one-for-one
#    replacements for Low, Moderate, or High impact levels."
#   "FedRAMP Certification Classes are not aligned to how secure a cloud
#    service offering is!"
# The published definitions are deliberately overlapping adequacy ranges: B is
# adequate for most Low and SOME Moderate or High; C for most Low or Moderate
# and SOME High; D for most systems regardless of impact level.
#
# So NOTHING may derive a Class from ``System.baseline``, or a baseline from a
# Class. Such a derivation is wrong in both directions, and
# tests/test_certification_class_is_independent.py enforces it.
CERTIFICATION_CLASSES: tuple[str, ...] = ("A", "B", "C", "D")

#: Program certification, or an agency-sponsored path to one.
CERTIFICATION_PATHS: tuple[str, ...] = ("program", "agency")
```

- [ ] **Step 4: Add the columns**

In `src/ccf/models.py`, in `System`, immediately after `baseline` (~line 357):

```python
    #: CR26 Certification Class. INDEPENDENT of ``baseline`` -- see
    #: ``ccf.constants.CERTIFICATION_CLASSES``. Never derive one from the other.
    #: Null means "not CR26-certified", correct for every Rev5-lane row.
    certification_class: Mapped[str | None] = mapped_column(
        Enum(*CERTIFICATION_CLASSES, name="certification_class", schema="ccf")
    )
    #: Program or agency-sponsored certification path. Null when not applicable.
    certification_path: Mapped[str | None] = mapped_column(
        Enum(*CERTIFICATION_PATHS, name="certification_path", schema="ccf")
    )
```

Import both constants at the top of `models.py` alongside the existing constants import. These are new enum types, so neither takes `create_type=False` — that argument appears on `fips199_level` only because that type is declared once and reused.

- [ ] **Step 5: Write the migration**

```python
# migrations/versions/0078_cr26_certification.py
"""CR26 Certification Class and Path on a system.

Two nullable columns, independent of ``baseline`` and of each other. FedRAMP
states a Certification Class is not a one-for-one replacement for an impact
level, and the published adequacy ranges overlap, so nothing derives one from
the other. Null means "not CR26-certified" -- correct for every existing row
and for the whole Rev5 lane, which is why neither column is backfilled.

Revision ID: 0078_cr26_certification
Revises: 0077_cci_source_spine
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0078_cr26_certification"
down_revision = "0077_cci_source_spine"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_CLASS = sa.Enum("A", "B", "C", "D", name="certification_class", schema=_SCHEMA)
_PATH = sa.Enum("program", "agency", name="certification_path", schema=_SCHEMA)


def upgrade() -> None:
    bind = op.get_bind()
    _CLASS.create(bind, checkfirst=True)
    _PATH.create(bind, checkfirst=True)
    op.add_column(
        "systems",
        sa.Column("certification_class", _CLASS, nullable=True),
        schema=_SCHEMA,
    )
    op.add_column(
        "systems",
        sa.Column("certification_path", _PATH, nullable=True),
        schema=_SCHEMA,
    )
    # Standard since 0054: grant only if the role exists, so a developer
    # database without ccf_app migrates cleanly.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    # No RLS change: systems is an existing tenant table and already carries its
    # own direct-shape policy. No new table, so no isolation count moves.


def downgrade() -> None:
    op.drop_column("systems", "certification_path", schema=_SCHEMA)
    op.drop_column("systems", "certification_class", schema=_SCHEMA)
    bind = op.get_bind()
    _PATH.drop(bind, checkfirst=True)
    _CLASS.drop(bind, checkfirst=True)
```

Open `migrations/versions/0077_cci_source_spine.py` first and copy its exact GRANT text and `revision`/`down_revision` style rather than trusting the transcription above.

- [ ] **Step 6: Migrate and verify exactly one head**

```bash
.venv/bin/alembic upgrade head
.venv/bin/alembic heads          # FULL output. Must print exactly ONE line.
```

Expected: `0078_cr26_certification (head)`. **Never pipe this through `tail`** — doing so hid a second head once in this programme and errored 1,992 tests.

Run: `.venv/bin/python3 -m pytest tests/test_cr26_certification_columns.py tests/test_rls_coverage.py -q`
Expected: pass. `systems` is an existing tenant table, so no RLS guard's hardcoded count changes — if one fails, you added a table by mistake.

- [ ] **Step 7: Commit**

```bash
git add src/ccf/constants.py src/ccf/models.py migrations/versions/0078_cr26_certification.py tests/test_cr26_certification_columns.py
git commit -m "feat(cr26): Certification Class and Path as independent axes

Two nullable columns on System, derived from nothing. FedRAMP states a
Certification Class is not a one-for-one replacement for an impact level, and
the published definitions are deliberately overlapping adequacy ranges -- B is
adequate for most Low and SOME Moderate or High -- so any mapping between Class
and baseline is wrong in both directions.

Null means 'not CR26-certified', correct for every existing row and for the
whole Rev5 lane. Through 2026-27 an offering may hold a Rev5 ATO and pursue a
CR26 Certification at once, so no row is forced to claim a Class it lacks.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: The no-derivation guard, and the record

**Files:**
- Create: `tests/test_certification_class_is_independent.py`
- Modify: `docs/architecture/forge-capability-inventory.md`, this plan file

- [ ] **Step 1: Write the guard**

```python
# tests/test_certification_class_is_independent.py
"""Nothing may derive a Certification Class from a baseline, or a baseline from
a Class.

FedRAMP: "Agencies should not treat Certification Classes as one-for-one
replacements for Low, Moderate, or High impact levels." The adequacy ranges
overlap -- a Class B offering may serve a High system, and a High system may be
served by B, C or D -- so a derivation is wrong in BOTH directions.

A source-shaped guard is the right instrument. A derivation added in a private
helper would not be caught by exercising any route, and the whole point is that
the mapping is tempting and wrong.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"
_BASELINE = ("baseline", "fedramp_baseline")
_CERT = {"certification_class", "certification_path"}


def _derivations(tree: ast.AST, label: str) -> list[str]:
    """Assignments whose target names one vocabulary and whose value mentions
    the other."""
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if node.value is None:
            continue
        names = {
            t.attr if isinstance(t, ast.Attribute) else getattr(t, "id", "")
            for t in targets
        }
        value = ast.dump(node.value)
        if names & _CERT and any(b in value for b in _BASELINE):
            hits.append(f"{label}:{node.lineno} derives a Class from a baseline")
        if names & set(_BASELINE) and any(c in value for c in _CERT):
            hits.append(f"{label}:{node.lineno} derives a baseline from a Class")
    return hits


def test_no_code_derives_a_class_from_a_baseline_or_the_reverse() -> None:
    hits: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits += _derivations(tree, str(path.relative_to(_SRC)))
    assert not hits, (
        "FedRAMP states Certification Classes are NOT one-for-one replacements "
        f"for impact levels, and the adequacy ranges overlap. Found: {hits}"
    )


def test_the_guard_detects_the_shape_it_forbids() -> None:
    """Prove the walker fires, without committing the violation it looks for."""
    forward = ast.parse("system.certification_class = _CLASS_FOR[system.baseline]")
    reverse = ast.parse("system.baseline = _BASELINE_FOR[system.certification_class]")
    assert _derivations(forward, "fake.py") == [
        "fake.py:1 derives a Class from a baseline"
    ]
    assert _derivations(reverse, "fake.py") == [
        "fake.py:1 derives a baseline from a Class"
    ]


def test_the_guard_actually_reads_the_source_tree() -> None:
    """A walker pointed at an empty directory passes vacuously forever."""
    assert len(list(_SRC.rglob("*.py"))) > 50
```

- [ ] **Step 2: Run it, then prove it bites against real source**

Run: `.venv/bin/python3 -m pytest tests/test_certification_class_is_independent.py -q` — expected: 3 passed.

Then temporarily add `self.certification_class = self.baseline` inside any function in `src/ccf/`, re-run, and confirm `test_no_code_derives_a_class_from_a_baseline_or_the_reverse` FAILS naming that file and line. **Revert it.** Paste both outputs in your report. `test_the_guard_detects_the_shape_it_forbids` proves the walker works on a literal; only this step proves it is pointed at the real tree.

- [ ] **Step 3: Record status in the capability inventory**

Add a section to `docs/architecture/forge-capability-inventory.md` in the established style of its neighbours — prose, specific, naming the load-bearing judgements rather than listing features. Read an adjacent section first and match its register. Cover:

- CR26 eliminates the provider-side POA&M and replaces it with Accepted Weaknesses; this platform already modelled the weakness, so the change is a classification, not a new record.
- The union is declared ∪ elapsed, and why the declared half is necessary: the rule says "is not **or will not be**", and a projection keyed only to age would report an accepted weakness as open work for up to 191 days.
- Class and Path are independent axes. The mapping FedRAMP disclaims was the thing blocking this work; closing it *removed* a schema change rather than specifying one.
- `certification_status` is deliberately absent — the vocabulary is not published in any reachable source, and inventing it is what the gap analysis rightly refused to do for Classes.
- The 192 days run from *evaluation*; `identified_on` is a stated assumption to confirm against the published VER when it lands.
- The binding deadline is **7 December 2026** for VDR/VER.

- [ ] **Step 4: Record the results in this plan**

Append a `## Results` section to this file: the full `alembic heads` output, the final suite count, the forced-failure evidence from Task 1 Step 5 and Task 4 Step 2, and any pre-existing test you had to update in Task 2 Step 5 with the reason.

- [ ] **Step 5: Full verification, then commit**

```bash
.venv/bin/python3 -m pytest -q      # explicit long timeout, e.g. 900000
.venv/bin/ruff check . && .venv/bin/mypy src
.venv/bin/alembic heads             # FULL output, exactly one head
```

```bash
git add tests/test_certification_class_is_independent.py docs/
git commit -m "test(cr26): guard the independence of Class and baseline; record status

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Notes for the executor

- **Do not add a table for Accepted Weakness.** It is a classification of a `POAM` row. Two records of one fact is the defect this design exists to avoid.
- **Do not collapse `POAM_ACTIVE_STATUSES` and `POAM_UNRESOLVED_STATUSES`.** `constants.py:90-113` explains why they answer different questions; unifying them would either hide accepted risk from the AO or count it as outstanding work.
- **Do not wire `classify` through `is_accepted_weakness`.** One measures an org's declared window, the other FedRAMP's fixed 192 days. They agree on which rows are accepted and must not be made to share a threshold.
- **Do not model `certification_status`.** The vocabulary is unpublished.
- **Do not backfill either new column.** Null is the correct value for every existing row.
- After committing a task, run `git show --stat` and confirm the intended files are in it. A green suite answers "does the tree work", not "is the tree committed".

## Results

All four tasks landed on this branch. Final state, verified independently by
the Task 4 executor rather than copied from earlier reports.

### `alembic heads` (after Task 3, re-confirmed after Task 4 and again after its fix round)

```
$ .venv/bin/alembic heads
0078_cr26_certification (head)
```

Exactly one head, every time.

### Suite counts as each task landed

| Task | Result |
|---|---|
| Task 1 (Accepted Weakness classification) | 2474 passed, 1 skipped |
| Task 2 (`risk_accepted` its own SLA bucket) | 2482 passed, 1 skipped |
| Task 3 (Certification Class / Path columns) | 2486 passed, 1 skipped |
| Task 4, first pass (no-derivation guard) | 2489 passed, 1 skipped |
| Task 4, after fix round 1 (guard now also covers constructor keywords, tuple targets, `AugAssign`) | 2493 passed, 1 skipped |

The single skip (`tests/test_fedramp20x_e2e.py:30`, missing `playwright`) is
pre-existing and unrelated to this plan. Task 4's first pass added exactly
the 3 tests in `tests/test_certification_class_is_independent.py` (2486 →
2489); fix round 1 added 4 more to close the constructor-keyword-argument
and tuple/`AugAssign` gaps a review found in the guard (2489 → 2493).

Task 4's full-suite run after the fix round, immediately before re-committing:

```
$ export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
$ export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
$ .venv/bin/python3 -m pytest -q
...
2493 passed, 1 skipped, 5 warnings in 207.89s (0:03:27)
```

The 5 warnings are the same pre-existing `DeprecationWarning: builtin type
Swig...` noise from earlier tasks' runs (SWIG-wrapped C-extension modules
lacking `__module__`), unrelated to this plan.

`ruff check .` → `All checks passed!`. `mypy src` (strict) →
`Success: no issues found in 287 source files`.

### Forced-failure evidence — Task 1 Step 5

The boundary test was proven to bite by changing the comparison operator
from `>` to `>=` in `is_accepted_weakness` (`src/ccf/patching/sla.py`),
which flips the inclusive-192-days boundary:

```
$ .venv/bin/python3 -m pytest tests/test_accepted_weakness.py -q
...F......                                                               [100%]
=================================== FAILURES ===================================
_________________ test_the_boundary_is_inclusive_like_classify _________________

    def test_the_boundary_is_inclusive_like_classify() -> None:
        """192 means 192 -- sla.classify's stated convention, reused verbatim."""
>       assert is_accepted_weakness(_aged(ACCEPTED_WEAKNESS_DAYS), today=TODAY) is False
E       AssertionError: assert True is False
E        +  where True = is_accepted_weakness(_Poam(status='open', identified_on=datetime.date(2026, 3, 8), closed_on=None), today=datetime.date(2026, 9, 16))
E        +    where _Poam(status='open', identified_on=datetime.date(2026, 3, 8), closed_on=None) = _aged(192)

tests/test_accepted_weakness.py:51: AssertionError
=========================== short test summary info ============================
FAILED tests/test_accepted_weakness.py::test_the_boundary_is_inclusive_like_classify
1 failed, 9 passed in 2.31s
```

Only that one test failed; the operator was reverted to `>` afterward (full
detail in `.superpowers/sdd/2026-09-16-cr26-vocabulary/task-1-report.md`).

### Forced-failure evidence — Task 4 Step 2

Added `self.certification_class = self.baseline` inside a throwaway function
appended to the end of `src/ccf/models.py` (a real module in `src/ccf`, not
the test's own literal-string fixture), re-ran the guard test:

```
$ .venv/bin/python3 -m pytest tests/test_certification_class_is_independent.py -q
F..                                                                      [100%]
=================================== FAILURES ===================================
_________ test_no_code_derives_a_class_from_a_baseline_or_the_reverse __________

    def test_no_code_derives_a_class_from_a_baseline_or_the_reverse() -> None:
        hits: list[str] = []
        for path in sorted(_SRC.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            hits += _derivations(tree, str(path.relative_to(_SRC)))
>       assert not hits, (
            "FedRAMP states Certification Classes are NOT one-for-one replacements "
            f"for impact levels, and the adequacy ranges overlap. Found: {hits}"
        )
E       AssertionError: FedRAMP states Certification Classes are NOT one-for-one replacements for impact levels, and the adequacy ranges overlap. Found: ['models.py:1921 derives a Class from a baseline']
E       assert not ['models.py:1921 derives a Class from a baseline']
=========================== short test summary info ============================
FAILED tests/test_certification_class_is_independent.py::test_no_code_derives_a_class_from_a_baseline_or_the_reverse
1 failed, 2 passed in 2.30s
```

Then reverted (`git checkout -- src/ccf/models.py`) and re-ran:

```
$ .venv/bin/python3 -m pytest tests/test_certification_class_is_independent.py -q
...                                                                      [100%]
3 passed in 3.50s
```

`git diff HEAD` and `git status --porcelain` after the Task 4 commit confirm
no trace of the mutation reached the commit or the working tree.

### Forced-failure evidence — Task 4 fix round 1 (constructor-keyword shape)

Review found the first-pass guard blind to the codebase's actual `System`
construction idiom — a keyword argument, not an attribute assignment (see
`src/ccf/api/routes/ui.py`'s `System(organization_id=org.id, name=sys_name,
baseline=(baseline or None))`). Fixed by extending `_derivations` to walk
every `Call` node's keyword arguments as targets in their own right, judged
independently of any other keyword on the same call. Proved the fix bites
against real source the same way as before: appended a second throwaway
function to `src/ccf/models.py`,

```python
def _scratch_mutation_for_guard_proof_kwarg() -> None:
    _sysm = System(certification_class=_CLASS_FOR[System.baseline], baseline=None)
```

re-ran the guard test:

```
$ .venv/bin/python3 -m pytest tests/test_certification_class_is_independent.py -q
F......                                                                  [100%]
=================================== FAILURES ===================================
_________ test_no_code_derives_a_class_from_a_baseline_or_the_reverse __________

    def test_no_code_derives_a_class_from_a_baseline_or_the_reverse() -> None:
        hits: list[str] = []
        for path in sorted(_SRC.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            hits += _derivations(tree, str(path.relative_to(_SRC)))
>       assert not hits, (
            "FedRAMP states Certification Classes are NOT one-for-one replacements "
            f"for impact levels, and the adequacy ranges overlap. Found: {hits}"
        )
E       AssertionError: FedRAMP states Certification Classes are NOT one-for-one replacements for impact levels, and the adequacy ranges overlap. Found: ['models.py:1921 derives a Class from a baseline']
E       assert not ['models.py:1921 derives a Class from a baseline']
=========================== short test summary info ============================
FAILED tests/test_certification_class_is_independent.py::test_no_code_derives_a_class_from_a_baseline_or_the_reverse
1 failed, 6 passed in 2.43s
```

Then reverted (`git checkout -- src/ccf/models.py`) and re-ran:

```
$ .venv/bin/python3 -m pytest tests/test_certification_class_is_independent.py -q
.......                                                                  [100%]
7 passed in 2.49s
```

`git diff HEAD` and `git status --porcelain` after re-committing confirm no
trace of this second mutation reached the commit or the working tree
either. **No genuine pre-existing derivation was found in `src/ccf/` by the
extended guard** — its only hit throughout both mutation proofs was the
deliberate, reverted line.

### Task 2 Step 5 — the warned-about pre-existing test did not need to change

Task 2's brief warned that `tests/test_patching_api.py` might break once
`risk_accepted` stopped landing in `breached`. That did not happen —
`risk_accepted` appears nowhere in that file, in
`src/ccf/api/routes/patching.py`, or in `src/ccf/models_patching.py`
(confirmed by `grep -n "risk_accepted"` returning nothing in any of the
three). No pre-existing test was modified in Task 2. The warning was stale.
