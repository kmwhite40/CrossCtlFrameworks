# Calibration Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an assessor record that a proposed finding was wrong, then measure how often the engine agrees with assessors — reporting the two error directions separately, and comparably across configuration changes.

**Architecture:** The acceptance gate already produces labelled data; it just never captured disagreement. Task 1 adds the missing reject path. Calibration is then a computation over rows that already exist — no new pipeline — with a snapshot table whose configuration fingerprint keeps metrics comparable across threshold changes.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Alembic, Postgres 16, FastAPI, Typer, pytest.

**Spec:** [docs/superpowers/specs/2026-08-11-calibration-harness-design.md](../specs/2026-08-11-calibration-harness-design.md)
**Depends on:** slices 1–3, all on `feat/evidence-prep-spine`.

## A note on this plan's form

Tasks 1 and 3 carry complete test bodies and implementations — they hold the schema and the metric definitions everything else depends on. Tasks 2, 4, 5 and 6 give each test's name, docstring and exact assertions but not full bodies; write those from the assertions, following the neighbouring test files each task names.

## Global Constraints

- **Python** 3.12, `line-length = 100`. **Ruff** selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected, so `# noqa: BLE001` trips `RUF100`. Known baseline: **25 pre-existing `PLR0917`** across ten untouched `src/ccf/api/routes/` files — add nothing to it, and watch positional-argument counts on new route handlers.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** `from ...logging import get_logger` (adjust depth); never `import structlog`; never `extra={...}`.
- **Tests:** real Postgres, `asyncio_mode = "auto"` — never `@pytest.mark.asyncio`. DB modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`. **Never run two pytest sessions concurrently.**
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — flush before any select or delete that must see pending adds.
- **Migrations:** `migrations/versions/00NN_<slug>.py`, explicit `revision`/`down_revision`. **Current head is `0056_objective_proposal_ai_run`.** Every table- or column-adding migration re-issues `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app`. `server_default=func.now()` columns also need `nullable=False`.
- **Tenancy:** endpoints take `Depends(get_principal)` and derive the org from it, never a body field; another tenant's resource is **404, not 403**.
- **Identifiers:** fold through `ccf.prep.screen.normalize_control_identifier` — the catalog mixes `AC-02`, `CP-9` and `AC.L2-3.1.1`.
- **Rejection must never write an `AssessmentControlResult`.** A rejected proposal produces no finding.
- **Assert every recorded field individually.** Five field mappings across this project were correct but untested until a reviewer mutated them. Each new column and each metric gets its own assertion.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot project.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/models_assessment_engine.py` | four rejection columns; `CalibrationSnapshot` |
| `migrations/versions/0057_reject_and_calibration.py` | columns + snapshot table + grant |
| `src/ccf/assessment/engine/service.py` | `reject_control_proposal`, `RejectionRefused` |
| `src/ccf/assessment/engine/calibration.py` | `CalibrationMetrics`, `compute_metrics`, `config_fingerprint`, `take_snapshot` |
| `src/ccf/api/routes/assessment_engine.py` | reject + calibration endpoints |
| `src/ccf/cli.py` | `ccf calibration-snapshot` |

---

### Task 1: Rejection columns and the snapshot table

**Files:**
- Modify: `src/ccf/models_assessment_engine.py`
- Create: `migrations/versions/0057_reject_and_calibration.py`
- Create: `tests/test_calibration_models.py`

**Interfaces:**
- Produces: `AssessmentControlProposal.corrected_finding | rejected_by | rejected_at | rejection_note`; `CalibrationSnapshot`; `CORRECTED_FINDINGS`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_calibration_models.py`:

```python
"""Rejection columns and the calibration snapshot table."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import (
    CORRECTED_FINDINGS,
    AssessmentControlProposal,
    CalibrationSnapshot,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _assessment(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-sys")
        s.add(system)
        await s.flush()
        a = Assessment(system_id=system.id, name=f"{name}-a", kind="self")
        s.add(a)
        await s.flush()
        return int(org.id), int(a.id)


def test_corrected_findings_excludes_insufficient_evidence() -> None:
    """An assessor correcting a verdict asserts what is true, never 'could not tell'."""
    assert CORRECTED_FINDINGS == ("satisfied", "other_than_satisfied", "not_applicable")
    assert "insufficient_evidence" not in CORRECTED_FINDINGS


async def test_rejection_columns_default_to_null() -> None:
    org_id, assessment_id = await _assessment("cal-defaults")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(p)
        await s.flush()
        assert p.corrected_finding is None
        assert p.rejected_by is None
        assert p.rejected_at is None
        assert p.rejection_note is None


async def test_rejection_columns_round_trip() -> None:
    org_id, assessment_id = await _assessment("cal-roundtrip")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            corrected_finding="other_than_satisfied",
            rejected_by="assessor@example.com",
            rejection_note="Policy predates the current boundary.",
        )
        s.add(p)
        await s.flush()
        pid = int(p.id)
    async with session_scope() as s:
        p = (
            await s.execute(
                select(AssessmentControlProposal).where(AssessmentControlProposal.id == pid)
            )
        ).scalar_one()
        assert p.corrected_finding == "other_than_satisfied"
        assert p.rejected_by == "assessor@example.com"
        assert p.rejection_note == "Policy predates the current boundary."


async def test_snapshot_stores_metrics_and_fingerprint() -> None:
    org_id, _ = await _assessment("cal-snapshot")
    async with session_scope() as s:
        snap = CalibrationSnapshot(
            organization_id=org_id,
            config_fingerprint="a" * 64,
            metrics={"decided": 10, "agreed": 8, "missed_findings": 1},
        )
        s.add(snap)
        await s.flush()
        assert snap.metrics["missed_findings"] == 1
        assert snap.computed_at is not None


async def test_snapshot_timestamp_is_not_null_in_live_schema() -> None:
    """Slice 1 shipped nullable timestamps the ORM declared non-null. Not again."""
    async with session_scope() as s:
        row = (
            await s.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_schema='ccf' AND table_name='calibration_snapshots' "
                    "AND column_name='computed_at'"
                )
            )
        ).scalar_one()
    assert row == "NO"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_calibration_models.py -v`
Expected: FAIL — `ImportError: cannot import name 'CORRECTED_FINDINGS'`.

- [ ] **Step 3: Add the constants and columns**

In `src/ccf/models_assessment_engine.py`, beside the other vocabularies:

```python
#: What an assessor may correct a proposed finding to. Deliberately excludes
#: ``insufficient_evidence``: that is a proposal-only state meaning the engine
#: could not tell, and an assessor overriding a verdict is asserting what is
#: true, not declining to say.
CORRECTED_FINDINGS = ("satisfied", "other_than_satisfied", "not_applicable")
```

Inside `AssessmentControlProposal`, beside `accepted_by`/`accepted_at`:

```python
    #: Set only on rejection: the finding the assessor believes is correct.
    corrected_finding: Mapped[str | None] = mapped_column(String(32))
    rejected_by: Mapped[str | None] = mapped_column(String(255))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Required on rejection. A rejection without a reason tells calibration the
    #: engine was wrong but not how, and "how" is what makes the metric useful.
    rejection_note: Mapped[str | None] = mapped_column(Text)
```

Then the snapshot model:

```python
class CalibrationSnapshot(Base):
    """A point-in-time calibration measurement, tied to the configuration that produced it.

    The fingerprint is what makes drift meaningful. A metric is comparable to an
    earlier one only if what was measured did not change underneath, so two
    snapshots with different fingerprints are reported as *not comparable* rather
    than as drift -- which matters because ``prep_screen_threshold`` has a narrow
    empirical margin and will be re-derived.
    """

    __tablename__ = "calibration_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    config_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
```

- [ ] **Step 4: Write the migration**

Create `migrations/versions/0057_reject_and_calibration.py` adding the four nullable columns to `ccf.assessment_control_proposals` and creating `ccf.calibration_snapshots` (with `computed_at` **`nullable=False`**, an FK to organizations `ON DELETE CASCADE`, and indexes on `organization_id` and `config_fingerprint`). End `upgrade()` with:

```python
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")
```

`revision = "0057_reject_and_calibration"`, `down_revision = "0056_objective_proposal_ai_run"`. `downgrade()` drops the table then the four columns.

- [ ] **Step 5: Round-trip the migration**

Run: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`

- [ ] **Step 6: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_calibration_models.py -v    # 5 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/models_assessment_engine.py \
        migrations/versions/0057_reject_and_calibration.py tests/test_calibration_models.py
git commit -m "feat(assessment): add rejection columns and the calibration snapshot table"
```

---

### Task 2: The reject path

**Files:**
- Modify: `src/ccf/assessment/engine/service.py`
- Create: `tests/test_assessment_rejection.py`

**Interfaces:**
- Consumes: Task 1's columns; `AiActionRun`; `ProposalError` and the stamping helper `accept_control_proposal` already uses.
- Produces: `RejectionRefused(ProposalError)`; `async reject_control_proposal(session, proposal_id: int, *, rejected_by: str, corrected_finding: str, note: str) -> AssessmentControlProposal`.

Mirror `accept_control_proposal`'s structure: guard, then stamp. Set `state="rejected"`, the four columns, and stamp every linked `AiActionRun` with `disposition="rejected"`, `reviewer=rejected_by`, `decided_at` — **leaving `mutation_applied` False**, because nothing authoritative was written.

- [ ] **Step 1: Write the failing tests** in `tests/test_assessment_rejection.py`, following `tests/test_assessment_acceptance.py`'s fixtures:

```python
async def test_rejection_records_all_four_columns() -> None:
    """state, corrected_finding, rejected_by, rejected_at and note, each asserted."""

async def test_rejection_writes_no_assessment_control_result() -> None:
    """The engine's wrong answer must not reach the SAR with a human's name on it.
    Assert zero AssessmentControlResult rows for the assessment afterwards."""

async def test_rejection_stamps_linked_runs_as_rejected() -> None:
    """disposition == 'rejected', reviewer == rejected_by, decided_at set,
    and mutation_applied still False."""

async def test_a_note_is_required() -> None:
    """An empty or whitespace-only note raises RejectionRefused."""

async def test_insufficient_evidence_is_not_a_valid_correction() -> None:
    """raises RejectionRefused -- an assessor asserts what is true."""

async def test_an_already_accepted_proposal_cannot_be_rejected() -> None:
async def test_an_already_rejected_proposal_cannot_be_rejected_again() -> None:

async def test_rejecting_one_proposal_does_not_stamp_another_proposals_runs() -> None:
    """Two proposals in one assessment; only the rejected one's runs are stamped."""

async def test_an_org_a_caller_cannot_reject_an_org_b_proposal() -> None:
    """Asserted at the service layer as an attack, matching the acceptance tests."""
```

- [ ] **Step 2: Run to verify failure** — expected `ImportError: cannot import name 'reject_control_proposal'`.

- [ ] **Step 3: Implement**, reusing acceptance's run-stamping approach (collect non-NULL `ai_action_run_id` values, one bulk UPDATE, mind `autoflush=False`).

- [ ] **Step 4–5: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_assessment_rejection.py -v
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/assessment/engine/service.py tests/test_assessment_rejection.py
git commit -m "feat(assessment): let an assessor reject a proposed finding"
```

---

### Task 3: The metrics

**Files:**
- Create: `src/ccf/assessment/engine/calibration.py`
- Create: `tests/test_calibration_metrics.py`

**Interfaces:**
- Produces:
  - `@dataclass(slots=True) FamilyMetrics` with `decided: int`, `agreed: int`, `missed_findings: int`, `false_alarms: int`
  - `@dataclass(slots=True) CalibrationMetrics` with `decided: int`, `agreed: int`, `agreement_rate: float`, `missed_findings: int`, `false_alarms: int`, `other_disagreements: int`, `by_family: dict[str, FamilyMetrics]`, and `def as_dict(self) -> dict[str, Any]`
  - `async compute_metrics(session, *, organization_id: int) -> CalibrationMetrics`
  - `def control_family(control_identifier: str) -> str`

- [ ] **Step 1: Write the failing test**

Create `tests/test_calibration_metrics.py`:

```python
"""Calibration metrics -- the two error directions are never conflated."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.assessment.engine.calibration import compute_metrics, control_family
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _assessment(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name}-sys")
        s.add(system)
        await s.flush()
        a = Assessment(system_id=system.id, name=f"{name}-a", kind="self")
        s.add(a)
        await s.flush()
        return int(org.id), int(a.id)


async def _decided(
    org_id: int, assessment_id: int, control: str, proposed: str,
    *, accepted: bool, corrected: str | None = None,
) -> None:
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier=control,
                state="accepted" if accepted else "rejected",
                proposed_finding=proposed,
                corrected_finding=corrected,
                rejected_by=None if accepted else "assessor@example.com",
                rejection_note=None if accepted else "wrong",
            )
        )


def test_control_family_folds_padded_and_unpadded() -> None:
    assert control_family("AC-02") == "AC"
    assert control_family("AC-2") == "AC"
    assert control_family("CP-9") == "CP"


def test_control_family_survives_a_cmmc_style_identifier() -> None:
    """Must not corrupt the grouping or raise."""
    assert control_family("AC.L2-3.1.1") == "AC"


async def test_zero_decisions_does_not_divide_by_zero() -> None:
    org_id, _ = await _assessment("cal-empty")
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.decided == 0
    assert m.agreement_rate == 0.0


async def test_an_accepted_proposal_counts_as_agreement() -> None:
    org_id, aid = await _assessment("cal-agree")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.decided == 1
    assert m.agreed == 1
    assert m.agreement_rate == 1.0
    assert m.missed_findings == 0


async def test_a_control_passing_that_should_not_is_a_missed_finding() -> None:
    """The dangerous direction: proposed satisfied, corrected to other_than_satisfied."""
    org_id, aid = await _assessment("cal-missed")
    await _decided(
        org_id, aid, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.missed_findings == 1
    assert m.false_alarms == 0
    assert m.agreed == 0


async def test_wasted_remediation_effort_is_a_false_alarm() -> None:
    org_id, aid = await _assessment("cal-false")
    await _decided(
        org_id, aid, "AC-2", "other_than_satisfied", accepted=False, corrected="satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.false_alarms == 1
    assert m.missed_findings == 0


async def test_the_two_error_directions_are_never_conflated() -> None:
    """One of each must not collapse into a single '2 errors' figure."""
    org_id, aid = await _assessment("cal-both")
    await _decided(
        org_id, aid, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    await _decided(
        org_id, aid, "SC-7", "other_than_satisfied", accepted=False, corrected="satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.missed_findings == 1
    assert m.false_alarms == 1
    assert m.decided == 2
    assert m.agreed == 0


async def test_a_correction_to_not_applicable_is_neither_direction() -> None:
    org_id, aid = await _assessment("cal-other")
    await _decided(
        org_id, aid, "AC-2", "satisfied", accepted=False, corrected="not_applicable"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.other_disagreements == 1
    assert m.missed_findings == 0
    assert m.false_alarms == 0


async def test_per_family_split_separates_a_weak_family_from_a_strong_one() -> None:
    """A model reliable on AC and unreliable on SC is a different problem
    from one uniformly mediocre -- the split is what tells them apart."""
    org_id, aid = await _assessment("cal-family")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    await _decided(org_id, aid, "AC-3", "satisfied", accepted=True)
    await _decided(
        org_id, aid, "SC-7", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.by_family["AC"].agreed == 2
    assert m.by_family["AC"].missed_findings == 0
    assert m.by_family["SC"].missed_findings == 1
    assert m.by_family["SC"].agreed == 0


async def test_undecided_proposals_are_excluded() -> None:
    """A draft or complete proposal is not a decision and must not dilute the rate."""
    org_id, aid = await _assessment("cal-undecided")
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=aid,
                control_identifier="AC-2", state="complete", proposed_finding="satisfied",
            )
        )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_id)
    assert m.decided == 0


async def test_metrics_are_scoped_to_one_organization() -> None:
    org_a, aid_a = await _assessment("cal-org-a")
    org_b, aid_b = await _assessment("cal-org-b")
    await _decided(org_a, aid_a, "AC-2", "satisfied", accepted=True)
    await _decided(
        org_b, aid_b, "AC-2", "satisfied", accepted=False, corrected="other_than_satisfied"
    )
    async with session_scope() as s:
        m = await compute_metrics(s, organization_id=org_a)
    assert m.decided == 1
    assert m.missed_findings == 0, "org B's rejection must not appear in org A's metrics"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_calibration_metrics.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.assessment.engine.calibration'`.

- [ ] **Step 3: Write the metrics module**

Create `src/ccf/assessment/engine/calibration.py`:

```python
"""Measure how often the engine's proposed findings match assessors' decisions.

There is no new pipeline here. The acceptance gate already produces labelled data
as a side effect of work assessors do anyway -- an accepted proposal is someone
saying the verdict was right, a rejected one says it was wrong and records what
should have been there instead. Calibration is a query over those rows.

The two error directions are reported separately and never averaged, because
their costs differ sharply. A control passing that should not is a missed finding
in an authorization package. The reverse is wasted remediation effort. Collapsing
them into one accuracy figure hides the number actually worth watching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models_assessment_engine import AssessmentControlProposal
from ...prep.screen import normalize_control_identifier


def control_family(control_identifier: str) -> str:
    """The family prefix (``AC``, ``SC``) a control belongs to.

    Folds through the shared identifier normaliser first, so ``AC-02`` and
    ``AC-2`` group together. CMMC-style identifiers (``AC.L2-3.1.1``) keep their
    leading alphabetic run, which is the family there too.
    """
    canonical = normalize_control_identifier(control_identifier)
    prefix = ""
    for char in canonical:
        if char.isalpha():
            prefix += char
        else:
            break
    return prefix or canonical


@dataclass(slots=True)
class FamilyMetrics:
    """One control family's agreement, split by error direction."""

    decided: int = 0
    agreed: int = 0
    missed_findings: int = 0
    false_alarms: int = 0


@dataclass(slots=True)
class CalibrationMetrics:
    """Agreement between proposed findings and assessors' decisions."""

    decided: int = 0
    agreed: int = 0
    agreement_rate: float = 0.0
    #: Proposed satisfied, corrected to other_than_satisfied -- a control passes
    #: that should not. The number to watch.
    missed_findings: int = 0
    #: Proposed other_than_satisfied, corrected to satisfied -- wasted effort.
    false_alarms: int = 0
    #: Any other corrected pair, e.g. a correction to not_applicable.
    other_disagreements: int = 0
    by_family: dict[str, FamilyMetrics] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """A JSONB-safe view, for storing on a snapshot."""
        return {
            "decided": self.decided,
            "agreed": self.agreed,
            "agreement_rate": self.agreement_rate,
            "missed_findings": self.missed_findings,
            "false_alarms": self.false_alarms,
            "other_disagreements": self.other_disagreements,
            "by_family": {
                name: {
                    "decided": f.decided,
                    "agreed": f.agreed,
                    "missed_findings": f.missed_findings,
                    "false_alarms": f.false_alarms,
                }
                for name, f in sorted(self.by_family.items())
            },
        }


async def compute_metrics(
    session: AsyncSession, *, organization_id: int
) -> CalibrationMetrics:
    """Compute calibration over one organization's decided proposals."""
    rows = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.organization_id == organization_id,
                AssessmentControlProposal.state.in_(("accepted", "rejected")),
            )
        )
    ).scalars().all()

    metrics = CalibrationMetrics()
    for row in rows:
        family = metrics.by_family.setdefault(
            control_family(row.control_identifier), FamilyMetrics()
        )
        metrics.decided += 1
        family.decided += 1

        if row.state == "accepted":
            metrics.agreed += 1
            family.agreed += 1
            continue

        proposed, corrected = row.proposed_finding, row.corrected_finding
        if proposed == "satisfied" and corrected == "other_than_satisfied":
            metrics.missed_findings += 1
            family.missed_findings += 1
        elif proposed == "other_than_satisfied" and corrected == "satisfied":
            metrics.false_alarms += 1
            family.false_alarms += 1
        else:
            metrics.other_disagreements += 1

    if metrics.decided:
        metrics.agreement_rate = metrics.agreed / metrics.decided
    return metrics
```

- [ ] **Step 4–6: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_calibration_metrics.py -v    # 12 pass
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/assessment/engine/calibration.py tests/test_calibration_metrics.py
git commit -m "feat(assessment): compute calibration metrics over decided proposals"
```

---

### Task 4: The configuration fingerprint and snapshots

**Files:**
- Modify: `src/ccf/assessment/engine/calibration.py`
- Create: `tests/test_calibration_snapshot.py`

**Interfaces:**
- Produces: `def config_fingerprint(*, model: str | None = None) -> str`; `async take_snapshot(session, *, organization_id: int, model: str | None = None) -> CalibrationSnapshot`; `async compare_snapshots(session, a_id: int, b_id: int) -> dict[str, Any]` returning `{"comparable": bool, ...}`.

The fingerprint is a SHA-256 over `get_settings().prep_screen_threshold`, a `ROLLUP_POLICY_VERSION` constant you add to `src/ccf/assessment/engine/rollup.py` (start at `"v1"`), and the model name. Canonicalise with `json.dumps(..., sort_keys=True)` so it is stable.

- [ ] **Step 1: Write the failing tests:**

```python
def test_the_same_configuration_fingerprints_identically() -> None:
def test_changing_the_screen_threshold_changes_the_fingerprint() -> None:
    """Monkeypatch CCF_PREP_SCREEN_THRESHOLD, clear the settings cache, re-fingerprint."""
def test_changing_the_model_changes_the_fingerprint() -> None:

async def test_take_snapshot_stores_metrics_and_fingerprint() -> None:
async def test_two_snapshots_under_one_configuration_are_comparable() -> None:
    """comparable is True and the metric deltas are reported."""
async def test_snapshots_under_different_configurations_are_not_comparable() -> None:
    """comparable is False. Re-deriving prep_screen_threshold -- which its ~0.03
    margin means will happen -- must read as an explained change, not drift."""
async def test_snapshots_are_scoped_to_one_organization() -> None:
```

- [ ] **Step 2–5: Verify failure, implement, run, gates, commit**

```bash
.venv/bin/pytest tests/test_calibration_snapshot.py -v
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/assessment/engine/calibration.py src/ccf/assessment/engine/rollup.py \
        tests/test_calibration_snapshot.py
git commit -m "feat(assessment): fingerprint calibration snapshots by configuration"
```

---

### Task 5: API and CLI

**Files:**
- Modify: `src/ccf/api/routes/assessment_engine.py`, `src/ccf/cli.py`
- Create: `tests/test_calibration_api.py`

**Interfaces:**
- `POST /api/assessment-engine/proposals/{id}/reject` — body `{corrected_finding, note}`, mirroring the accept endpoint. Refusals surface as **409**, matching repeat acceptance.
- `GET /api/assessment-engine/calibration` — live metrics for the principal's organization.
- `ccf calibration-snapshot` — gated on `assessment_engine_enabled`, like the other engine commands.

Both endpoints take `Depends(get_principal)` and derive the org from it. **No `organization_id` in any body or query** — slice 2 shipped three endpoints trusting one and an adversarial review found a live cross-tenant leak.

- [ ] **Step 1: Write the failing tests:**

```python
async def test_reject_records_the_correction_and_returns_200() -> None:
async def test_reject_refuses_an_already_decided_proposal_with_409() -> None:
async def test_reject_rejects_insufficient_evidence_as_a_correction() -> None:
async def test_reject_requires_a_note() -> None:
async def test_calibration_returns_metrics_for_the_principals_org() -> None:
async def test_calibration_reports_no_decisions_rather_than_zero_percent() -> None:
    """decided == 0 must be legible as 'nothing decided yet', not as 0% accuracy."""

async def test_an_org_a_principal_cannot_reject_an_org_b_proposal() -> None:
    """404, not 403 -- do not confirm another tenant's ids exist. Assert on rows:
    org B's proposal is unchanged afterwards."""
async def test_calibration_never_includes_another_orgs_decisions() -> None:
    """Attack-shaped: seed org B with a rejection, assert it is absent from org A's
    response body, by value not just by count."""
async def test_endpoints_are_absent_when_the_engine_is_disabled() -> None:
async def test_the_cli_exits_cleanly_when_the_engine_is_disabled() -> None:
```

- [ ] **Step 2–5: Verify failure, implement, run, gates, commit**

```bash
.venv/bin/pytest tests/test_calibration_api.py -v
.venv/bin/ccf calibration-snapshot --help
.venv/bin/pytest -q          # run alone
.venv/bin/ruff check . && .venv/bin/mypy src
git add src/ccf/api/routes/assessment_engine.py src/ccf/cli.py tests/test_calibration_api.py
git commit -m "feat(api): expose rejection and calibration"
```

---

### Task 6: Documentation

**Files:** `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`, and the module docstring in `src/ccf/assessment/engine/calibration.py`.

**Verify every statement against the code before writing it.** Slice 1's final review found three false doc claims; slice 3's Task 6 found three more, two of which had been written in earlier slices.

- [ ] **Step 1: Write the docs**

Cover, having confirmed each in source: an assessor can now reject a proposed finding with a correction and a required note; rejection stamps the linked AI runs `disposition="rejected"` and writes **no** `AssessmentControlResult`; calibration reports the two error directions separately and why; the per-family split; the configuration fingerprint and that mismatched snapshots read as **not comparable** rather than as drift; `CCF_ASSESSMENT_ENGINE_ENABLED` gating; and that **nothing is retrofitted** — proposals decided before this slice carry no recorded disagreement, so the first snapshot's denominator starts at zero.

State plainly what calibration does **not** do: it does not tune the threshold, does not gate CI, and does not generate synthetic evidence.

- [ ] **Step 2: Verify and commit**

```bash
.venv/bin/pytest -q          # run alone; cite the real count
git add docs/ARCHITECTURE.md README.md CHANGELOG.md src/ccf/assessment/engine/calibration.py
git commit -m "docs(assessment): document rejection and the calibration harness"
```

---

## Deferred, deliberately

- **No synthetic evidence generation** — a later slice, and synthetic evidence is exactly the clean input that flatters a retrieval pipeline, so it needs its own design.
- **No automatic threshold tuning.** The harness measures; a human decides.
- **No CI gate** on a metric change — that needs a baseline this slice exists to produce.
- **No retrofit** of decisions made before the reject path existed.
- **No calibration over objective-level verdicts**, only control-level findings. Objective verdicts are not individually accepted or rejected today, so there is no ground truth for them.
