# Closure & Remediation Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the loop the design doc identifies as open at both ends. An accepted `other_than_satisfied` finding becomes tracked remediation work (a POA&M) without a human remembering to trigger it, and completed remediation comes back for re-evaluation, surfacing as a proposal a human still has to accept — the engine never closes its own finding.

**Architecture:** Three parts, separable and shippable in sequence, exactly as the design doc scopes them. Part 1 (the bridge) makes `accept_control_proposal` create a POA&M for an accepted `other_than_satisfied` finding, keyed on `source_ref = f"assessment_control_result:{result.id}"` for idempotency, isolated in a `begin_nested()` savepoint so a POA&M-write failure never costs the caller their accepted finding. Part 2 (the closure trigger) hooks `poams.py`'s two closure paths (`PATCH /{pid}` and `POST /{pid}/close`) to enqueue a re-evaluation when an assessment-sourced POA&M transitions to `closed`. Part 3 (re-evaluation) is almost free: the existing worker (`ccf.assessment.engine.jobs.run_once`) already drives any `AssessmentJob` by loading its proposal and calling `evaluate_control_proposal`, which already writes no `AssessmentControlResult` — a re-evaluation proposal just needs to exist and carry `source_poam_id`.

**A schema conflict the design's "one column" framing does not resolve, and how this plan resolves it:** the design's own language — "create a **new** `AssessmentControlProposal`" for a re-evaluation, distinct from the accepted first-pass row, identifiable later by `source_poam_id` — requires a genuine second `INSERT` for the same `(assessment_id, control_identifier)` pair. But `assessment_control_proposals` already carries `uq_control_proposal_assessment_control`, a flat `UniqueConstraint` on exactly that pair, which would reject the second row outright. Task 1 replaces that constraint with two partial unique indexes: `uq_control_proposal_first_pass` on `(assessment_id, control_identifier) WHERE source_poam_id IS NULL` (preserving first-pass idempotency exactly as before) and `uq_control_proposal_source_poam` on `source_poam_id WHERE source_poam_id IS NOT NULL` (capping re-evaluation at one proposal per POA&M, belt-and-braces alongside the application-level check-then-insert). `open_control_proposal`'s existing lookup gains a `source_poam_id IS NULL` filter so it keeps returning exactly the first-pass row once a re-evaluation row exists alongside it, rather than raising `MultipleResultsFound`. This is documented inline in Task 1 and called out again in the final report — it is a resolution of the design's stated intent against the real schema, not a deviation from it.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Alembic, Postgres 16, FastAPI, Typer, pytest.

**Spec:** [docs/superpowers/specs/2026-08-11-closure-remediation-loop-design.md](../specs/2026-08-11-closure-remediation-loop-design.md)
**Depends on:** slices 1–4, all on `feat/evidence-prep-spine`.

## Global Constraints

- **Python** 3.12, `line-length = 100`. **Ruff** selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected, so a `# noqa: BLE001` or `# noqa: SLF001` trips `RUF100` (unused noqa) — don't add one. `PLC0415` means imports go at module top level, never inside a function body. Known baseline: **exactly 25 pre-existing `PLR0917`** in `src/ccf/api/routes/` — new route handlers in this slice use keyword-only parameters (a bare `*,` before them) so they add nothing to it.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** `from ...logging import get_logger` (adjust the relative depth per module); never `import structlog` directly; never `extra={...}` — it collides with reserved `LogRecord` attributes (e.g. `filename`) and raises `KeyError`. Pass plain kwargs to the logger call instead.
- **Tests:** real Postgres on port **5434**, container `ccf-test-db`. `asyncio_mode = "auto"` in `pytest.ini` — never write `@pytest.mark.asyncio`. DB-touching test modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`. **Never run two pytest sessions concurrently** — the session fixture drops and recreates the schema. Venv binaries only: `.venv/bin/pytest`, `.venv/bin/alembic`, `.venv/bin/ruff`, `.venv/bin/mypy` — never bare `python3` (system Python is 3.9). **Baseline: 895 passed, 1 skipped.**
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — a `SELECT` issued while a pending `add()` is unflushed sees nothing. Flush explicitly before any such read.
- **Migrations:** `migrations/versions/00NN_<slug>.py`, explicit `revision`/`down_revision`. **Current head is `0057_reject_and_calibration`**; this slice adds `0058_closure_reevaluation`. Every table- or column-adding migration re-issues `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app` at the end of `upgrade()`. `server_default=func.now()` columns must also be `nullable=False` in the migration, not just the ORM (none of this slice's new columns carry a `server_default`, but the rule still governs anything touched near one). `downgrade()` must round-trip: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`.
- **Status vocabularies** are `String(32)` (or narrower) with application-level checks, never Postgres enums, for anything new — `PROPOSAL_STATES`, `ASSESSMENT_JOB_STATES` already follow this. (`POAM.status`/`POAM.severity` are pre-existing Postgres enums from earlier slices; this plan does not touch their type, only reads/writes their existing values.)
- **Savepoint isolation:** `AsyncSession.rollback()` is **not** savepoint-scoped — it unwinds the whole transaction, not just the failing write. Slice 3 shipped a version that silently discarded the caller's work while reporting success. Any write whose failure must not cost the caller their own already-good work uses `async with session.begin_nested():`, never a bare `try`/`except` around a plain `session.add()` + `flush()`.
- **Tenant isolation:** derive the organization from `Depends(get_principal)`, never from a body/path/query argument; reconcile a foreign row's organization against the caller's *before* acting on it, not after. Another tenant's row is **404, not 403** — a 403 confirms the id exists.
- **Control identifiers** fold through `ccf.prep.screen.normalize_control_identifier` before being stored or compared — the catalog mixes `AC-02`, `CP-9`, and `AC.L2-3.1.1`.
- **Workers:** commit the claim immediately, commit each job's outcome independently, and call `reap_stale_jobs` **inside** the drain loop, not once before it — a fix wave once left it outside a `--loop` and silently disabled the dead-letter net. (`_assessment_drain_loop` in `src/ccf/cli.py` already does this correctly; this slice reuses it unchanged.)
- **Mutation discipline:** every guard and every recorded field gets its own assertion. Each task's final step verifies by mutation — comment out or invert the line under test, re-run, confirm the specific assertion fails, then revert. A dozen defects in this project were found this way; four tests passed against deliberately broken code before this discipline was standard.
- **Asymmetric fixtures:** wherever a bug could swap two values undetected (severities, org ids, verdicts, control identifiers), the test fixture uses two *different* values, never the same value twice — a symmetric fixture in slice 4 passed against transposed code and proved nothing.
- **Zero-count assertions** are scoped to the specific org/assessment/control/POA&M under test, never a bare "the table is empty" — an earlier test in this project asserted zero against a table that was empty for unrelated reasons and would have passed regardless.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot project.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/models_assessment_engine.py` | `AssessmentControlProposal.source_poam_id`; replace the flat unique constraint with two partial unique indexes |
| `migrations/versions/0058_closure_reevaluation.py` | column + index migration + grant |
| `src/ccf/assessment/engine/service.py` | acceptance→POA&M bridge (`_ensure_poam_for_other_than_satisfied`); `open_reevaluation_proposal`; `open_control_proposal`'s lookup gains a first-pass-only filter |
| `src/ccf/assessment/engine/jobs.py` | `enqueue_reevaluation` |
| `src/ccf/api/routes/poams.py` | closure hook (`_maybe_enqueue_reevaluation`), wired into `update_poam` and `close_poam` |
| `src/ccf/api/routes/assessment_engine.py` | `GET /api/assessment-engine/proposals?source_poam_id={id}` |
| `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md` | document the loop and its explicit non-goals |

---

### Task 1: `source_poam_id` and the constraint that has to change to allow it

**Files:**
- Modify: `src/ccf/models_assessment_engine.py`
- Create: `migrations/versions/0058_closure_reevaluation.py`
- Create: `tests/test_closure_reevaluation_models.py`

**Interfaces:**
- Produces: `AssessmentControlProposal.source_poam_id`; index `uq_control_proposal_first_pass`; index `uq_control_proposal_source_poam`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_closure_reevaluation_models.py`:

```python
"""``source_poam_id`` and the constraint change that lets a re-evaluation
proposal coexist with the first-pass proposal it re-evaluates.

The old ``uq_control_proposal_assessment_control`` constraint was a flat
unique index on ``(assessment_id, control_identifier)`` -- exactly the pair a
closure-triggered re-evaluation needs a *second* row for, alongside the
already-accepted first-pass row still sitting on that same pair. Replaced by
two partial unique indexes: first-pass idempotency now applies only to rows
with ``source_poam_id IS NULL``, and a second index caps re-evaluation at one
proposal per POA&M.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import POAM, Assessment, Organization, System
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


async def _poam_for(assessment_id: int) -> int:
    async with session_scope() as s:
        system_id = (
            await s.execute(select(Assessment.system_id).where(Assessment.id == assessment_id))
        ).scalar_one()
        poam = POAM(
            system_id=system_id,
            title="closure-reevaluation fixture",
            severity="moderate",
            status="open",
            source="assessment",
        )
        s.add(poam)
        await s.flush()
        return int(poam.id)


async def test_source_poam_id_defaults_to_null() -> None:
    org_id, assessment_id = await _assessment("close-defaults")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(p)
        await s.flush()
        assert p.source_poam_id is None


async def test_source_poam_id_round_trips() -> None:
    org_id, assessment_id = await _assessment("close-roundtrip")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            source_poam_id=poam_id,
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
        assert p.source_poam_id == poam_id


async def test_two_first_pass_proposals_for_the_same_control_still_collide() -> None:
    """uq_control_proposal_first_pass -- what the flat constraint used to
    enforce directly -- still blocks two source_poam_id-NULL rows for the
    same (assessment_id, control_identifier). First-pass idempotency must
    survive the constraint swap unchanged.
    """
    org_id, assessment_id = await _assessment("close-first-pass-collide")
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
            )
        )
        await s.flush()
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
            )
        )
        with pytest.raises(IntegrityError):
            await s.flush()


async def test_a_reevaluation_proposal_coexists_with_the_first_pass_row() -> None:
    """The whole point of the constraint swap: a second row for the same
    (assessment_id, control_identifier), distinguished only by carrying a
    source_poam_id, must be insertable alongside the first-pass row.
    """
    org_id, assessment_id = await _assessment("close-coexist")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
            )
        )
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-2",
                source_poam_id=poam_id,
            )
        )
        await s.flush()  # must not raise
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.assessment_id == assessment_id
                )
            )
        ).scalars().all()
    assert len(rows) == 2


async def test_only_one_proposal_per_source_poam_id() -> None:
    """uq_control_proposal_source_poam. Uses two *different* control
    identifiers (AC-2, AC-3) sharing the same source_poam_id, so a failure
    here can only be the source_poam_id index firing -- not a coincidental
    collision with uq_control_proposal_first_pass, which these two rows
    don't otherwise share.
    """
    org_id, assessment_id = await _assessment("close-one-per-poam")
    poam_id = await _poam_for(assessment_id)
    async with session_scope() as s:
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-2",
                source_poam_id=poam_id,
            )
        )
        await s.flush()
        s.add(
            AssessmentControlProposal(
                organization_id=org_id,
                assessment_id=assessment_id,
                control_identifier="AC-3",
                source_poam_id=poam_id,
            )
        )
        with pytest.raises(IntegrityError):
            await s.flush()


async def test_the_old_flat_unique_constraint_is_gone() -> None:
    async with session_scope() as s:
        row = (
            await s.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conname = 'uq_control_proposal_assessment_control'"
                )
            )
        ).scalar_one_or_none()
    assert row is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_closure_reevaluation_models.py -v`
Expected: FAIL — `TypeError: 'source_poam_id' is an invalid keyword argument for AssessmentControlProposal`.

- [ ] **Step 3: Add the column and swap the constraint**

In `src/ccf/models_assessment_engine.py`, add `text` to the `sqlalchemy` import:

```python
from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
```

Inside `AssessmentControlProposal`, beside `rejection_note`:

```python
    #: Set only on a closure-triggered re-evaluation: the POA&M whose closure
    #: raised this proposal. NULL for every first-pass proposal. Nullable
    #: (not just "usually null"): every existing proposal has no source
    #: POA&M, and a re-evaluation proposal must stay usable if the POA&M is
    #: later deleted (ON DELETE SET NULL, not CASCADE -- the proposal is a
    #: record of what happened, not a detail owned by the POA&M).
    source_poam_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.poams.id", ondelete="SET NULL"), index=True
    )
```

Replace `__table_args__`:

```python
    __table_args__ = (
        # First-pass idempotency (open_control_proposal's own reuse-or-create
        # logic) is scoped to source_poam_id IS NULL rows only -- see the
        # module docstring's note on why a flat (assessment_id,
        # control_identifier) constraint had to give way to this. A
        # closure-triggered re-evaluation for the same control is a second,
        # distinct row and must not collide with the accepted first-pass row
        # still sitting on that same pair.
        Index(
            "uq_control_proposal_first_pass",
            "assessment_id",
            "control_identifier",
            unique=True,
            postgresql_where=text("source_poam_id IS NULL"),
        ),
        # Caps re-evaluation at one proposal per POA&M -- belt-and-braces
        # alongside service.open_reevaluation_proposal's own
        # check-then-insert, which is what actually protects against a race
        # between two concurrent closures of the same POA&M.
        Index(
            "uq_control_proposal_source_poam",
            "source_poam_id",
            unique=True,
            postgresql_where=text("source_poam_id IS NOT NULL"),
        ),
        Index("ix_control_proposal_state", "organization_id", "state"),
    )
```

`UniqueConstraint` stays imported — `AssessmentObjectiveProposal.__table_args__` still uses it.

- [ ] **Step 4: Write the migration**

Create `migrations/versions/0058_closure_reevaluation.py`:

```python
"""Closure-triggered re-evaluation: source_poam_id, and the constraint swap
that lets a re-evaluation proposal coexist with the first-pass row it
re-evaluates.

An accepted other_than_satisfied finding now creates a POA&M (the
"bridge" -- see ccf.assessment.engine.service); closing that POA&M must be
able to enqueue a *second*, distinct AssessmentControlProposal for the same
(assessment_id, control_identifier) the first-pass proposal already
occupies. The flat uq_control_proposal_assessment_control constraint that
pair carried since migration 0055 would reject that second row outright, so
it is replaced here by two partial unique indexes: first-pass idempotency
now applies only to source_poam_id-NULL rows, and a second index caps
re-evaluation at one proposal per POA&M.

Revision ID: 0058_closure_reevaluation
Revises: 0057_reject_and_calibration
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0058_closure_reevaluation"
down_revision = "0057_reject_and_calibration"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PROPOSALS = "assessment_control_proposals"


def upgrade() -> None:
    op.add_column(
        _PROPOSALS,
        sa.Column(
            "source_poam_id",
            sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.poams.id", ondelete="SET NULL"),
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_control_proposal_source_poam_id",
        _PROPOSALS,
        ["source_poam_id"],
        schema=_SCHEMA,
    )

    op.drop_constraint(
        "uq_control_proposal_assessment_control", _PROPOSALS, schema=_SCHEMA, type_="unique"
    )
    op.create_index(
        "uq_control_proposal_first_pass",
        _PROPOSALS,
        ["assessment_id", "control_identifier"],
        unique=True,
        schema=_SCHEMA,
        postgresql_where=sa.text("source_poam_id IS NULL"),
    )
    op.create_index(
        "uq_control_proposal_source_poam",
        _PROPOSALS,
        ["source_poam_id"],
        unique=True,
        schema=_SCHEMA,
        postgresql_where=sa.text("source_poam_id IS NOT NULL"),
    )

    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app")


def downgrade() -> None:
    op.drop_index("uq_control_proposal_source_poam", table_name=_PROPOSALS, schema=_SCHEMA)
    op.drop_index("uq_control_proposal_first_pass", table_name=_PROPOSALS, schema=_SCHEMA)
    op.create_unique_constraint(
        "uq_control_proposal_assessment_control",
        _PROPOSALS,
        ["assessment_id", "control_identifier"],
        schema=_SCHEMA,
    )
    op.drop_index("ix_control_proposal_source_poam_id", table_name=_PROPOSALS, schema=_SCHEMA)
    op.drop_column(_PROPOSALS, "source_poam_id", schema=_SCHEMA)
```

- [ ] **Step 5: Round-trip the migration**

Run: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`

- [ ] **Step 6: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_closure_reevaluation_models.py -v    # 6 pass
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** temporarily change `uq_control_proposal_source_poam`'s `postgresql_where` to `text("source_poam_id IS NULL")` (inverted), re-migrate against a scratch DB or just re-run `test_only_one_proposal_per_source_poam_id` after manually recreating the index with that condition — confirm it now fails to catch the collision (or, faster: drop the `postgresql_where` clause on `uq_control_proposal_first_pass` entirely and confirm `test_a_reevaluation_proposal_coexists_with_the_first_pass_row` now fails with an `IntegrityError` it shouldn't raise). Revert before committing.

```bash
git add src/ccf/models_assessment_engine.py \
        migrations/versions/0058_closure_reevaluation.py \
        tests/test_closure_reevaluation_models.py
git commit -m "feat(assessment): add source_poam_id and the constraint swap it requires"
```

---

### Task 2: The bridge — acceptance creates a POA&M

**Files:**
- Modify: `src/ccf/assessment/engine/service.py`
- Create: `tests/test_assessment_poam_bridge.py`

**Interfaces:**
- Produces: `async def _ensure_poam_for_other_than_satisfied(session, *, proposal: AssessmentControlProposal, result: AssessmentControlResult) -> None`, called from inside `accept_control_proposal`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_assessment_poam_bridge.py`:

```python
"""Acceptance's other effect: an accepted other_than_satisfied finding
creates a POA&M, idempotently, without a human triggering it.

``insufficient_evidence`` is not exercised as a "creates none" case here:
``accept_control_proposal`` already refuses to accept an
``insufficient_evidence`` finding at all (``AcceptanceRefused``), so there is
no reachable path where the bridge could even run against one -- it is
untestable via the real acceptance path and asserting it in isolation would
just re-test the guard Task 2 of the calibration-harness slice already
covers.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.db import session_scope
from ccf.ingest.scanners import SEVERITY_SLA_DAYS
from ccf.models import POAM, Assessment, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-95"


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """One addressable control plus one sub-clause objective row -- mirrors
    test_assessment_acceptance.py's fixture shape.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Bridge Fixture Control",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the bridge fixture objective is met;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def _assessment(name: str) -> int:
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
        return int(a.id)


def _fake_evaluate(verdict: str) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


async def _accept(
    name: str, monkeypatch: pytest.MonkeyPatch, verdict: str, *, accepted_by: str = "a@x.test"
) -> tuple[int, int]:
    """Open, evaluate, and accept a proposal. Returns (proposal_id, result_id)."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate(verdict))
    assessment_id = await _assessment(name)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, int(proposal.id), accepted_by=accepted_by)
        return int(proposal.id), int(result.id)


async def _poams_for_result(result_id: int) -> list[POAM]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"assessment_control_result:{result_id}")
            )
        ).scalars().all()
        return list(rows)


async def test_an_accepted_other_than_satisfied_finding_creates_one_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, result_id = await _accept("bridge-ots", monkeypatch, "not_satisfied")
    poams = await _poams_for_result(result_id)
    assert len(poams) == 1
    poam = poams[0]
    assert poam.source == "assessment"
    assert poam.source_ref == f"assessment_control_result:{result_id}"
    assert poam.severity == "moderate"
    assert poam.status == "open"
    assert poam.identified_on is not None
    assert poam.due_on == poam.identified_on + timedelta(days=SEVERITY_SLA_DAYS["moderate"])


async def test_a_satisfied_finding_creates_no_poam(monkeypatch: pytest.MonkeyPatch) -> None:
    _, result_id = await _accept("bridge-satisfied", monkeypatch, "satisfied")
    assert await _poams_for_result(result_id) == []


async def test_a_not_applicable_finding_creates_no_poam(monkeypatch: pytest.MonkeyPatch) -> None:
    _, result_id = await _accept("bridge-na", monkeypatch, "not_applicable")
    assert await _poams_for_result(result_id) == []


async def test_reaccepting_is_idempotent_and_does_not_overwrite_an_edited_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accepting twice must yield one POA&M -- and a human's edit to it
    between the two acceptances must survive, not merely the count staying
    one. Re-evaluating under a different verdict and re-accepting exercises
    accept_control_proposal's own uq_assess_ctrl upsert path (see
    test_assessment_acceptance.py::test_accepting_twice_does_not_duplicate_the_result_row)
    while the POA&M bridge must stay a no-op the second time.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    assessment_id = await _assessment("bridge-idempotent")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        result = await accept_control_proposal(s, proposal_id, accepted_by="first@x.test")
        result_id = int(result.id)

    poams = await _poams_for_result(result_id)
    assert len(poams) == 1
    poam_id = poams[0].id

    # A human edits the POA&M between the two acceptances.
    async with session_scope() as s:
        poam = (await s.execute(select(POAM).where(POAM.id == poam_id))).scalar_one()
        poam.title = "Edited by a human, must survive re-acceptance"

    # Re-evaluate (still other_than_satisfied via a different verdict word,
    # so this is a genuine second evaluate+accept cycle, not a no-op) and
    # accept again.
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        proposal = await evaluate_control_proposal(s, proposal)
        await accept_control_proposal(s, proposal_id, accepted_by="second@x.test")

    poams = await _poams_for_result(result_id)
    assert len(poams) == 1, "re-acceptance must not create a second POA&M"
    assert poams[0].id == poam_id
    assert poams[0].title == "Edited by a human, must survive re-acceptance"


async def test_a_poam_write_failure_does_not_fail_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force a real DB-level failure (VARCHAR(512) truncation, not a plain
    Python exception the bridge's own try/except could trivially swallow
    without needing begin_nested) inside the bridge's savepoint, and confirm
    the AssessmentControlResult and the acceptance itself still persist.
    """

    class _OversizedTitlePOAM(service.POAM):  # type: ignore[misc,valid-type]
        def __init__(self, **kwargs: Any) -> None:
            kwargs["title"] = "x" * 600
            super().__init__(**kwargs)

    monkeypatch.setattr(service, "POAM", _OversizedTitlePOAM)
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    assessment_id = await _assessment("bridge-write-fails")
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)
        result = await accept_control_proposal(s, proposal_id, accepted_by="a@x.test")
        assert result.finding == "other_than_satisfied"
        result_id = int(result.id)

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert proposal.state == "accepted", "the acceptance itself must survive"

    assert await _poams_for_result(result_id) == [], "the failed POA&M write must not persist"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_assessment_poam_bridge.py -v`
Expected: FAIL — every test collects a zero-length `_poams_for_result` regardless of verdict, or the `_OversizedTitlePOAM` monkeypatch target `service.POAM` doesn't exist yet (`AttributeError`).

- [ ] **Step 3: Implement the bridge**

In `src/ccf/assessment/engine/service.py`, update the imports:

```python
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import get_settings
from ...ingest.scanners import SEVERITY_SLA_DAYS
from ...logging import get_logger
from ...models import POAM, Assessment, AssessmentControlResult, System
```

(`timedelta` and `POAM` are new; `SEVERITY_SLA_DAYS` is a new import line.)

Add, above `accept_control_proposal`:

```python
async def _ensure_poam_for_other_than_satisfied(
    session: AsyncSession,
    *,
    proposal: AssessmentControlProposal,
    result: AssessmentControlResult,
) -> None:
    """Create a POA&M for an accepted other_than_satisfied finding, idempotently.

    Only ``other_than_satisfied`` creates one. ``satisfied``, ``not_applicable``
    and (unreachable here -- acceptance already refuses it) ``insufficient_evidence``
    do not: manufacturing tracked remediation work out of the engine's own
    uncertainty would be worse than not creating anything.

    Idempotent on ``source_ref = f"assessment_control_result:{result.id}"``,
    not on title -- ``ui.py``'s inline duplicate dedupes on title alone and
    would collide across two systems assessing the same control. An existing
    POA&M with that source_ref is found and left alone: re-accepting a
    proposal (the result row upserts) must not silently overwrite a POA&M a
    human has since edited, assigned, or partially remediated.

    Runs in its own savepoint and never raises: acceptance writes the
    authoritative AssessmentControlResult, and losing the derived POA&M is
    recoverable while discarding a human's accepted finding because a
    derived row would not insert is not. AsyncSession.rollback() is NOT
    savepoint-scoped -- it would unwind this whole accept_control_proposal
    call, which is exactly the trap slice 3 hit with record_ai_run. This
    uses begin_nested() instead, which rolls back only this savepoint on
    failure and leaves the surrounding acceptance intact.
    """
    if result.finding != "other_than_satisfied":
        return
    source_ref = f"assessment_control_result:{result.id}"
    try:
        async with session.begin_nested():
            existing = (
                await session.execute(select(POAM.id).where(POAM.source_ref == source_ref))
            ).scalar_one_or_none()
            if existing is not None:
                return
            system_id = (
                await session.execute(
                    select(Assessment.system_id).where(Assessment.id == proposal.assessment_id)
                )
            ).scalar_one()
            severity = "moderate"
            today = datetime.now(UTC).date()
            due_on = today + timedelta(days=SEVERITY_SLA_DAYS.get(severity, 90))
            session.add(
                POAM(
                    system_id=system_id,
                    title=f"{proposal.control_identifier} — other than satisfied",
                    weakness=(
                        proposal.rollup_rationale
                        or f"{proposal.control_identifier} assessed other than satisfied."
                    ),
                    severity=severity,
                    status="open",
                    identified_on=today,
                    due_on=due_on,
                    original_due_on=due_on,
                    source="assessment",
                    source_ref=source_ref,
                )
            )
            await session.flush()
    except Exception as exc:  # a derived-row failure must not cost the acceptance
        log.warning(
            "assessment.poam_bridge_failed",
            proposal_id=proposal.id,
            result_id=result.id,
            error=str(exc),
        )
```

In `accept_control_proposal`, right after the existing final flush and before the `log.info`/`return result` at the end, add the call:

```python
    await session.flush()
    await _ensure_poam_for_other_than_satisfied(session, proposal=proposal, result=result)
    log.info(
        "assessment.control_proposal_accepted",
        assessment_id=proposal.assessment_id,
        control_identifier=proposal.control_identifier,
        accepted_by=accepted_by,
    )
    return result
```

(The flush must come first — it is what assigns `result.id` for a newly-inserted result row; `_ensure_poam_for_other_than_satisfied` needs that id for `source_ref`.)

- [ ] **Step 4: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_assessment_poam_bridge.py -v    # 5 pass
.venv/bin/pytest tests/test_assessment_acceptance.py tests/test_assessment_rejection.py -v   # unaffected
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** in `_ensure_poam_for_other_than_satisfied`, change `async with session.begin_nested():` to nothing (dedent its body one level, deleting that line) and re-run `test_a_poam_write_failure_does_not_fail_acceptance` — confirm it now fails (the poisoned transaction surfaces as an unhandled error on the enclosing `session_scope()`'s commit, since the DB-level `IntegrityError` triggered by the oversized title is no longer isolated to a savepoint). Revert. Then change the `if result.finding != "other_than_satisfied": return` line to `if result.finding == "other_than_satisfied": return` (inverted) and re-run `test_an_accepted_other_than_satisfied_finding_creates_one_poam` — confirm it now fails. Revert both.

```bash
git add src/ccf/assessment/engine/service.py tests/test_assessment_poam_bridge.py
git commit -m "feat(assessment): accept an other-than-satisfied finding into a POA&M"
```

---

### Task 3: The closure trigger — closing a POA&M enqueues a re-evaluation

**Files:**
- Modify: `src/ccf/assessment/engine/service.py`
- Modify: `src/ccf/assessment/engine/jobs.py`
- Modify: `src/ccf/api/routes/poams.py`
- Create: `tests/test_assessment_closure_trigger.py`

**Interfaces:**
- Produces: `async def open_reevaluation_proposal(session, *, result: AssessmentControlResult, source_poam_id: int) -> AssessmentControlProposal` (service.py); `async def enqueue_reevaluation(session, *, poam_id: int, source_ref: str, organization_id: int) -> AssessmentJob | None` (jobs.py); `async def _maybe_enqueue_reevaluation(session, obj: POAM) -> None` (poams.py), called from `update_poam` and `close_poam`.
- Consumes: Task 2's `source_ref` convention; Task 1's `source_poam_id` column and partial indexes.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_assessment_closure_trigger.py`:

```python
"""Closing an assessment-sourced POA&M enqueues a re-evaluation of the
control it remediated. Idempotent, scan-sourced POA&Ms excluded, and every
tenant check is exercised as an attack, not a happy path.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.assessment.engine import jobs as engine_jobs
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.db import session_scope
from ccf.models import POAM, Assessment, Control, Organization, PoamMilestone, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-96"


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Closure Trigger Fixture Control",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the closure trigger fixture objective is met;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _fake_evaluate(verdict: str) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


async def _bridged_poam(name: str, monkeypatch: pytest.MonkeyPatch) -> tuple[int, int, int]:
    """Build a real accepted other_than_satisfied finding through the Task 2
    bridge, then complete its one milestone so it can pass the closure gate.
    Returns (org_id, assessment_id, poam_id).
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
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
        org_id, assessment_id = int(org.id), int(a.id)

    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, int(proposal.id), accepted_by="a@x.test")
        result_id = int(result.id)

    async with session_scope() as s:
        poam = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"assessment_control_result:{result_id}")
            )
        ).scalar_one()
        poam_id = int(poam.id)
        s.add(
            PoamMilestone(
                poam_id=poam_id, description="remediated", status="completed", sort_order=0
            )
        )
    return org_id, assessment_id, poam_id


async def _proposal_for_poam(poam_id: int) -> AssessmentControlProposal | None:
    async with session_scope() as s:
        return (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.source_poam_id == poam_id
                )
            )
        ).scalar_one_or_none()


async def _jobs_for_proposal(proposal_id: int) -> list[AssessmentJob]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AssessmentJob).where(AssessmentJob.control_proposal_id == proposal_id)
            )
        ).scalars().all()
        return list(rows)


async def test_closing_an_assessment_sourced_poam_enqueues_one_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, assessment_id, poam_id = await _bridged_poam("close-trigger-one-job", monkeypatch)
    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/close")
    assert r.status_code == 200
    assert r.json()["status"] == "closed"

    proposal = await _proposal_for_poam(poam_id)
    assert proposal is not None
    assert proposal.assessment_id == assessment_id
    assert proposal.control_identifier == _SEQ
    jobs = await _jobs_for_proposal(int(proposal.id))
    assert len(jobs) == 1
    assert jobs[0].status == "pending"


async def test_reopening_and_reclosing_the_same_poam_enqueues_only_one_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine double-closure via the real reopen -> reclose workflow, not
    merely a repeated POST -- exercises open_reevaluation_proposal's own
    source_poam_id idempotency, not just a status-transition guard at the
    route layer.
    """
    _, _, poam_id = await _bridged_poam("close-trigger-reclose", monkeypatch)
    async with _client() as c:
        first = await c.post(f"/api/poams/{poam_id}/close")
        assert first.status_code == 200
        reopen = await c.patch(f"/api/poams/{poam_id}", json={"status": "open"})
        assert reopen.status_code == 200
        second = await c.post(f"/api/poams/{poam_id}/close")
        assert second.status_code == 200

    proposal = await _proposal_for_poam(poam_id)
    assert proposal is not None
    jobs = await _jobs_for_proposal(int(proposal.id))
    assert len(jobs) == 1, "reclosing the same POA&M must not enqueue a second job"


async def test_closing_a_scan_sourced_poam_enqueues_none() -> None:
    async with session_scope() as s:
        org = Organization(name="close-trigger-scan")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="close-trigger-scan-sys")
        s.add(system)
        await s.flush()
        poam = POAM(
            system_id=system.id,
            title="scan finding",
            severity="high",
            status="open",
            source="scan",
            scanner="nessus",
            finding_uid="fake-uid",
        )
        s.add(poam)
        await s.flush()
        poam_id = int(poam.id)
        s.add(
            PoamMilestone(
                poam_id=poam_id, description="patched", status="completed", sort_order=0
            )
        )

    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/close")
    assert r.status_code == 200

    assert await _proposal_for_poam(poam_id) is None


async def test_the_closure_gate_still_refuses_an_unremediated_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISSM-08/09's gate is untouched by this slice -- a POA&M with no
    completed milestone and no closure evidence still 409s, and closing
    fails before any proposal is created.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    async with session_scope() as s:
        org = Organization(name="close-trigger-gate")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="close-trigger-gate-sys")
        s.add(system)
        await s.flush()
        a = Assessment(system_id=system.id, name="close-trigger-gate-a", kind="self")
        s.add(a)
        await s.flush()
        assessment_id = int(a.id)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, int(proposal.id), accepted_by="a@x.test")
        result_id = int(result.id)
    async with session_scope() as s:
        poam = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"assessment_control_result:{result_id}")
            )
        ).scalar_one()
        poam_id = int(poam.id)
        # No milestone, no closure evidence -- the gate must refuse.

    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/close")
    assert r.status_code == 409
    assert await _proposal_for_poam(poam_id) is None


async def test_a_mismatched_organization_enqueues_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Attack shape: a POA&M's source_ref names a result belonging to
    another organization entirely. enqueue_reevaluation must refuse rather
    than enqueue a job crossing that boundary.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    async with session_scope() as s:
        org_a = Organization(name="close-trigger-org-a")
        s.add(org_a)
        org_b = Organization(name="close-trigger-org-b")
        s.add(org_b)
        await s.flush()
        system_b = System(organization_id=org_b.id, name="close-trigger-org-b-sys")
        s.add(system_b)
        await s.flush()
        assessment_b = Assessment(system_id=system_b.id, name="org-b-a", kind="self")
        s.add(assessment_b)
        await s.flush()
        org_a_id, assessment_b_id = int(org_a.id), int(assessment_b.id)

    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_b_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, int(proposal.id), accepted_by="a@x.test")
        result_id = int(result.id)

    async with session_scope() as s:
        job = await engine_jobs.enqueue_reevaluation(
            s,
            poam_id=999_999,
            source_ref=f"assessment_control_result:{result_id}",
            organization_id=org_a_id,  # the caller's org -- deliberately not org_b's
        )
        assert job is None

    rows = await _proposal_for_poam(999_999)
    assert rows is None
```

- [ ] **Step 2: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_assessment_closure_trigger.py -v`
Expected: FAIL — `AttributeError: module 'ccf.assessment.engine.jobs' has no attribute 'enqueue_reevaluation'`.

- [ ] **Step 3: Add `open_reevaluation_proposal` to `service.py`**

Add, below `open_control_proposal`:

```python
async def open_reevaluation_proposal(
    session: AsyncSession, *, result: AssessmentControlResult, source_poam_id: int
) -> AssessmentControlProposal:
    """Open (or return the existing) re-evaluation proposal for a remediated control.

    Idempotent on ``source_poam_id`` (``uq_control_proposal_source_poam``,
    migration 0058) -- closing the same POA&M twice returns the same
    proposal rather than violating that index with a second insert.
    Deliberately does not call :func:`open_control_proposal`: that
    function's own idempotency (``uq_control_proposal_first_pass``) is now
    scoped to ``source_poam_id IS NULL`` rows only, precisely so a fresh row
    here for the same ``(assessment_id, control_identifier)`` does not
    collide with the already-accepted first-pass proposal still sitting on
    that pair.
    """
    existing = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.source_poam_id == source_poam_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    row = (
        await session.execute(
            select(System.organization_id, System.id)
            .join(Assessment, Assessment.system_id == System.id)
            .where(Assessment.id == result.assessment_id)
        )
    ).first()
    if row is None:
        raise ProposalError(f"assessment {result.assessment_id} not found")
    organization_id = int(row[0])

    canonical = normalize_control_identifier(result.control_id)
    proposal = AssessmentControlProposal(
        organization_id=organization_id,
        assessment_id=result.assessment_id,
        control_identifier=canonical,
        source_poam_id=source_poam_id,
    )
    session.add(proposal)
    await session.flush()
    log.info(
        "assessment.reevaluation_proposal_opened",
        assessment_id=result.assessment_id,
        control_identifier=canonical,
        source_poam_id=source_poam_id,
    )
    return proposal
```

Then fix `open_control_proposal`'s own lookup so it keeps returning only the first-pass row once a re-evaluation proposal exists alongside it (otherwise `.scalar_one_or_none()` raises `MultipleResultsFound`). Change:

```python
    existing = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.assessment_id == assessment_id,
                AssessmentControlProposal.control_identifier == canonical,
            )
        )
    ).scalar_one_or_none()
```

to:

```python
    existing = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.assessment_id == assessment_id,
                AssessmentControlProposal.control_identifier == canonical,
                # Scoped to the first-pass row only (uq_control_proposal_first_pass,
                # migration 0058) -- a closure-triggered re-evaluation proposal for
                # this same control carries a non-NULL source_poam_id and must not
                # be returned here, or a second call after one exists would raise
                # MultipleResultsFound instead of reusing the first-pass row.
                AssessmentControlProposal.source_poam_id.is_(None),
            )
        )
    ).scalar_one_or_none()
```

- [ ] **Step 4: Add `enqueue_reevaluation` to `jobs.py`**

Update the imports:

```python
from ...models import Assessment, AssessmentControlResult, System
from ...models_assessment_engine import AssessmentControlProposal, AssessmentJob
from ...queue import claim_jobs, reap_stale_jobs
from .service import evaluate_control_proposal, open_control_proposal, open_reevaluation_proposal
```

Add, below `enqueue_control`:

```python
async def enqueue_reevaluation(
    session: AsyncSession, *, poam_id: int, source_ref: str, organization_id: int
) -> AssessmentJob | None:
    """Enqueue a re-evaluation of the control an assessment-sourced POA&M remediated.

    A no-op -- enqueues nothing, returns ``None`` -- for any ``source_ref``
    that does not match the ``assessment_control_result:{id}`` convention
    Task 2's bridge writes: a scan-sourced or profile-gap POA&M has no
    objective-level proposal to re-derive, and enqueueing one would run the
    engine against a control nobody assessed through it.

    ``organization_id`` is the POA&M's own organization -- resolved by the
    caller from its ``system_id``, never trusted from anywhere else -- and
    is reconciled here against the organization the named result's
    assessment actually belongs to *before* anything is written. A mismatch
    means the POA&M's source_ref, however that happened, names a finding in
    another tenant; nothing is enqueued and no proposal row is created for
    it, matching the fail-closed-before-any-write shape
    ``open_reevaluation_proposal`` itself cannot enforce on its own (it only
    ever sees the organization derived from the result, not the caller's).

    Idempotent via :func:`open_reevaluation_proposal`'s own
    ``source_poam_id`` key, plus reuse of any outstanding (``pending`` /
    ``claimed``) job already queued against that one proposal -- closing the
    same POA&M twice enqueues exactly one job.
    """
    if not source_ref.startswith("assessment_control_result:"):
        return None
    try:
        result_id = int(source_ref.split(":", 1)[1])
    except ValueError:
        return None

    result = (
        await session.execute(
            select(AssessmentControlResult).where(AssessmentControlResult.id == result_id)
        )
    ).scalar_one_or_none()
    if result is None:
        return None

    result_org_id = (
        await session.execute(
            select(System.organization_id)
            .join(Assessment, Assessment.system_id == System.id)
            .where(Assessment.id == result.assessment_id)
        )
    ).scalar_one_or_none()
    if result_org_id is None or int(result_org_id) != organization_id:
        log.warning(
            "assessment.reevaluation_org_mismatch",
            poam_id=poam_id,
            result_id=result_id,
            poam_organization_id=organization_id,
        )
        return None

    proposal = await open_reevaluation_proposal(session, result=result, source_poam_id=poam_id)

    existing = (
        await session.execute(
            select(AssessmentJob)
            .where(
                AssessmentJob.control_proposal_id == proposal.id,
                AssessmentJob.status.in_(_OUTSTANDING_JOB_STATUSES),
            )
            .order_by(AssessmentJob.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    job = AssessmentJob(
        organization_id=proposal.organization_id,
        control_proposal_id=proposal.id,
        status="pending",
    )
    session.add(job)
    await session.flush()
    log.info(
        "assessment.reevaluation_job_enqueued",
        job_id=job.id,
        control_proposal_id=proposal.id,
        source_poam_id=poam_id,
    )
    return job
```

- [ ] **Step 5: Wire the hook into `poams.py`**

Add imports:

```python
from ...assessment.engine import jobs as engine_jobs
from ...logging import get_logger
```

Add, near the top after `router = APIRouter(...)`:

```python
log = get_logger(__name__)
```

Add, after `_require_risk_accepted_gate` and before `list_poams`:

```python
async def _maybe_enqueue_reevaluation(session: AsyncSession, obj: POAM) -> None:
    """Best-effort: enqueue a re-evaluation of the control this POA&M remediated.

    Only assessment-sourced POA&Ms qualify -- see
    ``ccf.assessment.engine.jobs.enqueue_reevaluation`` for the ``source_ref``
    convention this relies on; a scan-sourced or profile-gap POA&M's
    ``source_ref`` never matches it, so this is silently a no-op for those.
    Called only after the closure itself is already committed, so a failure
    here must never surface as a failure of the closure -- the ISSM-08/09
    gate above already did the only thing that must be allowed to block a
    close.
    """
    if not obj.source_ref:
        return
    org_id = (
        await session.execute(select(System.organization_id).where(System.id == obj.system_id))
    ).scalar_one_or_none()
    if org_id is None:
        return
    try:
        job = await engine_jobs.enqueue_reevaluation(
            session, poam_id=obj.id, source_ref=obj.source_ref, organization_id=int(org_id)
        )
        if job is not None:
            await session.commit()
    except Exception as exc:  # the closure itself is already committed
        log.warning("poam.reevaluation_enqueue_failed", poam_id=obj.id, error=str(exc))
```

In `update_poam`, capture the pre-mutation status and call the hook after the existing commit:

```python
    obj = await _require_poam(session, pid, principal)
    data = body.model_dump(exclude_none=True)
    was_closed = obj.status == "closed"
    if data.get("status") == "closed":
        await _require_closure_gate(session, obj)
    elif data.get("status") == "risk_accepted":
        await _require_risk_accepted_gate(
            session,
            owner_user_id=data.get("owner_user_id", obj.owner_user_id),
            due_on=data.get("due_on", obj.due_on),
            poam_id=pid,
        )
    for k, v in data.items():
        setattr(obj, k, v)
    await bus.emit(
        session,
        verb="updated",
        entity_type="poam",
        entity_id=obj.id,
        summary=f"POA&M {obj.status}: {obj.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    if data.get("status") == "closed" and not was_closed:
        await _maybe_enqueue_reevaluation(session, obj)
    obj = await _require_poam(session, pid, principal)
    state = await entity_state(session, "poam", obj.id)
    return _out(obj, datetime.now(UTC).date(), state)
```

In `close_poam`:

```python
@router.post("/{pid}/close")
async def close_poam(
    pid: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    obj = await _require_poam(session, pid, principal)
    was_closed = obj.status == "closed"
    await _require_closure_gate(session, obj)
    obj.status = "closed"
    obj.closed_on = date.today()
    await bus.emit(
        session,
        verb="closed",
        entity_type="poam",
        entity_id=obj.id,
        summary=f"POA&M closed: {obj.title}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    if not was_closed:
        await _maybe_enqueue_reevaluation(session, obj)
    obj = await _require_poam(session, pid, principal)
    state = await entity_state(session, "poam", obj.id)
    return _out(obj, datetime.now(UTC).date(), state)
```

- [ ] **Step 6: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_assessment_closure_trigger.py -v    # 5 pass
.venv/bin/pytest tests/test_assessment_jobs.py tests/test_assessment_service.py -v   # unaffected
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** in `_maybe_enqueue_reevaluation`, delete the `if not obj.source_ref: return` guard and re-run `test_closing_a_scan_sourced_poam_enqueues_none` — confirm it now fails (a job gets created for the scan-sourced POA&M since `enqueue_reevaluation`'s own `source_ref.startswith(...)` check is the only remaining line of defense, and this proves the two-layer guard, not one, is what's actually tested). Revert. Then in `enqueue_reevaluation`, change `if result_org_id is None or int(result_org_id) != organization_id:` to `if False:` and re-run `test_a_mismatched_organization_enqueues_nothing` — confirm it now fails. Revert both.

```bash
git add src/ccf/assessment/engine/service.py src/ccf/assessment/engine/jobs.py \
        src/ccf/api/routes/poams.py tests/test_assessment_closure_trigger.py
git commit -m "feat(assessment): enqueue a re-evaluation when a POA&M closes"
```

---

### Task 4: The re-evaluation worker path

**Files:**
- Create: `tests/test_assessment_closure_worker.py`

**Interfaces:**
- Consumes only: Task 3's `enqueue_reevaluation`; the existing, unmodified `ccf.assessment.engine.jobs.run_once` and `evaluate_control_proposal`.

No production code changes. The worker (`run_once` → `_drive_one` → `evaluate_control_proposal`) already drives any `AssessmentJob` by loading its proposal and evaluating it, and `evaluate_control_proposal` already never touches `AssessmentControlResult`. This task proves that reuse actually holds for a re-evaluation proposal end to end, and — the design's central claim about this half of the loop — that the engine passing a re-test does not retire its own finding: the original `AssessmentControlResult` from Task 2's acceptance must be untouched by a later re-evaluation, satisfied or not.

- [ ] **Step 1: Write the failing test**

Create `tests/test_assessment_closure_worker.py`:

```python
"""The existing worker drives a closure-triggered re-evaluation exactly as
it drives a first-pass evaluation -- and the re-evaluation, even passing,
never touches the AssessmentControlResult acceptance already wrote.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, func, select

from ccf.assessment.engine import jobs as engine_jobs
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.db import session_scope
from ccf.models import (
    POAM,
    Assessment,
    AssessmentControlResult,
    Control,
    Organization,
    PoamMilestone,
    System,
)
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-97"


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Closure Worker Fixture Control",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the closure worker fixture objective is met;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


def _fake_evaluate(verdict: str) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


async def test_a_passing_reevaluation_proposes_closure_without_retiring_the_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First pass: not_satisfied -> other_than_satisfied -> accepted -> bridged POA&M.
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("not_satisfied"))
    async with session_scope() as s:
        org = Organization(name="close-worker")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="close-worker-sys")
        s.add(system)
        await s.flush()
        a = Assessment(system_id=system.id, name="close-worker-a", kind="self")
        s.add(a)
        await s.flush()
        org_id, assessment_id = int(org.id), int(a.id)

    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        result = await accept_control_proposal(s, int(proposal.id), accepted_by="a@x.test")
        result_id = int(result.id)
        assert result.finding == "other_than_satisfied"

    async with session_scope() as s:
        poam = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"assessment_control_result:{result_id}")
            )
        ).scalar_one()
        poam_id = int(poam.id)
        s.add(
            PoamMilestone(
                poam_id=poam_id, description="remediated", status="completed", sort_order=0
            )
        )

    # Closure trigger: enqueue the re-evaluation directly (Task 3's own
    # coverage exercises the HTTP route; this test's subject is the worker).
    async with session_scope() as s:
        job = await engine_jobs.enqueue_reevaluation(
            s,
            poam_id=poam_id,
            source_ref=f"assessment_control_result:{result_id}",
            organization_id=org_id,
        )
        assert job is not None
        assert job.status == "pending"

    # Remediation worked this time: the re-evaluation sees a different
    # verdict word than the first pass did (asymmetric on purpose -- a
    # worker that accidentally re-ran the *first* proposal instead of the
    # re-evaluation one would still show "not_satisfied" here and this
    # assertion would catch it).
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate("satisfied"))
    async with session_scope() as s:
        stats = await engine_jobs.run_once(s, worker="test-closure-worker", limit=10)
    assert stats == {"claimed": 1, "finished": 1, "failed": 0}

    async with session_scope() as s:
        reeval = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.source_poam_id == poam_id
                )
            )
        ).scalar_one()
        assert reeval.state == "complete"
        assert reeval.proposed_finding == "satisfied"
        assert reeval.source_poam_id == poam_id

        # The engine never retires its own finding: the original,
        # human-accepted result is untouched by the passing re-evaluation.
        # Scoped to this exact (assessment_id, control_id) pair, not a bare
        # row-count on the whole table.
        count = (
            await s.execute(
                select(func.count(AssessmentControlResult.id)).where(
                    AssessmentControlResult.assessment_id == assessment_id,
                    AssessmentControlResult.control_id == _SEQ,
                )
            )
        ).scalar_one()
        assert count == 1
        original = (
            await s.execute(
                select(AssessmentControlResult).where(AssessmentControlResult.id == result_id)
            )
        ).scalar_one()
        assert original.finding == "other_than_satisfied", (
            "a passing re-evaluation must not silently flip the accepted finding -- "
            "only a human accepting the new proposal may do that"
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_assessment_closure_worker.py -v`
Expected: FAIL — `AttributeError: module 'ccf.assessment.engine.jobs' has no attribute 'enqueue_reevaluation'` (Task 3 not yet merged when run standalone) or, once Task 3 lands, a passing collection with the test itself green already (this task adds no production code — its purpose is proving the existing worker generalizes, not building new behavior).

- [ ] **Step 3: No implementation step.** If the test above fails for any reason other than Task 3 being absent, that is a real defect in Task 3's wiring — fix it there, not by adding special-case logic for re-evaluation proposals to `_drive_one` or `run_once` (neither should ever need to know a proposal is a re-evaluation; that is the entire point of reusing `AssessmentJob`/`evaluate_control_proposal` unchanged).

- [ ] **Step 4: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_assessment_closure_worker.py -v    # 1 passes
.venv/bin/pytest tests/test_assessment_jobs.py tests/test_assessment_worker_cli.py -v   # unaffected
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** in `service.evaluate_control_proposal`, temporarily add `proposal.state = "accepted"` right after the existing `proposal.state = "complete"` line (simulating a worker that wrongly finalizes a re-evaluation the way acceptance does) and re-run — confirm `reeval.state == "complete"` now fails. Revert. Then temporarily add, at the very end of `evaluate_control_proposal` before its `return`, a stray write: `result.finding = "satisfied"` against a freshly-queried `AssessmentControlResult` for the same assessment/control (simulating the engine retiring its own finding) and re-run — confirm `original.finding == "other_than_satisfied"` now fails. Revert both; this second mutation is the sharpest test of the design's central asymmetry claim.

```bash
git add tests/test_assessment_closure_worker.py
git commit -m "test(assessment): confirm the existing worker drives a closure re-evaluation"
```

---

### Task 5: API — the re-evaluations for a remediated control

**Files:**
- Modify: `src/ccf/api/routes/assessment_engine.py`
- Create: `tests/test_closure_reevaluation_api.py`

**Interfaces:**
- Produces: `GET /api/assessment-engine/proposals?source_poam_id={id}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_closure_reevaluation_api.py`, following `tests/test_assessment_engine_api.py`'s fixtures (`_auth_enabled`, `_engine_enabled`, `_mk_user`, `_auth`, `_client`) exactly — copy those four fixtures and helpers verbatim into this file rather than importing them (that file has no `__init__.py`-exported surface; every existing engine test module duplicates its own copy of this fixture set).

```python
"""GET /api/assessment-engine/proposals?source_poam_id={id} -- the
re-evaluation(s) triggered by one closed POA&M's closure.
"""

from __future__ import annotations

import pytest

from ccf.db import session_scope
from ccf.models import POAM, System
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

# ... _auth_enabled, _engine_enabled, _client, _mk_user, _auth, _assessment_for:
# copied verbatim from tests/test_assessment_engine_api.py.


async def _poam_for_org(org_id: int, name: str) -> int:
    async with session_scope() as s:
        system = System(organization_id=org_id, name=f"{name}-sys")
        s.add(system)
        await s.flush()
        poam = POAM(
            system_id=system.id, title=name, severity="moderate", status="open", source="assessment"
        )
        s.add(poam)
        await s.flush()
        return int(poam.id)


async def _reevaluation_proposal_for(poam_id: int, org_id: int, assessment_id: int) -> int:
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            source_poam_id=poam_id,
            state="complete",
            proposed_finding="satisfied",
        )
        s.add(p)
        await s.flush()
        return int(p.id)


async def test_lists_the_reevaluation_for_the_callers_own_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("reeval-a@ae-api.test", "Reeval API Org A")
    assessment_id = await _assessment_for(org_id, "reeval-a")
    poam_id = await _poam_for_org(org_id, "reeval-a-poam")
    await _reevaluation_proposal_for(poam_id, org_id, assessment_id)

    async with _client() as client:
        response = await client.get(
            "/api/assessment-engine/proposals",
            params={"source_poam_id": poam_id},
            headers=_auth(token),
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["proposed_finding"] == "satisfied"
    assert body[0]["assessment_id"] == assessment_id


async def test_another_tenants_poam_id_404s_not_403s(monkeypatch: pytest.MonkeyPatch) -> None:
    token_a, org_a = await _mk_user("reeval-b-a@ae-api.test", "Reeval API Org B-A")
    token_b, org_b = await _mk_user("reeval-b-b@ae-api.test", "Reeval API Org B-B")
    assessment_b = await _assessment_for(org_b, "reeval-b")
    poam_b = await _poam_for_org(org_b, "reeval-b-poam")
    await _reevaluation_proposal_for(poam_b, org_b, assessment_b)

    async with _client() as client:
        response = await client.get(
            "/api/assessment-engine/proposals",
            params={"source_poam_id": poam_b},
            headers=_auth(token_a),
        )
    assert response.status_code == 404


async def test_a_nonexistent_poam_id_also_404s(monkeypatch: pytest.MonkeyPatch) -> None:
    token, _org_id = await _mk_user("reeval-c@ae-api.test", "Reeval API Org C")
    async with _client() as client:
        response = await client.get(
            "/api/assessment-engine/proposals",
            params={"source_poam_id": 999_999_999},
            headers=_auth(token),
        )
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_closure_reevaluation_api.py -v`
Expected: FAIL — `404 Not Found` for a request to an undefined route (or, if `_assessment_for`/other helpers aren't yet copied in, a `NameError`; finish copying the fixture set from `test_assessment_engine_api.py` before this step counts as failing for the right reason).

- [ ] **Step 3: Implement the endpoint**

In `src/ccf/api/routes/assessment_engine.py`, add `Query` to the fastapi import and `POAM` to the models import:

```python
from fastapi import APIRouter, Depends, HTTPException, Path, Query
...
from ...models import POAM, Assessment, AssessmentControlResult, System
```

Add, after `get_proposal` and before `_result_out`:

```python
@router.get("/proposals")
async def list_reevaluation_proposals(
    *,
    source_poam_id: int = Query(ge=1, le=_MAX_INT32),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """The re-evaluation proposal(s) triggered by one closed POA&M's closure.

    ``source_poam_id`` names a POA&M, not a proposal -- so it is validated
    against ``POAM.system_id -> System.organization_id`` the same way
    ``_require_proposal`` validates a proposal id: a POA&M belonging to
    another tenant 404s here too, not 403, so the response cannot be used to
    confirm that id exists at all.
    """
    poam_org_id = (
        await session.execute(
            select(System.organization_id)
            .join(POAM, POAM.system_id == System.id)
            .where(POAM.id == source_poam_id)
        )
    ).scalar_one_or_none()
    if poam_org_id is None or (
        principal.org_id is not None and int(poam_org_id) != principal.org_id
    ):
        raise HTTPException(404, "poam not found")

    rows = (
        await session.execute(
            select(AssessmentControlProposal)
            .where(AssessmentControlProposal.source_poam_id == source_poam_id)
            .order_by(AssessmentControlProposal.id)
        )
    ).scalars().all()
    return [await _proposal_detail(session, p) for p in rows]
```

- [ ] **Step 4: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_closure_reevaluation_api.py -v    # 3 pass
.venv/bin/pytest tests/test_assessment_engine_api.py -v       # unaffected
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** change the tenant check to `if poam_org_id is None:` (dropping the org comparison) and re-run `test_another_tenants_poam_id_404s_not_403s` — confirm it now fails (org B's proposal becomes readable by org A's token). Revert.

```bash
git add src/ccf/api/routes/assessment_engine.py tests/test_closure_reevaluation_api.py
git commit -m "feat(api): list the re-evaluation proposals a POA&M closure triggered"
```

---

### Task 6: Documentation

**Files:** `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`.

**Verify every statement against the code before writing it.** Slice 1's final review found three false doc claims; slice 3's Task 6 found three more, two of which had been written in earlier slices. In particular: `README.md` currently says (around the "Proposals are inert" sentence) that nothing an evaluation writes reaches "an auto-created POA&M" until acceptance — true before this slice, since nothing ever auto-created one at all; after Task 2, acceptance itself is what does the auto-creating, so that sentence must be corrected, not merely left to stand beside the new paragraph.

- [ ] **Step 1: `docs/ARCHITECTURE.md`**

Append a new bullet after the existing "Calibration harness" bullet (ends around line 323, "...so have no ground truth to compare against."), before the "The standing debt list this slice does not close:" sentence — insert a paragraph break and a new bullet:

```markdown
- **Closure & remediation loop** (`ccf.assessment.engine.service`, `.jobs`,
  `/api/poams`, `/api/assessment-engine/proposals?source_poam_id={id}`):
  closes the loop the calibration harness measures but does not act on.
  `accept_control_proposal` now creates a POA&M for an accepted
  `other_than_satisfied` finding (`satisfied`, `not_applicable`, and the
  unreachable-via-acceptance `insufficient_evidence` create none), keyed on
  `source_ref = f"assessment_control_result:{result.id}"` — found and left
  alone on a repeat acceptance, never overwritten, so a human's edit to the
  POA&M survives a re-acceptance. The write runs inside `begin_nested()` and
  logs a warning rather than raising on failure: `AsyncSession.rollback()`
  is not savepoint-scoped and would otherwise discard the caller's own
  already-good acceptance, the same trap slice 3 hit with `record_ai_run`.
  Closing an assessment-sourced POA&M (`PATCH /api/poams/{id}` or
  `POST /api/poams/{id}/close`, on a genuine `open`/`in_progress` →
  `closed` transition) enqueues a re-evaluation of the control it
  remediated; a scan-sourced or profile-gap POA&M's `source_ref` never
  matches the convention above and enqueues nothing. The re-evaluation is a
  second, distinct `AssessmentControlProposal` carrying `source_poam_id`
  (migration `0058`) — not a reuse of the accepted first-pass row — which
  required replacing the flat `uq_control_proposal_assessment_control`
  constraint with two partial unique indexes: `uq_control_proposal_first_pass`
  scopes first-pass idempotency to `source_poam_id IS NULL` rows, and
  `uq_control_proposal_source_poam` caps re-evaluation at one proposal per
  POA&M. The existing worker (`ccf assessment-worker` /
  `ccf.assessment.engine.jobs.run_once`) drives a re-evaluation job
  unmodified — it already writes no `AssessmentControlResult`. **The engine
  never retires its own finding**: a passing re-evaluation surfaces as a new
  proposal for a human to accept, exactly like a first pass; the original
  `AssessmentControlResult` from the earlier acceptance is untouched
  regardless of the re-evaluation's outcome. This is deliberately asymmetric
  with `ccf.ingest.scanners.reconcile_findings`, which *does* auto-close a
  POA&M absent from the latest scan: a vulnerability missing from a scan is
  direct evidence the weakness is gone, while a model re-reading prose
  evidence is an opinion about a control, and the two warrant different
  levels of trust. `GET /api/assessment-engine/proposals?source_poam_id={id}`
  lists the re-evaluation(s) for one POA&M, deriving its organization from
  the named POA&M's own `system_id -> organization_id` rather than trusting
  a query argument directly — a foreign tenant's POA&M id 404s, never 403.
  Not retrofitted: findings accepted before this slice get no POA&M created
  retroactively, and the closure gate (ISSM-08/09: all milestones complete,
  or dated closure evidence, plus a separation-of-duties approval when auth
  is enabled) is unchanged — this slice observes the transition to `closed`,
  it does not widen the path to it.
```

- [ ] **Step 2: `README.md`**

In the paragraph around "Proposals are inert: nothing an evaluation writes reaches the SAR generator", replace:

```markdown
  Proposals are inert: nothing an evaluation writes reaches the SAR generator
  or an auto-created POA&M until an assessor accepts it, and a proposal that
  settled on `insufficient_evidence` cannot be accepted at all — the engine
  could not tell, which is not the same as the control failing.
```

with:

```markdown
  Proposals are inert: nothing an evaluation writes reaches the SAR generator
  until an assessor accepts it, and a proposal that settled on
  `insufficient_evidence` cannot be accepted at all — the engine could not
  tell, which is not the same as the control failing. Accepting an
  `other_than_satisfied` finding auto-creates a POA&M (idempotent on a
  stable back-reference, never overwriting one a human has since edited),
  and closing that POA&M enqueues a re-evaluation of the control — a passing
  re-evaluation still surfaces as a proposal a human must accept, never an
  auto-close; see `docs/ARCHITECTURE.md`'s "Closure & remediation loop" for
  the full loop and its deliberate asymmetry with scan auto-closure.
```

- [ ] **Step 3: `CHANGELOG.md`**

Add a new `### Added` section under `## [Unreleased]`, above the existing "calibration harness" section:

```markdown
### Added — closure & remediation loop
- **An accepted other-than-satisfied finding now creates a POA&M**, closing
  the dead end where `accept_control_proposal`'s own docstring promised an
  auto-created POA&M that no caller ever actually triggered. Idempotent on
  `source_ref = f"assessment_control_result:{result.id}"` — a repeat
  acceptance finds and leaves alone any existing POA&M rather than
  duplicating or overwriting it. The write is isolated in a `begin_nested()`
  savepoint and logs a warning rather than raising on failure, so a derived
  POA&M write can never cost an assessor their already-accepted finding.
- **Closing an assessment-sourced POA&M enqueues a re-evaluation** of the
  control it remediated (`assessment_control_proposals.source_poam_id`,
  migration `0058`, plus a constraint swap — `uq_control_proposal_first_pass`
  and `uq_control_proposal_source_poam` replace the old flat unique
  constraint — that lets the re-evaluation proposal coexist with the
  first-pass row it re-evaluates). A scan-sourced or profile-gap POA&M
  enqueues nothing; closing the same POA&M twice enqueues exactly one job.
  Reuses the existing `assessment-worker` queue and `AssessmentJob`
  unchanged. `GET /api/assessment-engine/proposals?source_poam_id={id}`
  lists the result.
- **The engine never retires its own finding**: a passing re-evaluation
  produces a new proposal for a human to accept, exactly like a first-pass
  evaluation — never an auto-close. Deliberately asymmetric with the
  scanner's own auto-close-on-absence behavior, documented as such.
- Not retrofitted: findings accepted before this slice get no POA&M created
  retroactively. The closure gate (ISSM-08/09) is unchanged.
```

- [ ] **Step 4: Verify and commit**

```bash
.venv/bin/pytest -q          # run alone; confirm the count and cite it in the commit if it moved
git add docs/ARCHITECTURE.md README.md CHANGELOG.md
git commit -m "docs(assessment): document the closure and remediation loop"
```

---

## Deferred, deliberately

- **No retrofit** of already-accepted findings into POA&Ms.
- **No auto-close** on a passing re-evaluation — a human always accepts.
- **No email.** No SMTP/SES/SendGrid transport exists anywhere in `src/ccf`; delivery stays in-app `Notification` rows plus outbound webhooks.
- **No overdue escalation or reminders** for either a POA&M or a re-evaluation proposal sitting unaddressed.
- **No unification of the two legacy POA&M-from-findings paths** (`assessments.py:205`'s `/poams-from-findings`, reading the legacy `AssessmentResult` table, and `ui.py`'s inline duplicate, deduping on title alone). Both remain, unreconciled, as standing debt — this slice adds a third, distinct `source_ref` convention (`assessment_control_result:{id}`) rather than touching either.
- **No `AssessmentJob` partial-unique-index dedup** for the general enqueue race (`enqueue_control`'s own SELECT-then-INSERT check) — carried forward from the prior slice's debt list; `enqueue_reevaluation` inherits the same shape for the same reason and is no worse than the first-pass path it mirrors.
