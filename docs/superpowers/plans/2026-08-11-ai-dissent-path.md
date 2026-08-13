# AI Dissent Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every assessment objective today gets exactly one verdict from one model call, with a self-reported `model_confidence` that nothing challenges. A model that is confidently wrong is the failure slice 4's calibration harness was built to detect, and it is the expensive failure direction: a `satisfied` verdict on a control that is not satisfied becomes a **missed finding** in an authorization package. Slice 4 measures that after the fact, from an assessor's rejection. This slice tries to catch it before an assessor ever sees it, by running an independent second model call — a challenger — against `satisfied` verdicts only, recording disagreement as a first-class, retained signal, and making the effect measurable through the calibration harness slice 4 already built.

**Architecture:** Four things change, in dependency order, each landing as its own task with its own test cycle:

1. **The data model** (migration `0059`): three nullable columns on `assessment_objective_proposals` (`challenger_verdict`, `challenger_rationale`, `challenger_ai_action_run_id`) and one `NOT NULL` counter on `assessment_control_proposals` (`dissent_count`). NULL rather than a sentinel on the challenger columns, so "not challenged" and "challenged and agreed" stay distinguishable — the calibration measurement depends on that distinction.
2. **The challenger call itself** (`ccf.assessment.engine.evaluate`): a second, bounded call that receives the same objective and the *same* retrieved passages the primary call saw, and is asked to argue the strongest case for the opposite conclusion. Only ever attempted when `CCF_ASSESSMENT_DISSENT_ENABLED` is on **and** the primary verdict was `satisfied` — the satisfied-only policy is named and versioned (`DISSENT_CHALLENGE_POLICY_VERSION`) rather than left implicit, so a later change to which verdicts get challenged is visible rather than silent. A credible disagreement (a differing, cited verdict — never a confidence threshold) overwrites the objective's own `verdict` to `insufficient_evidence`; the two verdicts are never averaged, majority-voted, or tie-broken, and both are retained on the new columns. A challenger failure — provider error, timeout, malformed response — must never cost the objective its primary verdict: the challenge call runs inside its own `begin_nested()` savepoint, nested one level deeper than the per-objective savepoint `ccf.assessment.engine.service` already wraps each objective's evaluation in, so a failure there rolls back only the challenge's own partial writes, never the primary verdict already computed in the same call. This all lives in `evaluate.py` because `evaluate_objective` is the one place that has both the primary verdict and the retrieved passages together — `service.py` never sees the raw units.
3. **Wiring the challenger's output into persistence** (`ccf.assessment.engine.service`): `AssessmentObjectiveProposal` gains the three challenger fields (straight passthrough from `ObjectiveEvaluation`), and `AssessmentControlProposal.dissent_count` is reset to `0` at the top of every `evaluate_control_proposal` run and incremented once per genuinely-dissenting objective. No change to `rollup.py` at all: a dissenting objective's `verdict` is already `insufficient_evidence` by the time it reaches the rollup, and `rollup.roll_up`'s existing unanimity check already forces the whole control to `insufficient_evidence` on any such objective — that is the end-to-end property this slice exists to produce, and it falls out of the existing rollup logic for free.
4. **Making the change measurable** (`ccf.assessment.engine.calibration`): `config_fingerprint` folds in `CCF_ASSESSMENT_DISSENT_ENABLED` and `DISSENT_CHALLENGE_POLICY_VERSION`, so enabling dissent between two calibration snapshots makes them compare as **not comparable**, never as an unexplained shift in `missed_findings`. This is also how the slice gets evaluated in practice: the calibration harness answers whether dissent actually reduces missed findings, or only reduces throughput.
5. **Surfacing** (`GET /api/assessment-engine/proposals/{id}`, `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`): the new fields on the existing, already tenant-isolated response; no new route, no new tenant surface.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Alembic, Postgres 16, FastAPI, pytest.

**Spec:** [docs/superpowers/specs/2026-08-11-ai-dissent-path-design.md](../specs/2026-08-11-ai-dissent-path-design.md)
**Depends on:** slices 1–5, all on `feat/evidence-prep-spine`.

## Global Constraints

- **Python** 3.12, `line-length = 100`. **Ruff** selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected, so a `# noqa: BLE001` or `# noqa: SLF001` trips `RUF100` (unused noqa) — don't add one. `PLC0415` means imports go at module top level, never inside a function body. `RUF059` means an unused unpacked variable gets a leading underscore (e.g. `_exc`), not a bare unused name. Known baseline: **exactly 25 pre-existing `PLR0917`** in `src/ccf/api/routes/`; this slice adds no new route handlers with positional parameters (only new fields on an existing response), so it should add nothing to that count.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** `from ...logging import get_logger` (adjust the relative depth per module); never `import structlog` directly; never `extra={...}` — it collides with reserved `LogRecord` attributes (e.g. `filename`) and raises `KeyError`. Pass plain kwargs to the logger call instead.
- **Tests:** real Postgres on port **5434**, container `ccf-test-db`. `asyncio_mode = "auto"` in `pytest.ini` — never write `@pytest.mark.asyncio`. DB-touching test modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`. **Never run two pytest sessions concurrently** — the session fixture drops and recreates the schema. **Always run pytest in the foreground** — a past implementer backgrounded a long test run, it stalled, and the branch was left uncommitted; do not background it. Venv binaries only: `.venv/bin/pytest`, `.venv/bin/alembic`, `.venv/bin/ruff`, `.venv/bin/mypy` — never bare `python3` (system Python is 3.9). **Baseline: 919 passed, 1 skipped.** `test_assessment_closure_trigger.py` is known to leave `pending` `AssessmentJob` rows across test runs — any test in this slice that asserts something about the *count* of jobs (this plan's tasks do not add any) would need its own isolating fixture; none of this slice's assertions are job-count assertions, so this is noted, not triggered.
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — a `SELECT` issued while a pending `add()` is unflushed sees nothing. Flush explicitly before any such read.
- **Migrations:** `migrations/versions/00NN_<slug>.py`, explicit `revision`/`down_revision`. **Current head is `0058_closure_reevaluation`**; this slice adds `0059_ai_dissent_path`. Every table- or column-adding migration re-issues `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app` at the end of `upgrade()`. A `server_default` (or ORM-side `default`) column declared `NOT NULL`/non-`Optional` in the ORM (`Mapped[int]`, not `Mapped[int | None]`) must **also** be declared `nullable=False` explicitly in the migration's `sa.Column(...)` — SQLAlchemy's typed declarative mapping does not retroactively make `op.add_column` infer nullability. `downgrade()` must round-trip: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`. **`0059` must carry the `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app')` guard** that migration `0054` establishes as this repo's standard for the blanket `GRANT` — migrations `0057` and `0058` both omitted it (a bare, unguarded `GRANT` statement) and that omission stays on the standing debt list; this slice does not fix those two, but must not add a third instance of the same omission.
- **Status vocabularies** are `String(32)` (or narrower) with application-level checks, never Postgres enums — `challenger_verdict` follows `AssessmentObjectiveProposal.verdict`'s own existing `String(32)` exactly, checked only in Python against `OBJECTIVE_VERDICTS`.
- **Savepoint isolation:** `AsyncSession.rollback()` is **not** savepoint-scoped — it unwinds the whole transaction, not just the failing write. Slice 3 shipped a version that silently discarded the caller's work while reporting success. Any write whose failure must not cost the caller their own already-good work uses `async with session.begin_nested():`, never a bare `try`/`except` around a plain `session.add()` + `flush()`, and never a manual `session.rollback()` inside the `except` clause.
- **Tenant isolation:** derive the organization from `Depends(get_principal)`, never from a body/path/query argument. Another tenant's row is **404, not 403** — a 403 confirms the id exists. An HTTP-level cross-tenant test can pass purely because Postgres RLS filters the row before the application's own comparison runs, which makes that comparison untested by any HTTP test — see `tests/test_closure_reevaluation_api.py::test_the_app_level_org_check_holds_independently_of_rls` for the pattern (drive the handler directly on a `session_scope()` session, which authenticates as the bootstrap role and is *not* RLS-filtered, so a pass cannot be Postgres doing the work). This slice adds no new route and no new tenant-scoped lookup — `GET /api/assessment-engine/proposals/{id}`'s existing tenant check (`_require_proposal`) is unchanged and already covered by that module's own existing tests — so no new instance of this test is required by this slice; this constraint is recorded because it governs the code being touched, not because a new test of it is owed.
- **Mutation discipline:** every guard and every recorded field gets its own assertion, verified by mutation — break the specific line, re-run the specific test, confirm it fails for the reason expected, then revert. A subtler trap: a best-effort `except Exception` handler makes "skipped correctly" and "raised and was swallowed" indistinguishable to a test that only asserts the absence of a side effect — such a test must also assert that nothing was logged at `warning`, not just that a column stayed `NULL`.
- **Asymmetric fixtures:** wherever a bug could swap two values undetected (a primary verdict and a challenger verdict, an agreeing objective and a dissenting one, two different confidence values, two different rationale strings), the test fixture uses two *different* values, never the same value twice.
- **Zero-count / exact-count assertions** are scoped to the specific org/assessment/control under test, never a bare "the table is empty" or "the table has N rows" — an assertion must name the row it expects to be absent or present, not infer it from an unscoped count.
- **Counting model calls:** a test asserting the challenger's satisfied-only policy must assert the **number** of provider calls made (or the exact sequence, by `purpose`), not only the resulting columns — the policy is about not making a call at all, and a test that only checks `challenger_verdict is None` cannot distinguish "never called" from "called and its result was discarded."
- **Provenance:** every model call — primary and challenger — is recorded through `ccf.ai_actions.provenance.record_ai_run`, never through the approval-gated `ccf.ai_actions.service.run_action`; pipeline runs carry `status="recorded"` (`PIPELINE_RUN_STATUS` in `provenance.py`). `record_ai_run` is documented to never raise (it wraps its own writes in `begin_nested()` and returns `None` on failure), but call sites in this codebase do not lean on that promise holding forever — every call site wraps its own call in a `try`/`except` regardless.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot project.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/models_assessment_engine.py` | `AssessmentObjectiveProposal.challenger_verdict` / `.challenger_rationale` / `.challenger_ai_action_run_id`; `AssessmentControlProposal.dissent_count` |
| `migrations/versions/0059_ai_dissent_path.py` | the four columns + guarded grant |
| `src/ccf/config.py` | `Settings.assessment_dissent_enabled` (`CCF_ASSESSMENT_DISSENT_ENABLED`, default `False`) |
| `src/ccf/assessment/engine/evaluate.py` | the challenger call: schema, prompt, satisfied-only gate, disagreement routing, failure isolation |
| `src/ccf/assessment/engine/service.py` | persist the challenger fields; reset/increment `dissent_count` |
| `src/ccf/assessment/engine/calibration.py` | `config_fingerprint` folds in the dissent flag and policy version |
| `src/ccf/api/routes/assessment_engine.py` | `_proposal_detail` surfaces `dissent_count` and per-objective challenger fields |
| `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md` | document the challenger, the satisfied-only policy and why, the routing to `insufficient_evidence`, and that it is off by default |

---

### Task 1: The four columns and migration `0059`

**Files:**
- Modify: `src/ccf/models_assessment_engine.py`
- Create: `migrations/versions/0059_ai_dissent_path.py`
- Create: `tests/test_dissent_models.py`

**Interfaces:**
- Produces: `AssessmentObjectiveProposal.challenger_verdict`, `.challenger_rationale`, `.challenger_ai_action_run_id`; `AssessmentControlProposal.dissent_count`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_dissent_models.py`:

```python
"""The four AI-dissent-path columns (migration 0059): three nullable
challenger columns on assessment_objective_proposals, and a NOT NULL
dissent_count rollup on assessment_control_proposals.

NULL rather than a sentinel on the challenger columns, so "not challenged"
and "challenged and agreed" stay distinguishable -- the calibration
measurement depends on that distinction (see ccf.assessment.engine.evaluate).
dissent_count is NOT NULL with a default of 0: every existing control
proposal, and every un-challenged one going forward, gets a real, comparable
zero rather than a NULL a reader would need to special-case.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_ai_actions import AiActionRun
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal

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


async def _control_proposal(org_id: int, assessment_id: int, control: str = "AC-2") -> int:
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier=control
        )
        s.add(p)
        await s.flush()
        return int(p.id)


async def _ai_run(org_id: int) -> int:
    async with session_scope() as s:
        run = AiActionRun(
            organization_id=org_id,
            action_key="challenge_assessment_objective",
            entity_type="assessment_objective",
            entity_id="AC-2a",
            status="recorded",
            provider="anthropic",
        )
        s.add(run)
        await s.flush()
        return int(run.id)


async def test_challenger_columns_default_to_null() -> None:
    org_id, assessment_id = await _assessment("dissent-defaults")
    proposal_id = await _control_proposal(org_id, assessment_id)
    async with session_scope() as s:
        o = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=proposal_id,
            label="AC-2a",
            objective_text="x",
            objective_text_sha256="0" * 64,
        )
        s.add(o)
        await s.flush()
        assert o.challenger_verdict is None
        assert o.challenger_rationale is None
        assert o.challenger_ai_action_run_id is None


async def test_challenger_columns_round_trip() -> None:
    org_id, assessment_id = await _assessment("dissent-roundtrip")
    proposal_id = await _control_proposal(org_id, assessment_id)
    run_id = await _ai_run(org_id)
    async with session_scope() as s:
        o = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=proposal_id,
            label="AC-2a",
            objective_text="x",
            objective_text_sha256="0" * 64,
            challenger_verdict="not_satisfied",
            challenger_rationale="the challenger's own argument",
            challenger_ai_action_run_id=run_id,
        )
        s.add(o)
        await s.flush()
        oid = int(o.id)
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(AssessmentObjectiveProposal.id == oid)
            )
        ).scalar_one()
        assert row.challenger_verdict == "not_satisfied"
        assert row.challenger_rationale == "the challenger's own argument"
        assert row.challenger_ai_action_run_id == run_id


async def test_deleting_the_challenger_ai_run_sets_the_link_null_not_cascade() -> None:
    """ON DELETE SET NULL: the objective proposal is a record of what
    happened and must survive its provenance row being cleaned up -- exactly
    matching this same table's existing ai_action_run_id FK (migration 0056).
    """
    org_id, assessment_id = await _assessment("dissent-fk-set-null")
    proposal_id = await _control_proposal(org_id, assessment_id)
    run_id = await _ai_run(org_id)
    async with session_scope() as s:
        o = AssessmentObjectiveProposal(
            organization_id=org_id,
            control_proposal_id=proposal_id,
            label="AC-2a",
            objective_text="x",
            objective_text_sha256="0" * 64,
            challenger_verdict="satisfied",
            challenger_ai_action_run_id=run_id,
        )
        s.add(o)
        await s.flush()
        oid = int(o.id)
    async with session_scope() as s:
        await s.execute(text("DELETE FROM ccf.ai_action_runs WHERE id = :id"), {"id": run_id})
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentObjectiveProposal).where(AssessmentObjectiveProposal.id == oid)
            )
        ).scalar_one()
        assert row.challenger_ai_action_run_id is None
        assert row.challenger_verdict == "satisfied", "the verdict itself must survive"


async def test_dissent_count_defaults_to_zero_not_null() -> None:
    org_id, assessment_id = await _assessment("dissent-count-default")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id, assessment_id=assessment_id, control_identifier="AC-2"
        )
        s.add(p)
        await s.flush()
        assert p.dissent_count == 0


async def test_dissent_count_column_is_not_nullable() -> None:
    """Guards migration 0059 declaring nullable=False in the migration
    itself, not just relying on the ORM's Mapped[int] -- a migration that
    forgot nullable=False would let a raw INSERT (bypassing the ORM's own
    Python-side default entirely) slip a NULL past it.
    """
    async with session_scope() as s:
        is_nullable = (
            await s.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_schema = 'ccf' AND table_name = 'assessment_control_proposals' "
                    "AND column_name = 'dissent_count'"
                )
            )
        ).scalar_one()
    assert is_nullable == "NO"


async def test_dissent_count_round_trips() -> None:
    org_id, assessment_id = await _assessment("dissent-count-roundtrip")
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            dissent_count=3,
        )
        s.add(p)
        await s.flush()
        pid = int(p.id)
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(AssessmentControlProposal.id == pid)
            )
        ).scalar_one()
        assert row.dissent_count == 3


async def test_inserting_dissent_count_null_directly_is_rejected() -> None:
    """Belt-and-braces alongside test_dissent_count_column_is_not_nullable:
    a raw INSERT that explicitly supplies NULL (rather than omitting the
    column, which the ORM's Python-side default of 0 would silently fill)
    must be rejected by the database itself, not merely by application code.
    """
    org_id, assessment_id = await _assessment("dissent-count-null-insert")
    async with session_scope() as s:
        with pytest.raises(IntegrityError):
            await s.execute(
                text(
                    "INSERT INTO ccf.assessment_control_proposals "
                    "(organization_id, assessment_id, control_identifier, dissent_count) "
                    "VALUES (:org_id, :assessment_id, 'AC-3', NULL)"
                ),
                {"org_id": org_id, "assessment_id": assessment_id},
            )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/pytest tests/test_dissent_models.py -v`
Expected: FAIL — `TypeError: 'challenger_verdict' is an invalid keyword argument for AssessmentObjectiveProposal` (and similarly for `dissent_count` on `AssessmentControlProposal`).

- [ ] **Step 3: Add the columns to the ORM models**

In `src/ccf/models_assessment_engine.py`, inside `AssessmentControlProposal`, add `dissent_count` right after `objectives_evaluated`:

```python
    objectives_total: Mapped[int] = mapped_column(Integer, default=0)
    objectives_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    #: How many of this control's objectives were contested by a challenger
    #: (AI dissent path, migration 0059) -- so a reviewer sees it without a
    #: join. Reset to 0 at the top of every evaluate_control_proposal rerun
    #: (ccf.assessment.engine.service), same as objectives_evaluated above,
    #: so a clean re-evaluation does not carry a prior run's dissent forward.
    dissent_count: Mapped[int] = mapped_column(Integer, default=0)
```

Inside `AssessmentObjectiveProposal`, add the three challenger columns right after `error`, before `created_at`:

```python
    error: Mapped[str | None] = mapped_column(Text)

    #: AI dissent path (2026-08-11 design). All three NULL together mean
    #: "not challenged" -- the primary verdict above was not satisfied, or
    #: CCF_ASSESSMENT_DISSENT_ENABLED was off -- and all three NULL can *also*
    #: mean "challenged, but the challenge call itself failed": those two
    #: cases are distinguishable only in the logs (assessment.challenger_failed),
    #: never from these columns alone. See ccf.assessment.engine.evaluate's
    #: module docstring for the full reasoning.
    #:
    #: The challenger's own verdict, retained separately from `verdict` above
    #: rather than overwriting it -- overwriting would destroy the record that
    #: a disagreement happened at all, which is what an assessor needs in
    #: order to adjudicate it. Populated whenever a challenge ran and
    #: succeeded, agreement included -- "challenged and agreed" must stay
    #: distinguishable from "not challenged".
    challenger_verdict: Mapped[str | None] = mapped_column(String(32))
    #: The challenger's own argument, shown to the assessor. Populated
    #: alongside challenger_verdict under the same rule.
    challenger_rationale: Mapped[str | None] = mapped_column(Text)
    #: Provenance for the challenger's own model call, recorded through
    #: ccf.ai_actions.provenance.record_ai_run under its own
    #: action_key="challenge_assessment_objective" -- a distinct row from the
    #: primary verdict's own ai_action_run_id above, so one query over
    #: ai_action_runs can separate a verdict from the argument made against
    #: it. ON DELETE SET NULL, not CASCADE: this row is a record of what
    #: happened and must survive its provenance row being cleaned up, exactly
    #: matching ai_action_run_id's own existing FK on this table (migration
    #: 0056).
    challenger_ai_action_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="SET NULL"), index=True
    )
```

- [ ] **Step 4: Write the migration**

Create `migrations/versions/0059_ai_dissent_path.py`:

```python
"""AI dissent path: challenger verdict columns on
assessment_objective_proposals, and a dissent_count rollup on
assessment_control_proposals.

A qualifying (satisfied-only) verdict can now be challenged by an
independent second model call, recorded through
ccf.ai_actions.provenance.record_ai_run under its own action_key. Three new
columns on assessment_objective_proposals hold the challenger's own verdict,
its rationale, and a link to the AiActionRun that produced it -- all
nullable, all NULL together for an un-challenged objective (see
ccf.assessment.engine.evaluate's module docstring for the two distinct
meanings a NULL can carry). assessment_control_proposals gains dissent_count,
NOT NULL with a default of 0, so a reviewer sees how many of a control's
objectives were contested without a join.

Revision ID: 0059_ai_dissent_path
Revises: 0058_closure_reevaluation
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0059_ai_dissent_path"
down_revision = "0058_closure_reevaluation"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_OBJECTIVES = "assessment_objective_proposals"
_CONTROLS = "assessment_control_proposals"
_INDEX = "ix_objective_proposal_challenger_ai_action_run_id"


def upgrade() -> None:
    op.add_column(_OBJECTIVES, sa.Column("challenger_verdict", sa.String(32)), schema=_SCHEMA)
    op.add_column(_OBJECTIVES, sa.Column("challenger_rationale", sa.Text()), schema=_SCHEMA)
    op.add_column(
        _OBJECTIVES,
        sa.Column(
            "challenger_ai_action_run_id",
            sa.BigInteger(),
            sa.ForeignKey(f"{_SCHEMA}.ai_action_runs.id", ondelete="SET NULL"),
        ),
        schema=_SCHEMA,
    )
    op.create_index(_INDEX, _OBJECTIVES, ["challenger_ai_action_run_id"], schema=_SCHEMA)

    op.add_column(
        _CONTROLS,
        sa.Column("dissent_count", sa.Integer(), nullable=False, server_default="0"),
        schema=_SCHEMA,
    )

    # Matches 0054's exact block -- the repo standard this migration must
    # carry that 0057 and 0058 both omitted (a bare, unguarded GRANT
    # statement in each): a no-op if ccf_app doesn't exist in this
    # environment (e.g. a dev DB that never split roles), and otherwise
    # ensures every table in the schema is usable by the scoped application
    # role regardless of which role actually ran the migrations.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )


def downgrade() -> None:
    op.drop_column(_CONTROLS, "dissent_count", schema=_SCHEMA)
    op.drop_index(_INDEX, table_name=_OBJECTIVES, schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "challenger_ai_action_run_id", schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "challenger_rationale", schema=_SCHEMA)
    op.drop_column(_OBJECTIVES, "challenger_verdict", schema=_SCHEMA)
    # The GRANT is intentionally not reversed -- every prior migration that
    # re-issues it does the same (see 0037, 0054), since revoking a blanket
    # grant on downgrade could strand other, unrelated tables whose own
    # migrations already ran and still need it.
```

- [ ] **Step 5: Round-trip the migration**

Run: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`
Expected: all three commands succeed; `.venv/bin/alembic heads` reports `0059_ai_dissent_path (head)` afterward.

- [ ] **Step 6: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_dissent_models.py -v   # 7 pass
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** in the migration, remove `nullable=False` from the `dissent_count` column (leave `server_default="0"`), re-run the round-trip (Step 5) against a fresh test database, then re-run `test_dissent_count_column_is_not_nullable` and `test_inserting_dissent_count_null_directly_is_rejected` — confirm both now fail (`is_nullable` reports `'YES'`; the raw `INSERT ... NULL` no longer raises `IntegrityError`). Revert. Then, in the ORM model, change `challenger_ai_action_run_id`'s `ondelete="SET NULL"` to `ondelete="CASCADE"`, regenerate the migration's FK accordingly (or just re-run against a DB where the constraint was created without `nullable=False` complications — simplest: temporarily edit the migration's FK to `ondelete="CASCADE"`, re-run the round-trip, re-run `test_deleting_the_challenger_ai_run_sets_the_link_null_not_cascade`) — confirm it now fails (the whole `AssessmentObjectiveProposal` row is gone, not just its link). Revert both.

```bash
git add src/ccf/models_assessment_engine.py \
        migrations/versions/0059_ai_dissent_path.py \
        tests/test_dissent_models.py
git commit -m "feat(assessment): add the AI dissent path's four columns (migration 0059)"
```

---

### Task 2: The challenger call — prompt, schema, satisfied-only policy, disagreement routing, failure isolation

**Files:**
- Modify: `src/ccf/config.py`
- Modify: `src/ccf/assessment/engine/evaluate.py`
- Create: `tests/test_assessment_dissent_evaluate.py`

**Interfaces:**
- Produces: `Settings.assessment_dissent_enabled`; `evaluate.DISSENT_CHALLENGE_ACTION_KEY`, `.DISSENT_CHALLENGE_PURPOSE`, `.DISSENT_CHALLENGE_POLICY_VERSION`, `.CHALLENGE_SCHEMA`, `.build_challenge_prompt`; `ObjectiveEvaluation.challenger_verdict` / `.challenger_rationale` / `.challenger_ai_action_run_id`.
- Consumes: Task 1's four columns are not touched here — this task only extends the in-memory `ObjectiveEvaluation` dataclass. `service.py` (Task 3) is what persists these fields.

- [ ] **Step 1: Add the setting**

In `src/ccf/config.py`, inside `Settings`, add `assessment_dissent_enabled` right after `assessment_worker_reap_interval_seconds`:

```python
    assessment_worker_poll_interval_seconds: float = Field(default=30.0)
    assessment_worker_reap_interval_seconds: float = Field(default=300.0)
    # AI dissent path (slice 6): runs an independent second model call (a
    # "challenger") against a satisfied verdict before an assessor ever sees
    # it -- a satisfied verdict that is wrong is a missed finding in an
    # authorization package, the expensive error direction slice 4's
    # calibration harness measures after the fact. Off by default: like
    # assessment_engine_enabled above, this doubles model calls on the
    # passing subset, and a deployment must opt into that cost. See
    # ccf.assessment.engine.evaluate's module docstring for the full
    # reasoning.
    assessment_dissent_enabled: bool = Field(default=False)
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_assessment_dissent_evaluate.py`:

```python
"""The challenger call: satisfied-only policy, disagreement routing to
insufficient_evidence, and failure isolation.

CCF_ASSESSMENT_DISSENT_ENABLED is off by default -- these tests enable it
explicitly via monkeypatch.setenv + get_settings.cache_clear(), mirroring
test_calibration_snapshot.py's pattern for the same reason: Settings is
process-wide and lru_cache'd (ccf.config.get_settings), so a stale cached
instance from an earlier test would silently ignore the env var.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.assessment.engine import evaluate as evaluate_module
from ccf.assessment.engine.evaluate import (
    DISSENT_CHALLENGE_ACTION_KEY,
    DISSENT_CHALLENGE_PURPOSE,
    PURPOSE,
    evaluate_objective,
)
from ccf.assessment.engine.objectives import Objective, objective_sha256
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import AiActionRun
from ccf.prep import retriever
from ccf.prep.retriever import RetrievedUnit

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _objective(text: str = "multifactor authentication is implemented;") -> Objective:
    return Objective(label="IA-2a", text=text, text_sha256=objective_sha256(text), sort_order=0)


def _unit(unit_id: int, content: str) -> RetrievedUnit:
    return RetrievedUnit(
        unit_id=unit_id, content=content, score=0.5, page_numbers=[3],
        section_path="Access Control", table_coordinates=None,
        source_kind="evidence_version", control_identifiers=["IA-2"],
        evidence_strength="strong", lexical_rank=1, vector_rank=1,
    )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def _resolved(
    data: dict[str, Any], model: str = "fake-model", provider: str = "fake"
) -> gateway.StructuredResult:
    return gateway.StructuredResult(data=data, model=model, provider=provider)


def _enable_dissent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_ASSESSMENT_DISSENT_ENABLED", "true")
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Any:
    yield
    get_settings.cache_clear()


def _dispatching_structured(
    primary: dict[str, Any], challenge: dict[str, Any] | Exception | None
) -> tuple[Any, list[str]]:
    """A fake generate_structured_resolved that answers differently for the
    primary call (purpose=PURPOSE) and the challenge call
    (purpose=DISSENT_CHALLENGE_PURPOSE) -- dispatch on purpose, not call
    order, so "no second call was made" is unambiguous. Returns (fake_fn,
    calls), where calls records every purpose seen, in order, so a test can
    assert the exact call count -- not just the resulting columns, since the
    satisfied-only policy is specifically about not making a call at all.
    """
    calls: list[str] = []

    async def _fake(session: Any, org_id: Any, *, purpose: str, **kwargs: Any) -> Any:
        calls.append(purpose)
        if purpose == PURPOSE:
            return _resolved(primary)
        assert purpose == DISSENT_CHALLENGE_PURPOSE
        if challenge is None:
            raise AssertionError("no challenge call was expected")
        if isinstance(challenge, Exception):
            raise challenge
        return _resolved(challenge, model="challenger-model", provider="fake")

    return _fake, calls


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    org_id: int,
    primary: dict[str, Any],
    challenge: dict[str, Any] | Exception | None,
) -> tuple[Any, list[str]]:
    fake, calls = _dispatching_structured(primary, challenge)

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "Admins use MFA.")]

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", fake)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2", objective=_objective(), system_id=None,
        )
    return result, calls


_SATISFIED = {
    "verdict": "satisfied", "cited_unit_ids": [7], "gaps": [], "contradictions": [],
    "rationale": "The primary reviewer's own rationale.", "confidence": 0.95,
}
_NOT_SATISFIED = {
    "verdict": "not_satisfied", "cited_unit_ids": [], "gaps": ["nothing addresses key rotation"],
    "contradictions": [], "rationale": "The primary reviewer's own rationale.", "confidence": 0.9,
}
_INSUFFICIENT = {
    "verdict": "insufficient_evidence", "cited_unit_ids": [], "gaps": ["ambiguous"],
    "contradictions": [], "rationale": "The primary reviewer's own rationale.", "confidence": 0.4,
}


# --- Disabled by default / satisfied-only ------------------------------------


async def test_disabled_by_default_makes_no_challenger_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, calls = await _run(monkeypatch, await _org("dissent-disabled"), _SATISFIED, None)
    assert calls == [PURPOSE]
    assert result.verdict == "satisfied"
    assert result.challenger_verdict is None


async def test_a_not_satisfied_primary_verdict_is_never_challenged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dissent(monkeypatch)
    result, calls = await _run(monkeypatch, await _org("dissent-skip-ns"), _NOT_SATISFIED, None)
    assert calls == [PURPOSE], "a not_satisfied verdict must not trigger a second model call"
    assert result.verdict == "not_satisfied"
    assert result.challenger_verdict is None


async def test_an_insufficient_evidence_primary_verdict_is_never_challenged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dissent(monkeypatch)
    result, calls = await _run(monkeypatch, await _org("dissent-skip-ie"), _INSUFFICIENT, None)
    assert calls == [PURPOSE], "insufficient_evidence must not trigger a second model call"
    assert result.verdict == "insufficient_evidence"
    assert result.challenger_verdict is None


# --- Agreement vs disagreement ------------------------------------------------


async def test_agreement_is_recorded_without_escalating(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dissent(monkeypatch)
    challenge_agrees = {
        "verdict": "satisfied", "cited_unit_ids": [7],
        "rationale": "The challenger's own, distinct argument -- also satisfied.",
    }
    result, calls = await _run(
        monkeypatch, await _org("dissent-agree"), _SATISFIED, challenge_agrees
    )
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "satisfied", "agreement must not change the objective's verdict"
    assert result.challenger_verdict == "satisfied"
    assert (
        result.challenger_rationale
        == "The challenger's own, distinct argument -- also satisfied."
    )
    assert result.challenger_ai_action_run_id is not None


async def test_disagreement_flips_the_verdict_and_retains_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asymmetric fixture: primary and challenger carry different confidence,
    different rationale text, and different verdicts, so a swap bug (primary
    and challenger rationale/verdict transposed) would be caught, and a
    confidence-weighted "average" implementation would visibly disagree with
    the asserted outcome.
    """
    _enable_dissent(monkeypatch)
    challenge_disagrees = {
        "verdict": "not_satisfied", "cited_unit_ids": [7],
        "rationale": "The challenger's own argument: passage 7 does not actually cover rotation.",
    }
    result, calls = await _run(
        monkeypatch, await _org("dissent-disagree"), _SATISFIED, challenge_disagrees
    )
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "insufficient_evidence", (
        "a credible disagreement routes to insufficient_evidence -- never satisfied "
        "(the primary) and never not_satisfied (the challenger): the two are never "
        "tie-broken toward either side"
    )
    assert result.rationale == "The primary reviewer's own rationale.", (
        "the primary's own rationale must survive unchanged"
    )
    assert result.challenger_verdict == "not_satisfied"
    assert (
        result.challenger_rationale
        == "The challenger's own argument: passage 7 does not actually cover rotation."
    )
    assert result.challenger_ai_action_run_id is not None


async def test_an_uncited_disagreement_does_not_escalate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bar is a differing verdict WITH at least one citation -- an
    uncited disagreement is still recorded (challenger_verdict populated) but
    must not flip the objective. Confirms escalation is never gated on the
    challenger's own confidence either, since this fixture supplies none.
    """
    _enable_dissent(monkeypatch)
    challenge_uncited = {
        "verdict": "not_satisfied", "cited_unit_ids": [],
        "rationale": "The challenger's argument, but grounded in nothing offered.",
    }
    result, _ = await _run(
        monkeypatch, await _org("dissent-uncited"), _SATISFIED, challenge_uncited
    )
    assert result.verdict == "satisfied"
    assert result.challenger_verdict == "not_satisfied"


# --- Failure isolation --------------------------------------------------------


async def test_a_raising_challenger_call_leaves_the_primary_verdict_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dissent(monkeypatch)
    warn = MagicMock()
    monkeypatch.setattr(evaluate_module.log, "warning", warn)
    result, calls = await _run(
        monkeypatch,
        await _org("dissent-raise"),
        _SATISFIED,
        RuntimeError("simulated provider timeout"),
    )
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "satisfied"
    assert result.challenger_verdict is None
    assert result.challenger_rationale is None
    assert result.challenger_ai_action_run_id is None
    warn.assert_called_once()
    assert warn.call_args.args[0] == "assessment.challenger_failed"


async def test_a_challenger_call_that_never_ran_logs_no_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The subtler trap: a best-effort except handler makes "skipped
    correctly" and "raised and was swallowed" indistinguishable to a test
    that only asserts the absence of the challenger columns. Assert the
    warning log's absence too, on the disabled-by-default path where no
    challenge is even attempted.
    """
    warn = MagicMock()
    monkeypatch.setattr(evaluate_module.log, "warning", warn)
    await _run(monkeypatch, await _org("dissent-no-warn"), _SATISFIED, None)
    warn.assert_not_called()


async def test_a_malformed_challenger_response_rolls_back_its_own_partial_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """record_ai_run for the challenge call succeeds and writes a real
    AiActionRun row *before* this function parses c_data["verdict"] -- a
    challenge response missing "verdict" raises there, after that write. With
    the challenger call wrapped in its own begin_nested(), that partial write
    is rolled back cleanly; without it, the row would survive as an orphan
    even though the challenge is reported as failed. This is what actually
    discriminates begin_nested()'s presence: record_ai_run's own internal
    savepoint means it never raises on its own, so a plain monkeypatched
    RuntimeError (as in the test above) cannot distinguish "wrapped in its
    own savepoint" from "just a bare try/except" -- this test can.
    """
    _enable_dissent(monkeypatch)
    org_id = await _org("dissent-orphan-rollback")
    malformed_challenge = {"cited_unit_ids": [7], "rationale": "missing the verdict key"}
    result, calls = await _run(monkeypatch, org_id, _SATISFIED, malformed_challenge)
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "satisfied"
    assert result.challenger_verdict is None

    async with session_scope() as s:
        orphans = (
            await s.execute(
                select(AiActionRun).where(
                    AiActionRun.action_key == DISSENT_CHALLENGE_ACTION_KEY,
                    AiActionRun.organization_id == org_id,
                )
            )
        ).scalars().all()
    assert orphans == [], (
        "a failed challenge must leave no orphan AiActionRun row behind for this "
        "organization -- this is what begin_nested() actually protects"
    )
```

- [ ] **Step 3: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_assessment_dissent_evaluate.py -v`
Expected: FAIL — `ImportError: cannot import name 'DISSENT_CHALLENGE_ACTION_KEY' from 'ccf.assessment.engine.evaluate'`.

- [ ] **Step 4: Add the challenger's constants and schema**

In `src/ccf/assessment/engine/evaluate.py`, right after the closing `}` of `EVALUATION_SCHEMA` and before `_SYSTEM_PROMPT`, add:

```python
#: Provenance action_key for the challenger's own model call -- distinct from
#: ACTION_KEY above, so one query over ai_action_runs can separate a primary
#: verdict from the argument made against it.
DISSENT_CHALLENGE_ACTION_KEY = "challenge_assessment_objective"
DISSENT_CHALLENGE_PURPOSE = "assessment.challenge_objective"

#: Identifies the policy that decides which verdicts get challenged --
#: currently "satisfied only" (see evaluate_objective's own docstring for
#: why: challenging a satisfied verdict guards against a missed finding, the
#: expensive error direction; challenging not_satisfied or
#: insufficient_evidence would not). Named and versioned, not left implicit,
#: so a later change to which verdicts get challenged is visible rather than
#: silent -- imported into
#: ccf.assessment.engine.calibration.config_fingerprint for exactly that
#: reason, mirroring ccf.assessment.engine.rollup.ROLLUP_POLICY_VERSION.
DISSENT_CHALLENGE_POLICY_VERSION = "v1"

#: The challenger's own structured-output contract. Deliberately identical in
#: shape to EVALUATION_SCHEMA -- the challenger is doing the same job (judge
#: the objective against the same passages), just under a system prompt that
#: instructs it to argue the opposite conclusion -- kept as its own named
#: constant rather than aliased so the two can diverge later without
#: coupling them.
CHALLENGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["satisfied", "not_satisfied", "not_applicable", "insufficient_evidence"],
        },
        "cited_unit_ids": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "Passage ids that support the challenger's verdict, from those offered.",
        },
        "rationale": {"type": "string"},
    },
    "required": ["verdict", "cited_unit_ids", "rationale"],
    "additionalProperties": False,
}
```

- [ ] **Step 5: Add the challenger's system prompt and prompt builder**

Right after `_SYSTEM_PROMPT`'s closing `)`, add:

```python
_CHALLENGE_SYSTEM_PROMPT = (
    "You are a second, independent reviewer. A first reviewer read the same evidence "
    "passages and judged that this NIST SP 800-53A assessment objective is satisfied. "
    "Your job is to make the strongest possible case that it is NOT satisfied, using "
    "only the passages you are shown -- the same passages the first reviewer saw. Do "
    "not simply agree for the sake of agreement, and do not invent evidence outside "
    "what you were given: if the passages genuinely support satisfied and you cannot "
    "construct a credible case against it, say so honestly by answering satisfied "
    "yourself. Cite only the passage ids you were given."
)
```

Right after `build_prompt`'s closing `)`, before `def _citation_label`, add:

```python
def build_challenge_prompt(objective_text: str, units: list[RetrievedUnit]) -> str:
    """Build the challenger's prompt for one objective -- the same passages
    build_prompt uses, framed as a request to argue the opposite conclusion.
    Same citation set as the primary call is load-bearing (see the design
    doc): it isolates the variable being tested to "does the evidence
    support this," not "did the challenger find different evidence."
    """
    passages = "\n\n".join(
        f"[{u.unit_id}] (page {', '.join(str(p) for p in u.page_numbers) or 'n/a'}"
        f"{f', {u.section_path}' if u.section_path else ''})\n{u.content}"
        for u in units
    )
    return (
        f"Assessment objective:\n{objective_text}\n\n"
        f"Evidence passages (the same ones a first reviewer judged as satisfying this "
        f"objective):\n{passages}\n\n"
        "Argue the strongest case that these passages do NOT demonstrate the objective "
        "is met. Cite the passage ids that support your position. If you genuinely "
        "cannot construct a credible case against it, answer satisfied instead of "
        "manufacturing a disagreement."
    )
```

- [ ] **Step 6: Extend `ObjectiveEvaluation`**

Replace the `ObjectiveEvaluation` dataclass:

```python
@dataclass(slots=True)
class ObjectiveEvaluation:
    """One objective's verdict, with everything needed to review it."""

    verdict: str
    rationale: str
    confidence: float
    cited_unit_ids: list[int] = field(default_factory=list)
    retrieved_unit_ids: list[int] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    model_name: str | None = None
    ai_action_run_id: int | None = None
    #: AI dissent path (2026-08-11 design). Populated only when
    #: CCF_ASSESSMENT_DISSENT_ENABLED challenged this objective -- which only
    #: ever happens when `verdict` above was "satisfied" *before* any
    #: challenge could flip it (the satisfied-only policy,
    #: DISSENT_CHALLENGE_POLICY_VERSION). NULL means either "not challenged"
    #: or "challenged but the challenge call itself failed" -- those two are
    #: distinguishable only in the logs (assessment.challenger_failed), never
    #: from this field alone.
    challenger_verdict: str | None = None
    challenger_rationale: str | None = None
    challenger_ai_action_run_id: int | None = None
```

- [ ] **Step 7: Wire the challenger into `evaluate_objective`**

In `evaluate_objective`, replace everything from the second `try:` block (the one wrapping the model-call path's `record_ai_run`) through the end of the function with:

```python
    try:
        # record_ai_run is documented to never raise -- it wraps its own
        # writes in a begin_nested() savepoint and returns None on failure --
        # but this call site does not lean on that promise holding forever. A
        # provenance failure, however it happens, must cost this objective its
        # ai_action_run_id, never its verdict: the verdict can become a
        # Security Assessment Report finding, and losing it to a provenance
        # bug would be far worse than a missing audit row.
        ai_run = await record_ai_run(
            session,
            action_key=ACTION_KEY,
            entity_type="assessment_objective",
            entity_id=objective.label,
            organization_id=org_id,
            provider=result.provider,
            model=result.model,
            prompt=prompt,
            output=data,
            citations=citations,
        )
    except Exception as exc:
        log.warning(
            "assessment.evaluate_provenance_failed",
            control_identifier=control_identifier,
            label=objective.label,
            error=str(exc),
        )
        ai_run = None

    verdict = str(data["verdict"])
    rationale = str(data.get("rationale", ""))
    final_verdict = verdict

    challenger_verdict: str | None = None
    challenger_rationale: str | None = None
    challenger_ai_action_run_id: int | None = None

    # AI dissent path (design 2026-08-11). Satisfied-only policy
    # (DISSENT_CHALLENGE_POLICY_VERSION): a satisfied verdict that is wrong is
    # a missed finding in an authorization package, the expensive error
    # direction slice 4 measures after the fact -- this challenges it before
    # an assessor ever sees it. Off by default (CCF_ASSESSMENT_DISSENT_ENABLED):
    # this doubles model calls on the passing subset, and a deployment must
    # opt into that cost.
    if get_settings().assessment_dissent_enabled and verdict == "satisfied":
        try:
            # Runs inside its own savepoint, nested one level deeper than the
            # per-objective savepoint ccf.assessment.engine.service already
            # wraps this whole call in. A challenger failure must never fail
            # the evaluation -- the primary verdict above is the deliverable,
            # the challenge is an enhancement -- so this except clause, not a
            # bare session.rollback() (which is NOT savepoint-scoped and would
            # unwind the caller's already-good work, exactly the trap slice 3
            # hit with record_ai_run), is what keeps a challenger fault from
            # costing this objective its primary verdict.
            async with session.begin_nested():
                challenge_prompt = build_challenge_prompt(objective.text, units)
                challenge_result = await gateway.generate_structured_resolved(
                    session,
                    org_id,
                    prompt=challenge_prompt,
                    schema=CHALLENGE_SCHEMA,
                    purpose=DISSENT_CHALLENGE_PURPOSE,
                    system=_CHALLENGE_SYSTEM_PROMPT,
                )
                c_data = challenge_result.data

                # Same offered/units_by_id sets the primary citation
                # validation above used -- the challenger sees the same
                # retrieved passages, never a fresh retrieval. Contesting
                # which evidence was retrieved is a different problem and
                # would confound the measurement (see the design doc's
                # non-goals).
                c_cited: list[int] = []
                c_seen: set[int] = set()
                for raw in c_data.get("cited_unit_ids", []):
                    try:
                        c_unit_id = int(raw)
                    except (TypeError, ValueError):
                        continue
                    if c_unit_id in offered and c_unit_id not in c_seen:
                        c_cited.append(c_unit_id)
                        c_seen.add(c_unit_id)
                c_citations = [
                    CitationRef(
                        source_type="prep_unit",
                        source_id=str(c_unit_id),
                        label=_citation_label(units_by_id[c_unit_id]),
                    )
                    for c_unit_id in c_cited
                ]

                challenger_run = await record_ai_run(
                    session,
                    action_key=DISSENT_CHALLENGE_ACTION_KEY,
                    entity_type="assessment_objective",
                    entity_id=objective.label,
                    organization_id=org_id,
                    provider=challenge_result.provider,
                    model=challenge_result.model,
                    prompt=challenge_prompt,
                    output=c_data,
                    citations=c_citations,
                )

                c_verdict = str(c_data["verdict"])
                challenger_verdict = c_verdict
                challenger_rationale = str(c_data.get("rationale", ""))
                challenger_ai_action_run_id = (
                    challenger_run.id if challenger_run is not None else None
                )

                # The bar is any credible disagreement -- a differing verdict
                # with at least one citation, never a confidence threshold
                # (the challenger's self-reported confidence is exactly the
                # signal this slice exists because we do not trust it). Two
                # verdicts are never averaged, majority-voted, or
                # tie-broken: a disagreement routes to insufficient_evidence,
                # a state that already means "the engine could not tell" and
                # already forces the whole control to insufficient_evidence
                # in rollup.py with no rollup change required.
                if c_verdict != "satisfied" and c_cited:
                    final_verdict = "insufficient_evidence"
        except Exception as exc:
            log.warning(
                "assessment.challenger_failed",
                control_identifier=control_identifier,
                label=objective.label,
                error=str(exc),
            )
            challenger_verdict = None
            challenger_rationale = None
            challenger_ai_action_run_id = None

    return ObjectiveEvaluation(
        verdict=final_verdict,
        rationale=rationale,
        confidence=float(data.get("confidence", 0.0)),
        cited_unit_ids=cited,
        retrieved_unit_ids=retrieved_ids,
        gaps=[str(g) for g in data.get("gaps", [])],
        contradictions=[str(c) for c in data.get("contradictions", [])],
        model_name=result.model,
        ai_action_run_id=ai_run.id if ai_run is not None else None,
        challenger_verdict=challenger_verdict,
        challenger_rationale=challenger_rationale,
        challenger_ai_action_run_id=challenger_ai_action_run_id,
    )
```

Also update the module docstring's second paragraph (the one describing recording) to mention the challenger — after the sentence ending `...auto-create a POA&M, so this is the record that answers "which model decided this, and from what evidence."`, add:

```
When CCF_ASSESSMENT_DISSENT_ENABLED is on and the primary verdict is
"satisfied", a second, independent call -- the challenger -- argues the
opposite conclusion from the *same* retrieved passages, and is recorded
under its own action_key (DISSENT_CHALLENGE_ACTION_KEY). A credible
disagreement (a differing, cited verdict) overwrites this objective's own
verdict to "insufficient_evidence"; the two verdicts are never averaged,
majority-voted, or tie-broken, and both are retained --
AssessmentObjectiveProposal.challenger_verdict alongside the unchanged
verdict column. A challenger failure never costs the objective its primary
verdict.
```

- [ ] **Step 8: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_assessment_dissent_evaluate.py -v    # 10 pass
.venv/bin/pytest tests/test_assessment_evaluate.py -v             # unaffected, still all pass
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check** (revert after each):
1. Change the gate from `if get_settings().assessment_dissent_enabled and verdict == "satisfied":` to `if get_settings().assessment_dissent_enabled:` (drop the verdict check) — re-run `test_a_not_satisfied_primary_verdict_is_never_challenged` — confirm it now fails (`calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]` instead of `[PURPOSE]`).
2. Delete the `except Exception as exc: ... challenger_ai_action_run_id = None` block entirely (let the challenger's exception propagate) — re-run `test_a_raising_challenger_call_leaves_the_primary_verdict_intact` — confirm it now errors (the `RuntimeError` propagates out of `evaluate_objective` instead of being caught).
3. Dedent the body of `async with session.begin_nested():` so it runs directly in the outer transaction (delete just that one line) — re-run `test_a_malformed_challenger_response_rolls_back_its_own_partial_write` — confirm it now fails (`orphans` has length 1, not 0).
4. Change `if c_verdict != "satisfied" and c_cited:` to `if c_verdict != "satisfied":` (drop the citation requirement) — re-run `test_an_uncited_disagreement_does_not_escalate` — confirm it now fails (`result.verdict == "insufficient_evidence"` instead of `"satisfied"`).

```bash
git add src/ccf/config.py src/ccf/assessment/engine/evaluate.py \
        tests/test_assessment_dissent_evaluate.py
git commit -m "feat(assessment): add the dissent challenger call, satisfied-only policy"
```

---

### Task 3: Wiring the challenger into the evaluate stage — persistence and `dissent_count`

**Files:**
- Modify: `src/ccf/assessment/engine/service.py`
- Create: `tests/test_assessment_dissent_service.py`

**Interfaces:**
- Consumes: Task 1's four columns; Task 2's `ObjectiveEvaluation.challenger_verdict` / `.challenger_rationale` / `.challenger_ai_action_run_id`.
- Modifies: `evaluate_control_proposal`'s per-objective loop.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_assessment_dissent_service.py`:

```python
"""Wiring the challenger's output into the evaluate stage:
challenger_verdict/challenger_rationale/challenger_ai_action_run_id land on
AssessmentObjectiveProposal, dissent_count aggregates on
AssessmentControlProposal, and the whole thing forces the rollup consequence
the design exists to produce -- a contested control that
accept_control_proposal then refuses.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import delete, select

from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import (
    AcceptanceRefused,
    accept_control_proposal,
    evaluate_control_proposal,
    open_control_proposal,
)
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentObjectiveProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-97"


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """Two sub-clause objectives -- ...a and ...b -- so a control can carry
    one dissenting and one agreeing objective at once: an asymmetric fixture
    a naive "any dissent forces dissent_count to objectives_total"
    implementation would fail (only one of the two dissents here).
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ, sequence_control=_SEQ, control_name="Dissent Wiring Fixture",
                assessment_objective="Determine if:", source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1", sequence_control=_SEQ, ap_acronym=f"{_SEQ}a",
                assessment_objective="the first fixture objective is met;", source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2", sequence_control=_SEQ, ap_acronym=f"{_SEQ}b",
                assessment_objective="the second fixture objective is met;", source_row=3,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


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


def _by_label(results: dict[str, ObjectiveEvaluation]) -> Any:
    async def _fake(
        session: Any, *, org_id: int, control_identifier: str, objective: Any,
        system_id: int | None,
    ) -> ObjectiveEvaluation:
        return results[objective.label]

    return _fake


def _agreeing() -> ObjectiveEvaluation:
    return ObjectiveEvaluation(
        verdict="satisfied", rationale="primary agrees", confidence=0.9,
        challenger_verdict="satisfied", challenger_rationale="challenger agrees too",
        challenger_ai_action_run_id=101,
    )


def _dissenting() -> ObjectiveEvaluation:
    return ObjectiveEvaluation(
        verdict="insufficient_evidence", rationale="primary said satisfied",
        confidence=0.9, challenger_verdict="not_satisfied",
        challenger_rationale="challenger disagrees, with a citation",
        challenger_ai_action_run_id=202,
    )


async def _objective_row(proposal_id: int, label: str) -> AssessmentObjectiveProposal:
    async with session_scope() as s:
        return (
            await s.execute(
                select(AssessmentObjectiveProposal).where(
                    AssessmentObjectiveProposal.control_proposal_id == proposal_id,
                    AssessmentObjectiveProposal.label == label,
                )
            )
        ).scalar_one()


async def test_challenger_fields_land_on_the_objective_proposal_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, assessment_id = await _assessment("dissent-wiring-fields")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": _dissenting(), f"{_SEQ}b": _agreeing()}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        proposal_id = int(proposal.id)

    dissenting_row = await _objective_row(proposal_id, f"{_SEQ}a")
    assert dissenting_row.verdict == "insufficient_evidence"
    assert dissenting_row.challenger_verdict == "not_satisfied"
    assert dissenting_row.challenger_rationale == "challenger disagrees, with a citation"
    assert dissenting_row.challenger_ai_action_run_id == 202

    agreeing_row = await _objective_row(proposal_id, f"{_SEQ}b")
    assert agreeing_row.verdict == "satisfied"
    assert agreeing_row.challenger_verdict == "satisfied"
    assert agreeing_row.challenger_ai_action_run_id == 101


async def test_dissent_count_counts_the_dissenting_objective_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asymmetric fixture: one of the two objectives dissents, the other
    agrees -- dissent_count must land on exactly 1, not 0 (missed it
    entirely) and not 2 (counted the agreeing one too).
    """
    org_id, assessment_id = await _assessment("dissent-wiring-count")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": _dissenting(), f"{_SEQ}b": _agreeing()}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 1


async def test_dissent_count_resets_on_a_clean_reevaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """evaluate_control_proposal reruns cleanly (existing behaviour, this
    slice does not change it) -- dissent_count must reset to 0 on a rerun
    that no longer dissents, not carry the prior run's count forward.
    """
    org_id, assessment_id = await _assessment("dissent-wiring-reset")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": _dissenting(), f"{_SEQ}b": _agreeing()}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 1
        proposal_id = int(proposal.id)

    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": _agreeing(), f"{_SEQ}b": _agreeing()}),
    )
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.dissent_count == 0, "a clean rerun must not carry the prior dissent forward"


async def test_a_contested_control_rolls_up_to_insufficient_evidence_and_acceptance_refuses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The end-to-end property the whole slice exists to produce: one
    contested objective, among several agreeing ones, still forces the
    *whole* control to insufficient_evidence (rollup.py's existing
    counts["insufficient_evidence"] branch -- no rollup code change), and
    accept_control_proposal then refuses it. Asserted against this specific
    assessment/control, not a table-wide count.
    """
    org_id, assessment_id = await _assessment("dissent-wiring-rollup")
    monkeypatch.setattr(
        service, "evaluate_objective",
        _by_label({f"{_SEQ}a": _dissenting(), f"{_SEQ}b": _agreeing()}),
    )
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        assert proposal.proposed_finding == "insufficient_evidence", (
            f"control {_SEQ} in assessment {assessment_id} must roll up to "
            "insufficient_evidence with one dissenting objective among two"
        )
        proposal_id = int(proposal.id)

    async with session_scope() as s:
        with pytest.raises(AcceptanceRefused):
            await accept_control_proposal(s, proposal_id, accepted_by="assessor@x.test")
```

- [ ] **Step 2: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_assessment_dissent_service.py -v`
Expected: FAIL — `dissenting_row.challenger_verdict` is `None` for all four tests (the fields are computed by the fake `evaluate_objective` but never persisted), and `dissent_count` stays `0` throughout.

- [ ] **Step 3: Persist the challenger fields and aggregate `dissent_count`**

In `src/ccf/assessment/engine/service.py`, inside `evaluate_control_proposal`, reset `dissent_count` alongside the existing top-of-function assignments:

```python
    settings = get_settings()
    proposal.state = "draft"
    proposal.dissent_count = 0
    proposal.config_snapshot = {
        "retrieval_limit": settings.assessment_engine_retrieval_limit,
        "max_objectives": settings.assessment_engine_max_objectives_per_control,
    }
```

In the per-objective loop, extend the `AssessmentObjectiveProposal(...)` construction with the three challenger fields, and add the `dissent_count` increment right after the existing `await session.flush()` inside the same `async with session.begin_nested():` block:

```python
                session.add(
                    AssessmentObjectiveProposal(
                        organization_id=proposal.organization_id,
                        control_proposal_id=proposal.id,
                        label=objective.label,
                        objective_text=objective.text,
                        objective_text_sha256=objective.text_sha256,
                        sort_order=objective.sort_order,
                        state="complete",
                        verdict=evaluation.verdict,
                        cited_unit_ids=evaluation.cited_unit_ids,
                        retrieved_unit_ids=evaluation.retrieved_unit_ids,
                        gaps=evaluation.gaps,
                        contradictions=evaluation.contradictions,
                        rationale=evaluation.rationale,
                        model_name=evaluation.model_name,
                        # Deliberate rename: ObjectiveEvaluation.confidence is a
                        # model's output, model_confidence is a column. Map
                        # explicitly rather than renaming either side.
                        model_confidence=evaluation.confidence,
                        # Set inside this same per-objective savepoint:
                        # evaluate_objective already recorded (or, on a
                        # provenance failure, tried and got None back for) the
                        # AI run before returning here, so this is a plain
                        # field assignment, not a second provenance attempt.
                        ai_action_run_id=evaluation.ai_action_run_id,
                        # AI dissent path (slice 6): all three NULL together
                        # for an un-challenged objective, or for a challenge
                        # that failed -- see evaluate_objective's own
                        # docstring for why those two cases are
                        # distinguishable only in the logs, not here.
                        challenger_verdict=evaluation.challenger_verdict,
                        challenger_rationale=evaluation.challenger_rationale,
                        challenger_ai_action_run_id=evaluation.challenger_ai_action_run_id,
                    )
                )
                await session.flush()
                # A challenger reaching a different, cited verdict is the one
                # condition evaluate_objective folds into `verdict` itself
                # (insufficient_evidence) rather than a separate flag.
                # challenger_verdict is not None only when a challenge
                # actually ran and succeeded -- evaluate_objective resets it
                # to None on failure -- so this combination can only be true
                # for a genuine disagreement: it can never be true for the
                # no-evidence path or for a primary verdict that was already
                # insufficient_evidence on its own, since neither of those
                # ever reaches the challenge gate (which only fires on a
                # primary verdict of "satisfied").
                if (
                    evaluation.challenger_verdict is not None
                    and evaluation.verdict == "insufficient_evidence"
                ):
                    proposal.dissent_count += 1
```

- [ ] **Step 4: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_assessment_dissent_service.py -v    # 4 pass
.venv/bin/pytest tests/test_assessment_service.py tests/test_assessment_acceptance.py -v   # unaffected
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check** (revert after each):
1. Comment out `proposal.dissent_count += 1` — re-run `test_dissent_count_counts_the_dissenting_objective_only` — confirm it now fails (`proposal.dissent_count == 0`).
2. Delete `proposal.dissent_count = 0` from the top of `evaluate_control_proposal` — re-run `test_dissent_count_resets_on_a_clean_reevaluation` — confirm it now fails (`proposal.dissent_count == 1` on the rerun, carried over from the prior run).
3. Remove the three `challenger_*=evaluation.challenger_*` keyword arguments from the `AssessmentObjectiveProposal(...)` construction — re-run `test_challenger_fields_land_on_the_objective_proposal_row` — confirm it now fails (all four challenger assertions fail, since the columns stay `NULL`).

```bash
git add src/ccf/assessment/engine/service.py tests/test_assessment_dissent_service.py
git commit -m "feat(assessment): persist challenger fields and aggregate dissent_count"
```

---

### Task 4: The calibration fingerprint change

**Files:**
- Modify: `src/ccf/assessment/engine/calibration.py`
- Modify: `tests/test_calibration_snapshot.py`

**Interfaces:**
- Consumes: `Settings.assessment_dissent_enabled` (Task 2); `evaluate.DISSENT_CHALLENGE_POLICY_VERSION` (Task 2).
- Modifies: `config_fingerprint`'s hashed payload.

- [ ] **Step 1: Write the failing tests**

In `tests/test_calibration_snapshot.py`, add these tests in the "The fingerprint itself" section, right after `test_changing_the_rollup_policy_version_changes_the_fingerprint`:

```python
def test_toggling_dissent_enabled_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = config_fingerprint(model="claude-sonnet-5")
    monkeypatch.setenv("CCF_ASSESSMENT_DISSENT_ENABLED", "true")
    get_settings.cache_clear()
    try:
        after = config_fingerprint(model="claude-sonnet-5")
    finally:
        get_settings.cache_clear()
    assert before != after


def test_changing_the_dissent_challenge_policy_version_changes_the_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = config_fingerprint(model="claude-sonnet-5")
    monkeypatch.setattr(calibration, "DISSENT_CHALLENGE_POLICY_VERSION", "v2-test")
    after = config_fingerprint(model="claude-sonnet-5")
    assert before != after
```

And add this test in the "Snapshots" section, right after `test_snapshots_under_different_configurations_are_not_comparable`:

```python
async def test_two_snapshots_with_dissent_toggled_between_them_are_not_comparable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This is how the slice actually gets evaluated (design doc, section 4):
    enabling dissent must read as a configuration change, not as an
    unexplained shift in missed_findings.
    """
    org_id, aid = await _assessment("snap-dissent-not-comparable")
    await _decided(org_id, aid, "AC-2", "satisfied", accepted=True)
    async with session_scope() as s:
        first = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
        await s.flush()
        first_id = int(first.id)

    monkeypatch.setenv("CCF_ASSESSMENT_DISSENT_ENABLED", "true")
    get_settings.cache_clear()
    try:
        async with session_scope() as s:
            second = await take_snapshot(s, organization_id=org_id, model="claude-sonnet-5")
            await s.flush()
            second_id = int(second.id)

        async with session_scope() as s:
            result = await compare_snapshots(s, first_id, second_id, organization_id=org_id)
    finally:
        get_settings.cache_clear()

    assert result["comparable"] is False
    assert "deltas" not in result
```

- [ ] **Step 2: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_calibration_snapshot.py -v -k dissent`
Expected: FAIL — `test_toggling_dissent_enabled_changes_the_fingerprint` and the "not comparable" test both fail with `before == after` / `result["comparable"] is True` (the flag is not folded into the fingerprint yet); `test_changing_the_dissent_challenge_policy_version_changes_the_fingerprint` fails with `AttributeError: module 'ccf.assessment.engine.calibration' has no attribute 'DISSENT_CHALLENGE_POLICY_VERSION'`.

- [ ] **Step 3: Fold the dissent flag and policy version into the fingerprint**

In `src/ccf/assessment/engine/calibration.py`, add the import right after `from .rollup import ROLLUP_POLICY_VERSION`:

```python
from .evaluate import DISSENT_CHALLENGE_POLICY_VERSION
from .rollup import ROLLUP_POLICY_VERSION
```

Replace `config_fingerprint`:

```python
def config_fingerprint(*, model: str | None = None) -> str:
    """A SHA-256 digest over what a calibration measurement depends on.

    A metric is comparable to an earlier one only if what was being measured
    did not change underneath it. Five things determine that here:
    ``prep_screen_threshold`` (the screening cutoff decides which passages ever
    reach evaluation), the rollup policy identity (the rule that turns objective
    verdicts into a proposed finding), the evaluation model name (a different
    model is a different measuring instrument), whether the AI dissent path
    (``CCF_ASSESSMENT_DISSENT_ENABLED``) is on, and which verdicts it
    challenges (``DISSENT_CHALLENGE_POLICY_VERSION``, currently "satisfied
    only" -- see ``ccf.assessment.engine.evaluate``). Dissent changes what is
    being measured just as surely as the other four: enabling it must make a
    prior snapshot read as *not comparable*, never as an unexplained shift in
    ``missed_findings``. Anything read but not folded into this digest is
    invisible to a comparison -- it can change and the comparison will keep
    reporting drift instead of "not comparable".

    The five inputs are serialised through a fixed set of dict keys and hashed
    with ``sort_keys=True`` so the digest never depends on dict iteration order --
    the same configuration must always produce the same digest, or every
    comparison degrades to "not comparable" even when nothing changed.

    ``model`` defaults to ``get_settings().ai_model``, mirroring how
    ``ccf.ai.gateway.resolve`` falls back to it when a caller does not pin a
    model explicitly.
    """
    settings = get_settings()
    payload = {
        "prep_screen_threshold": settings.prep_screen_threshold,
        "rollup_policy_version": ROLLUP_POLICY_VERSION,
        "model": model if model is not None else settings.ai_model,
        "assessment_dissent_enabled": settings.assessment_dissent_enabled,
        "dissent_challenge_policy_version": DISSENT_CHALLENGE_POLICY_VERSION,
    }
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_calibration_snapshot.py -v    # all pass, 3 new
.venv/bin/pytest tests/test_calibration_metrics.py tests/test_calibration_api.py -v   # unaffected
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** remove the `"assessment_dissent_enabled": settings.assessment_dissent_enabled,` line from the payload — re-run `test_toggling_dissent_enabled_changes_the_fingerprint` — confirm it now fails (`before == after`). Revert. Remove the `"dissent_challenge_policy_version": DISSENT_CHALLENGE_POLICY_VERSION,` line — re-run `test_changing_the_dissent_challenge_policy_version_changes_the_fingerprint` — confirm it now fails. Revert both.

```bash
git add src/ccf/assessment/engine/calibration.py tests/test_calibration_snapshot.py
git commit -m "feat(assessment): fold the dissent flag and policy version into config_fingerprint"
```

---

### Task 5: API surfacing and documentation

**Files:**
- Modify: `src/ccf/api/routes/assessment_engine.py`
- Create: `tests/test_assessment_dissent_api.py`
- Modify: `docs/ARCHITECTURE.md`, `README.md`, `CHANGELOG.md`

**Interfaces:**
- Modifies: `_proposal_detail`'s returned dict (`dissent_count` at the top level; `challenger_verdict` / `challenger_rationale` per objective).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_assessment_dissent_api.py`:

```python
"""GET /api/assessment-engine/proposals/{id} surfaces the AI dissent path:
dissent_count on the proposal, challenger_verdict/challenger_rationale on
each objective. Tenant isolation for this endpoint is exhaustively covered
already in test_assessment_engine_api.py (_require_proposal, 404-not-403,
the RLS-independent app-level check) -- this slice only adds fields to an
already-isolated response, it does not add a new tenant surface, so those
attacks are not re-run here.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from ccf.api.main import create_app
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import evaluate_control_proposal, open_control_proposal
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-98"


@pytest.fixture(autouse=True)
def _auth_enabled() -> Any:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _engine_enabled() -> Any:
    os.environ["CCF_ASSESSMENT_ENGINE_ENABLED"] = "true"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_ASSESSMENT_ENGINE_ENABLED", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ, sequence_control=_SEQ, control_name="Dissent API Fixture",
                assessment_objective="Determine if:", source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1", sequence_control=_SEQ, ap_acronym=f"{_SEQ}a",
                assessment_objective="the dissent API fixture objective is met;", source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role="viewer",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


async def _assessment_for(org_id: int, name: str) -> int:
    async with session_scope() as s:
        system = System(organization_id=org_id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(assessment.id)


def _fake_evaluate(
    verdict: str = "satisfied",
    *,
    challenger_verdict: str | None = None,
    challenger_rationale: str | None = None,
) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(
            verdict=verdict, rationale="primary rationale", confidence=0.9,
            challenger_verdict=challenger_verdict, challenger_rationale=challenger_rationale,
            challenger_ai_action_run_id=None,
        )

    return _fake


async def _evaluated_proposal(
    assessment_id: int, monkeypatch: pytest.MonkeyPatch, fake: Any
) -> int:
    monkeypatch.setattr(service, "evaluate_objective", fake)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        return int(proposal.id)


async def test_an_unchallenged_objective_reports_null_challenger_fields_and_zero_dissent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("dissent-null-a@ae-api.test", "Dissent API Null Org")
    assessment_id = await _assessment_for(org_id, "dissent-null")
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch, _fake_evaluate("satisfied")
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    assert response.status_code == 200
    body = response.json()
    assert body["dissent_count"] == 0
    objective = body["objectives"][0]
    assert objective["verdict"] == "satisfied"
    assert objective["challenger_verdict"] is None
    assert objective["challenger_rationale"] is None


async def test_an_agreeing_challenge_is_surfaced_without_affecting_dissent_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("dissent-agree-a@ae-api.test", "Dissent API Agree Org")
    assessment_id = await _assessment_for(org_id, "dissent-agree")
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch,
        _fake_evaluate("satisfied", challenger_verdict="satisfied", challenger_rationale="agrees"),
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    body = response.json()
    assert body["dissent_count"] == 0
    objective = body["objectives"][0]
    assert objective["verdict"] == "satisfied"
    assert objective["challenger_verdict"] == "satisfied"
    assert objective["challenger_rationale"] == "agrees"


async def test_a_disagreement_is_surfaced_and_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    token, org_id = await _mk_user("dissent-disagree-a@ae-api.test", "Dissent API Disagree Org")
    assessment_id = await _assessment_for(org_id, "dissent-disagree")
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch,
        _fake_evaluate(
            "insufficient_evidence", challenger_verdict="not_satisfied",
            challenger_rationale="the challenger's own distinct argument",
        ),
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    body = response.json()
    assert body["dissent_count"] == 1
    objective = body["objectives"][0]
    assert objective["verdict"] == "insufficient_evidence"
    assert objective["challenger_verdict"] == "not_satisfied"
    assert objective["challenger_rationale"] == "the challenger's own distinct argument"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `.venv/bin/pytest tests/test_assessment_dissent_api.py -v`
Expected: FAIL — `KeyError: 'dissent_count'` (the response body has no such key yet).

- [ ] **Step 3: Surface the fields**

In `src/ccf/api/routes/assessment_engine.py`, inside `_proposal_detail`, extend the `objectives_out` comprehension:

```python
    objectives_out = [
        {
            "label": o.label,
            "objective_text": o.objective_text,
            "state": o.state,
            "verdict": o.verdict,
            "rationale": o.rationale,
            "model_confidence": o.model_confidence,
            "gaps": o.gaps,
            "contradictions": o.contradictions,
            "citations": await _citations(session, o.cited_unit_ids, proposal.organization_id),
            # AI dissent path (slice 6): NULL on every un-challenged
            # objective, and NULL again -- not the challenger's last output
            # -- if CCF_ASSESSMENT_DISSENT_ENABLED was on but the challenge
            # itself failed. See ccf.assessment.engine.evaluate's module
            # docstring: the two NULL cases are distinguishable only in the
            # logs, not in this response.
            "challenger_verdict": o.challenger_verdict,
            "challenger_rationale": o.challenger_rationale,
        }
        for o in objectives
    ]
```

And extend the returned dict, adding `dissent_count` right after `objectives_evaluated`:

```python
    return {
        "id": proposal.id,
        "assessment_id": proposal.assessment_id,
        "control_identifier": proposal.control_identifier,
        "state": proposal.state,
        "error": proposal.error,
        "job_status": job.status if job is not None else None,
        "job_last_error": job.last_error if job is not None else None,
        "proposed_finding": proposal.proposed_finding,
        "rollup_rationale": proposal.rollup_rationale,
        "objectives_total": proposal.objectives_total,
        "objectives_evaluated": proposal.objectives_evaluated,
        "dissent_count": proposal.dissent_count,
        "objectives": objectives_out,
    }
```

- [ ] **Step 4: Run tests, verify gates**

```bash
.venv/bin/pytest tests/test_assessment_dissent_api.py -v          # 3 pass
.venv/bin/pytest tests/test_assessment_engine_api.py -v            # unaffected, still all pass
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** remove `"dissent_count": proposal.dissent_count,` from the returned dict — re-run `test_a_disagreement_is_surfaced_and_counted` — confirm it now fails with `KeyError: 'dissent_count'`. Revert. Remove the two `"challenger_verdict"` / `"challenger_rationale"` keys from `objectives_out` — re-run the same test — confirm it now fails on `objective["challenger_verdict"]`. Revert both.

- [ ] **Step 5: `docs/ARCHITECTURE.md`**

Insert a new bullet immediately after the "Closure & remediation loop" bullet (which ends with `...the repo standard for exactly this GRANT.`) and before `## Schemas`:

```markdown
- **AI dissent path** (`ccf.assessment.engine.evaluate`, `.calibration`,
  `CCF_ASSESSMENT_DISSENT_ENABLED`, migration `0059`): runs an independent
  second model call — a challenger — against a verdict where being wrong is
  expensive. Self-reported `model_confidence` (`AssessmentObjectiveProposal
  .model_confidence`) is a weak error signal on its own: a model confidently
  wrong is exactly the failure the calibration harness above measures after
  the fact, from an assessor's rejection, and the expensive direction is a
  `satisfied` verdict on a control that is not — a missed finding in an
  authorization package. This tries to catch that before an assessor ever
  sees it, without waiting for a rejection to exist.

  **Satisfied-only, named and versioned as a policy**
  (`DISSENT_CHALLENGE_POLICY_VERSION`, currently `"v1"`): only a `satisfied`
  verdict is challenged. Challenging every objective doubles model calls —
  AC-4 alone has 98 — and a `not_satisfied` or `insufficient_evidence`
  verdict is the cheap error direction (wasted remediation effort, or the
  engine already declining to conclude) rather than the expensive one. The
  challenger sees the *same* retrieved passages the primary call saw, never a
  fresh retrieval — contesting which evidence was retrieved is a different
  problem and would confound the measurement.

  **Disagreement is never averaged, majority-voted, or tie-broken.** When the
  challenger reaches a different, cited verdict, the objective's own `verdict`
  column is overwritten to `insufficient_evidence` — a third, neutral outcome
  that is neither reviewer's opinion — and the challenger's own verdict and
  rationale are retained separately on `challenger_verdict` /
  `challenger_rationale`, so the disagreement itself is not destroyed by
  being resolved one way or the other. `insufficient_evidence` already does
  everything this needs with no further code change: the rollup
  (`rollup.py`) already forces the whole control to `insufficient_evidence`
  on any such objective, `accept_control_proposal` already refuses to accept
  it, and the calibration harness already excludes it from
  `CORRECTED_FINDINGS`. The bar for escalation is any *credible* disagreement
  — a differing verdict with at least one citation — never a confidence
  threshold: gating on the challenger's self-reported confidence would make
  the escalation depend on exactly the signal this slice exists because it
  is not trusted. An **agreeing** challenge is recorded too, not just a
  disagreeing one — `challenger_verdict` populated, the objective's own
  `verdict` unchanged — so "not challenged" (`challenger_verdict IS NULL`)
  stays distinguishable from "challenged and agreed."

  `AssessmentControlProposal.dissent_count` (migration `0059`, `NOT NULL`,
  default `0`, reset to `0` at the top of every `evaluate_control_proposal`
  rerun) counts how many of a control's objectives were contested, so a
  reviewer sees it without a join; `GET /api/assessment-engine/proposals/
  {id}` surfaces it alongside each objective's `challenger_verdict` /
  `challenger_rationale`. The three challenger columns on
  `assessment_objective_proposals` are all nullable, all `NULL` for an
  un-challenged objective by design (never a sentinel), and
  `challenger_ai_action_run_id` is a `NULL`-on-delete FK to
  `ai_action_runs.id` — the challenger's own call is recorded through
  `ccf.ai_actions.provenance.record_ai_run` under its own
  `action_key="challenge_assessment_objective"`, exactly like the primary
  verdict's own recording, and deliberately not through the approval-gated
  `run_action`, for the same reasons the primary evaluation isn't (see
  "Objective-level assessment engine" above).

  **Failure isolation.** A challenger failure — a provider error, a timeout,
  a malformed response — must never fail the evaluation: the primary verdict
  is the deliverable, the challenge is an enhancement. The challenger call
  runs inside its own `begin_nested()` savepoint, nested one level deeper
  than the per-objective savepoint `ccf.assessment.engine.service` already
  wraps each objective's evaluation in, and a bare `except Exception` — never
  a manual `session.rollback()`, which is not savepoint-scoped and would
  unwind the caller's already-good primary verdict, the same trap
  `record_ai_run` itself guards against — leaves the objective with its
  primary verdict, `NULL` challenger columns, and a warning log
  (`assessment.challenger_failed`). A `NULL` `challenger_verdict` therefore
  means either "not challenged" or "challenged, but the challenge failed" —
  the two are distinguishable only in the logs, never from this column
  alone.

  **`CCF_ASSESSMENT_DISSENT_ENABLED`** defaults to `false`: like the prep and
  assessment engines above, this spends real money on model calls, doubling
  them on the passing subset, and a deployment must opt in. With it unset,
  `evaluate_objective` never attempts a second call regardless of verdict.
  Enabling it **changes what calibration is measuring**, exactly as much as
  `prep_screen_threshold`, the rollup policy, or the model name do:
  `ccf.assessment.engine.calibration.config_fingerprint` folds in both
  `CCF_ASSESSMENT_DISSENT_ENABLED` and `DISSENT_CHALLENGE_POLICY_VERSION`, so
  toggling dissent between two snapshots makes `compare_snapshots` report
  `{"comparable": false, ...}` rather than an unexplained shift in
  `missed_findings` — this is in fact how the slice is meant to be evaluated:
  the calibration harness answers whether dissent actually reduces missed
  findings, or only throughput. Not retrofitted: objectives evaluated before
  this slice, and any objective evaluated with the flag off, carry no
  dissent record at all.
```

- [ ] **Step 6: `README.md`**

Insert a new bullet immediately after the `CCF_ASSESSMENT_ENGINE_ENABLED` bullet (which ends `...all deliberately out of scope for this slice.`) and before `## Security posture`:

```markdown
- `CCF_ASSESSMENT_DISSENT_ENABLED` — run an independent second model call (a
  "challenger") against a `satisfied` verdict before an assessor ever sees
  it; **disabled by default**, same reasoning as the other AI-call flags
  above: this doubles model calls on the passing subset, and a deployment
  must opt into that cost. Only `satisfied` is ever challenged — the
  expensive error direction is a control passing that should not, not the
  reverse — and the challenger sees the exact same retrieved passages the
  primary call saw, never a fresh retrieval. A challenger that reaches a
  different, cited verdict flips the objective to `insufficient_evidence`
  (never averaged, majority-voted, or tie-broken toward either side) and
  increments `AssessmentControlProposal.dissent_count`; one contested
  objective is enough to force the whole control's rollup to
  `insufficient_evidence`, which `accept_control_proposal` already refuses.
  Both verdicts are retained — `AssessmentObjectiveProposal.challenger_verdict`
  / `.challenger_rationale` — surfaced on `GET /api/assessment-engine/
  proposals/{id}` alongside each objective. A challenger failure (provider
  error, timeout, malformed response) never fails the evaluation: the
  primary verdict persists, the challenger columns stay `NULL`, and a
  warning is logged — a `NULL` `challenger_verdict` means either "not
  challenged" or "challenged but failed," distinguishable only in the logs.
  Toggling this flag changes what the calibration harness above is
  measuring, so `config_fingerprint` folds it in (plus
  `DISSENT_CHALLENGE_POLICY_VERSION`, naming the "satisfied only" policy so
  a later change to which verdicts get challenged is visible too) — two
  snapshots taken with the flag toggled between them compare as **not
  comparable**, not drift. Not retrofitted: objectives evaluated before this
  slice, or with the flag off, carry no dissent record. Migration `0059`
  adds the four new columns (three nullable challenger columns on
  `assessment_objective_proposals`, `dissent_count` `NOT NULL default 0` on
  `assessment_control_proposals`); see `docs/ARCHITECTURE.md`'s "AI dissent
  path" for the full reasoning.
```

- [ ] **Step 7: `CHANGELOG.md`**

Add a new `### Added — AI dissent path` section as the first entry under `## [Unreleased]`, above the existing `### Added — closure & remediation loop` section:

```markdown
### Added — AI dissent path
- **A `satisfied` verdict can now be challenged** by an independent second
  model call before an assessor ever sees it (`CCF_ASSESSMENT_DISSENT_ENABLED`,
  **disabled by default**). Only `satisfied` is challenged — the expensive
  error direction is a missed finding, not a false alarm — and the
  challenger sees the exact same retrieved passages the primary call saw,
  never a fresh retrieval.
- **Disagreement is never averaged, majority-voted, or tie-broken.** A
  challenger reaching a different, cited verdict flips the objective to
  `insufficient_evidence` (both verdicts retained on
  `AssessmentObjectiveProposal.challenger_verdict` /
  `.challenger_rationale`) and increments
  `AssessmentControlProposal.dissent_count`; the existing rollup already
  forces the whole control to `insufficient_evidence` on any such objective,
  and `accept_control_proposal` already refuses to accept it — no rollup
  code change required. The bar is any *credible* disagreement — a differing
  verdict with at least one citation — never a confidence threshold.
- **Failure isolation:** a challenger failure (provider error, timeout,
  malformed response) never fails the evaluation — the primary verdict
  persists, the challenger columns stay `NULL`, and a warning is logged.
  Runs inside its own `begin_nested()` savepoint, nested inside the
  per-objective savepoint the evaluation already uses.
- **Migration `0059`** adds `dissent_count` (`NOT NULL`, default `0`) to
  `assessment_control_proposals` and three nullable columns —
  `challenger_verdict`, `challenger_rationale`, `challenger_ai_action_run_id`
  (`FK -> ai_action_runs.id`, `ON DELETE SET NULL`) — to
  `assessment_objective_proposals`. Recorded through
  `ccf.ai_actions.provenance.record_ai_run` under its own
  `action_key="challenge_assessment_objective"`, the same pipeline-provenance
  path the primary verdict uses, not the approval-gated `run_action`.
- **Calibration is fingerprint-aware of dissent:** `config_fingerprint` now
  folds in `CCF_ASSESSMENT_DISSENT_ENABLED` and
  `DISSENT_CHALLENGE_POLICY_VERSION` (naming and versioning the
  "satisfied-only" policy), so two snapshots taken with dissent toggled
  between them compare as **not comparable**, never as an unexplained shift
  in `missed_findings`. This is how the slice gets evaluated: the
  calibration harness answers whether dissent reduces missed findings, or
  only throughput.
- `GET /api/assessment-engine/proposals/{id}` surfaces `dissent_count` on
  the proposal and `challenger_verdict` / `challenger_rationale` on each
  objective.
- Not retrofitted: objectives evaluated before this slice, or with the flag
  off, carry no dissent record — a `NULL` `challenger_verdict` means either
  "not challenged" or "challenged but the challenge itself failed,"
  distinguishable only in the logs (`assessment.challenger_failed`), never
  from this column alone.
```

- [ ] **Step 8: Verify and commit**

```bash
.venv/bin/pytest -q          # run alone; confirm the count and cite it in the commit if it moved
git add src/ccf/api/routes/assessment_engine.py tests/test_assessment_dissent_api.py \
        docs/ARCHITECTURE.md README.md CHANGELOG.md
git commit -m "docs(assessment): surface the AI dissent path and document it"
```

---

## Deferred, deliberately

- **No voting, no averaging, no tie-breaking third call.** Two verdicts are never reduced to one by consensus — a disagreement routes to `insufficient_evidence`, a neutral third outcome, never to whichever of the two verdicts a heuristic favors.
- **No new refusal state.** Disagreement reuses the existing `insufficient_evidence` — no schema change to the verdict vocabulary, no new gate for `accept_control_proposal` or the rollup to learn.
- **No challenge of the retrieval step.** The challenger sees the same citations the primary saw; contesting *which* evidence was retrieved is a different problem and would confound the measurement.
- **No retrofit.** Objectives evaluated before this slice, or evaluated with `CCF_ASSESSMENT_DISSENT_ENABLED` off, carry no dissent record — nothing backfills a challenge that never ran.
- **No automatic threshold tuning, no CI gate on a metric change.** The calibration harness (already built, this slice only extends its fingerprint) measures whether dissent helps; a human decides what to do with that measurement.

The standing debt list this slice does not close: `prep_screen_threshold`'s narrow ~0.03 margin; base-control collapse meaning enhancements are never individually cited; re-preparation duplicating passages across runs; scanned-PDF pages skipped without a persisted marker; `AssessmentJob` enqueue de-duplication wanting a partial unique index; migrations `0057` and `0058` still missing the `pg_roles` GRANT guard (`0059` carries it, per this slice's own constraint, but does not retrofit the two before it); and the two unreconciled legacy POA&M-from-findings paths, one of which still dedupes on title alone.
