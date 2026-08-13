# RLS Coverage for the Engine Tables — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 110 of the 135 tables in the `ccf` schema carry a `tenant_isolation` row-level-security policy. Eleven do not — `prep_runs`, `prep_lines`, `prep_screens`, `prep_units`, `prep_classifications`, `prep_embeddings`, `prep_jobs`, `assessment_jobs`, `calibration_snapshots`, `assessment_control_proposals`, `assessment_objective_proposals` — every one of them tenant data slices 1–6 built with no database backstop, sitting directly beside tables (`assessment_control_results`, `poams`, `evidence`) that have one. Not because a leak is known to exist — application-level checks are present and mutation-tested — but because of what happened while building those checks: three endpoints leaked cross-tenant by trusting a body field, one laundered through a foreign-key id belonging to another organization, and in slice 5 an app-level organization check turned out to be passing its test only because RLS filtered the row first, so the check itself was never exercised. On an RLS-backed table a forgotten filter is contained by Postgres; on these eleven, nothing contains it.

**The DDL is trivial. The verification is the slice.** `current_tenant() IS NULL` means *unrestricted* — a botched job yields a policy that exists, reports as enabled, and filters nothing, which is worse than not doing the work because it retires the concern without addressing it. Two independent routes produce that silent no-op: a missing `FORCE ROW LEVEL SECURITY` (the table's owner, role `ccf`, bypasses its own policies unless forced — checked live: all 135 `ccf` tables are owned by `ccf`, all 110 existing RLS tables are forced), or a code path that never sets the tenant GUC. Every test in this plan asserts the thing that actually matters — that org A's session cannot see org B's row, and that `relforcerowsecurity`, not merely `relrowsecurity`, is true — never merely that a policy row exists in `pg_policies`.

**Architecture**, in dependency order:

1. **Migration `0060`** adds `ENABLE`+`FORCE ROW LEVEL SECURITY` and a `tenant_isolation` policy — `USING/WITH CHECK (current_tenant() IS NULL OR organization_id = current_tenant())`, the same predicate and policy name the other 110 use, verified live against `information_schema.columns` to carry `organization_id` directly on all eleven — matching migrations `0020`/`0022`'s exact `FOR ALL USING ... WITH CHECK ...` form (the design doc's own inline SQL sketch omits `WITH CHECK` for brevity; Postgres defaults an unqualified `USING` to the same expression for `WITH CHECK` on a `FOR ALL` policy, but this migration spells it out explicitly to literally match the other 121 policies an operator will read in `pg_policies`, not merely behave equivalently to them). Every one of the eleven gets a parametrized structural test (`relrowsecurity` **and** `relforcerowsecurity`, plus the policy's presence) and a parametrized behavioral test (org A's session, with the tenant GUC actually set, cannot see org B's row on that exact table) — parametrized so a twelfth table added later without a policy fails the *same* test, not a new one. `tests/test_rls_coverage.py`'s existing hardcoded snapshot (110 tables) is updated to 121 in the same task, since it would otherwise fail the moment `0060` ships.
2. **The GUC audit** (open question in the design, closed here by reading the code and asserting on it): every API route uses `Depends(get_session)` (`ccf.api.deps`), which sets the tenant GUC from the authenticated principal. Every CLI command and both worker drain loops (`ccf prep-worker`, `ccf assessment-worker`) use `ccf.db.session_scope()`, which **always** calls `set_session_tenant(session, None)` — `RESET ROLE` plus a cleared `ccf.tenant_id` GUC, the bootstrap role `ccf` (a superuser) staying in effect. This is not a bug to fix: `models_prep.py` and `models_assessment_engine.py` already document it as deliberate — one worker process drains every organization's queued jobs by design, and `ccf.queue.claim_jobs` has no organization filter on purpose. What is missing is a *direct* test of the mechanism itself (not just its downstream effect, which `tests/test_prep_tenant_isolation.py` and `tests/test_assessment_engine_api.py`'s `..._indep_of_rls` test already cover for the laundering/read-leak attack vectors) — so a future change that accidentally scopes `session_scope()` is caught here rather than silently orphaning every other organization's queued jobs the moment `0060`'s `FORCE RLS` starts actually restricting something. The two model modules' "no RLS, deliberate" docstrings are corrected to "has RLS via `0060`, worker deliberately bypasses it" in this task, since after Task 1 they are simply false.
3. **The registry test** — distinct from Task 1's hardcoded-snapshot regression guard — is a live, structural query over `information_schema.columns` and `pg_policy`: the set of `ccf` tables carrying `organization_id` with no `tenant_isolation` policy must be empty, and the set of tables with neither must equal an explicit, named 14-table allow-list (verified live: `controls`, `frameworks`, `control_families`, `framework_mappings`, `worksheets`, `worksheet_rows`, `ingestion_runs`, `catalog_sources`, `catalog_checks`, `scoring_controls`, `statement_templates`, `ksis`, `ai_action_definitions`, `alembic_version` — none carry `organization_id`). This is the test that stops the gap reopening: every future slice adding a tenant-owned table fails it until a policy is written, with no dependency on anyone remembering to touch a hardcoded set.
4. **Documentation** — `docs/ARCHITECTURE.md`'s "Evidence preparation" and "Objective-level assessment engine" sections currently state the eleven tables "deliberately carry no row-level-security policies"; both are corrected to state they now carry `tenant_isolation`, that the worker's own claim path remains an intentional, named bypass, and that RLS here is defence in depth — the application-level checks remain the primary, tested control, so no future reader deletes one believing the other suffices. `CHANGELOG.md` records the hardening.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Alembic, Postgres 16, FastAPI, pytest.

**Spec:** [docs/superpowers/specs/2026-08-12-rls-coverage-design.md](../specs/2026-08-12-rls-coverage-design.md)
**Depends on:** slices 1–6, all on `feat/evidence-prep-spine`.

## Global Constraints

- **Python** 3.12, `line-length = 100`. **Ruff** selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected, so a `# noqa: BLE001` or `# noqa: SLF001` trips `RUF100` (unused noqa) — don't add one. `PLC0415` means imports go at module top level, never inside a function body. `RUF059` means an unused unpacked variable gets a leading underscore (e.g. `_exc`), not a bare unused name. Known baseline: **exactly 25 pre-existing `PLR0917`**; this slice adds no new function with more than five positional parameters, so it should add nothing to that count.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** `from ...logging import get_logger` (adjust the relative depth per module); never `import structlog` directly; never `extra={...}` — it collides with reserved `LogRecord` attributes and raises `KeyError`. Pass plain kwargs to the logger call instead. This slice adds no new logging call sites of its own (Task 2 reads and confirms existing ones), so this constraint governs only what must not regress.
- **Tests:** real Postgres on port **5434**, container `ccf-test-db`. `asyncio_mode = "auto"` in `pytest.ini` — never write `@pytest.mark.asyncio`. DB-touching test modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`. `fresh_engine` (see `tests/conftest.py`) is **function-scoped** — it disposes and rebuilds the SQLAlchemy engine after every test so each test gets a fresh engine on its own event loop, but it does **not** truncate data — so every RLS test below seeds its own uniquely-named throwaway orgs/rows per test function, the same convention `tests/test_rls_coverage.py` already uses, rather than relying on a shared module-scoped async fixture (which would bind to a since-disposed event loop). **Never run two pytest sessions concurrently** — the session fixture drops and recreates the schema. **Always run pytest in the foreground** — a past implementer backgrounded a long test run, it stalled, and the branch was left uncommitted; do not background it. Venv binaries only: `.venv/bin/pytest`, `.venv/bin/alembic`, `.venv/bin/ruff`, `.venv/bin/mypy` — never bare `python3` (system Python is 3.9). **Baseline: 948 passed, 1 skipped.** `test_assessment_closure_trigger.py` is known to leave `pending` `AssessmentJob` rows across test runs — Task 2's worker-claim tests seed and claim their own uniquely-named jobs and assert by id, never by a bare table count, so this pollution cannot affect them.
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — a `SELECT` issued while a pending `add()` is unflushed sees nothing. Flush explicitly before any such read. Every seed helper below flushes after each `add`/`add_all` before using the assigned ids.
- **Migrations:** `migrations/versions/00NN_<slug>.py`, explicit `revision`/`down_revision`. **Current head is `0059_ai_dissent_path`**; this slice adds `0060_engine_rls_coverage`. **`0060` must carry the `IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app')` guard** that migration `0054` establishes as this repo's standard for the blanket `GRANT` — migrations `0057` and `0058` both omitted it and that omission stays on the standing debt list; this slice does not fix those two, but must not add a third instance of the same omission. `downgrade()` must fully reverse `upgrade()` and round-trip: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`.
- **RLS mechanics (this slice's own domain, stated once here since every task depends on it):** `ccf.current_tenant()` is a `STABLE` SQL function reading the `ccf.tenant_id` GUC; `NULL` means unrestricted. A table's owner (role `ccf`, confirmed live via `\du`/`pg_class.relowner` — a superuser besides) bypasses its own RLS policies unless the table carries `FORCE ROW LEVEL SECURITY` — checked live, not assumed: **both** `relrowsecurity` and `relforcerowsecurity` must be asserted, never `relrowsecurity` alone, since only the pair is meaningful. `ccf.db.set_session_tenant` is what binds the GUC: given a real `tenant_id` it sets `ccf.tenant_id` and `SET ROLE ccf_app` (the non-owning role RLS actually restricts); given `None` it `RESET ROLE`s and clears the GUC, which every policy here treats as bypass. `ccf.api.deps.get_session` calls it with the authenticated principal's org; `ccf.db.session_scope()` (every CLI command, both worker drain loops) always calls it with `None`.
- **Mutation discipline:** every guard gets its own assertion, verified by mutation — break the specific line (drop a policy, remove `FORCE`, make `session_scope()` scope itself), re-run the specific test, confirm it fails for the reason expected, then revert. A subtler trap: a best-effort `except Exception` handler makes "skipped correctly" and "raised and was swallowed" indistinguishable to a test that only asserts the absence of a side effect — no handler of that shape is added by this slice, but Task 2's mutation check on `resolve_source_organization_id`'s app-level guard is exactly this class of check applied to *existing* code, to prove the app-level guard — not RLS, which cannot help on an unscoped worker session — is what is actually being tested.
- **Asymmetric fixtures:** wherever a bug could swap two values undetected (org A's row id and org B's row id, org A's content and org B's content), the test fixture uses two *different*, distinguishable values, never the same value or a same-shaped placeholder twice. Every seed helper below tags org A and org B's rows with different literal content strings for exactly this reason.
- **No removal of any application-level org check.** This slice is defence in depth, not a replacement — `resolve_source_organization_id`'s ownership check, `_assessment_organization_id`'s comparison, and every other existing app-level guard on these eleven tables stay exactly as they are.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot project.

## File structure

| File | Responsibility |
|---|---|
| `migrations/versions/0060_engine_rls_coverage.py` | `ENABLE`+`FORCE ROW LEVEL SECURITY` + `tenant_isolation` policy on all eleven tables, guarded `GRANT` |
| `tests/test_rls_engine_tables.py` | Structural (`relrowsecurity`+`relforcerowsecurity`+policy present) and behavioral (org A cannot see org B's row) tests, parametrized over the eleven |
| `tests/test_rls_coverage.py` | `EXPECTED_TENANT_ISOLATION_TABLES` snapshot updated 110 → 121 |
| `src/ccf/models_prep.py`, `src/ccf/models_assessment_engine.py` | "No RLS, deliberate" module docstrings corrected to "has RLS via 0060, worker deliberately bypasses it" |
| `tests/test_rls_worker_guc_bypass.py` | Direct assertion that `session_scope()` leaves the tenant GUC unset and the bootstrap role in effect; both workers' claim queries still see every organization's jobs after `0060` |
| `tests/test_rls_registry_no_gap.py` | Live structural registry test: no `organization_id`-carrying table lacks a policy; the allow-list of tables with neither is named and closed |
| `docs/ARCHITECTURE.md`, `CHANGELOG.md` | Coverage statement, the 14-table allow-list with reasons, the worker-bypass exception, and the hardening entry |

---

### Task 1: Migration `0060` and the per-table structural + behavioral tests

**Files:**
- Create: `migrations/versions/0060_engine_rls_coverage.py`
- Create: `tests/test_rls_engine_tables.py`
- Modify: `tests/test_rls_coverage.py`

**Interfaces:**
- Produces: `tenant_isolation` RLS policies, `ENABLE`+`FORCE ROW LEVEL SECURITY`, on `prep_runs`, `prep_lines`, `prep_screens`, `prep_units`, `prep_classifications`, `prep_embeddings`, `prep_jobs`, `assessment_jobs`, `calibration_snapshots`, `assessment_control_proposals`, `assessment_objective_proposals`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_rls_engine_tables.py`:

```python
"""Structural + behavioral RLS coverage for the eleven engine tables slices
1-6 built without it -- migration 0060 (2026-08-12 RLS-coverage design).

`current_tenant() IS NULL` means *unrestricted*. The failure mode this module
exists to catch is not an outage -- it is a policy that exists, reports as
enabled, and filters nothing, because FORCE was omitted (the table's owner,
role `ccf`, bypasses its own policy without it) or because the session under
test never had the tenant GUC set. So every table gets two independent
assertions, not one:

1. STRUCTURAL: `relrowsecurity` AND `relforcerowsecurity` are both true, and
   a `tenant_isolation` row exists in `pg_policy` for that table. Asserting
   `relrowsecurity` alone would pass on a table an operator could still read
   in full as the owning role -- the two columns are separate and only the
   pair is meaningful (see the design doc's "Ownership and FORCE" section).
2. BEHAVIORAL: with the tenant GUC actually set to org A (via
   `ccf.db.set_session_tenant`, the same call `ccf.api.deps.get_session`
   makes on every real request), org B's row is invisible -- both from a
   list query and from a direct fetch by id. Asserted against a *scoped*
   session, never the bootstrap session `session_scope()` opens by default,
   which every policy here treats as bypass and would make this assertion
   vacuous.

Parametrized over the eleven so a twelfth table added later without a policy
is caught by the same test, not a new one -- see also
tests/test_rls_registry_no_gap.py, which catches the same gap from the
schema side (no organization_id-carrying table lacking a policy) rather than
this module's enumerated side.

`_seed_chain` builds one full chain per organization -- prep_runs through
prep_embeddings/prep_jobs, and the assessment_control_proposals through
assessment_jobs chain, plus a standalone calibration_snapshots row -- so
every one of the eleven tables gets a real row per org in one call. Content
strings differ between org A and org B (asymmetric fixtures): a bug that
swapped which org's id was checked would otherwise be invisible.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text

from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import (
    AssessmentControlProposal,
    AssessmentJob,
    AssessmentObjectiveProposal,
    CalibrationSnapshot,
)
from ccf.models_prep import (
    PrepClassification,
    PrepEmbedding,
    PrepJob,
    PrepLine,
    PrepRun,
    PrepScreen,
    PrepUnit,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


ENGINE_TABLES: tuple[str, ...] = (
    "prep_runs",
    "prep_lines",
    "prep_screens",
    "prep_units",
    "prep_classifications",
    "prep_embeddings",
    "prep_jobs",
    "assessment_control_proposals",
    "assessment_objective_proposals",
    "assessment_jobs",
    "calibration_snapshots",
)

_MODEL_BY_TABLE: dict[str, type] = {
    "prep_runs": PrepRun,
    "prep_lines": PrepLine,
    "prep_screens": PrepScreen,
    "prep_units": PrepUnit,
    "prep_classifications": PrepClassification,
    "prep_embeddings": PrepEmbedding,
    "prep_jobs": PrepJob,
    "assessment_control_proposals": AssessmentControlProposal,
    "assessment_objective_proposals": AssessmentObjectiveProposal,
    "assessment_jobs": AssessmentJob,
    "calibration_snapshots": CalibrationSnapshot,
}


async def _seed_chain(tag: str) -> tuple[int, dict[str, int]]:
    """One full chain across all eleven tables for a fresh throwaway org
    tagged ``tag`` ("A" or "B") -- content and identifiers differ between
    tags so a swap bug is never silently undetectable.
    """
    async with session_scope() as s:  # bootstrap role -- unscoped, full access
        org = Organization(name=f"RlsEngineOrg{tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"RlsEngineSys{tag}")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"RlsEngineAssess{tag}", kind="self")
        s.add(assessment)
        await s.flush()

        run = PrepRun(organization_id=org.id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()

        line = PrepLine(
            run_id=run.id,
            organization_id=org.id,
            line_number=1,
            content=f"Engine RLS line content, organization {tag}.",
        )
        s.add(line)
        await s.flush()

        screen = PrepScreen(line_id=line.id, run_id=run.id, organization_id=org.id)
        unit = PrepUnit(
            run_id=run.id,
            organization_id=org.id,
            trigger_line_id=line.id,
            content=f"Engine RLS unit content, organization {tag}.",
        )
        s.add_all([screen, unit])
        await s.flush()

        classification = PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org.id)
        embedding = PrepEmbedding(
            unit_id=unit.id, run_id=run.id, organization_id=org.id, model_name="rls-test-model"
        )
        job = PrepJob(run_id=run.id, organization_id=org.id)
        s.add_all([classification, embedding, job])
        await s.flush()

        control_proposal = AssessmentControlProposal(
            organization_id=org.id, assessment_id=assessment.id, control_identifier=f"AC-{tag}"
        )
        s.add(control_proposal)
        await s.flush()

        objective_proposal = AssessmentObjectiveProposal(
            organization_id=org.id,
            control_proposal_id=control_proposal.id,
            label=f"AC-2{tag.lower()}",
            objective_text=f"Objective text, organization {tag}.",
            objective_text_sha256=("a" if tag == "A" else "b") * 64,
        )
        assessment_job = AssessmentJob(
            organization_id=org.id, control_proposal_id=control_proposal.id
        )
        calibration = CalibrationSnapshot(
            organization_id=org.id, config_fingerprint=("11" if tag == "A" else "22") * 4
        )
        s.add_all([objective_proposal, assessment_job, calibration])
        await s.flush()

        return int(org.id), {
            "prep_runs": int(run.id),
            "prep_lines": int(line.id),
            "prep_screens": int(screen.id),
            "prep_units": int(unit.id),
            "prep_classifications": int(classification.id),
            "prep_embeddings": int(embedding.id),
            "prep_jobs": int(job.id),
            "assessment_control_proposals": int(control_proposal.id),
            "assessment_objective_proposals": int(objective_proposal.id),
            "assessment_jobs": int(assessment_job.id),
            "calibration_snapshots": int(calibration.id),
        }


@pytest.mark.parametrize("table", ENGINE_TABLES)
async def test_engine_table_rls_enabled_and_forced(table: str) -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        row = (
            await s.execute(
                text(
                    "SELECT c.relrowsecurity, c.relforcerowsecurity, "
                    "EXISTS(SELECT 1 FROM pg_policy p JOIN pg_class pc ON pc.oid = p.polrelid "
                    "  WHERE pc.relname = :t AND p.polname = 'tenant_isolation') AS has_policy "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'ccf' AND c.relname = :t"
                ),
                {"t": table},
            )
        ).one()
    assert row.relrowsecurity is True, f"ccf.{table}: ROW LEVEL SECURITY is not ENABLED"
    assert row.relforcerowsecurity is True, f"ccf.{table}: ROW LEVEL SECURITY is not FORCED"
    assert row.has_policy is True, f"ccf.{table}: tenant_isolation policy is missing"


@pytest.mark.parametrize("table", ENGINE_TABLES)
async def test_engine_table_scopes_to_owning_org(table: str) -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, ids_a = await _seed_chain("A")
    org_b, ids_b = await _seed_chain("B")
    model = _MODEL_BY_TABLE[table]
    id_a, id_b = ids_a[table], ids_b[table]

    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        visible = (await s.execute(select(model.id))).scalars().all()  # type: ignore[attr-defined]
        assert id_a in visible, f"{table}: org A cannot see its own row"
        assert id_b not in visible, f"{table}: org A can see org B's row"
        direct = (
            await s.execute(select(model).where(model.id == id_b))  # type: ignore[attr-defined]
        ).scalar_one_or_none()
        assert direct is None, f"{table}: direct fetch of org B's row by id succeeded under org A"

    async with session_scope() as s:
        await set_session_tenant(s, org_b)
        visible = (await s.execute(select(model.id))).scalars().all()  # type: ignore[attr-defined]
        assert id_b in visible, f"{table}: org B cannot see its own row"
        assert id_a not in visible, f"{table}: org B can see org A's row"
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `.venv/bin/pytest tests/test_rls_engine_tables.py -v`
Expected: FAIL — every `test_engine_table_rls_enabled_and_forced[...]` case fails on `assert row.relrowsecurity is True` (currently `False`), and every `test_engine_table_scopes_to_owning_org[...]` case fails on `assert id_b not in visible` (the unscoped-by-default table hides nothing).

- [ ] **Step 3: Write the migration**

Create `migrations/versions/0060_engine_rls_coverage.py`:

```python
"""RLS coverage for the eleven engine tables slices 1-6 built without it.

110 of the 135 tables in the ccf schema carry a tenant_isolation policy.
prep_runs, prep_lines, prep_screens, prep_units, prep_classifications,
prep_embeddings, prep_jobs, assessment_jobs, calibration_snapshots,
assessment_control_proposals, and assessment_objective_proposals do not --
every one of them tenant data with no database backstop, sitting directly
beside tables (assessment_control_results, poams, evidence) that have one.
All eleven carry organization_id directly (verified against
information_schema.columns), so none needs the parent-join derivation poams
(system_id -> systems.organization_id) or assessment_control_results
(assessment_id -> assessments -> systems) use -- the policy is the simplest
form in the codebase, identical predicate and policy name to the other 110
(see e.g. migrations 0020, 0022): `current_tenant() IS NULL OR
organization_id = current_tenant()`. `current_tenant() IS NULL` means
*unrestricted* -- CLI/ETL/migrations/global principals stay unaffected, the
same semantics every existing RLS-backed table already uses.

FORCE is required, not optional: the owning role (`ccf`) bypasses its own
policy without it, which would produce a policy that exists, reports as
enabled, and is bypassed on exactly the connections the application uses --
checked live, not assumed: all 135 ccf tables are owned by role `ccf`, and
all 110 pre-existing RLS tables already carry FORCE.

See docs/superpowers/specs/2026-08-12-rls-coverage-design.md for the full
reasoning, including why the eleven tables' worker/CLI code paths are left
deliberately unscoped by session_scope() rather than fixed here (Task 2 of
the implementation plan audits and documents that as a named exception, not
a gap this migration needs to close).

Revision ID: 0060_engine_rls_coverage
Revises: 0059_ai_dissent_path
Create Date: 2026-08-12
"""

from __future__ import annotations

from alembic import op

revision = "0060_engine_rls_coverage"
down_revision = "0059_ai_dissent_path"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"

#: Every table verified live to carry organization_id directly and no
#: tenant_isolation policy as of this writing (see the design doc's "The
#: policy" section). Order is alphabetical within the prep chain then the
#: assessment-engine chain, matching models_prep.py / models_assessment_engine.py.
TENANT_TABLES: tuple[str, ...] = (
    "prep_runs",
    "prep_lines",
    "prep_screens",
    "prep_units",
    "prep_classifications",
    "prep_embeddings",
    "prep_jobs",
    "assessment_control_proposals",
    "assessment_objective_proposals",
    "assessment_jobs",
    "calibration_snapshots",
)

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"


def upgrade() -> None:
    # Matches 0054's exact block (the repo standard 0057 and 0058 both
    # omitted): a no-op if ccf_app doesn't exist in this environment (e.g. a
    # dev DB that never split roles), and otherwise ensures every table in
    # the schema is usable by the scoped application role regardless of
    # which role actually ran the migrations.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.execute(f"ALTER TABLE ccf.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} DISABLE ROW LEVEL SECURITY")
    # The GRANT is intentionally not reversed -- every prior migration that
    # re-issues it does the same (see 0037, 0054), since revoking a blanket
    # grant on downgrade could strand other, unrelated tables whose own
    # migrations already ran and still need it.
```

- [ ] **Step 4: Round-trip the migration**

Run: `.venv/bin/alembic upgrade head && .venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`
Expected: all three commands succeed; `.venv/bin/alembic heads` reports `0060_engine_rls_coverage (head)` afterward.

- [ ] **Step 5: Update the existing 110-table snapshot to 121**

`tests/test_rls_coverage.py`'s `test_rls_policy_structural_guard` enumerates every `tenant_isolation` policy live from `pg_policy` and compares it against a hardcoded `EXPECTED_TENANT_ISOLATION_TABLES` snapshot — after `0060`, that snapshot is 11 tables short and the test's `unexpected` assertion fails. Update the docstring's point 1 and the frozenset:

In `tests/test_rls_coverage.py`, change:
```python
   110 tables spanning migrations 0010 through 0046) — so the test fails loudly if a table's policy is
```
to:
```python
   121 tables spanning migrations 0010 through 0060) — so the test fails loudly if a table's policy is
```

Add the eleven names into `EXPECTED_TENANT_ISOLATION_TABLES` (alphabetized into the existing frozenset, matching its own ordering convention) and change the trailing count assertion:
```python
    assert len(found) == len(EXPECTED_TENANT_ISOLATION_TABLES) == 110
```
to:
```python
    assert len(found) == len(EXPECTED_TENANT_ISOLATION_TABLES) == 121
```

The eleven additions land alphabetically as: `assessment_control_proposals` (after `artifacts`), `assessment_jobs` (after `assessment_control_results`), `assessment_objective_proposals` (after `assessment_jobs`... but before `assessment_results` alphabetically — insert accordingly), `calibration_snapshots` (after `authorization_packages`, before `capture_snapshots`), `prep_classifications`, `prep_embeddings`, `prep_jobs`, `prep_lines`, `prep_runs`, `prep_screens`, `prep_units` (as a contiguous alphabetical block after `policy_versions`, before `questionnaire_responses`).

- [ ] **Step 6: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_rls_engine_tables.py tests/test_rls_coverage.py -v   # 25 pass (22 parametrized + 3 existing)
.venv/bin/pytest -q          # run alone, foreground; confirm 970 passed, 1 skipped (948 baseline + 22 new parametrized cases) -- cite the actual count in the commit if it differs
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check:** in the migration, comment out the `op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")` line, round-trip a fresh test database (`.venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`), re-run `tests/test_rls_engine_tables.py -k test_engine_table_rls_enabled_and_forced` — confirm every case now fails on `relforcerowsecurity`. Revert, round-trip again to restore. Separately: comment out one table's `CREATE POLICY` block entirely (e.g. `prep_jobs`), round-trip, re-run both parametrized tests filtered to `-k prep_jobs` — confirm both fail (`has_policy` false; `id_b in visible` — the bootstrap-owner-without-FORCE case and the no-policy-at-all case are different failures, and this confirms the test distinguishes neither by accident). Revert, round-trip again.

```bash
git add migrations/versions/0060_engine_rls_coverage.py \
        tests/test_rls_engine_tables.py \
        tests/test_rls_coverage.py
git commit -m "feat(db): add RLS coverage for the eleven engine tables (migration 0060)"
```

---

### Task 2: The GUC audit — worker/CLI paths, and correcting the stale "no RLS" docstrings

**Files:**
- Create: `tests/test_rls_worker_guc_bypass.py`
- Modify: `src/ccf/models_prep.py`
- Modify: `src/ccf/models_assessment_engine.py`

**Interfaces:**
- Consumes: `ccf.db.session_scope`, `ccf.db.set_session_tenant`, `ccf.prep.jobs.claim`, `ccf.queue.claim_jobs`. No new production interfaces — this task is verification and documentation of behavior Task 1's migration does not change.

- [ ] **Step 1: Read and confirm the worker/CLI paths (no code change yet)**

Confirm, by reading, that every write/read path touching the eleven tables outside the API runs through `session_scope()`:
- `src/ccf/cli.py`: every `@app.command` (including `prep-worker` at line 376, `assessment-worker` at line 448, `calibration-snapshot` at line 475) opens its session via `async with session_scope() as session:` — grep confirms **zero** uses of `Depends(get_session)` or manual `set_session_tenant(session, <non-None>)` anywhere in this file.
- `src/ccf/prep/jobs.py::claim` and `src/ccf/queue.py::claim_jobs` (the shared primitive both `PrepJob` and `AssessmentJob` use) issue `SELECT ... FOR UPDATE SKIP LOCKED WHERE status = 'pending'` with **no** `organization_id` filter — by design, so one worker process drains every organization's queue (see both modules' own docstrings, already explicit about this).
- The application-level guards that stand in RLS's place on these exact paths already exist and are already tested: `ccf.prep.sources.resolve_source_organization_id` + `SourceOwnershipMismatch` (raised by `ccf.prep.jobs.enqueue` before a run is ever opened, covered end-to-end by `tests/test_prep_tenant_isolation.py::test_enqueue_refuses_a_cross_tenant_evidence_version_source_id`), `ccf.prep.pipeline`'s per-stage `organization_id` reconciliation (covered by that same module's two `..._reconciles_organization_id` tests), and `ccf.assessment.engine.jobs.enqueue_reevaluation`'s `result_org_id != organization_id` check (logged as `assessment.reevaluation_org_mismatch` on refusal). Nothing in this task removes or weakens any of them — this step is confirmation, not a code change.

- [ ] **Step 2: Write the mechanism tests**

Create `tests/test_rls_worker_guc_bypass.py`:

```python
"""GUC audit (2026-08-12 RLS-coverage design, Task 2): direct assertions on
the mechanism that makes the worker/CLI paths' unscoped access to the eleven
newly-RLS'd engine tables (migration 0060) deliberate rather than an
oversight.

`ccf.db.session_scope()` -- every CLI command, both worker drain loops
(`ccf prep-worker`, `ccf assessment-worker`) -- always calls
`set_session_tenant(session, None)`: RESET ROLE plus a cleared
`ccf.tenant_id` GUC, leaving the bootstrap role `ccf` (a superuser) in
effect. `current_tenant() IS NULL` is what every tenant_isolation policy in
this schema treats as bypass, by design: one worker process must drain every
organization's queued jobs in a single claim query
(`ccf.queue.claim_jobs`/`ccf.prep.jobs.claim` have no organization_id
filter, intentionally). This is not new to this slice -- `models_prep.py`
and `models_assessment_engine.py` already documented it before migration
0060 existed, when it read as "no RLS at all"; both docstrings are updated
in this same task to say "has RLS via 0060, worker deliberately bypasses
it," since after Task 1 the old wording is simply false.

What was missing before this module: a *direct* assertion on the mechanism
itself, on the exact session type the worker opens, rather than only on its
downstream effect. `tests/test_prep_tenant_isolation.py` and
`tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls`
already prove the *application*-level guards hold even though RLS cannot
help on this session type -- this module is not a duplicate of either; it
instead pins the GUC/role state itself, so a future change that accidentally
scopes `session_scope()` (e.g. it starts calling SET ROLE ccf_app) is caught
here, as a worker silently seeing only one organization's jobs from then on,
rather than discovered later as orphaned queues in every other organization.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob
from ccf.models_prep import PrepJob, PrepRun
from ccf.prep import jobs as prep_jobs
from ccf.queue import claim_jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def test_session_scope_leaves_the_tenant_guc_unset_and_the_bootstrap_role_in_effect() -> (
    None
):
    """Direct assertion on the mechanism, not just its effect: session_scope()
    never sets ccf.tenant_id and never SET ROLEs to ccf_app. It stays on the
    bootstrap `ccf` role, which the eleven tables' new FORCE RLS (migration
    0060) cannot restrict -- a table's owner bypasses its own policy unless
    it queries as a *different*, non-owning role (see the design doc's
    "Ownership and FORCE" section, and Global Constraints' "RLS mechanics").
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        tenant_guc = (
            await s.execute(text("SELECT current_setting('ccf.tenant_id', true)"))
        ).scalar_one()
        role = (await s.execute(text("SELECT current_user"))).scalar_one()
    assert tenant_guc in ("", None), f"session_scope() left ccf.tenant_id={tenant_guc!r}"
    assert role == "ccf", f"session_scope() switched role to {role!r}, expected bootstrap 'ccf'"


async def test_prep_worker_claim_drains_two_organizations_in_one_cycle() -> None:
    """The deliberate cross-tenant behavior, through the real worker entrypoint
    (`prep_jobs.claim`, exactly what `ccf.prep.jobs.run_once` -- and therefore
    `ccf prep-worker` -- calls) on a `session_scope()` session, exactly as the
    CLI opens it. Two organizations' pending jobs are claimed in the same
    call: proof migration 0060's FORCE RLS does not narrow this on the one
    path that would fail loudly (a job silently never claimed, sitting
    `pending` forever) rather than leak.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        org_a = Organization(name="RlsGucWorkerOrgA")
        org_b = Organization(name="RlsGucWorkerOrgB")
        s.add_all([org_a, org_b])
        await s.flush()
        run_a = PrepRun(organization_id=org_a.id, source_kind="evidence_version", source_id=201)
        run_b = PrepRun(organization_id=org_b.id, source_kind="evidence_version", source_id=202)
        s.add_all([run_a, run_b])
        await s.flush()
        job_a = PrepJob(run_id=run_a.id, organization_id=org_a.id, status="pending")
        job_b = PrepJob(run_id=run_b.id, organization_id=org_b.id, status="pending")
        s.add_all([job_a, job_b])
        await s.flush()
        job_a_id, job_b_id = int(job_a.id), int(job_b.id)

    async with session_scope() as s:
        claimed = await prep_jobs.claim(s, worker="rls-guc-audit", limit=10)
        await s.commit()
    claimed_ids = {int(j.id) for j in claimed}
    assert job_a_id in claimed_ids and job_b_id in claimed_ids, (
        "one worker session must claim pending jobs across both organizations in the "
        "same cycle -- claiming only one org's job means FORCE RLS is narrowing the "
        "worker's own claim query, the silent-no-op failure this slice exists to prevent"
    )


async def test_assessment_worker_claim_drains_two_organizations_in_one_cycle() -> None:
    """Mirrors the prep-worker test above for `assessment_jobs`, via
    `ccf.queue.claim_jobs` directly -- `ccf.assessment.engine.jobs` has no
    local `claim` wrapper of its own; `run_once` calls the shared primitive
    inline, so this test does too, matching the real call site exactly.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        org_a = Organization(name="RlsGucAssessOrgA")
        org_b = Organization(name="RlsGucAssessOrgB")
        s.add_all([org_a, org_b])
        await s.flush()
        system_a = System(organization_id=org_a.id, name="RlsGucAssessSysA")
        system_b = System(organization_id=org_b.id, name="RlsGucAssessSysB")
        s.add_all([system_a, system_b])
        await s.flush()
        assessment_a = Assessment(system_id=system_a.id, name="RlsGucAssessA", kind="self")
        assessment_b = Assessment(system_id=system_b.id, name="RlsGucAssessB", kind="self")
        s.add_all([assessment_a, assessment_b])
        await s.flush()
        proposal_a = AssessmentControlProposal(
            organization_id=org_a.id, assessment_id=assessment_a.id, control_identifier="AC-GUC-A"
        )
        proposal_b = AssessmentControlProposal(
            organization_id=org_b.id, assessment_id=assessment_b.id, control_identifier="AC-GUC-B"
        )
        s.add_all([proposal_a, proposal_b])
        await s.flush()
        job_a = AssessmentJob(organization_id=org_a.id, control_proposal_id=proposal_a.id)
        job_b = AssessmentJob(organization_id=org_b.id, control_proposal_id=proposal_b.id)
        s.add_all([job_a, job_b])
        await s.flush()
        job_a_id, job_b_id = int(job_a.id), int(job_b.id)

    async with session_scope() as s:
        claimed = await claim_jobs(s, AssessmentJob, worker="rls-guc-audit", limit=10)
        await s.commit()
    claimed_ids = {int(j.id) for j in claimed}
    assert job_a_id in claimed_ids and job_b_id in claimed_ids, (
        "one assessment-worker session must claim pending jobs across both organizations "
        "in the same cycle -- see the prep-worker version of this test for why"
    )
```

`AssessmentControlProposal.assessment_id` is a real FK — Postgres requires the referenced row to exist — so this seeds a real `Organization` → `System` → `Assessment` chain per org first, the same pattern `tests/test_rls_engine_tables.py::_seed_chain` uses in Task 1.

- [ ] **Step 3: Run the tests to verify they pass against current code**

Run: `.venv/bin/pytest tests/test_rls_worker_guc_bypass.py -v`
Expected: PASS — all three tests, since `session_scope()`'s unscoped behavior and the claim queries' lack of an org filter are both pre-existing, unchanged by Task 1.

- [ ] **Step 4: Correct the stale "no RLS, deliberate" docstrings**

In `src/ccf/models_prep.py`, replace the module docstring's third paragraph:

```python
**These seven tables deliberately carry no row-level-security policies** —
unlike 110 of Concord's 131 ``ccf`` tables, which do. Isolation is
application-layer instead: every prep query filters by ``organization_id``
explicitly (``ccf.prep.retriever._base_filters`` and the equivalent per-stage
filters in ``screen.py``/``expand.py``/``classify.py``/``embed.py``), and
:func:`ccf.prep.jobs.claim` is intentionally unscoped by organization, since
one worker process drains every organization's queued jobs by design. This
exemption from Concord's usual RLS-by-default posture is explicit and
deliberate, not an oversight to be inferred — see ``docs/ARCHITECTURE.md``'s
"Evidence preparation" section for the same note alongside the rest of the
pipeline's description.
```

with:

```python
**These seven tables carry a ``tenant_isolation`` RLS policy** (migration
``0060``, 2026-08-12 RLS-coverage design), matching 121 of Concord's 135
``ccf`` tables. It is defence in depth, not the primary control: every prep
query still filters by ``organization_id`` explicitly
(``ccf.prep.retriever._base_filters`` and the equivalent per-stage filters in
``screen.py``/``expand.py``/``classify.py``/``embed.py``), and those checks
are not removed or relaxed by the policy's addition.
:func:`ccf.prep.jobs.claim` is **intentionally, still, unscoped** by
organization — one worker process drains every organization's queued jobs by
design — which means the RLS policy above provides no protection on that
specific path: ``ccf.prep.jobs.claim`` runs through ``ccf.db.session_scope()``,
which leaves the tenant GUC unset and the bootstrap (table-owning) role in
effect, and an unset GUC is exactly what every policy in this schema treats
as bypass. The application-level guards on that path —
:func:`ccf.prep.sources.resolve_source_organization_id` and
``ccf.prep.pipeline``'s per-stage organization reconciliation — are what
actually protect it, verified by
``tests/test_prep_tenant_isolation.py`` and (for the GUC mechanism itself)
``tests/test_rls_worker_guc_bypass.py``. See ``docs/ARCHITECTURE.md``'s
"Evidence preparation" section for the same note alongside the rest of the
pipeline's description.
```

In `src/ccf/models_assessment_engine.py`, replace the analogous paragraph (the one beginning `**These three tables carry no row-level-security policies**`) with the equivalent correction — same structure: state the policy now exists (migration `0060`), name it as defence in depth, name `ccf.assessment.engine.jobs`'s claim as the deliberately-still-unscoped exception with its reason (one worker drains every organization's queue), and point at `ccf.assessment.engine.jobs.enqueue_reevaluation`'s `result_org_id` check plus `tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls` and `tests/test_rls_worker_guc_bypass.py` as what actually verifies it.

- [ ] **Step 5: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_rls_worker_guc_bypass.py tests/test_prep_tenant_isolation.py tests/test_assessment_engine_api.py -v
.venv/bin/pytest -q          # run alone, foreground; confirm no regression
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check (two, both required):**

1. *The GUC mechanism itself.* In `src/ccf/db.py::set_session_tenant`, temporarily change the `tenant_id is None` branch to also `await session.execute(text("SET ROLE ccf_app"))` (simulating the exact accidental-scoping bug this module exists to catch). Re-run `tests/test_rls_worker_guc_bypass.py` — confirm `test_session_scope_leaves_the_tenant_guc_unset_and_the_bootstrap_role_in_effect` fails on the `role == "ccf"` assertion, and both claim-drain tests fail (each claims only one organization's job — the bootstrap-turned-`ccf_app` role now has no tenant GUC set either, so it would see *neither* org's rows under `FORCE RLS`, and the claim query would return nothing at all: assert this is in fact what happens, not merely that the assertion as written fails). Revert.
2. *The application-level guard, proven load-bearing precisely because RLS cannot help here.* In `src/ccf/prep/jobs.py::enqueue`, temporarily comment out the `if true_org != organization_id: raise SourceOwnershipMismatch(...)` block. Re-run `tests/test_prep_tenant_isolation.py::test_enqueue_refuses_a_cross_tenant_evidence_version_source_id` — confirm it now fails (a 404 was expected; the run opens instead). This is the demonstration that on this exact table set, with the worker's session unscoped by design, the application check — not Postgres — is the only thing standing between a caller and another organization's evidence, exactly as the design doc's risk section states. Revert.

```bash
git add tests/test_rls_worker_guc_bypass.py src/ccf/models_prep.py src/ccf/models_assessment_engine.py
git commit -m "test(db): pin the worker/CLI unscoped-GUC bypass as a verified, documented exception"
```

---

### Task 3: The registry test that stops the gap reopening

**Files:**
- Create: `tests/test_rls_registry_no_gap.py`

**Interfaces:**
- Consumes: `information_schema.columns`, `pg_class`/`pg_policy` (live catalog queries, no new production code).

- [ ] **Step 1: Write the test**

Create `tests/test_rls_registry_no_gap.py`:

```python
"""Registry test (2026-08-12 RLS-coverage design): the set of ccf tables that
carry ``organization_id`` directly and have no ``tenant_isolation`` policy
must be empty. This is the test that stops the gap this slice closes from
reopening — a twelfth table added later with ``organization_id`` and no
policy fails this test immediately, with no new test to write, distinct from
``tests/test_rls_coverage.py``'s hardcoded 121-table snapshot (which only
notices a *removed* policy, not a newly-added unpolicied table, since
`found - EXPECTED` there is asserted empty but nothing asserts anything
about tables neither set mentions).

A second assertion covers the other side: tables with *neither*
``organization_id`` nor a ``tenant_isolation`` policy are legitimate only if
they are genuinely global reference data — the fourteen named in the design
doc's "The remaining fourteen" section, verified live against
``information_schema.columns`` to carry no ``organization_id`` at all. A new
global-looking table is not assumed exempt; it must appear on this explicit
allow-list, so adding it is a decision made in review, not an omission
discovered later. (A table scoped via a parent FK rather than a direct
``organization_id`` column — e.g. ``poams`` via ``system_id`` — is neither
caught nor missed by either assertion here: it already carries its own
``tenant_isolation`` policy, covered by ``tests/test_rls_coverage.py``, and
is absent from both of this module's queries because it lacks
``organization_id`` *and* has a policy.)
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


#: Global reference data with no tenant dimension (2026-08-12 design, "The
#: remaining fourteen"). Verified live: none of these carry an
#: organization_id column, so none is scoped by any tenant. A future table on
#: this side of the split must be added here explicitly, in the same review
#: that adds the table — test_tables_without_organization_id_match_the_named_global_allowlist
#: below fails loudly if it is not.
GLOBAL_TABLES: frozenset[str] = frozenset(
    {
        "controls",
        "frameworks",
        "control_families",
        "framework_mappings",
        "worksheets",
        "worksheet_rows",
        "ingestion_runs",
        "catalog_sources",
        "catalog_checks",
        "scoring_controls",
        "statement_templates",
        "ksis",
        "ai_action_definitions",
        "alembic_version",
    }
)

_ORG_TABLES_WITHOUT_POLICY_SQL = text(
    "SELECT c.relname FROM pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'ccf' AND c.relkind = 'r' "
    "AND EXISTS (SELECT 1 FROM information_schema.columns col "
    "  WHERE col.table_schema = 'ccf' AND col.table_name = c.relname "
    "  AND col.column_name = 'organization_id') "
    "AND NOT EXISTS (SELECT 1 FROM pg_policy p "
    "  WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation')"
)

_TABLES_WITHOUT_ORG_COLUMN_OR_POLICY_SQL = text(
    "SELECT c.relname FROM pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'ccf' AND c.relkind = 'r' "
    "AND NOT EXISTS (SELECT 1 FROM information_schema.columns col "
    "  WHERE col.table_schema = 'ccf' AND col.table_name = c.relname "
    "  AND col.column_name = 'organization_id') "
    "AND NOT EXISTS (SELECT 1 FROM pg_policy p "
    "  WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation')"
)


async def test_no_tenant_owned_table_is_missing_its_rls_policy() -> None:
    """The load-bearing assertion: every ccf table with organization_id has a
    tenant_isolation policy. An empty result is the pass condition.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        rows = (await s.execute(_ORG_TABLES_WITHOUT_POLICY_SQL)).scalars().all()
    assert rows == [], (
        f"tenant-owned table(s) with no tenant_isolation policy: {sorted(rows)} — "
        "add the policy (see migration 0060 for the pattern) before this can pass"
    )


async def test_tables_without_organization_id_match_the_named_global_allowlist() -> None:
    """The other side of the split, defended explicitly rather than by
    omission: a table with neither organization_id nor a policy is legitimate
    only if it is on GLOBAL_TABLES.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        rows = (await s.execute(_TABLES_WITHOUT_ORG_COLUMN_OR_POLICY_SQL)).scalars().all()
    found = frozenset(rows)
    missing_from_allowlist = found - GLOBAL_TABLES
    stale_in_allowlist = GLOBAL_TABLES - found
    assert not missing_from_allowlist, (
        f"unpolicied table(s) not on GLOBAL_TABLES: {sorted(missing_from_allowlist)} — "
        "either give it organization_id + a tenant_isolation policy, or add it to "
        "GLOBAL_TABLES with a documented reason it has no tenant dimension"
    )
    assert not stale_in_allowlist, (
        f"GLOBAL_TABLES names table(s) that no longer exist or now carry a policy: "
        f"{sorted(stale_in_allowlist)} — update the allow-list"
    )
```

- [ ] **Step 2: Run the test**

Run: `.venv/bin/pytest tests/test_rls_registry_no_gap.py -v`
Expected: PASS — both tests, since Task 1's migration `0060` already closed the gap this module checks for.

- [ ] **Step 3: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_rls_registry_no_gap.py -v
.venv/bin/pytest -q          # run alone, foreground
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check (two, both required — this is precisely the test whose entire purpose is catching a reopened gap, so both directions must be proven, not assumed):**

1. In migration `0060`, comment out `prep_jobs`'s `CREATE POLICY` block, round-trip a fresh test database (`.venv/bin/alembic downgrade -1 && .venv/bin/alembic upgrade head`), re-run `test_no_tenant_owned_table_is_missing_its_rls_policy` — confirm it fails, naming `prep_jobs` specifically. Revert, round-trip again.
2. In this test file, remove `"ksis"` from `GLOBAL_TABLES`, re-run `test_tables_without_organization_id_match_the_named_global_allowlist` — confirm it fails on `missing_from_allowlist = {'ksis'}`. Revert.

```bash
git add tests/test_rls_registry_no_gap.py
git commit -m "test(db): add the RLS registry test that catches a future unpolicied tenant table"
```

---

### Task 4: Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `CHANGELOG.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: `docs/ARCHITECTURE.md` — "Evidence preparation"**

Replace the sentence (currently the last two sentences of that bullet, around line 170):

```markdown
  The seven `prep_*` tables deliberately carry no row-level-security policies
  (unlike 110 of Concord's 131 `ccf` tables) — every prep query filters by
  `organization_id` in application code instead (`ccf.prep.retriever._base_filters`
  and equivalent per-stage filters), the same pattern the worker already
  relies on (`claim()` is intentionally unscoped, since one worker drains
  every organization's jobs). See `models_prep.py` for the same note next to
  the table definitions.
```

with:

```markdown
  The seven `prep_*` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), matching 121 of Concord's 135
  `ccf` tables — defence in depth, not a replacement: every prep query still
  filters by `organization_id` in application code
  (`ccf.prep.retriever._base_filters` and equivalent per-stage filters), and
  the worker's own claim path (`ccf.prep.jobs.claim`) is **still
  intentionally unscoped**, since one worker drains every organization's
  jobs in a single query. That path runs through `ccf.db.session_scope()`,
  which leaves the tenant GUC unset — exactly what every policy here treats
  as bypass — so the RLS policy above provides no protection on it; the
  application-level ownership check
  (`ccf.prep.sources.resolve_source_organization_id`) is what actually does,
  verified independently of RLS by `tests/test_prep_tenant_isolation.py` and
  `tests/test_rls_worker_guc_bypass.py`. See `models_prep.py` for the same
  note next to the table definitions.
```

- [ ] **Step 2: `docs/ARCHITECTURE.md` — "Objective-level assessment engine"**

Replace the paragraph (currently around line 238):

```markdown
  The three `assessment_control_proposals` / `assessment_objective_proposals`
  / `assessment_jobs` tables deliberately carry no row-level-security
  policies, the same exemption as the `prep_*` tables and for the same
  reason: every route and service function filters by `organization_id` in
  application code instead (derived from `Assessment -> System ->
  Organization`, never from a caller-supplied id), and the job claim is
  intentionally unscoped, since one worker drains every organization's queue.
  `systems`, `assessments`, and `assessment_control_results` — the tables the
  accepted finding actually lands in — do carry the `tenant_isolation` RLS
  policy. See `models_assessment_engine.py` for the same RLS and AI-action
  notes next to the table definitions.
```

with:

```markdown
  The three `assessment_control_proposals` / `assessment_objective_proposals`
  / `assessment_jobs` tables carry a `tenant_isolation` RLS policy (migration
  `0060`), the same hardening as the `prep_*` tables and for the same
  reason: defence in depth beneath the existing application-level checks,
  which filter by `organization_id` in code (derived from `Assessment ->
  System -> Organization`, never from a caller-supplied id) and are not
  removed or weakened by the policy's addition. The job claim
  (`ccf.assessment.engine.jobs`, via `ccf.queue.claim_jobs`) is **still
  intentionally unscoped**, since one worker drains every organization's
  queue — RLS provides no protection on that path (its session, opened
  through `ccf.db.session_scope()`, never sets the tenant GUC), so
  `enqueue_reevaluation`'s `result_org_id` check is what actually protects
  it, verified independently of RLS by
  `tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls`
  and `tests/test_rls_worker_guc_bypass.py`. `systems`, `assessments`, and
  `assessment_control_results` — the tables the accepted finding actually
  lands in — carry the same `tenant_isolation` policy and always have. See
  `models_assessment_engine.py` for the same RLS and AI-action notes next to
  the table definitions.
```

- [ ] **Step 3: `docs/ARCHITECTURE.md` — coverage statement and allow-list**

Add a new paragraph immediately after the "Objective-level assessment engine" bullet block (Step 2's edit) and before "Calibration harness":

```markdown
- **RLS coverage** (migration `0060`, 2026-08-12 RLS-coverage design): 121 of
  the 135 tables in the `ccf` schema carry a `tenant_isolation` policy —
  every tenant-owned table has one. The remaining fourteen are global
  reference data with no tenant dimension and are named explicitly rather
  than exempted by omission: `controls`, `frameworks`, `control_families`,
  `framework_mappings`, `worksheets`, `worksheet_rows`, `ingestion_runs`,
  `catalog_sources`, `catalog_checks`, `scoring_controls`,
  `statement_templates`, `ksis`, `ai_action_definitions`, and
  `alembic_version` — none carries an `organization_id` column.
  `tests/test_rls_registry_no_gap.py` asserts both sides of this split live
  against the schema, so a future tenant-owned table added without a policy
  fails CI immediately rather than shipping unnoticed. **RLS here is defence
  in depth, not a replacement for application-level scoping** — every route,
  service function, and worker still derives and checks `organization_id` in
  code, and this slice removes none of those checks. The one place RLS
  provides no protection at all is the prep and assessment-engine worker
  processes' own job-claim queries, which run unscoped by design (one worker
  drains every organization's queue in a single query) — see "Evidence
  preparation" and "Objective-level assessment engine" above for that
  exception named alongside the application-level check that actually
  covers it.
```

- [ ] **Step 4: `CHANGELOG.md`**

Add a new `### Added — RLS coverage for the engine tables` section as the first entry under `## [Unreleased]`, above the existing `### Added — AI dissent path` section:

```markdown
### Added — RLS coverage for the engine tables
- **121 of the 135 tables in the `ccf` schema now carry a `tenant_isolation`
  RLS policy** (migration `0060`) — up from 110. The eleven added:
  `prep_runs`, `prep_lines`, `prep_screens`, `prep_units`,
  `prep_classifications`, `prep_embeddings`, `prep_jobs`, `assessment_jobs`,
  `calibration_snapshots`, `assessment_control_proposals`,
  `assessment_objective_proposals` — every table slices 1–6 added with no
  database backstop, filtered by application-level `organization_id` checks
  alone until now.
- **Both `ENABLE` and `FORCE ROW LEVEL SECURITY`**: the owning role (`ccf`)
  bypasses its own policy without `FORCE`, which would have produced a
  policy that exists, reports as enabled, and is bypassed on exactly the
  connections the application uses. `relforcerowsecurity`, not merely
  `relrowsecurity`, is asserted by every new test.
- **Defence in depth, not a replacement**: no application-level
  organization check was removed. The prep and assessment-engine workers'
  own job-claim queries remain deliberately unscoped (one worker drains
  every organization's queue by design) — RLS provides no protection there,
  since that session never sets the tenant GUC, so the pre-existing
  application-level ownership checks are what actually protect it, now
  verified independently of RLS by `tests/test_rls_worker_guc_bypass.py`.
- **A registry test** (`tests/test_rls_registry_no_gap.py`) asserts, live
  against the schema, that no tenant-owned table lacks a policy and that the
  fourteen tables with neither a tenant column nor a policy are exactly the
  named global-reference-data allow-list — so a future table added without a
  policy fails CI immediately.
```

- [ ] **Step 5: Verify and commit**

```bash
.venv/bin/pytest -q          # run alone, foreground; confirm the final count and cite it in the commit
git add docs/ARCHITECTURE.md CHANGELOG.md
git commit -m "docs(db): document RLS coverage for the engine tables and the worker's named bypass"
```

---

## Deferred, deliberately

- **No changes to the fourteen global tables.** `controls`, `frameworks`, `control_families`, `framework_mappings`, `worksheets`, `worksheet_rows`, `ingestion_runs`, `catalog_sources`, `catalog_checks`, `scoring_controls`, `statement_templates`, `ksis`, `ai_action_definitions`, `alembic_version` — no tenant column, no tenant meaning.
- **No removal of any application-level check.** Every existing `organization_id` comparison, ownership resolver, and reconciliation step stays exactly as it was; RLS is added beneath them, not instead of them.
- **No new tenancy model.** `current_tenant()` and the existing role plumbing (`ccf` owning role, `ccf_app` scoped role, `SET ROLE`) are used exactly as they are — no `ALTER ROLE ... SET search_path` or equivalent connection-time approach, which would be wrong for the same reason noted in the design doc: this application authenticates as one role and then becomes another, so a role-level setting applied at connection time would not track the switch.
- **No fix to the prep/assessment worker's unscoped claim query.** It is correct as-is — one worker process must drain every organization's queue in a single `SELECT ... FOR UPDATE SKIP LOCKED`, and `current_tenant() IS NULL` is designed to allow exactly that. This slice's job was to confirm it, name it, and pin it with a direct test, not to change it.

The standing debt list this slice does not close: migrations `0057` and `0058` still missing the `pg_roles` GRANT guard (`0060` carries it, per this slice's own constraint, but does not retrofit the two before it); `prep_screen_threshold`'s narrow ~0.03 margin; base-control collapse meaning enhancements are never individually cited; re-preparation duplicating passages across runs; scanned-PDF pages skipped without a persisted marker; `AssessmentJob` enqueue de-duplication wanting a partial unique index; the two unreconciled legacy POA&M-from-findings paths; and `docs/ARCHITECTURE.md`'s "Deferred / planned" section still listing "RLS for multi-tenant (app-level org scoping is live today)" as not-yet-done — stale well before this slice (RLS has covered 110+ tables since migrations 0010–0022) and not corrected here to keep this slice's documentation changes scoped to the eleven tables it actually touches.
