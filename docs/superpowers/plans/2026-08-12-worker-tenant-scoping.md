# Worker Tenant Scoping — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migration `0060` put a `tenant_isolation` policy on the eleven tables the
evidence-prep and assessment-engine slices created, but that policy protects them on
the **request path only**. `ccf.db.session_scope` (`src/ccf/db.py:98`) calls
`set_session_tenant(session, None)` — commented *"CLI/ETL run unscoped (bypass)"* —
and the policy's `current_tenant() IS NULL` escape means RLS does not filter those
sessions at all. So the paths that write the most rows into those tables —
`ccf.prep.jobs.run_once` and `ccf.assessment.engine.jobs.run_once`, the two queue
workers' drain loops — are exactly the paths RLS does not cover. This is narrower
than the debt note that opened this investigation implied: the governance scheduler
(`governance/scheduler.py:61`, `_run_per_tenant_cycle`) is already scoped, per
organization, with a savepoint per step; only the two queue workers and the CLI are
not. `JobLike` (`ccf/queue.py:115`) requires `organization_id` on every job model, and
both `PrepJob` and `AssessmentJob` carry it — a claimed job already knows which tenant
it belongs to, with no lookup and no new column.

**The design this plan implements: claim unscoped, process scoped.** `claim_jobs`
keeps its single cross-tenant `SELECT ... FOR UPDATE SKIP LOCKED` query exactly as it
is — it reads only `id` from a single jobs table and writes only status, attempts and
claim bookkeeping to rows it just selected, never evidence, passages, proposals or
citations. A leak there would disclose that some other tenant has a queued job, not
its contents. Once a job is claimed, the worker sets the tenant to *that job's own*
`organization_id` for the processing work — `pipeline.advance` and
`evaluate_control_proposal` read and write across every one of the eleven policied
tables, which is exactly what the RLS policy exists to contain — and clears it
afterwards. This is the same shape `_run_per_tenant_cycle` already uses: scope around
the unit of work, not around the dispatch. Two considered-and-rejected alternatives,
named in the design doc so a future reader doesn't re-litigate them: per-tenant claim
loops (would turn one query per cycle into one per organization and introduce
fairness questions the queue does not currently answer, to protect the least
sensitive statement in the whole path), and scoping the claim query itself (same
objection, more directly).

**A hazard the design doc names and this plan tests explicitly: the tenant must be
cleared between jobs.** A drain loop processes jobs from different organizations on
one shared session. If the GUC set for job N survives into job N+1, that job runs
under the wrong tenant — and because RLS then filters *correctly for the wrong org*,
the symptom is not an error but silently missing rows: a stage that appears to
succeed having seen nothing. Both `run_once` functions therefore reset the tenant
explicitly after each job, rather than relying on the next job's own assignment to
overwrite it — so a job that fails before it manages to set anything can never
inherit its predecessor's scope.

**A second, named hazard: `reap_stale_jobs` must stay unscoped**, and therefore run
*outside* the per-job scoping, not inside it. Over-scoping is the likelier mistake
here than under-scoping: a scoped reaper silently stops sweeping other tenants' stale
claims and the dead-letter net quietly dies, with no error to notice. Both tasks below
include a test that reaps a stale claim belonging to an organization other than the
one most recently processed, run on the very session the batch just used — the
sharpest place an accidental over-scoping bug would show up.

**A third hazard, found while reading the code rather than stated in the design
doc — this is the trap that shapes both tasks' actual diffs.** `AsyncSession.rollback()`
is **not** savepoint-scoped; it unwinds the whole transaction, matching the trap
`governance/scheduler.py`'s own docstring documents in full and that this plan
reproduces the fix for. Both `_drive_one` functions, as they exist today, catch their
own DB-level failures internally with a bare `try/except` that calls a **full**
`session.rollback()` before recording the failure — and that is correct *today*,
because nothing else is pending in the transaction at that point (each job already
commits independently). Once tenant scoping sits *before* `_drive_one`'s call in the
same transaction, that same full rollback becomes destructive: Postgres treats a plain
(non-`LOCAL`) `SET ROLE`/`set_config` issued inside a transaction as part of that
transaction's own state, and undoes it on **any** rollback of that transaction —
savepoint or full — the same way it undoes an ordinary row write. A full
`session.rollback()` called after the tenant was set for this job would silently wipe
that scoping out from under the failure-recording code that runs right after it. The
fix, precedented by `_run_per_tenant_cycle` itself (`set_session_tenant(session,
org_id)` runs *before* each step's own `try: async with session.begin_nested():`, never
inside it), is to set the tenant **before** entering a `session.begin_nested()` block
that wraps the job's own risky work, so a `ROLLBACK TO SAVEPOINT` on failure undoes
only that job's writes and clears any DB-level ABORTED state, while leaving the tenant
GUC set immediately before it completely untouched. This means `_drive_one` can no
longer catch and roll back its own failure internally — that responsibility moves to
the loop in `run_once`, which already needs to sit outside the savepoint anyway to set
and clear the tenant around it. Every existing test that exercises a DB-level failure
(a real, unqualified table reference, not a mock) was re-traced against this refactor
before it was written into the tasks below, and all of them still pass unchanged: the
propagated exception crosses `begin_nested()`'s boundary, which itself performs
`ROLLBACK TO SAVEPOINT` (clearing the abort) before `run_once`'s `except` block runs
its direct `UPDATE` — the same direct-`UPDATE`-not-ORM-mutation discipline the current
code already uses and for the same reason (a savepoint rollback expires every ORM
object in the session, same as a full rollback does).

**Architecture**, in dependency order:

1. **The prep worker's drain loop** (Task 1): `ccf.prep.jobs.run_once` sets the
   tenant to each claimed job's own `organization_id` before calling `_drive_one`,
   inside a `session.begin_nested()` savepoint entered *after* the tenant is set, and
   clears the tenant explicitly once that job's outcome commits. `_drive_one` no
   longer catches or rolls back its own DB-level failure — that moves to `run_once`'s
   own `except`, for the reason above. `reap_stale`/`claim` are untouched.
2. **The assessment-engine worker's drain loop** (Task 2): the same shape, applied to
   `ccf.assessment.engine.jobs.run_once`/`_drive_one`. The two loops are **not**
   quite the same shape once you look past the wrapper: assessment's failure path
   writes to *two* tables (`AssessmentJob` **and** its `AssessmentControlProposal`,
   both direct `UPDATE`s) where prep's writes to one, assessment has no
   organization-reconciliation step (prep's `_drive_one` syncs `job.organization_id`
   to the source's true org after every `pipeline.advance`; assessment has nothing
   analogous), and assessment's success path has no partial "still `pending`, more
   stages remain" outcome the way prep's multi-stage pipeline does — it is always
   `"done"` or `"failed"`. Given that, no shared helper is introduced beyond what
   `ccf.queue` already provides; each `run_once` keeps its own loop, matching the
   precedent `2026-08-12-recovery-closure.md` set when its own two "superficially
   similar" helpers turned out to differ in exactly this way.
3. **Documentation** (Task 3): `docs/ARCHITECTURE.md`'s three passages that currently
   state RLS protects these tables "only on the request path" are corrected — that
   claim becomes false the moment this ships, and a reader must be able to tell,
   without reading the code, which paths RLS now covers. `models_prep.py` and
   `models_assessment_engine.py` get one additional paragraph each next to their
   existing "worker path is unscoped" note. `CHANGELOG.md` records the hardening.

**No migration.** No new table, column, role, or status value is added — `claim_jobs`
and `reap_stale_jobs` are untouched, and scoping reuses the tenant GUC mechanism
migration `0060` and `ccf.db.set_session_tenant` already provide. Current alembic head
is `0060_engine_rls_coverage`; this slice does not touch it. If implementation reveals
a need for a migration, stop and say why rather than adding one silently.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Postgres 16, FastAPI, pytest.

**Spec:** [docs/superpowers/specs/2026-08-12-worker-tenant-scoping-design.md](../specs/2026-08-12-worker-tenant-scoping-design.md)
**Depends on:** the branch state at `a2b0120` on `feat/evidence-prep-spine` (the design
doc itself landed at `6d13364`, one commit later, adding no code).

## Global Constraints

- **Python** 3.12, `line-length = 100`. **Ruff** selects
  `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected,
  so a `# noqa: BLE001`/`# noqa: SLF001` comment trips `RUF100` (unused noqa) — the
  `except Exception:` blocks this plan adds carry no such noqa, since none is needed.
  `PLC0415` means imports go at module top level, never inside a function body.
  `RUF059` means an unused unpacked variable gets a leading underscore. Known
  baseline: **exactly 25 pre-existing `PLR0917`**; neither task adds a function with
  more than five positional parameters (every new/changed signature here is
  keyword-only past `session`), so this plan should add nothing to that count.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** both `prep/jobs.py` and `assessment/engine/jobs.py` already import
  `from ..logging import get_logger` / `from ...logging import get_logger` and hold a
  module-level `log = get_logger(__name__)` — reuse it. Never `import structlog`
  directly, never `extra={...}` (collides with reserved `LogRecord` attributes and
  raises `KeyError`) — pass plain kwargs, matching the existing
  `log.warning("prep.job_failed", job_id=job_id, run_id=job_run_id, error=last_error)`
  call this plan preserves (relocated, not reworded).
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — a `SELECT` issued while a
  pending `add()` is unflushed sees nothing. Every new query this plan adds reads rows
  a *prior*, already-flushed write created (a job or run seeded in an earlier
  `session_scope()` block, or a row read back after `await s.flush()` in the same
  block), so no additional flush beyond what already exists is needed — but this must
  be verified at each new query site, not assumed.
- **Savepoints:** `AsyncSession.rollback()` is **not** savepoint-scoped — it unwinds
  the whole transaction, not just the failing derived write, and (the trap this plan
  specifically designs around, absent from the scheduler's own version of this note)
  it also undoes any plain `SET ROLE`/`set_config` issued earlier in that same
  transaction, savepoint or full rollback alike. `session.begin_nested()` is entered
  only *after* `set_session_tenant` is called for the job about to run, never before —
  precedented by `governance/scheduler.py:81-113` (`_run_per_tenant_cycle`: tenant set,
  *then* `try: async with session.begin_nested():` per step) and
  `assessment/engine/service.py:437-488` (`_ensure_poam_for_other_than_satisfied`, the
  "derived write must never cost the authoritative one" shape both tasks below reuse
  for the exception-boundary itself, though not for tenant ordering, which only the
  scheduler precedent establishes).
- **Commit discipline, unchanged:** the claim (and its `attempts` bump) is committed
  immediately, before any job's processing begins; each job's outcome commits
  independently before the next job starts. `claim_jobs`'/`reap_stale_jobs`' query
  shape in `ccf/queue.py` is not touched by this plan at all.
- **Best-effort ≠ silent.** A bare `except Exception:` that swallows without logging
  makes "correctly skipped" and "raised and was swallowed" observably identical —
  three findings in the last slice alone traced to exactly this. Every test in this
  plan that forces a failure asserts a warning **was** logged with the exact event
  name (`prep.job_failed` / `assessment.job_failed`, both pre-existing, unchanged by
  this plan) via `monkeypatch.setattr(<module>.log, "warning", <capture>)`, and also
  asserts the surviving job(s) in the same batch actually finished — never a
  "nothing happened" assertion standing alone.
- **Asymmetric fixtures.** Wherever two values could be swapped undetected — two
  organizations' identifying data, which job runs first vs. second in a batch — the
  fixture uses two distinct, distinguishable values and the assertions are written to
  hold regardless of which one a database without a guaranteed re-select order
  happens to process first (see Task 1 Step 1 for why `claim_jobs`' re-select is not
  itself ordered).
- **Assert against the specific row, not a table.** This test suite runs against one
  shared, session-scoped Postgres database with **no per-test data wipe** —
  `tests/conftest.py`'s `clean_migrated_db` runs `alembic downgrade base` /
  `upgrade head` exactly once per pytest session, and `fresh_engine` only disposes the
  SQLAlchemy engine object, never table data. Multiple existing test modules
  (`test_rls_engine_tables.py`, `test_rls_worker_guc_bypass.py`,
  `test_assessment_engine_models.py`, and `test_assessment_closure_trigger.py`, called
  out explicitly below) leave `pending` `PrepJob`/`AssessmentJob` rows behind with no
  cleanup. Every test in this plan that calls `run_once` therefore sizes its `limit`
  to the actual pending backlog counted immediately beforehand (the
  `tests/test_rls_worker_guc_bypass.py` precedent), and every assertion after a
  `run_once`/`reap_stale`/`reap` call checks the **specific** row(s) this test itself
  created by id — never a bare `stats["claimed"] == 2`-style count that a stray row
  from another module could throw off, and never an absence check against a whole
  table that may be nonzero for unrelated reasons.
- **Never run two pytest sessions concurrently — not even a background one alongside
  foreground runs.** **Always run pytest in the foreground**, with at least 300s of
  timeout — the full suite takes roughly 70s. Venv binaries only: `.venv/bin/pytest`,
  `.venv/bin/ruff`, `.venv/bin/mypy` — never bare `python3` (system Python is 3.9).
  Test Postgres is on port **5434**, container `ccf-test-db`.
- **`asyncio_mode = "auto"`** in `pytest.ini` — new test functions in this plan are
  written **without** `@pytest.mark.asyncio` (redundant under `auto`, and every file
  this plan's new modules are patterned after already omits it). DB-touching test
  modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")`.
- **Baseline: 1031 passed, 1 skipped.** Migration head: **`0060`**. Ruff baseline:
  **exactly 25 pre-existing `PLR0917`**.
- **Mutation discipline.** Every guard added by this plan is verified by mutation:
  delete or invert it, re-run the specific test named for that guard, confirm it fails
  for the expected reason, then revert. Each task's final step states this explicitly
  and instructs reporting plainly if a mutation produces no failure, rather than
  adjusting the test until it looks right.
- **No application-level check is removed.** The worker-path ownership guard in
  `prep/jobs.py`'s `enqueue` (`resolve_source_organization_id`) and the
  cross-tenant guard in `assessment/engine/jobs.py`'s `enqueue_reevaluation`
  (`result_org_id != organization_id`) are untouched — RLS is defence in depth, not a
  replacement.
- **No change to the CLI.** `src/ccf/cli.py`'s `_drain_loop`/`_assessment_drain_loop`
  and the `--once/--loop` commands are not modified by this plan — scoping happens
  entirely inside the library-level `run_once` functions the CLI already calls.
- **No new role, no migration.** A dedicated `ccf_worker` role with explicit
  `bypassrls` is filed as a follow-up in the spec's "What this leaves open" section,
  not built here. Alembic head stays `0060`.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot
  project.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/prep/jobs.py` | `_drive_one` no longer catches/rolls back its own DB-level failure; `run_once` sets the tenant to each claimed job's `organization_id` before a `session.begin_nested()`-wrapped `_drive_one` call, records any failure in its own `except`, commits, and clears the tenant |
| `tests/test_prep_worker_tenant_scoping.py` | New: processing scopes to the job's own tenant; the reset-between-jobs attack (two orgs, asymmetric data); a raising job leaves no tenant set for the next; `reap_stale` still sweeps another org's stale claim after processing scoped a job; full-suite regression |
| `src/ccf/assessment/engine/jobs.py` | Same shape as `prep/jobs.py`, applied to `AssessmentJob`/`AssessmentControlProposal`; failure recording stays two-table (job + proposal) |
| `tests/test_assessment_worker_tenant_scoping.py` | New: mirrors the prep test file for `AssessmentJob`/`AssessmentControlProposal` |
| `docs/ARCHITECTURE.md` | Corrects the three passages stating RLS covers these tables "only on the request path" |
| `src/ccf/models_prep.py`, `src/ccf/models_assessment_engine.py` | One additional paragraph each, next to the existing "claim is unscoped" note, stating that processing is no longer unscoped |
| `CHANGELOG.md` | Records the hardening |

---

### Task 1: `ccf.prep.jobs` — scope the drain loop's per-job processing to its own tenant

**Files:**
- Modify: `src/ccf/prep/jobs.py`
- Create: `tests/test_prep_worker_tenant_scoping.py`

**Interfaces:**
- Modifies: `prep.jobs._drive_one(session, job) -> str` (no longer catches or rolls back
  its own DB-level failure; a raised exception now propagates to the caller).
- Modifies: `prep.jobs.run_once(session, *, worker, limit) -> dict[str, int]` (sets and
  clears the tenant GUC around each job; wraps `_drive_one` in `session.begin_nested()`;
  records a job's failure in its own `except`, via the same direct-`UPDATE` shape
  `_drive_one` used to use).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_prep_worker_tenant_scoping.py`:

```python
"""Per-job tenant scoping for the prep worker's drain loop (2026-08-12
worker-tenant-scoping design). ``claim()`` stays unscoped -- it reads only
ids and writes only claim bookkeeping, disclosing at most that some
organization has a queued job, never its contents -- but once a job is
claimed, ``ccf.prep.jobs.run_once`` now sets the RLS tenant GUC to that
job's own ``organization_id`` before driving it through ``pipeline.advance``,
which reads and writes across every one of the eleven tables migration
``0060`` policied.

Two hazards this module exists to catch, neither of which fails loudly:

1. The tenant must be cleared BETWEEN jobs. A drain loop shares one session
   across jobs from different organizations; a GUC left over from job N
   makes job N+1 filter correctly for the WRONG tenant -- the symptom is
   silently missing rows, not an error. Tested with two organizations
   carrying DIFFERENT data, not an identical fixture, which would pass
   against code that never switched tenant at all.
2. ``reap_stale_jobs`` must stay unscoped and keep sweeping every
   organization's stale claims regardless of which org's job the batch most
   recently processed. Over-scoping it is the likelier mistake, since a
   scoped reaper fails silently -- it just stops finding rows.

This suite runs against one shared, session-scoped Postgres database with no
per-test wipe (see ``tests/conftest.py``): several existing modules
(``test_rls_engine_tables.py``, ``test_rls_worker_guc_bypass.py``, among
others) leave ``pending`` ``PrepJob`` rows behind with no cleanup. Every
``run_once`` call below therefore sizes ``limit`` to the actual pending
backlog counted immediately beforehand (matching
``tests/test_rls_worker_guc_bypass.py``'s own precedent), and every
assertion checks a specific row by id, never a bare ``stats["claimed"]``
count or an absence check against the whole table.

See docs/superpowers/specs/2026-08-12-worker-tenant-scoping-design.md.
"""

from __future__ import annotations

import itertools
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, func, select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, Policy, PolicyVersion
from ccf.models_prep import PrepJob, PrepRun
from ccf.prep import jobs

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
async def _clean_job_queue() -> AsyncIterator[None]:
    """Mirrors ``tests/test_prep_jobs.py``'s own ``_clean_job_queue`` fixture,
    scoped to this module's own ``wts-prep-*``-named organizations -- tidies
    up what this module itself creates. It does not, and cannot, protect
    against the pollution the module docstring above describes (rows other
    modules leave behind under their own org names); the ``limit``-sizing
    pattern each test below uses is what actually protects against that.
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            org_ids = (
                (
                    await s.execute(
                        select(Organization.id).where(Organization.name.like("wts-prep-%"))
                    )
                )
                .scalars()
                .all()
            )
            if org_ids:
                await s.execute(delete(PrepRun).where(PrepRun.organization_id.in_(org_ids)))

    await _wipe()
    yield
    await _wipe()


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


_policy_name_seq = itertools.count(1)


async def _uri_only_policy_version(org_id: int) -> int:
    """A real, same-org ``PolicyVersion`` with no inline body -- passes
    ``jobs.enqueue``'s ownership check but resolves to "orphaned" at the
    parse stage (a terminal state), matching ``tests/test_prep_jobs.py``'s
    identical helper.
    """
    async with session_scope() as s:
        policy = Policy(organization_id=org_id, name=f"WTS Policy {next(_policy_name_seq)}")
        s.add(policy)
        await s.flush()
        version = PolicyVersion(policy_id=policy.id, version="1.0")
        s.add(version)
        await s.flush()
        return int(version.id)


async def _pending_backlog() -> int:
    async with session_scope() as s:
        return int(
            (
                await s.execute(
                    select(func.count()).select_from(PrepJob).where(PrepJob.status == "pending")
                )
            ).scalar_one()
        )


async def test_processing_scopes_to_the_jobs_own_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row belonging to a DIFFERENT organization -- never queued as a job
    at all -- must not be visible while this job's own processing runs.
    Observed by querying from inside ``pipeline.advance`` itself (mocked),
    not merely by reading the GUC back, since the point is that RLS is
    actually filtering, not just that a setting was assigned.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_id = await _org("wts-prep-scope-own")
    other_org_id = await _org("wts-prep-scope-other")
    source_id = await _uri_only_policy_version(org_id)
    other_source_id = await _uri_only_policy_version(other_org_id)
    async with session_scope() as s:
        job = await jobs.enqueue(
            s, organization_id=org_id, source_kind="policy_version", source_id=source_id
        )
        job_id, own_run_id = int(job.id), int(job.run_id)
        other_run = PrepRun(
            organization_id=other_org_id, source_kind="policy_version", source_id=other_source_id
        )
        s.add(other_run)
        await s.flush()
        other_run_id = int(other_run.id)

    seen: dict[str, Any] = {}
    real_advance = jobs.pipeline.advance

    async def _advance(session: Any, run: Any) -> Any:
        own = (
            await session.execute(select(PrepRun.id).where(PrepRun.id == own_run_id))
        ).scalar_one_or_none()
        other = (
            await session.execute(select(PrepRun.id).where(PrepRun.id == other_run_id))
        ).scalar_one_or_none()
        seen["own_visible"] = own is not None
        seen["other_visible"] = other is not None
        return await real_advance(session, run)

    monkeypatch.setattr(jobs.pipeline, "advance", _advance)
    limit = await _pending_backlog()
    async with session_scope() as s:
        await jobs.run_once(s, worker="w1", limit=limit)

    assert seen["own_visible"] is True, "the job could not see its own run row while processing"
    assert seen["other_visible"] is False, (
        "the job could see another organization's run row while processing -- "
        "processing is not actually scoped to the claimed job's own tenant"
    )
    async with session_scope() as s:
        row = (await s.execute(select(PrepJob).where(PrepJob.id == job_id))).scalar_one()
        assert row.status == "done"


async def test_tenant_is_cleared_between_two_organizations_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The attack the design doc's hazard describes: two jobs for two
    DIFFERENT organizations, drained in one batch on one shared session. If
    the tenant GUC set for the first job survives into the second, the
    second job runs scoped to the WRONG organization -- and RLS then filters
    *correctly for the wrong org*, so the symptom is missing rows, not an
    error. The two organizations' sources are distinguishable (different
    names, different ids); an identical fixture would pass against code that
    never switched tenant at all.

    ``claim_jobs``' own re-select (``ccf/queue.py``'s ``claim_jobs``) has no
    ``ORDER BY``, so which of these two jobs is processed first is not
    guaranteed by the query itself -- the assertions below are written to
    hold regardless of order: whichever job runs, it must see its own run
    and never the other's.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a = await _org("wts-prep-reset-a")
    org_b = await _org("wts-prep-reset-b")
    source_a = await _uri_only_policy_version(org_a)
    source_b = await _uri_only_policy_version(org_b)
    async with session_scope() as s:
        job_a = await jobs.enqueue(
            s, organization_id=org_a, source_kind="policy_version", source_id=source_a
        )
        job_b = await jobs.enqueue(
            s, organization_id=org_b, source_kind="policy_version", source_id=source_b
        )
        run_a_id, run_b_id = int(job_a.run_id), int(job_b.run_id)

    other_run_of = {run_a_id: run_b_id, run_b_id: run_a_id}
    events: list[dict[str, Any]] = []
    real_advance = jobs.pipeline.advance

    async def _advance(session: Any, run: Any) -> Any:
        if int(run.id) in other_run_of:
            other_id = other_run_of[int(run.id)]
            own = (
                await session.execute(select(PrepRun.id).where(PrepRun.id == run.id))
            ).scalar_one_or_none()
            other = (
                await session.execute(select(PrepRun.id).where(PrepRun.id == other_id))
            ).scalar_one_or_none()
            events.append(
                {"run_id": int(run.id), "own_visible": own is not None, "other_visible": other is not None}
            )
        return await real_advance(session, run)

    monkeypatch.setattr(jobs.pipeline, "advance", _advance)
    limit = await _pending_backlog()
    async with session_scope() as s:
        await jobs.run_once(s, worker="w1", limit=limit)

    assert len(events) == 2, "both seeded jobs must have been processed and observed"
    for ev in events:
        assert ev["own_visible"] is True, f"run {ev['run_id']} could not see its own row"
        assert ev["other_visible"] is False, (
            f"run {ev['run_id']} could see the other organization's row -- if this is the "
            "job processed SECOND, the tenant GUC from the first job's processing was not "
            "cleared before this one began"
        )


async def test_a_failing_job_does_not_leak_its_tenant_to_the_next_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure-containment hazard, reproduced for the worker: the
    scheduler's own documented ABORTED-transaction trap
    (``governance/scheduler.py``'s ``_run_per_tenant_cycle`` docstring) is
    forced here with a REAL DB-level failure (an unqualified reference to a
    nonexistent table), not a mock exception -- a plain Python exception
    never aborts the underlying Postgres transaction in the first place, so
    only a genuine DBAPI error actually exercises ``ROLLBACK TO SAVEPOINT``
    clearing the abort. Proves both halves of the drain loop continues:
    the SURVIVING job's own processing must see its OWN tenant GUC (read
    directly via ``current_setting('ccf.tenant_id', true)``), not the failed
    job's leftover scope and not an unset one -- order-agnostic, since
    whichever of the two seeded jobs is NOT the one forced to fail gets its
    GUC checked -- and it must actually finish, not merely "not be failed".

    Also asserts a warning WAS logged with the exact event name -- a
    best-effort ``except Exception`` that swallows without logging would
    make "correctly failed" and "silently swallowed" look identical from
    the stats alone.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a = await _org("wts-prep-raise-a")
    org_b = await _org("wts-prep-raise-b")
    source_a = await _uri_only_policy_version(org_a)
    source_b = await _uri_only_policy_version(org_b)
    async with session_scope() as s:
        job_a = await jobs.enqueue(
            s, organization_id=org_a, source_kind="policy_version", source_id=source_a
        )
        job_b = await jobs.enqueue(
            s, organization_id=org_b, source_kind="policy_version", source_id=source_b
        )
        run_a_id, run_b_id = int(job_a.run_id), int(job_b.run_id)
    expected_tenant = {run_a_id: str(org_a), run_b_id: str(org_b)}
    raising_run_id = run_a_id

    warn_calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        jobs.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    seen: dict[int, str] = {}
    real_advance = jobs.pipeline.advance

    async def _advance(session: Any, run: Any) -> Any:
        if int(run.id) == raising_run_id:
            # A genuine DBAPI error, not a mock -- see the docstring above.
            await session.execute(text("SELECT * FROM ccf.this_table_does_not_exist_at_all"))
            return None
        tenant_guc = (
            await session.execute(text("SELECT current_setting('ccf.tenant_id', true)"))
        ).scalar_one()
        seen[int(run.id)] = tenant_guc
        return await real_advance(session, run)

    monkeypatch.setattr(jobs.pipeline, "advance", _advance)
    limit = await _pending_backlog()
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=limit)

    surviving_run_id = run_b_id
    assert seen.get(surviving_run_id) == expected_tenant[surviving_run_id], (
        f"the surviving job ran under tenant {seen.get(surviving_run_id)!r}, expected its "
        f"own {expected_tenant[surviving_run_id]!r} -- the failed job's tenant (or no "
        "tenant at all) must not leak into the next job"
    )
    assert any(event == "prep.job_failed" for event, _ in warn_calls), (
        "a warning must be logged on failure -- a silent swallow is indistinguishable "
        "from a correctly-handled skip otherwise"
    )
    async with session_scope() as s:
        failed = (await s.execute(select(PrepJob).where(PrepJob.run_id == raising_run_id))).scalar_one()
        succeeded = (
            await s.execute(select(PrepJob).where(PrepJob.run_id == surviving_run_id))
        ).scalar_one()
    assert failed.status == "failed"
    assert failed.last_error and "this_table_does_not_exist_at_all" in failed.last_error
    assert succeeded.status == "done", "the surviving job must actually have finished, not merely 'not failed'"
    assert stats["failed"] >= 1 and stats["finished"] >= 1


async def test_reap_stale_still_sweeps_another_org_after_processing_scopes_a_job() -> None:
    """``reap_stale_jobs`` must stay unscoped and keep sweeping every
    organization's stale claims regardless of which org's job was just
    processed. Reused deliberately on the SAME session ``run_once`` just
    used (not a fresh ``session_scope()``) -- a fresh session would reset to
    bypass on its own via ``session_scope()``'s own entry behavior, which
    would make this test pass even against a version of ``run_once`` that
    left the session scoped to the last-processed org after returning.
    Reusing the session is what actually exercises "the reset after the
    last job in a batch," not just "a fresh session resets."
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_processed = await _org("wts-prep-reap-processed")
    org_stale = await _org("wts-prep-reap-stale")
    source_processed = await _uri_only_policy_version(org_processed)
    source_stale = await _uri_only_policy_version(org_stale)

    async with session_scope() as s:
        job_stale = await jobs.enqueue(
            s, organization_id=org_stale, source_kind="policy_version", source_id=source_stale
        )
        job_stale.status = "claimed"
        job_stale.claimed_by = "dead-worker"
        job_stale.claimed_at = datetime.now(UTC) - timedelta(hours=3)
        await s.flush()
        stale_job_id = int(job_stale.id)

    async with session_scope() as s:
        await jobs.enqueue(
            s,
            organization_id=org_processed,
            source_kind="policy_version",
            source_id=source_processed,
        )

    # limit is sized to the actual pending backlog, not a fixed 1 -- other
    # modules in this shared, session-scoped database leave pending PrepJob
    # rows behind too (see the module docstring), and claim() is FIFO by
    # created_at, so a fixed small limit risks claiming only THEIR older
    # rows and never reaching org_processed's job at all. The exact org
    # run_once ends up scoped to when it returns does not matter for this
    # test -- only that at least one job (this test's own, guaranteed
    # included since the limit covers the whole backlog) actually ran and
    # committed on this session before reap_stale is called on it.
    limit = await _pending_backlog()
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=limit)
        assert stats["claimed"] >= 1
        reaped = await jobs.reap_stale(s, older_than_minutes=60)
        assert reaped >= 1, "reap_stale must still find the OTHER organization's stale claim"

    async with session_scope() as s:
        row = (await s.execute(select(PrepJob).where(PrepJob.id == stale_job_id))).scalar_one()
        assert row.status == "pending", "the other organization's stale job must be requeued"
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `.venv/bin/pytest tests/test_prep_worker_tenant_scoping.py -v`
Expected: FAIL on every test that inspects `other_visible` or the tenant GUC —
`_drive_one`/`run_once` never call `set_session_tenant` today, so processing runs on
whatever the ambient `session_scope()` bypass state is: `other_visible` comes back
`True` (nothing filters it) in the first two tests, and `current_setting('ccf.tenant_id',
true)` comes back `''`/`None` (never the expected org id) in the third.
`test_reap_stale_still_sweeps_another_org_after_processing_scopes_a_job` passes
already today (there is no scoping yet to leak) — expected and fine; it starts
actually testing something once Step 3 lands.

- [ ] **Step 3: Implement the scoping in `prep/jobs.py`**

Add the import:

```python
from ..db import set_session_tenant
```

Replace `_drive_one` (it no longer catches or rolls back its own failure — that moves
to `run_once`):

```python
async def _drive_one(session: AsyncSession, job: PrepJob) -> str:
    """Advance one already-claimed job's run and update the job to match.

    Does not commit, and does not manage the tenant GUC or catch a DB-level
    failure -- :func:`run_once` sets the tenant to this job's
    ``organization_id``, wraps this call in ``session.begin_nested()``,
    records any failure, commits, and clears the tenant, all *around* this
    function. See :func:`run_once`'s docstring for why the savepoint
    boundary sits there rather than here. Returns ``"done"`` or ``"failed"``
    for the caller's counters; a job left ``pending`` for the next cycle
    counts as neither.
    """
    run = await pipeline.load_run(session, job.run_id)
    if run is None:
        job.status = "failed"
        job.last_error = f"run {job.run_id} no longer exists"
        return "failed"

    await pipeline.advance(session, run)

    # pipeline.advance() reconciles run.organization_id to the source's true
    # org before every stage (see pipeline._reconcile_organization) -- sync
    # the job row to match. Nothing reads PrepJob.organization_id for
    # authorization (claim() has no org filter, by design), but leaving it
    # stale after a reparent would mean "every prep_* row for a run shares
    # one organization" is no longer literally true of this table too.
    job.organization_id = run.organization_id

    if run.status in _TERMINAL:
        job.status = "done"
        return "done"
    if run.status == "failed":
        job.status = "failed"
        job.last_error = run.error
        return "failed"
    # Progress made but stages remain — return it for the next cycle.
    job.status = "pending"
    job.next_stage = pipeline.next_stage(run) or "parse"
    job.claimed_by = None
    job.claimed_at = None
    return "pending"
```

Replace `run_once`:

```python
async def run_once(session: AsyncSession, *, worker: str, limit: int) -> dict[str, int]:
    """Claim and drive a batch of jobs, each committed independently and
    scoped to its own organization while it processes.

    Every job in the batch shares this one ``session``/connection, but not
    one transaction: the claim is committed before any stage work runs, and
    each job's outcome is committed before the next job starts. A worker
    killed partway through the batch therefore loses at most the one job it
    was mid-stage on — not the whole batch, and not the durable ``claimed``
    record (with its ``attempts`` bump) that lets :func:`reap_stale` find
    that job again later.

    **Tenant scoping (2026-08-12 worker-tenant-scoping design).** ``claim()``
    stays unscoped — it reads only ``id``\\ s and writes only claim
    bookkeeping, never evidence content, so a leak there discloses that some
    organization has a queued job, not its contents. Once a job is claimed,
    though, its own processing reads and writes across every one of the
    eleven RLS'd tables (``pipeline.advance`` touches passages,
    classifications, embeddings...) — exactly what migration ``0060``'s
    policy exists to contain — so the tenant GUC is set to *that job's own*
    ``organization_id`` (:func:`ccf.db.set_session_tenant`) immediately
    before :func:`_drive_one` runs, and cleared again, explicitly, right
    after that job's outcome commits. The reset never waits for the next
    job's own assignment to overwrite it: a job that fails before it manages
    to set anything must not inherit its predecessor's scope, and
    :func:`reap_stale` (called by the CLI drain loop, `cli.py`'s
    `_drain_loop`, on its own session immediately after a batch) must see a
    clean, unscoped session regardless of which organization's job ran last.

    The tenant is set *before* entering ``session.begin_nested()``, not
    inside it, matching ``governance.scheduler._run_per_tenant_cycle``'s
    exact ordering. A plain (non-``LOCAL``) ``SET ROLE``/``set_config``
    issued inside a transaction is itself undone by any rollback of that
    transaction — savepoint or full — so setting the tenant *inside* the
    savepoint would mean a failed job's ``ROLLBACK TO SAVEPOINT`` also undoes
    its own tenant scoping, right before the ``except`` branch below needs it
    to record that same job's failure. Setting it outside means the
    savepoint's rollback undoes only the failed job's own writes and clears
    any DB-level ABORTED state (see the scheduler's own docstring for the
    full trap this guards against), while leaving the tenant untouched
    underneath it.

    This is also why :func:`_drive_one` no longer catches or rolls back its
    own DB-level failures the way an earlier version did, directly, with a
    full ``session.rollback()``: that was safe before tenant scoping existed,
    because nothing else was pending in the transaction at that point, but a
    full rollback issued *after* the tenant was set for this job would undo
    that ``SET`` too, same as above. A failure now propagates out of
    ``_drive_one`` to this loop's own ``except``, which records it via a
    direct ``UPDATE`` (not an ORM mutation — ``session.rollback()``/
    ``ROLLBACK TO SAVEPOINT`` expires every ORM object already in the
    session, so ``job``'s in-memory attributes can no longer be trusted to
    still reflect anything set on it before the rollback).
    """
    claimed = await claim(session, worker=worker, limit=limit)
    await session.commit()
    job_ids = [int(j.id) for j in claimed]

    finished = 0
    failed = 0
    for job_id in job_ids:
        job = await session.get(PrepJob, job_id)
        if job is None:  # pragma: no cover - not deletable via any current API
            continue
        job_run_id = int(job.run_id)
        organization_id = int(job.organization_id)
        await set_session_tenant(session, organization_id)
        try:
            async with session.begin_nested():
                outcome = await _drive_one(session, job)
        except Exception as exc:  # a worker must survive any one job
            last_error = str(exc)[:_MAX_LAST_ERROR_CHARS]
            await session.execute(
                update(PrepJob)
                .where(PrepJob.id == job_id)
                .values(status="failed", last_error=last_error)
            )
            log.warning("prep.job_failed", job_id=job_id, run_id=job_run_id, error=last_error)
            outcome = "failed"
        await session.commit()
        await set_session_tenant(session, None)
        if outcome == "done":
            finished += 1
        elif outcome == "failed":
            failed += 1
    return {"claimed": len(claimed), "finished": finished, "failed": failed}
```

- [ ] **Step 4: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_prep_worker_tenant_scoping.py -v   # 4 new tests pass
.venv/bin/pytest tests/test_prep_jobs.py tests/test_rls_worker_guc_bypass.py tests/test_rls_engine_tables.py -v   # no regression to existing claim/reap/failure-path tests
.venv/bin/pytest -q          # run alone, foreground, 300s+ timeout; confirm no regression from the 1031 passed, 1 skipped baseline plus the 4 new tests; cite the actual count in the commit if it differs
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check (all three required):**

1. *The per-job tenant set.* In `run_once`, comment out
   `await set_session_tenant(session, organization_id)`. Re-run
   `tests/test_prep_worker_tenant_scoping.py::test_processing_scopes_to_the_jobs_own_tenant`
   — confirm it now fails (`other_visible` becomes `True`: with no scoping, the
   bypass session sees every organization's row). Revert.
2. *The reset after each job.* Remove `await set_session_tenant(session, None)` after
   the commit. Re-run
   `tests/test_prep_worker_tenant_scoping.py::test_reap_stale_still_sweeps_another_org_after_processing_scopes_a_job`
   — confirm it now fails (`reap_stale`, called on the same still-scoped session,
   misses the other organization's stale claim). Revert.
3. *The failure isolation.* In `run_once`'s `except` block, remove the
   `log.warning(...)` call (keep the `UPDATE` and `outcome = "failed"`). Re-run
   `tests/test_prep_worker_tenant_scoping.py::test_a_failing_job_does_not_leak_its_tenant_to_the_next_job`
   — confirm it now fails on the `any(event == "prep.job_failed" ...)` assertion,
   proving the test would catch a silent swallow, not just a status change. Revert.

Report plainly if any of the three produces no failure, rather than adjusting the test
until it looks right.

```bash
git add src/ccf/prep/jobs.py tests/test_prep_worker_tenant_scoping.py
git commit -m "feat(prep): scope the drain loop's per-job processing to the claimed job's tenant"
```

---

### Task 2: `ccf.assessment.engine.jobs` — the same scoping for the assessment-engine drain loop

**Files:**
- Modify: `src/ccf/assessment/engine/jobs.py`
- Create: `tests/test_assessment_worker_tenant_scoping.py`

**Interfaces:**
- Modifies: `assessment.engine.jobs._drive_one(session, job) -> str` (same change as
  Task 1: no longer catches or rolls back its own DB-level failure).
- Modifies: `assessment.engine.jobs.run_once(session, *, worker, limit) -> dict[str, int]`
  (same shape as Task 1's `run_once`, except the failure `except` block records the
  failure on **two** tables — `AssessmentJob` and its `AssessmentControlProposal` —
  matching what `_drive_one` used to do internally).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_assessment_worker_tenant_scoping.py`:

```python
"""Per-job tenant scoping for the assessment-engine worker's drain loop
(2026-08-12 worker-tenant-scoping design) -- mirrors
``tests/test_prep_worker_tenant_scoping.py`` for
``ccf.assessment.engine.jobs``. See that module's docstring for the two
hazards this exists to catch; the same reasoning applies verbatim, just
against ``AssessmentJob``/``AssessmentControlProposal`` instead of
``PrepJob``/``PrepRun``, and against ``evaluate_control_proposal`` instead of
``pipeline.advance``.

This suite shares the same one-database-no-per-test-wipe reality as the prep
version. ``tests/test_assessment_closure_trigger.py`` in particular leaves
``pending`` ``AssessmentJob`` rows behind by design (its subject is the
closure trigger, not the worker) -- ``tests/test_assessment_jobs.py``'s own
``_isolate`` fixture documents this and wipes the WHOLE ``AssessmentJob``
table, unconditionally, before and after every test in that module. This
module does the same, for the same reason -- sizing ``limit`` to the pending
backlog is not sufficient here on its own, since ``AssessmentJob`` rows
(unlike ``PrepJob`` rows) are cheap enough, and common enough in this suite,
that a full-table wipe is the simpler and more robust guard, matching
``test_assessment_jobs.py``'s own precedent exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, select, text

from ccf.assessment.engine import jobs
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "WTS-88"


@pytest.fixture(autouse=True)
async def _isolate() -> Any:
    """Mirrors ``tests/test_assessment_jobs.py``'s own ``_isolate`` fixture
    and ``tests/test_assessment_closure_worker.py``'s identically-reasoned
    one: ``AssessmentJob`` is a genuinely global queue with no organization
    filter on ``claim``, so any ``pending`` row left by another module in
    this shared, session-scoped database would be claimed alongside this
    module's own jobs and throw off the exact-batch assertions below.
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            await s.execute(delete(AssessmentJob))

    await _wipe()
    yield
    await _wipe()


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Worker Tenant Scoping Fixture Control",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the worker tenant scoping fixture objective is met;",
                source_row=2,
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
        system = System(organization_id=org.id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(org.id), int(assessment.id)


async def test_processing_scopes_to_the_jobs_own_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """A proposal belonging to a DIFFERENT organization -- never queued as a
    job at all -- must not be visible while this job's own evaluation runs.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_id, assessment_id = await _assessment("wts-ae-scope-own")
    other_org_id, other_assessment_id = await _assessment("wts-ae-scope-other")
    async with session_scope() as s:
        job = await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
        job_id, own_proposal_id = int(job.id), int(job.control_proposal_id)
        other_proposal = AssessmentControlProposal(
            organization_id=other_org_id,
            assessment_id=other_assessment_id,
            control_identifier="WTS-SCOPE-OTHER",
        )
        s.add(other_proposal)
        await s.flush()
        other_proposal_id = int(other_proposal.id)

    seen: dict[str, Any] = {}

    async def _fake_evaluate(session: Any, proposal: Any) -> Any:
        own = (
            await session.execute(
                select(AssessmentControlProposal.id).where(
                    AssessmentControlProposal.id == own_proposal_id
                )
            )
        ).scalar_one_or_none()
        other = (
            await session.execute(
                select(AssessmentControlProposal.id).where(
                    AssessmentControlProposal.id == other_proposal_id
                )
            )
        ).scalar_one_or_none()
        seen["own_visible"] = own is not None
        seen["other_visible"] = other is not None

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _fake_evaluate)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["finished"] == 1

    assert seen["own_visible"] is True, "the job could not see its own proposal while processing"
    assert seen["other_visible"] is False, (
        "the job could see another organization's proposal while processing -- "
        "processing is not actually scoped to the claimed job's own tenant"
    )
    async with session_scope() as s:
        row = (await s.execute(select(AssessmentJob).where(AssessmentJob.id == job_id))).scalar_one()
        assert row.status == "done"


async def test_tenant_is_cleared_between_two_organizations_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reset-between-jobs attack, mirrored from the prep worker's
    version: two jobs for two DIFFERENT organizations in one batch on one
    shared session. Order-agnostic -- whichever job runs, it must see its
    own proposal and never the other's.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, assessment_a = await _assessment("wts-ae-reset-a")
    org_b, assessment_b = await _assessment("wts-ae-reset-b")
    async with session_scope() as s:
        job_a = await jobs.enqueue_control(s, assessment_id=assessment_a, control_identifier=_SEQ)
        job_b = await jobs.enqueue_control(s, assessment_id=assessment_b, control_identifier=_SEQ)
        proposal_a_id, proposal_b_id = int(job_a.control_proposal_id), int(job_b.control_proposal_id)

    other_proposal_of = {proposal_a_id: proposal_b_id, proposal_b_id: proposal_a_id}
    events: list[dict[str, Any]] = []

    async def _fake_evaluate(session: Any, proposal: Any) -> Any:
        pid = int(proposal.id)
        if pid in other_proposal_of:
            other_id = other_proposal_of[pid]
            own = (
                await session.execute(
                    select(AssessmentControlProposal.id).where(AssessmentControlProposal.id == pid)
                )
            ).scalar_one_or_none()
            other = (
                await session.execute(
                    select(AssessmentControlProposal.id).where(
                        AssessmentControlProposal.id == other_id
                    )
                )
            ).scalar_one_or_none()
            events.append(
                {"proposal_id": pid, "own_visible": own is not None, "other_visible": other is not None}
            )

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _fake_evaluate)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["claimed"] == 2

    assert len(events) == 2, "both seeded jobs must have been processed and observed"
    for ev in events:
        assert ev["own_visible"] is True, f"proposal {ev['proposal_id']} could not see its own row"
        assert ev["other_visible"] is False, (
            f"proposal {ev['proposal_id']} could see the other organization's row -- if this "
            "is the job processed SECOND, the tenant GUC from the first job's processing was "
            "not cleared before this one began"
        )


async def test_a_failing_job_does_not_leak_its_tenant_to_the_next_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mirrors the prep worker's identical test: the failure-containment
    hazard (the scheduler's own documented ABORTED-transaction trap),
    reproduced here with a REAL DB-level failure -- an unqualified reference
    to a nonexistent table, not a mock exception, since a plain Python
    exception never aborts the underlying Postgres transaction in the first
    place. The job forced to fail must leave no tenant set for the
    surviving job, proved by reading the GUC directly from inside the
    surviving job's own evaluation. Also asserts a warning WAS logged and
    the surviving job actually finished.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a, assessment_a = await _assessment("wts-ae-raise-a")
    org_b, assessment_b = await _assessment("wts-ae-raise-b")
    async with session_scope() as s:
        job_a = await jobs.enqueue_control(s, assessment_id=assessment_a, control_identifier=_SEQ)
        job_b = await jobs.enqueue_control(s, assessment_id=assessment_b, control_identifier=_SEQ)
        proposal_a_id, proposal_b_id = int(job_a.control_proposal_id), int(job_b.control_proposal_id)
    expected_tenant = {proposal_a_id: str(org_a), proposal_b_id: str(org_b)}
    raising_proposal_id = proposal_a_id

    warn_calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(jobs.log, "warning", lambda event, **kw: warn_calls.append((event, kw)))
    seen: dict[int, str] = {}

    async def _fake_evaluate(session: Any, proposal: Any) -> Any:
        pid = int(proposal.id)
        if pid == raising_proposal_id:
            # A genuine DBAPI error, not a mock -- see the docstring above.
            await session.execute(text("SELECT * FROM ccf.this_table_does_not_exist_either"))
            return None
        tenant_guc = (
            await session.execute(text("SELECT current_setting('ccf.tenant_id', true)"))
        ).scalar_one()
        seen[pid] = tenant_guc
        return None

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _fake_evaluate)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)

    surviving_proposal_id = proposal_b_id
    assert seen.get(surviving_proposal_id) == expected_tenant[surviving_proposal_id], (
        f"the surviving job ran under tenant {seen.get(surviving_proposal_id)!r}, expected "
        f"its own {expected_tenant[surviving_proposal_id]!r} -- the failed job's tenant "
        "must not leak into the next job"
    )
    assert any(event == "assessment.job_failed" for event, _ in warn_calls), (
        "a warning must be logged on failure -- a silent swallow is indistinguishable "
        "from a correctly-handled skip otherwise"
    )
    async with session_scope() as s:
        failed = (
            await s.execute(
                select(AssessmentJob).where(AssessmentJob.control_proposal_id == raising_proposal_id)
            )
        ).scalar_one()
        succeeded = (
            await s.execute(
                select(AssessmentJob).where(
                    AssessmentJob.control_proposal_id == surviving_proposal_id
                )
            )
        ).scalar_one()
        failed_proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == raising_proposal_id
                )
            )
        ).scalar_one()
    assert failed.status == "failed"
    assert failed.last_error and "this_table_does_not_exist_either" in failed.last_error
    assert failed_proposal.state == "failed"
    assert failed_proposal.error and "this_table_does_not_exist_either" in failed_proposal.error
    assert succeeded.status == "done", "the surviving job must actually have finished"
    assert stats["failed"] >= 1 and stats["finished"] >= 1


async def test_reap_still_sweeps_another_org_after_processing_scopes_a_job() -> None:
    """``reap_stale_jobs`` must stay unscoped, reused deliberately on the
    SAME session ``run_once`` just used -- see the prep worker's identical
    test for why a fresh ``session_scope()`` would not actually exercise
    this.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_processed, assessment_processed = await _assessment("wts-ae-reap-processed")
    org_stale, assessment_stale = await _assessment("wts-ae-reap-stale")

    async with session_scope() as s:
        job_stale = await jobs.enqueue_control(
            s, assessment_id=assessment_stale, control_identifier=_SEQ
        )
        job_stale.status = "claimed"
        job_stale.claimed_by = "dead-worker"
        job_stale.claimed_at = datetime.now(UTC) - timedelta(hours=3)
        await s.flush()
        stale_job_id = int(job_stale.id)

    async with session_scope() as s:
        await jobs.enqueue_control(
            s, assessment_id=assessment_processed, control_identifier=_SEQ
        )

    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=1)
        assert stats["claimed"] == 1
        reaped = await jobs.reap(s)
        total = reaped["requeued"] + reaped["dead_lettered"]
        assert total >= 1, "reap must still find the OTHER organization's stale claim"

    async with session_scope() as s:
        row = (await s.execute(select(AssessmentJob).where(AssessmentJob.id == stale_job_id))).scalar_one()
        assert row.status == "pending", "the other organization's stale job must be requeued"
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `.venv/bin/pytest tests/test_assessment_worker_tenant_scoping.py -v`
Expected: FAIL for the same reasons as Task 1's Step 2 — `run_once` never calls
`set_session_tenant` today, so `other_visible` comes back `True` and the tenant GUC
check comes back empty/unset in the first three tests.
`test_reap_still_sweeps_another_org_after_processing_scopes_a_job` passes already
today, same as Task 1's equivalent — expected and fine.

- [ ] **Step 3: Implement the scoping in `assessment/engine/jobs.py`**

Add the import:

```python
from ...db import set_session_tenant
```

Replace `_drive_one`:

```python
async def _drive_one(session: AsyncSession, job: AssessmentJob) -> str:
    """Evaluate one already-claimed job's control proposal.

    Does not commit, and does not manage the tenant GUC or catch a DB-level
    failure -- :func:`run_once` sets the tenant to this job's
    ``organization_id``, wraps this call in ``session.begin_nested()``,
    records any failure (on both the job and its proposal), commits, and
    clears the tenant, all *around* this function. See :func:`run_once`'s
    docstring, and ``ccf.prep.jobs.run_once``'s identical reasoning, for why
    the savepoint boundary sits there rather than here. Returns ``"done"``
    or ``"failed"`` for the caller's counters.
    """
    control_proposal_id = int(job.control_proposal_id)
    proposal = (
        await session.execute(
            select(AssessmentControlProposal).where(
                AssessmentControlProposal.id == control_proposal_id
            )
        )
    ).scalar_one_or_none()
    if proposal is None:
        job.status = "failed"
        job.last_error = f"control proposal {control_proposal_id} no longer exists"
        return "failed"

    await evaluate_control_proposal(session, proposal)

    job.status = "done"
    return "done"
```

Replace `run_once`:

```python
async def run_once(session: AsyncSession, *, worker: str, limit: int) -> dict[str, int]:
    """Claim and drive a batch of jobs, each committed independently and
    scoped to its own organization while it processes.

    Mirrors ``ccf.prep.jobs.run_once`` — see that function's docstring for
    the full reasoning behind the claim/commit boundaries and, especially,
    the tenant-scoping ordering (2026-08-12 worker-tenant-scoping design):
    the tenant is set to the claimed job's own ``organization_id`` *before*
    ``session.begin_nested()`` opens, not inside it, and cleared explicitly
    after that job's outcome commits — never left for the next job's own
    assignment to overwrite. ``claim_jobs`` itself stays unscoped (it reads
    only ``id``\\ s and writes only claim bookkeeping); processing does not,
    since :func:`evaluate_control_proposal` reads and writes across the
    RLS'd proposal/objective tables.

    Unlike the prep queue, one job's failure here writes to *two* tables —
    ``AssessmentJob`` and its ``AssessmentControlProposal`` — both inside
    the same direct-``UPDATE`` recovery below, for the same
    expired-object/ORM-mutation-is-unsafe reason ``ccf.prep.jobs`` documents.
    """
    claimed = await claim_jobs(session, AssessmentJob, worker=worker, limit=limit)
    await session.commit()
    job_ids = [int(j.id) for j in claimed]

    finished = 0
    failed = 0
    for job_id in job_ids:
        job = await session.get(AssessmentJob, job_id)
        if job is None:  # pragma: no cover - not deletable via any current API
            continue
        control_proposal_id = int(job.control_proposal_id)
        organization_id = int(job.organization_id)
        await set_session_tenant(session, organization_id)
        try:
            async with session.begin_nested():
                outcome = await _drive_one(session, job)
        except Exception as exc:  # a worker must survive any one job
            last_error = str(exc)[:_MAX_LAST_ERROR_CHARS]
            await session.execute(
                update(AssessmentJob)
                .where(AssessmentJob.id == job_id)
                .values(status="failed", last_error=last_error)
            )
            await session.execute(
                update(AssessmentControlProposal)
                .where(AssessmentControlProposal.id == control_proposal_id)
                .values(state="failed", error=last_error)
            )
            log.warning(
                "assessment.job_failed",
                job_id=job_id,
                control_proposal_id=control_proposal_id,
                error=last_error,
            )
            outcome = "failed"
        await session.commit()
        await set_session_tenant(session, None)
        if outcome == "done":
            finished += 1
        elif outcome == "failed":
            failed += 1
    return {"claimed": len(claimed), "finished": finished, "failed": failed}
```

- [ ] **Step 4: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_assessment_worker_tenant_scoping.py -v   # 4 new tests pass
.venv/bin/pytest tests/test_assessment_jobs.py tests/test_rls_worker_guc_bypass.py tests/test_rls_engine_tables.py tests/test_assessment_closure_worker.py -v   # no regression
.venv/bin/pytest -q          # run alone, foreground, 300s+ timeout; confirm no regression from Task 1's count plus these 4 new tests; cite the actual count in the commit if it differs
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check (all three required):**

1. *The per-job tenant set.* Comment out
   `await set_session_tenant(session, organization_id)` in `run_once`. Re-run
   `tests/test_assessment_worker_tenant_scoping.py::test_processing_scopes_to_the_jobs_own_tenant`
   — confirm it now fails (`other_visible` becomes `True`). Revert.
2. *The reset after each job.* Remove `await set_session_tenant(session, None)`. Re-run
   `tests/test_assessment_worker_tenant_scoping.py::test_reap_still_sweeps_another_org_after_processing_scopes_a_job`
   — confirm it now fails (`reap`, on the same still-scoped session, misses the other
   organization's stale claim). Revert.
3. *The failure isolation.* Remove the `log.warning(...)` call from `run_once`'s
   `except` block (keep both `UPDATE`s and `outcome = "failed"`). Re-run
   `tests/test_assessment_worker_tenant_scoping.py::test_a_failing_job_does_not_leak_its_tenant_to_the_next_job`
   — confirm it now fails on the `any(event == "assessment.job_failed" ...)` assertion.
   Revert.

Report plainly if any of the three produces no failure, rather than adjusting the test
until it looks right.

```bash
git add src/ccf/assessment/engine/jobs.py tests/test_assessment_worker_tenant_scoping.py
git commit -m "feat(assessment): scope the drain loop's per-job evaluation to the claimed job's tenant"
```

---

### Task 3: Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `src/ccf/models_prep.py`
- Modify: `src/ccf/models_assessment_engine.py`
- Modify: `CHANGELOG.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: `docs/ARCHITECTURE.md` — "Evidence preparation" section**

Replace the paragraph (currently reading, in full):

```markdown
  The seven `prep_*` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), matching 121 of Concord's 135
  `ccf` tables — but as defence in depth, not the primary control: every prep
  query still filters by `organization_id` in application code
  (`ccf.prep.retriever._base_filters` and equivalent per-stage filters), and
  `claim()` is **still, intentionally, unscoped by organization**, since one
  worker drains every organization's jobs by design. That claim path runs
  through `ccf.db.session_scope()`, which leaves the tenant GUC unset and the
  bootstrap (table-owning) role in effect — exactly what every policy in this
  schema treats as bypass — so RLS protects these tables only on the request
  path, not on the worker/CLI path; the application-level guards
  (`ccf.prep.sources.resolve_source_organization_id`, `ccf.prep.pipeline`'s
  per-stage organization reconciliation) are what actually protect that path,
  verified by `tests/test_prep_tenant_isolation.py` and (for the GUC
  mechanism itself) `tests/test_rls_worker_guc_bypass.py`. See
  `models_prep.py` for the same note next to the table definitions.
```

with:

```markdown
  The seven `prep_*` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), matching 121 of Concord's 135
  `ccf` tables. Two different scopes apply to the worker path, deliberately
  (2026-08-12 worker-tenant-scoping design): `claim()` is **still,
  intentionally, unscoped by organization**, since one worker drains every
  organization's jobs in a single query, and a claim touches only `id`,
  status and claim bookkeeping on `prep_jobs` itself — never evidence
  content — so a leak there discloses only that some organization has a
  queued job, not its contents. Once a job is claimed, though,
  `ccf.prep.jobs.run_once` sets the tenant GUC to *that job's own*
  `organization_id` (`ccf.db.set_session_tenant`) before driving it through
  `pipeline.advance`, which reads and writes across every one of the eleven
  RLS'd tables — exactly what the policy exists to contain — and clears the
  tenant explicitly after each job commits, rather than relying on the next
  job's own assignment to overwrite it, so a job that fails before setting
  its own tenant can never inherit its predecessor's. `reap_stale_jobs`
  remains deliberately unscoped and runs on the same session immediately
  after the batch, outside any per-job scoping, so it keeps sweeping every
  organization's stale claims regardless of which org's job the batch most
  recently processed. RLS is defence in depth throughout — every prep query
  still filters by `organization_id` in application code
  (`ccf.prep.retriever._base_filters` and equivalent per-stage filters),
  and none of those checks is removed. Verified by
  `tests/test_prep_tenant_isolation.py` (application-level guards),
  `tests/test_rls_worker_guc_bypass.py` (the claim path's GUC/role
  mechanism), and `tests/test_prep_worker_tenant_scoping.py` (the
  processing path's scoping and its reset-between-jobs discipline). See
  `models_prep.py` for the same note next to the table definitions.
```

- [ ] **Step 2: `docs/ARCHITECTURE.md` — "Objective-level assessment engine" section**

Replace the paragraph (currently reading, in full):

```markdown
  The three `assessment_control_proposals` / `assessment_objective_proposals`
  / `assessment_jobs` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), the same as the `prep_*` tables —
  but as defence in depth, not the primary control: every route and service
  function still filters by `organization_id` in application code
  (derived from `Assessment -> System -> Organization`, never from a caller-supplied
  id), and the job claim is **still, intentionally, unscoped**, since one
  worker drains every organization's queue by design. That claim path runs
  through `ccf.db.session_scope()`, which leaves the tenant GUC unset and the
  bootstrap (table-owning) role in effect — exactly what every policy in this
  schema treats as bypass — so RLS protects these three tables only on the
  request path, not on the worker/CLI path; the application-level guard
  (`ccf.assessment.engine.jobs.enqueue_reevaluation`'s `result_org_id`
  check) is what actually protects that path, verified by
  `tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls`
  and (for the GUC mechanism itself) `tests/test_rls_worker_guc_bypass.py`.
```

with:

```markdown
  The three `assessment_control_proposals` / `assessment_objective_proposals`
  / `assessment_jobs` tables carry a `tenant_isolation` RLS policy (migration
  `0060`, 2026-08-12 RLS-coverage design), the same as the `prep_*` tables.
  Two different scopes apply to the worker path, deliberately (2026-08-12
  worker-tenant-scoping design): the job claim (`ccf.queue.claim_jobs`) is
  **still, intentionally, unscoped**, since one worker drains every
  organization's queue in a single query and touches only `id`, status, and
  claim bookkeeping — never proposal or objective content — so a leak there
  discloses at most that some organization has a queued job. Once a job is
  claimed, though, `ccf.assessment.engine.jobs.run_once` sets the tenant GUC
  to *that job's own* `organization_id` before driving it through
  `evaluate_control_proposal`, which reads and writes across all three
  RLS'd tables, and clears the tenant explicitly after each job commits,
  rather than relying on the next job's own assignment to overwrite it. RLS
  is defence in depth throughout — every route and service function still
  filters by `organization_id` in application code (derived from
  `Assessment -> System -> Organization`, never from a caller-supplied id),
  and none of those checks is removed. Verified by
  `tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls`
  (application-level guard), `tests/test_rls_worker_guc_bypass.py` (the
  claim path's GUC/role mechanism), and
  `tests/test_assessment_worker_tenant_scoping.py` (the processing path's
  scoping and its reset-between-jobs discipline).
```

- [ ] **Step 3: `docs/ARCHITECTURE.md` — "RLS coverage" bullet**

Replace the last sentence of the bullet (currently reading):

```markdown
  **RLS here is defence
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

with:

```markdown
  **RLS here is defence
  in depth, not a replacement for application-level scoping** — every route,
  service function, and worker still derives and checks `organization_id` in
  code, and this slice removes none of those checks. The one place RLS
  provides no protection at all is the prep and assessment-engine worker
  processes' own job-*claim* queries, which run unscoped by design (one
  worker drains every organization's queue in a single query, touching only
  job-bookkeeping columns) — everything downstream of a claim, the actual
  processing of that job, runs scoped to the claimed job's own organization
  (2026-08-12 worker-tenant-scoping design) — see "Evidence preparation" and
  "Objective-level assessment engine" above for that one remaining
  exception, named alongside the application-level check that actually
  covers it.
```

- [ ] **Step 4: `src/ccf/models_prep.py`**

After the existing module docstring's final sentence (`...for the same note alongside
the rest of the pipeline's description.`), before the closing `"""`, add:

```
Once a job is claimed, though, its *processing* is no longer unscoped
(2026-08-12 worker-tenant-scoping design): ``ccf.prep.jobs.run_once`` sets
the tenant GUC to the claimed job's own ``organization_id`` before driving
it through ``pipeline.advance`` -- which reads and writes across every one
of these seven tables -- and clears it explicitly after each job commits.
Only the claim query itself remains a deliberate, documented exception, for
the reason above (it touches no evidence content). See
``tests/test_prep_worker_tenant_scoping.py``.
```

- [ ] **Step 5: `src/ccf/models_assessment_engine.py`**

After the existing module docstring's final sentence (`...for the same note alongside
the rest of the engine's description.`), before the closing `"""`, add:

```
Once a job is claimed, though, its *processing* is no longer unscoped
(2026-08-12 worker-tenant-scoping design): ``ccf.assessment.engine.jobs.
run_once`` sets the tenant GUC to the claimed job's own ``organization_id``
before driving it through ``evaluate_control_proposal`` -- which reads and
writes across all three of these tables -- and clears it explicitly after
each job commits. Only the claim query itself remains a deliberate,
documented exception, for the reason above (it touches no proposal or
objective content). See ``tests/test_assessment_worker_tenant_scoping.py``.
```

- [ ] **Step 6: `CHANGELOG.md`**

Add a new `### Added — Worker-path tenant scoping for the prep and assessment-engine
job queues` section as the first entry under `## [Unreleased]`, above the existing
`### Added — Recovery closure for control tests and ConMon` section:

```markdown
### Added — Worker-path tenant scoping for the prep and assessment-engine job queues
- **Once a job is claimed, its processing now runs scoped to that job's own
  tenant.** `ccf.prep.jobs.run_once` and `ccf.assessment.engine.jobs.run_once`
  set the RLS tenant GUC (`ccf.db.set_session_tenant`) to the claimed job's
  own `organization_id` before driving it through `pipeline.advance` /
  `evaluate_control_proposal` — the work that reads and writes across the
  eleven tables migration `0060` policied — and clear it explicitly after
  each job's outcome commits. Previously both drain loops ran their entire
  cycle on an unscoped (bypass) session, so RLS never applied to the paths
  that write the most rows into those tables.
- **The claim query stays deliberately unscoped** — `claim_jobs` still reads
  every organization's pending jobs in one query, touching only `id`,
  status, and claim bookkeeping, never evidence content, so a leak there
  discloses at most that some organization has a queued job. Named and
  documented as the one remaining exception, not left as an unstated gap.
- **The tenant is cleared explicitly after every job, not left for the next
  job's own assignment to overwrite** — a drain loop shares one session
  across jobs from different organizations, and a stale GUC would make the
  next job filter *correctly for the wrong tenant*: silently missing rows,
  not an error.
- **`reap_stale_jobs` stays unscoped**, running immediately after a batch on
  the same session the batch just used, so it keeps sweeping every
  organization's stale claims regardless of which org's job ran last.
- **No application-level check removed, no CLI change, no new role, no
  migration.** A dedicated `ccf_worker` role with explicit `bypassrls` is
  filed as a follow-up — it would add no additional isolation but would
  make the claim path's bypass explicit and auditable rather than an
  implicit property of `session_scope()`.
```

- [ ] **Step 7: Verify and commit**

```bash
.venv/bin/pytest -q          # run alone, foreground, 300s+ timeout; confirm the final count and cite it in the commit
.venv/bin/ruff check . && .venv/bin/mypy src
git add docs/ARCHITECTURE.md src/ccf/models_prep.py src/ccf/models_assessment_engine.py CHANGELOG.md
git commit -m "docs: document per-job tenant scoping on the prep and assessment-engine worker paths"
```

---

## Deferred, deliberately

- **The claim query stays unscoped**, on both queues — this is the load-bearing
  design decision of the whole slice (see the Goal section above), not an oversight
  to revisit later. It is named explicitly in code comments, both model docstrings,
  and `docs/ARCHITECTURE.md`, matching the standard `scanners.py`'s auto-close
  exception already sets in this codebase for "a documented exception is not a gap."
- **No `ccf_worker` role.** Filed as a follow-up in the spec's "What this leaves
  open" section. It would add no additional isolation over what this plan already
  provides — the claim query is still, deliberately, bypass — but would convert that
  bypass from an implicit property of `session_scope()` into an explicit, greppable,
  auditable grant.
- **No change to the CLI.** `cli.py`'s `_drain_loop`/`_assessment_drain_loop` are
  untouched; scoping lives entirely in the library-level `run_once` functions they
  already call.
- **No per-tenant claim loops.** Considered and rejected in the design doc: it would
  turn one query per cycle into one per organization and introduce fairness questions
  the queue does not currently have to answer, to protect the least sensitive
  statement in the whole path (a claim discloses only that a job exists, not its
  contents).
- **No new tables, columns, roles, or migrations.** Alembic head stays `0060`.
- **No shared helper extracted between the two `run_once` loops**, beyond what
  `ccf.queue` already provides. Task 2 documents the concrete places the two loops'
  failure paths diverge (one table updated vs. two, a reconciliation step vs. none,
  a partial-`pending` outcome vs. always-terminal) — the same shape of finding
  `2026-08-12-recovery-closure.md` made about its own two candidate helpers.
