# Worker Tenant Scoping — Design

**Date:** 2026-08-12
**Status:** Approved (design), pending implementation plan
**Slice:** hardening; the last item of filed debt from the RLS coverage work
**Depends on:** the branch state at `a2b0120` on `feat/evidence-prep-spine`

## Context

Migration `0060` put a `tenant_isolation` policy on the eleven tables the
evidence-prep and assessment-engine slices created. That policy protects them on
the **request path only**. `ccf.db.session_scope` (`src/ccf/db.py:98`) calls
`set_session_tenant(session, None)` — commented *"CLI/ETL run unscoped
(bypass)"* — and the policy's `current_tenant() IS NULL` escape means RLS does
not filter those sessions at all.

So the paths that write the most rows into those tables are the paths RLS does
not cover.

### What is actually unscoped, established by reading rather than assumed

Narrower than the debt note implied:

- **The governance scheduler is already scoped.** `_run_per_tenant_cycle`
  (`src/ccf/governance/scheduler.py:61`) runs each organization's slice under its
  own `set_session_tenant`, with a savepoint per step so one org's DB-level
  failure cannot abort the shared transaction and take the cycle down.
- **The two queue workers are not** — `src/ccf/prep/jobs.py` and
  `src/ccf/assessment/engine/jobs.py`, which claim and drive jobs across all
  tenants on one unscoped session.
- **The CLI is not**, for every command.

The scheduler is the precedent this design follows. The pattern already exists in
this codebase; the workers simply never adopted it.

### The enabling fact

`JobLike` (`src/ccf/queue.py:115`) **requires `organization_id`** on every job
model, and both `PrepJob` and `AssessmentJob` carry it. A claimed job therefore
already knows which tenant it belongs to, with no lookup and no new column.

## Goals

1. The work that touches tenant data on the worker paths runs with the tenant GUC
   set, so RLS applies to it.
2. No loss of claim throughput and no change to the queue's concurrency
   semantics.
3. The remaining unscoped surface is small, named, and deliberate.

## Non-goals

- **No change to `claim_jobs`' query shape.** `SELECT ... FOR UPDATE SKIP LOCKED`
  plus the atomic `UPDATE` stays exactly as it is.
- **No per-tenant claim loops.** Considered and rejected — see below.
- **No removal of any application-level check.** RLS is defence in depth. The
  worker-path ownership guard in `prep/jobs.py` was only just given its own test;
  it stays.
- **No new role.** Filed as a follow-up instead — see "What this leaves open".
- **No change to the CLI**, whose commands are operator-run and single-tenant by
  invocation. Scoping them is a separate question with a different risk profile.

## The design: claim unscoped, process scoped

`claim_jobs` keeps its single cross-tenant query. Once a job is claimed, the
worker sets the tenant to **that job's `organization_id`** for the processing
work, and clears it afterwards.

**Why the claim itself does not need scoping.** It reads only `id` from a single
jobs table and writes only status, attempts and claim bookkeeping to rows it just
selected. It never touches evidence, passages, proposals or citations. A leak
there would disclose that some other tenant has a queued job — not its contents.
Scoping it would turn one query per cycle into one per organization and introduce
fairness questions the queue does not currently have to answer, in exchange for
protecting the least sensitive statement in the whole path.

**Why the processing does.** `pipeline.advance` and `evaluate_control_proposal`
read and write across every one of the eleven policied tables — evidence
passages, classifications, embeddings, objective verdicts, citations. That is
where a missing organization filter becomes a cross-tenant disclosure, and it is
exactly what the RLS policy was written to contain.

This is the same shape the scheduler already uses: **scope around the unit of
work, not around the dispatch.**

### Failure containment, which is not optional here

The scheduler's docstring records the trap in detail and it applies unchanged: on
a DB-level failure the whole shared Postgres transaction goes ABORTED, and a bare
`try/except` swallows the Python exception while leaving the abort in place — so
the *next* statement on that session, even a later job's `set_session_tenant`,
raises and takes down the whole drain loop.

Each job's processing therefore runs inside `session.begin_nested()`, whose
`ROLLBACK TO SAVEPOINT` undoes the failed work *and* clears the abort. Note also
that `AsyncSession.rollback()` is **not** savepoint-scoped and unwinds
everything; slice 3 shipped a version that silently discarded the caller's work
while reporting success.

The workers already commit each job's outcome independently — that discipline
stays, and `reap_stale_jobs` must remain **inside** the loop, not outside it. A
fix wave in an earlier slice moved it out and silently disabled the dead-letter
net.

### The tenant must be cleared between jobs

A drain loop processes jobs from different organizations on one session. If the
GUC set for job N survives into job N+1, that job runs under the wrong tenant —
and because RLS would then filter *correctly for the wrong org*, the symptom is
not an error but silently missing rows: a stage that appears to succeed having
seen nothing. Reset explicitly after each job rather than relying on the next
job's assignment, so a job that fails before it sets its own tenant cannot
inherit its predecessor's.

## Risk

The realistic failure is a worker query that legitimately needs to see across
tenants — a metrics roll-up, a reaper sweep — and silently returns nothing once
scoped. `reap_stale_jobs` is the obvious candidate: it sweeps stale claims across
all tenants and **must stay unscoped**, which means it has to run outside the
per-job scoping, not inside it.

The suite is the net: 1031 passed, 1 skipped before this slice, with roughly 200
tests across the eleven tables. A path that breaks under scoping should fail
loudly. The one that will not fail loudly is a path that starts returning zero
rows and treats that as "nothing to do" — those are found by reading the drain
loops for cross-tenant reads, not by running the suite, and that reading is part
of the work.

## Testing

- **Per worker:** a job for org A processes with the tenant set to org A —
  asserted by observing that a row belonging to org B is *not* visible from
  inside the processing, not merely that the GUC was assigned.
- **The reset between jobs, asserted as an attack:** queue two jobs for
  different organizations, and assert the second cannot see the first's rows.
  Make the two orgs' data **different** so a leak is visible; an identical
  fixture would pass against code that never switched tenant.
- **A job that raises leaves no tenant set** for the next one.
- **`reap_stale_jobs` still sweeps across tenants** — assert it reaps a stale
  claim belonging to an organization other than the last one processed. This is
  the test that catches over-scoping, which is the likelier mistake.
- **Failure containment:** force one job to fail at the DB level and assert the
  drain loop continues and later jobs still commit — the scheduler's documented
  ABORTED-transaction trap, reproduced for the workers.
- **No regression:** the full suite, run alone, unchanged.
- **Mutation discipline:** every guard verified by deleting it and confirming a
  test fails. Roughly two dozen defects in this project were found that way and
  almost none by reading. Note the recurring trap: a best-effort
  `except Exception` makes "correctly skipped" and "raised and was swallowed"
  observably identical — three findings in the last slice alone traced to it — so
  any test asserting only that nothing happened must **also** assert nothing was
  logged at warning, and that the intended work did occur.

## What this leaves open

**The claim query remains unscoped by design.** That is a deliberate exception
and must be documented as one, with its reason, the way `scanners.py`'s
auto-close is documented as a deliberate exception to the POA&M closure gate. An
undocumented unscoped path is indistinguishable from a bug.

**A dedicated `ccf_worker` role** with explicit `bypassrls` is filed as a
follow-up. It adds no isolation, but it converts the remaining bypass from an
implicit property of `session_scope` into an explicit, greppable, auditable
grant. Worth doing; not worth blocking this on.

**The CLI stays unscoped.** Its commands are operator-run and single-tenant by
invocation, and scoping them is a separate question about operator ergonomics
rather than about tenant isolation between concurrent workloads.

## Documentation

`docs/ARCHITECTURE.md` and `CHANGELOG.md` state what is now scoped, what remains
deliberately unscoped and why, and — this matters — **correct the existing claim
that these tables are protected on the request path only**, which becomes
outdated the moment this ships. A reader must be able to tell, without reading
the code, which paths RLS covers.
