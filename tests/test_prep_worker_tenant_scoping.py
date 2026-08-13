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
                {
                    "run_id": int(run.id),
                    "own_visible": own is not None,
                    "other_visible": other is not None,
                }
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
        failed = (
            await s.execute(select(PrepJob).where(PrepJob.run_id == raising_run_id))
        ).scalar_one()
        succeeded = (
            await s.execute(select(PrepJob).where(PrepJob.run_id == surviving_run_id))
        ).scalar_one()
    assert failed.status == "failed"
    assert failed.last_error and "this_table_does_not_exist_at_all" in failed.last_error
    assert succeeded.status == "done", (
        "the surviving job must actually have finished, not merely 'not failed'"
    )
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
