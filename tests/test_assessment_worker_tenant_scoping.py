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
    _org_id, assessment_id = await _assessment("wts-ae-scope-own")
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
        row = (
            await s.execute(select(AssessmentJob).where(AssessmentJob.id == job_id))
        ).scalar_one()
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
    _org_a, assessment_a = await _assessment("wts-ae-reset-a")
    _org_b, assessment_b = await _assessment("wts-ae-reset-b")
    async with session_scope() as s:
        job_a = await jobs.enqueue_control(s, assessment_id=assessment_a, control_identifier=_SEQ)
        job_b = await jobs.enqueue_control(s, assessment_id=assessment_b, control_identifier=_SEQ)
        proposal_a_id = int(job_a.control_proposal_id)
        proposal_b_id = int(job_b.control_proposal_id)

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
                {
                    "proposal_id": pid,
                    "own_visible": own is not None,
                    "other_visible": other is not None,
                }
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
    to a nonexistent table, not a mock exception -- since a plain Python
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
        proposal_a_id = int(job_a.control_proposal_id)
        proposal_b_id = int(job_b.control_proposal_id)
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
                select(AssessmentJob).where(
                    AssessmentJob.control_proposal_id == raising_proposal_id
                )
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
    _org_processed, assessment_processed = await _assessment("wts-ae-reap-processed")
    _org_stale, assessment_stale = await _assessment("wts-ae-reap-stale")

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
        row = (
            await s.execute(select(AssessmentJob).where(AssessmentJob.id == stale_job_id))
        ).scalar_one()
        assert row.status == "pending", "the other organization's stale job must be requeued"
