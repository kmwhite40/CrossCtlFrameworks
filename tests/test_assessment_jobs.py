"""``assessment_jobs`` on the shared queue helper -- drives control evaluation."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import delete, select, text, update

from ccf.assessment.engine import jobs, service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "AEJ-77"


@pytest.fixture(autouse=True)
async def _isolate() -> AsyncIterator[None]:
    """``assessment_jobs`` is a genuinely global queue -- ``claim_jobs``
    (``ccf.queue``) has no organization filter, by design, so one worker
    drains jobs for every org. Two contamination sources need clearing, not
    one: this module's own repeated tests (organizations named
    ``"aejobs-%"``, a prefix no other module uses -- ``test_prep_jobs.py``
    uses ``"jobs-%"``, ``test_queue_helper.py`` uses ``"queue-helper-%"``),
    and any ``AssessmentJob`` row a *different* test module left ``pending``
    -- e.g. ``test_assessment_engine_models.py``'s own
    ``test_assessment_job_defaults``, whose org (named ``"ae-job"``, outside
    this module's own prefix) is never touched by an org-scoped delete. A
    stray pending row from either source would be claimed alongside this
    module's own jobs in the full suite and throw off exact-count assertions
    like ``stats["claimed"]``.

    Every ``AssessmentJob`` row is therefore wiped outright, unconditionally
    -- no test anywhere depends on one surviving past its own test -- while
    ``AssessmentControlProposal`` rows (never selected without an
    org/assessment filter, so not a contamination risk the same way) are only
    cleared for this module's own organizations.
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            await s.execute(delete(AssessmentJob))
            org_ids = (
                (
                    await s.execute(
                        select(Organization.id).where(Organization.name.like("aejobs-%"))
                    )
                )
                .scalars()
                .all()
            )
            if org_ids:
                await s.execute(
                    delete(AssessmentControlProposal).where(
                        AssessmentControlProposal.organization_id.in_(org_ids)
                    )
                )

    await _wipe()
    yield
    await _wipe()


@pytest.fixture(autouse=True)
async def _catalog_rows() -> AsyncIterator[None]:
    """One addressable control plus a single sub-clause objective row.

    Mirrors ``tests/test_assessment_service.py``'s fixture shape: a parent row
    with a bare "Determine if:" header, and a sub-clause row carrying the
    actual objective text with ``control_name`` NULL.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Test Control For Job Queue",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the thing under test is defined;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def _assessment(name: str) -> tuple[int, int]:
    """Create an org + system + assessment. Returns ``(org_id, assessment_id)``."""
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


def _fake_evaluate_always(verdict: str = "satisfied"):
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(verdict=verdict, rationale="ok", confidence=0.5)

    return _fake


async def test_enqueue_opens_a_proposal_and_a_pending_job() -> None:
    org_id, assessment_id = await _assessment("aejobs-enqueue")
    async with session_scope() as s:
        job = await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
        assert job.status == "pending"
        assert job.organization_id == org_id
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == job.control_proposal_id
                )
            )
        ).scalar_one()
        assert proposal.assessment_id == assessment_id
        assert proposal.control_identifier == _SEQ


async def test_enqueue_reuses_an_outstanding_pending_job_rather_than_queuing_another(
) -> None:
    """I6: the proposal is idempotent; the job was not. Three POSTs for a
    large control (e.g. AC-4, ~98 objectives) previously queued three full
    evaluations -- ~294 model calls -- and let two workers claim two of them
    concurrently for the one proposal, colliding on the objective-label
    unique constraint. A second enqueue while the first job is still pending
    must return that same job, not create a new one.
    """
    _, assessment_id = await _assessment("aejobs-dedup-pending")
    async with session_scope() as s:
        first = await jobs.enqueue_control(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        second = await jobs.enqueue_control(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
    assert first.id == second.id

    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(AssessmentJob).where(
                        AssessmentJob.control_proposal_id == first.control_proposal_id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1


async def test_enqueue_reuses_a_claimed_job_too() -> None:
    """A job already claimed by a worker (mid-evaluation) is still going to
    run -- must not be duplicated either, only a job in a terminal state
    (done/failed) should trigger a fresh one.
    """
    _, assessment_id = await _assessment("aejobs-dedup-claimed")
    async with session_scope() as s:
        first = await jobs.enqueue_control(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        first_id = int(first.id)
        await s.execute(
            update(AssessmentJob).where(AssessmentJob.id == first_id).values(status="claimed")
        )

    async with session_scope() as s:
        second = await jobs.enqueue_control(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
    assert int(second.id) == first_id


async def test_enqueue_after_a_job_reaches_a_terminal_state_creates_a_fresh_one() -> None:
    """A caller re-enqueuing after done/failed wants a fresh evaluation, not
    the stale result of the last one -- must NOT be deduplicated.
    """
    _, assessment_id = await _assessment("aejobs-dedup-terminal")
    async with session_scope() as s:
        first = await jobs.enqueue_control(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        first_id = int(first.id)
        await s.execute(
            update(AssessmentJob).where(AssessmentJob.id == first_id).values(status="done")
        )

    async with session_scope() as s:
        second = await jobs.enqueue_control(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
    assert int(second.id) != first_id

    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(AssessmentJob).where(
                        AssessmentJob.control_proposal_id == first.control_proposal_id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 2


async def test_run_once_drives_a_job_to_done(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())
    _, assessment_id = await _assessment("aejobs-cycle")
    async with session_scope() as s:
        job = await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
        job_id = int(job.id)

    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["claimed"] == 1
        assert stats["finished"] == 1
        assert stats["failed"] == 0

    async with session_scope() as s:
        job = (
            await s.execute(select(AssessmentJob).where(AssessmentJob.id == job_id))
        ).scalar_one()
        assert job.status == "done"
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == job.control_proposal_id
                )
            )
        ).scalar_one()
        assert proposal.state == "complete"
        assert proposal.proposed_finding == "satisfied"


async def test_a_failing_job_records_a_durable_last_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Roll back before recording, so an aborted transaction cannot lose it.

    Reproduces a genuine DBAPI error (an unqualified reference to a
    nonexistent table), not a mock -- a raw DBAPI error leaves Postgres
    refusing any further statement on the transaction until it is rolled
    back, so the same ORM-mutation-then-commit sequence a plain Python
    exception tolerates would instead raise out of ``run_once`` itself,
    losing ``last_error`` entirely (the job would stay ``"claimed"`` with
    ``last_error=NULL``).
    """
    _, assessment_id = await _assessment("aejobs-failure")
    async with session_scope() as s:
        job = await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
        job_id = int(job.id)

    async def _boom(session: Any, proposal: Any) -> Any:
        await session.execute(text("SELECT * FROM ccf.this_table_does_not_exist_at_all"))

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _boom)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["failed"] == 1
        assert stats["finished"] == 0

    async with session_scope() as s:
        job = (
            await s.execute(select(AssessmentJob).where(AssessmentJob.id == job_id))
        ).scalar_one()
    assert job.status == "failed"
    assert job.last_error, "last_error must survive, not be lost to the aborted transaction"
    assert "this_table_does_not_exist_at_all" in job.last_error


async def test_a_failing_job_also_records_the_failure_on_its_control_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I3: evaluate_control_proposal sets proposal.state = "draft" as its
    first act, but that assignment lives only in the transaction _drive_one
    rolls back on failure -- so before this fix, a crashed evaluation left
    the proposal looking merely "draft" in the DB, indistinguishable from
    "queued but never started", with AssessmentControlProposal.error never
    written at all. An operator had no way to learn why a proposal was stuck.
    """
    _, assessment_id = await _assessment("aejobs-proposal-error")
    async with session_scope() as s:
        job = await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
        job_id = int(job.id)
        control_proposal_id = int(job.control_proposal_id)

    async def _boom(session: Any, proposal: Any) -> Any:
        await session.execute(text("SELECT * FROM ccf.this_table_does_not_exist_either"))

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _boom)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["failed"] == 1

    async with session_scope() as s:
        job = (
            await s.execute(select(AssessmentJob).where(AssessmentJob.id == job_id))
        ).scalar_one()
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == control_proposal_id
                )
            )
        ).scalar_one()
    assert job.status == "failed"
    assert proposal.state == "failed"
    assert proposal.error, "AssessmentControlProposal.error must be written on failure"
    assert "this_table_does_not_exist_either" in proposal.error


async def test_one_job_failing_does_not_strand_the_rest_of_the_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """5 jobs across 5 orgs, job 2 raises: the other 4 still reach done."""
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate_always())

    job_ids: list[int] = []
    org_ids: list[int] = []
    for i in range(5):
        _, assessment_id = await _assessment(f"aejobs-batch-{i}")
        async with session_scope() as s:
            job = await jobs.enqueue_control(
                s, assessment_id=assessment_id, control_identifier=_SEQ
            )
            job_ids.append(int(job.id))
            org_ids.append(int(job.organization_id))

    failing_org_id = org_ids[1]
    real_evaluate = jobs.evaluate_control_proposal

    async def _maybe_boom(session: Any, proposal: Any) -> Any:
        if int(proposal.organization_id) == failing_org_id:
            raise RuntimeError("simulated evaluation failure on job 2")
        return await real_evaluate(session, proposal)

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _maybe_boom)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker="w1", limit=5)
        assert stats["claimed"] == 5
        assert stats["finished"] == 4
        assert stats["failed"] == 1

    async with session_scope() as s:
        rows = (
            (await s.execute(select(AssessmentJob).where(AssessmentJob.id.in_(job_ids))))
            .scalars()
            .all()
        )
    by_id = {int(j.id): j for j in rows}
    statuses = [by_id[jid].status for jid in job_ids]
    assert statuses.count("done") == 4
    assert statuses.count("failed") == 1
    assert by_id[job_ids[1]].status == "failed"
    assert by_id[job_ids[1]].last_error


async def test_the_claim_is_committed_before_evaluation_begins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The claim (and its ``attempts`` bump) must be durable before evaluation
    runs -- not merely flushed into ``run_once``'s own uncommitted transaction
    -- otherwise a worker crash during evaluation would silently roll the
    claim back too, and ``reap`` would never see the job as stale. Proved by
    reading the job from an *independent* session inside the patched
    evaluator -- a second connection can only see what is actually committed,
    not merely what is visible within ``run_once``'s own session.
    """
    _, assessment_id = await _assessment("aejobs-durable-claim")
    async with session_scope() as s:
        job = await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
        job_id = int(job.id)

    seen: dict[str, Any] = {}

    async def _check_from_another_session(session: Any, proposal: Any) -> Any:
        async with session_scope() as s2:
            row = (
                await s2.execute(select(AssessmentJob).where(AssessmentJob.id == job_id))
            ).scalar_one()
            seen["status"] = row.status
            seen["attempts"] = row.attempts
        raise RuntimeError("stop before real evaluation runs")

    monkeypatch.setattr(jobs, "evaluate_control_proposal", _check_from_another_session)
    async with session_scope() as s:
        await jobs.run_once(s, worker="w1", limit=5)

    assert seen["status"] == "claimed"
    assert seen["attempts"] == 1
