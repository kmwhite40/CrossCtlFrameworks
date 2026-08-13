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
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-97"


@pytest.fixture(autouse=True)
async def _isolate_jobs() -> Any:
    """``assessment_jobs`` is a genuinely global queue -- ``claim_jobs``
    (``ccf.queue``) has no organization filter, by design, so ``run_once``
    here would claim any ``pending`` ``AssessmentJob`` left behind by another
    module, not just the one this test enqueues. In full-suite order,
    ``test_assessment_closure_trigger.py`` (alphabetically first) enqueues
    several and never drains them -- its subject is the trigger, not the
    worker. Left unguarded, this test's ``stats == {"claimed": 1, ...}``
    assertion would pick those up too and fail only when run alongside other
    modules, exactly the trap ``test_assessment_jobs.py``'s own ``_isolate``
    fixture documents and fixes the same way: wipe the whole table, not just
    this module's rows.
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
