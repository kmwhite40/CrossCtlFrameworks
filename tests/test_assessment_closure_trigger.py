"""Closing an assessment-sourced POA&M enqueues a re-evaluation of the
control it remediated. Idempotent, scan-sourced POA&Ms excluded, and every
tenant check is exercised as an attack, not a happy path.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from ccf.api.main import create_app
from ccf.api.routes import poams as poams_routes
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


async def test_closing_a_scan_sourced_poam_enqueues_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan-sourced POA&M must be skipped *cleanly*, not crash and get swallowed.

    _maybe_enqueue_reevaluation catches every exception so a derived-row
    failure can never fail a close. That makes "skipped correctly" and
    "raised and was swallowed" produce identical observable state -- asserting
    only that no proposal exists passes either way. Deleting the source_ref
    guard entirely left this test green, because the resulting AttributeError
    went straight into that handler.

    So the warning log is asserted too: a clean skip logs nothing.
    """
    warnings: list[str] = []
    monkeypatch.setattr(
        poams_routes.log, "warning", lambda event, **kw: warnings.append(event)
    )

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
    assert warnings == [], (
        "a scan-sourced POA&M must be skipped by the source_ref guard, "
        f"not raise into the best-effort handler; got {warnings}"
    )


async def test_a_control_test_sourced_poam_enqueues_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case the source_ref guard actually exists for.

    The scan test above cannot exercise it: a scan-sourced POA&M has a NULL
    source_ref, so _maybe_enqueue_reevaluation returns before it ever calls
    enqueue_reevaluation. Other creation sites do set one --
    "control_test:{id}" (control_tests.py:202), "conmon:impl:{id}"
    (conmon.py:242), "audit_finding:{id}" (grc.py:590). Without the startswith
    guard, "control_test:N" parses to result_id N and looks up whichever
    AssessmentControlResult holds that id -- an unrelated control's row.

    The id used here is a real AssessmentControlResult id, so a missing guard
    finds something rather than harmlessly finding nothing. Deleting the guard
    leaves every other test in this file green; this one fails.
    """
    warnings: list[str] = []
    monkeypatch.setattr(
        poams_routes.log, "warning", lambda event, **kw: warnings.append(event)
    )
    _org_id, _assessment_id, bridged_poam_id = await _bridged_poam(
        "close-trigger-ctest", monkeypatch
    )

    async with session_scope() as s:
        bridged = await s.get(POAM, bridged_poam_id)
        assert bridged is not None and bridged.source_ref is not None
        real_result_id = bridged.source_ref.split(":", 1)[1]
        system_id = int(bridged.system_id)
        decoy = POAM(
            system_id=system_id,
            title="control test failed",
            status="open",
            severity="moderate",
            source="control_test",
            source_ref=f"control_test:{real_result_id}",
        )
        s.add(decoy)
        await s.flush()
        decoy_id = int(decoy.id)
        s.add(
            PoamMilestone(
                poam_id=decoy_id, description="fixed", status="completed", sort_order=0
            )
        )

    async with _client() as c:
        r = await c.post(f"/api/poams/{decoy_id}/close")
    assert r.status_code == 200

    assert await _proposal_for_poam(decoy_id) is None
    assert warnings == [], f"must be skipped by the guard, not raised into the handler: {warnings}"


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


async def test_enqueue_failure_does_not_poison_the_close_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Enqueueing must be isolated in its own savepoint
    (``async with session.begin_nested()``), not merely wrapped in a bare
    try/except. ``AsyncSession.rollback()`` is not savepoint-scoped: a
    DB-level error raised by ``enqueue_reevaluation`` (not just a plain
    Python exception the ORM can shrug off) leaves the whole session
    transaction aborted unless confined to a savepoint, and every query the
    route still has to run afterward -- re-fetching the POA&M to build the
    response -- would then blow up with an aborted-transaction error instead
    of the clean 200 this asserts. The closure itself is already committed
    by the time this runs, so this is purely about the *response*, not
    losing the closure.
    """
    _, _, poam_id = await _bridged_poam("close-trigger-savepoint", monkeypatch)

    async def _boom(
        session: Any, *, poam_id: int, source_ref: str, organization_id: int
    ) -> AssessmentJob | None:
        # A real DBAPI-level error (division by zero at the database), the
        # same shape as the constraint violation this guards against in
        # production -- not a plain Python exception the ORM would shrug off.
        await session.execute(text("SELECT 1/0"))
        return None  # pragma: no cover - unreachable, the execute above raises

    monkeypatch.setattr(engine_jobs, "enqueue_reevaluation", _boom)

    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/close")
    assert r.status_code == 200
    assert r.json()["status"] == "closed"
