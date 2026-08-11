"""HTTP surface for proposal rejection and live calibration metrics.

Mirrors ``test_assessment_engine_api.py``'s approach: exercised through the
real, authenticated HTTP path (bearer token -> ``get_principal`` ->
``deps.get_session``), and the tenant-isolation tests are written as attacks
-- asserting 404 (never 403, so a response cannot confirm another tenant's id
exists) and asserting on rows/values, not just status codes.

This closes out the one assertion Task 2's calibration-metrics tests could
not write yet, because no route existed at the time
(``test_calibration_metrics.py`` covers only ``compute_metrics`` directly):
an org-A principal hitting ``/reject`` or ``/calibration`` must never see or
touch org B's decisions.

Fixtures are built directly at the ORM layer (``AssessmentControlProposal``
rows inserted straight into ``session_scope()``, as
``test_calibration_snapshot.py``'s ``_decided`` helper does) rather than
running a real evaluation through the catalog + AI gateway --
``reject_control_proposal`` only cares about a proposal's ``state``, not how
it got there, so nothing else needs to be real.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from typer.testing import CliRunner

from ccf import cli
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System, User
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")

runner = CliRunner()


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
    """``/api/assessment-engine/*`` is only registered when
    ``CCF_ASSESSMENT_ENGINE_ENABLED`` is set -- off by default. Set here
    rather than flipping the default; the one test that needs it unset
    overrides it locally.
    """
    os.environ["CCF_ASSESSMENT_ENGINE_ENABLED"] = "true"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_ASSESSMENT_ENGINE_ENABLED", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
    """Create an org + a real (viewer-role, non-admin) user in it; return
    (bearer token, org id) -- identical shape to
    ``test_assessment_engine_api.py::_mk_user``.
    """
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _assessment_for(org_id: int, name: str) -> int:
    async with session_scope() as s:
        system = System(organization_id=org_id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(assessment.id)


async def _proposal(
    org_id: int,
    assessment_id: int,
    control: str,
    *,
    state: str = "complete",
    proposed_finding: str | None = "satisfied",
    corrected_finding: str | None = None,
    accepted_by: str | None = None,
    rejected_by: str | None = None,
) -> int:
    """Insert one control-proposal row directly, bypassing evaluation entirely
    -- ``reject_control_proposal`` and ``compute_metrics`` only read ``state``,
    ``proposed_finding`` and ``corrected_finding``, so nothing else needs a
    real evaluation run behind it.
    """
    async with session_scope() as s:
        proposal = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier=control,
            state=state,
            proposed_finding=proposed_finding,
            corrected_finding=corrected_finding,
            accepted_by=accepted_by,
            rejected_by=rejected_by,
        )
        s.add(proposal)
        await s.flush()
        return int(proposal.id)


# --- Reject: happy path and refusals ------------------------------------------


async def test_reject_records_the_correction_and_returns_200() -> None:
    token, org_id = await _mk_user("reject-a@calib-api.test", "Calib API Reject Org")
    assessment_id = await _assessment_for(org_id, "reject")
    proposal_id = await _proposal(org_id, assessment_id, "AC-2", proposed_finding="satisfied")

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/reject",
            json={"corrected_finding": "other_than_satisfied", "note": "no evidence of MFA"},
            headers=_auth(token),
        )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "rejected"
    assert body["corrected_finding"] == "other_than_satisfied"
    assert body["rejection_note"] == "no evidence of MFA"
    assert body["rejected_by"] == "reject-a@calib-api.test"

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert row.state == "rejected"
        assert row.corrected_finding == "other_than_satisfied"
        assert row.rejection_note == "no evidence of MFA"
        assert row.rejected_by == "reject-a@calib-api.test"


async def test_reject_refuses_an_already_decided_proposal_with_409() -> None:
    """The guard stopping a reject from re-deciding an already-accepted
    proposal must survive the HTTP layer and surface as a real client error,
    not a 500 -- matching how repeat acceptance already behaves.
    """
    token, org_id = await _mk_user("reject-decided-a@calib-api.test", "Calib API Decided Org")
    assessment_id = await _assessment_for(org_id, "reject-decided")
    proposal_id = await _proposal(
        org_id,
        assessment_id,
        "AC-2",
        state="accepted",
        proposed_finding="satisfied",
        accepted_by="someone-else@calib-api.test",
    )

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/reject",
            json={"corrected_finding": "other_than_satisfied", "note": "too late"},
            headers=_auth(token),
        )
    assert response.status_code == 409

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert row.state == "accepted", "a refused reject must leave the proposal untouched"
        assert row.corrected_finding is None
        assert row.rejected_by is None


async def test_reject_rejects_insufficient_evidence_as_a_correction() -> None:
    token, org_id = await _mk_user("reject-ie-a@calib-api.test", "Calib API IE Org")
    assessment_id = await _assessment_for(org_id, "reject-ie")
    proposal_id = await _proposal(org_id, assessment_id, "AC-2", proposed_finding="satisfied")

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/reject",
            json={"corrected_finding": "insufficient_evidence", "note": "cannot tell either"},
            headers=_auth(token),
        )
    assert response.status_code == 409

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert row.state == "complete", "a refused reject must leave the proposal untouched"


async def test_reject_requires_a_note() -> None:
    token, org_id = await _mk_user("reject-note-a@calib-api.test", "Calib API Note Org")
    assessment_id = await _assessment_for(org_id, "reject-note")
    proposal_id = await _proposal(org_id, assessment_id, "AC-2", proposed_finding="satisfied")

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/reject",
            json={"corrected_finding": "other_than_satisfied", "note": ""},
            headers=_auth(token),
        )
    assert response.status_code == 422

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert row.state == "complete", "a rejected-without-a-note request must write nothing"


# --- Calibration: happy path and the empty-denominator distinction -----------


async def test_calibration_returns_metrics_for_the_principals_org() -> None:
    token, org_id = await _mk_user("calib-a@calib-api.test", "Calib API Metrics Org")
    assessment_id = await _assessment_for(org_id, "calib-metrics")
    # Asymmetric: 3 accepted, 1 missed-finding rejection -- not a 50/50 split,
    # so a transposed agreed/decided or accepted/rejected mapping could not
    # pass this by accident.
    await _proposal(org_id, assessment_id, "AC-2", state="accepted", proposed_finding="satisfied")
    await _proposal(org_id, assessment_id, "AC-3", state="accepted", proposed_finding="satisfied")
    await _proposal(org_id, assessment_id, "AC-4", state="accepted", proposed_finding="satisfied")
    await _proposal(
        org_id,
        assessment_id,
        "SC-7",
        state="rejected",
        proposed_finding="satisfied",
        corrected_finding="other_than_satisfied",
        rejected_by="assessor@calib-api.test",
    )

    async with _client() as client:
        response = await client.get("/api/assessment-engine/calibration", headers=_auth(token))
    assert response.status_code == 200
    body = response.json()
    assert body["decided"] == 4
    assert body["agreed"] == 3
    assert body["missed_findings"] == 1
    assert body["false_alarms"] == 0
    assert body["agreement_rate"] == pytest.approx(0.75)
    assert body["by_family"]["AC"]["decided"] == 3
    assert body["by_family"]["SC"]["missed_findings"] == 1


async def test_calibration_reports_no_decisions_rather_than_zero_percent() -> None:
    """decided == 0 must be legible as 'nothing decided yet', not as 0%
    accuracy -- collapsing an empty denominator into 0.0 would misrepresent
    an engine that has made zero calls as one that is always wrong.
    """
    token, org_id = await _mk_user("calib-empty-a@calib-api.test", "Calib API Empty Org")
    assessment_id = await _assessment_for(org_id, "calib-empty")
    # A proposal that exists but is not yet decided must not count either.
    await _proposal(org_id, assessment_id, "AC-2", state="complete", proposed_finding="satisfied")

    async with _client() as client:
        response = await client.get("/api/assessment-engine/calibration", headers=_auth(token))
    assert response.status_code == 200
    body = response.json()
    assert body["decided"] == 0
    assert body["agreement_rate"] is None, (
        "an empty denominator must not present as 0.0 -- that reads as 'always wrong', "
        "not as 'nothing decided yet'"
    )


# --- Attacks: cross-tenant reject/calibration must both refuse ---------------


async def test_an_org_a_principal_cannot_reject_an_org_b_proposal() -> None:
    """404, not 403 -- do not confirm another tenant's ids exist. Assert on
    rows: org B's proposal is unchanged afterwards.
    """
    token_a, _org_a = await _mk_user("reject-atk-a@calib-tenant.test", "Calib Tenant Reject A")
    _token_b, org_b = await _mk_user("reject-atk-b@calib-tenant.test", "Calib Tenant Reject B")
    assessment_b = await _assessment_for(org_b, "reject-victim")
    proposal_id = await _proposal(org_b, assessment_b, "AC-2", proposed_finding="satisfied")

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/reject",
            json={"corrected_finding": "other_than_satisfied", "note": "attacker's note"},
            headers=_auth(token_a),
        )
    assert response.status_code == 404

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert row.state == "complete", "an org-A caller must not reject org B's proposal"
        assert row.corrected_finding is None
        assert row.rejected_by is None
        assert row.rejection_note is None


async def test_calibration_never_includes_another_orgs_decisions() -> None:
    """Attack-shaped: seed org B with a rejection, assert it is absent from
    org A's response body, by value not just by count.
    """
    token_a, org_a = await _mk_user("calib-atk-a@calib-tenant.test", "Calib Tenant Metrics A")
    _token_b, org_b = await _mk_user("calib-atk-b@calib-tenant.test", "Calib Tenant Metrics B")
    assessment_a = await _assessment_for(org_a, "calib-atk-a")
    assessment_b = await _assessment_for(org_b, "calib-atk-b")

    await _proposal(org_a, assessment_a, "AC-2", state="accepted", proposed_finding="satisfied")
    # Org B's decision uses a distinct control family (SC, not AC) and a
    # distinguishable disagreement shape, so a leak shows up by value, not
    # merely by an inflated count.
    await _proposal(
        org_b,
        assessment_b,
        "SC-7",
        state="rejected",
        proposed_finding="satisfied",
        corrected_finding="other_than_satisfied",
        rejected_by="victim-assessor@calib-tenant.test",
    )

    async with _client() as client:
        response = await client.get("/api/assessment-engine/calibration", headers=_auth(token_a))
    assert response.status_code == 200
    body = response.json()
    assert body["decided"] == 1, "org B's decision must not inflate org A's count"
    assert body["agreed"] == 1
    assert body["missed_findings"] == 0, "org B's missed finding must not leak into org A"
    assert "SC" not in body["by_family"], "org B's control family must not appear in org A's body"


# --- Feature-flag gating -------------------------------------------------------


async def test_endpoints_are_absent_when_the_engine_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("disabled-a@calib-api.test", "Calib API Disabled Org")
    assessment_id = await _assessment_for(org_id, "disabled")
    proposal_id = await _proposal(org_id, assessment_id, "AC-2", proposed_finding="satisfied")
    monkeypatch.setenv("CCF_ASSESSMENT_ENGINE_ENABLED", "false")
    get_settings.cache_clear()

    async with _client() as client:
        reject_response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/reject",
            json={"corrected_finding": "other_than_satisfied", "note": "n/a"},
            headers=_auth(token),
        )
        calibration_response = await client.get(
            "/api/assessment-engine/calibration", headers=_auth(token)
        )
    assert reject_response.status_code == 404
    assert calibration_response.status_code == 404
    get_settings.cache_clear()


def test_the_cli_exits_cleanly_when_the_engine_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ccf calibration-snapshot`` is gated exactly like ``ccf
    assessment-worker`` (see ``test_assessment_worker_cli.py``): a disabled
    engine exits 0 with a clear message and does no work.
    """
    settings = get_settings()
    monkeypatch.setattr(settings, "assessment_engine_enabled", False)

    result = runner.invoke(cli.app, ["calibration-snapshot", "1"])

    assert result.exit_code == 0
    assert "disabled" in result.stdout.lower()
