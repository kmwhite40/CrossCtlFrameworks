"""REST surface for the objective-level assessment engine.

**Highest-risk module in this slice.** Three endpoints in the previous slice
shipped trusting a client-supplied ``organization_id``, which an adversarial
review demonstrated as both a cross-tenant read leak and a laundering path
(see ``test_prep_tenant_isolation.py`` for that regression's full writeup).
This module's tenant tests are written the same way: as attacks, not happy
paths -- asserting 404 (never 403, so a response cannot confirm another
tenant's id exists) and asserting the *absence* of any row a laundering
attempt might have created, not just the response status code.

Exercised through the real, authenticated HTTP path (bearer token ->
``get_principal`` -> ``deps.get_session``), not ``session_scope()`` directly,
so the tenant tests below exercise exactly the boundary an attacker would.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import evaluate_control_proposal, open_control_proposal
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, AssessmentControlResult, Control, Organization, System, User
from ccf.models_assessment_engine import AssessmentControlProposal, AssessmentJob
from ccf.models_prep import PrepLine, PrepUnit
from ccf.prep import pipeline

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-91"


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
    ``CCF_ASSESSMENT_ENGINE_ENABLED`` is set -- off by default, matching every
    other billable-AI-call feature in this app. Set here rather than flipping
    the default; the one test that needs it unset overrides it locally.
    """
    os.environ["CCF_ASSESSMENT_ENGINE_ENABLED"] = "true"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_ASSESSMENT_ENGINE_ENABLED", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """Seed one addressable control plus one sub-clause objective row --
    mirrors ``test_assessment_acceptance.py``'s fixture shape (a parent row
    with a bare "Determine if:" header, one sub-clause row carrying the real
    objective text with control_name NULL).
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Test Policy And Procedures",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym=f"{_SEQ}a",
                assessment_objective="the thing under test is done;",
                source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
    """Create an org + a real (viewer-role, non-admin) user in it; return
    (bearer token, org id) -- identical shape to
    ``test_prep_tenant_isolation.py::_mk_user``.
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


def _fake_evaluate(verdict: str = "satisfied", cited_unit_ids: list[int] | None = None) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        ids = cited_unit_ids or []
        return ObjectiveEvaluation(
            verdict=verdict,
            rationale="ok",
            confidence=0.5,
            cited_unit_ids=ids,
            retrieved_unit_ids=ids,
        )

    return _fake


async def _seed_prep_unit(org_id: int, page_numbers: list[int]) -> int:
    """One minimal, real PrepUnit -- just enough to satisfy the FKs -- so the
    GET endpoint's citation-resolution join has a real row with real page
    numbers to find.
    """
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=1
        )
        line = PrepLine(
            run_id=run.id,
            organization_id=org_id,
            line_number=1,
            page_number=page_numbers[0] if page_numbers else 1,
            section_path="Access Control",
            content="cited passage content",
        )
        s.add(line)
        await s.flush()
        unit = PrepUnit(
            run_id=run.id,
            organization_id=org_id,
            trigger_line_id=line.id,
            source_line_ids=[line.id],
            content="cited passage content",
            page_numbers=page_numbers,
            section_path="Access Control",
            token_count=4,
        )
        s.add(unit)
        await s.flush()
        return int(unit.id)


async def _evaluated_proposal(
    assessment_id: int,
    monkeypatch: pytest.MonkeyPatch,
    *,
    verdict: str = "satisfied",
    cited_unit_ids: list[int] | None = None,
) -> int:
    """Open + evaluate a proposal for the ZQ-91 fixture control, bypassing the
    worker (matching ``test_assessment_acceptance.py::_evaluated_proposal``).
    Returns the proposal id.
    """
    monkeypatch.setattr(service, "evaluate_objective", _fake_evaluate(verdict, cited_unit_ids))
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        return int(proposal.id)


# --- Happy paths -------------------------------------------------------------


async def test_post_enqueues_and_returns_identifiers() -> None:
    token, org_id = await _mk_user("post-a@ae-api.test", "AE API Post Org")
    assessment_id = await _assessment_for(org_id, "post")

    async with _client() as client:
        response = await client.post(
            "/api/assessment-engine/proposals",
            json={"assessment_id": assessment_id, "control_identifier": _SEQ},
            headers=_auth(token),
        )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    async with session_scope() as s:
        assert (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == body["proposal_id"]
                )
            )
        ).scalar_one_or_none() is not None
        assert (
            await s.execute(select(AssessmentJob).where(AssessmentJob.id == body["job_id"]))
        ).scalar_one_or_none() is not None


async def test_get_returns_objectives_with_citations_and_page_numbers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("get-a@ae-api.test", "AE API Get Org")
    assessment_id = await _assessment_for(org_id, "get")
    unit_id = await _seed_prep_unit(org_id, [3, 4])
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch, cited_unit_ids=[unit_id]
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "complete"
    assert len(body["objectives"]) == 1
    objective = body["objectives"][0]
    assert objective["verdict"] == "satisfied"
    assert objective["citations"] == [
        {"unit_id": unit_id, "page_numbers": [3, 4], "section_path": "Access Control"}
    ]


async def test_accept_projects_into_the_result_store(monkeypatch: pytest.MonkeyPatch) -> None:
    token, org_id = await _mk_user("accept-a@ae-api.test", "AE API Accept Org")
    assessment_id = await _assessment_for(org_id, "accept")
    proposal_id = await _evaluated_proposal(assessment_id, monkeypatch)

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/accept", headers=_auth(token)
        )
    assert response.status_code == 200
    body = response.json()
    assert body["finding"] == "satisfied"
    assert body["reviewed"] is True

    async with session_scope() as s:
        result = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_id,
                    AssessmentControlResult.control_id == _SEQ,
                )
            )
        ).scalar_one()
        assert result.finding == "satisfied"
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert proposal.state == "accepted"


async def test_accepting_an_already_accepted_proposal_is_refused_not_500(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one guard stopping a repeated accept from re-accepting an already
    accepted proposal (state != "complete") must survive the HTTP layer and
    surface as a real client error, not a 500.
    """
    token, org_id = await _mk_user("accept-twice-a@ae-api.test", "AE API Accept Twice Org")
    assessment_id = await _assessment_for(org_id, "accept-twice")
    proposal_id = await _evaluated_proposal(assessment_id, monkeypatch)

    async with _client() as client:
        first = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/accept", headers=_auth(token)
        )
        assert first.status_code == 200
        second = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/accept", headers=_auth(token)
        )
    assert second.status_code == 409


async def test_endpoints_are_absent_when_the_engine_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("disabled-a@ae-api.test", "AE API Disabled Org")
    assessment_id = await _assessment_for(org_id, "disabled")
    monkeypatch.setenv("CCF_ASSESSMENT_ENGINE_ENABLED", "false")
    get_settings.cache_clear()

    async with _client() as client:
        response = await client.post(
            "/api/assessment-engine/proposals",
            json={"assessment_id": assessment_id, "control_identifier": _SEQ},
            headers=_auth(token),
        )
    assert response.status_code == 404
    get_settings.cache_clear()


async def test_unauthenticated_access_is_refused() -> None:
    async with _client() as client:
        response = await client.post(
            "/api/assessment-engine/proposals",
            json={"assessment_id": 1, "control_identifier": _SEQ},
        )
    assert response.status_code == 401


# --- Attacks: cross-tenant read/accept/enqueue must all 404 ------------------


async def test_an_org_a_principal_cannot_read_an_org_b_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """404, not 403 -- do not confirm another tenant's ids exist."""
    token_a, _org_a = await _mk_user("read-a@ae-tenant.test", "AE Tenant Read A")
    _token_b, org_b = await _mk_user("read-b@ae-tenant.test", "AE Tenant Read B")
    assessment_b = await _assessment_for(org_b, "read-victim")
    secret_rationale = "org B's confidential rollup rationale"
    proposal_id = await _evaluated_proposal(assessment_b, monkeypatch)
    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        proposal.rollup_rationale = secret_rationale
        await s.flush()

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token_a)
        )
    assert response.status_code == 404
    assert secret_rationale not in response.text


async def test_an_org_a_principal_cannot_accept_an_org_b_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_a, _org_a = await _mk_user("accept-atk-a@ae-tenant.test", "AE Tenant Accept A")
    _token_b, org_b = await _mk_user("accept-atk-b@ae-tenant.test", "AE Tenant Accept B")
    assessment_b = await _assessment_for(org_b, "accept-victim")
    proposal_id = await _evaluated_proposal(assessment_b, monkeypatch)

    async with _client() as client:
        response = await client.post(
            f"/api/assessment-engine/proposals/{proposal_id}/accept", headers=_auth(token_a)
        )
    assert response.status_code == 404

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.id == proposal_id
                )
            )
        ).scalar_one()
        assert proposal.state == "complete", "an org-A caller must not accept org B's proposal"
        leaked = (
            await s.execute(
                select(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == assessment_b
                )
            )
        ).scalar_one_or_none()
        assert leaked is None


async def test_an_org_a_principal_cannot_enqueue_against_an_org_b_assessment() -> None:
    """The laundering shape from slice 1: a foreign assessment_id must 404,
    and no proposal row may be created at all -- not just the right status.
    """
    token_a, org_a = await _mk_user("launder-a@ae-tenant.test", "AE Tenant Launder A")
    _token_b, org_b = await _mk_user("launder-b@ae-tenant.test", "AE Tenant Launder B")
    assessment_b = await _assessment_for(org_b, "launder-victim")

    async with _client() as client:
        response = await client.post(
            "/api/assessment-engine/proposals",
            json={"assessment_id": assessment_b, "control_identifier": _SEQ},
            headers=_auth(token_a),
        )
    assert response.status_code == 404

    async with session_scope() as s:
        leaked = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.assessment_id == assessment_b
                )
            )
        ).scalars().all()
        assert leaked == [], "no proposal should have been opened against the victim's assessment"
        # And nothing was opened under the attacker's own org either.
        leaked_as_a = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.organization_id == org_a
                )
            )
        ).scalars().all()
        assert leaked_as_a == []
