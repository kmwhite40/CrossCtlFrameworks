"""GET /api/assessment-engine/proposals/{id} surfaces the AI dissent path:
dissent_count on the proposal, challenger_verdict/challenger_rationale on
each objective. Tenant isolation for this endpoint is exhaustively covered
already in test_assessment_engine_api.py (_require_proposal, 404-not-403,
the RLS-independent app-level check) -- this slice only adds fields to an
already-isolated response, it does not add a new tenant surface, so those
attacks are not re-run here.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from ccf.api.main import create_app
from ccf.assessment.engine import service
from ccf.assessment.engine.evaluate import ObjectiveEvaluation
from ccf.assessment.engine.service import evaluate_control_proposal, open_control_proposal
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Control, Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-98"


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
    os.environ["CCF_ASSESSMENT_ENGINE_ENABLED"] = "true"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_ASSESSMENT_ENGINE_ENABLED", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ, sequence_control=_SEQ, control_name="Dissent API Fixture",
                assessment_objective="Determine if:", source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1", sequence_control=_SEQ, ap_acronym=f"{_SEQ}a",
                assessment_objective="the dissent API fixture objective is met;", source_row=2,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
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


async def _assessment_for(org_id: int, name: str) -> int:
    async with session_scope() as s:
        system = System(organization_id=org_id, name=f"{name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        return int(assessment.id)


def _fake_evaluate(
    verdict: str = "satisfied",
    *,
    challenger_verdict: str | None = None,
    challenger_rationale: str | None = None,
) -> Any:
    async def _fake(session: Any, **kwargs: Any) -> ObjectiveEvaluation:
        return ObjectiveEvaluation(
            verdict=verdict, rationale="primary rationale", confidence=0.9,
            challenger_verdict=challenger_verdict, challenger_rationale=challenger_rationale,
            challenger_ai_action_run_id=None,
        )

    return _fake


async def _evaluated_proposal(
    assessment_id: int, monkeypatch: pytest.MonkeyPatch, fake: Any
) -> int:
    monkeypatch.setattr(service, "evaluate_objective", fake)
    async with session_scope() as s:
        proposal = await open_control_proposal(
            s, assessment_id=assessment_id, control_identifier=_SEQ
        )
        proposal = await evaluate_control_proposal(s, proposal)
        return int(proposal.id)


async def test_an_unchallenged_objective_reports_null_challenger_fields_and_zero_dissent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("dissent-null-a@ae-api.test", "Dissent API Null Org")
    assessment_id = await _assessment_for(org_id, "dissent-null")
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch, _fake_evaluate("satisfied")
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    assert response.status_code == 200
    body = response.json()
    assert body["dissent_count"] == 0
    objective = body["objectives"][0]
    assert objective["verdict"] == "satisfied"
    assert objective["challenger_verdict"] is None
    assert objective["challenger_rationale"] is None


async def test_an_agreeing_challenge_is_surfaced_without_affecting_dissent_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("dissent-agree-a@ae-api.test", "Dissent API Agree Org")
    assessment_id = await _assessment_for(org_id, "dissent-agree")
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch,
        _fake_evaluate("satisfied", challenger_verdict="satisfied", challenger_rationale="agrees"),
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    body = response.json()
    assert body["dissent_count"] == 0
    objective = body["objectives"][0]
    assert objective["verdict"] == "satisfied"
    assert objective["challenger_verdict"] == "satisfied"
    assert objective["challenger_rationale"] == "agrees"


async def test_a_disagreement_is_surfaced_and_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    token, org_id = await _mk_user("dissent-disagree-a@ae-api.test", "Dissent API Disagree Org")
    assessment_id = await _assessment_for(org_id, "dissent-disagree")
    proposal_id = await _evaluated_proposal(
        assessment_id, monkeypatch,
        _fake_evaluate(
            "insufficient_evidence", challenger_verdict="not_satisfied",
            challenger_rationale="the challenger's own distinct argument",
        ),
    )

    async with _client() as client:
        response = await client.get(
            f"/api/assessment-engine/proposals/{proposal_id}", headers=_auth(token)
        )
    body = response.json()
    assert body["dissent_count"] == 1
    objective = body["objectives"][0]
    assert objective["verdict"] == "insufficient_evidence"
    assert objective["challenger_verdict"] == "not_satisfied"
    assert objective["challenger_rationale"] == "the challenger's own distinct argument"
