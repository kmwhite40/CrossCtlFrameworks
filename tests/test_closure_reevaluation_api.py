"""GET /api/assessment-engine/proposals?source_poam_id={id} -- the
re-evaluation(s) triggered by one closed POA&M's closure.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Assessment, Organization, System, User
from ccf.models_assessment_engine import AssessmentControlProposal

pytestmark = pytest.mark.usefixtures("fresh_engine")


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


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


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


async def _poam_for_org(org_id: int, name: str) -> int:
    async with session_scope() as s:
        system = System(organization_id=org_id, name=f"{name}-sys")
        s.add(system)
        await s.flush()
        poam = POAM(
            system_id=system.id, title=name, severity="moderate", status="open", source="assessment"
        )
        s.add(poam)
        await s.flush()
        return int(poam.id)


async def _reevaluation_proposal_for(poam_id: int, org_id: int, assessment_id: int) -> int:
    async with session_scope() as s:
        p = AssessmentControlProposal(
            organization_id=org_id,
            assessment_id=assessment_id,
            control_identifier="AC-2",
            source_poam_id=poam_id,
            state="complete",
            proposed_finding="satisfied",
        )
        s.add(p)
        await s.flush()
        return int(p.id)


async def test_lists_the_reevaluation_for_the_callers_own_poam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token, org_id = await _mk_user("reeval-a@ae-api.test", "Reeval API Org A")
    assessment_id = await _assessment_for(org_id, "reeval-a")
    poam_id = await _poam_for_org(org_id, "reeval-a-poam")
    await _reevaluation_proposal_for(poam_id, org_id, assessment_id)

    async with _client() as client:
        response = await client.get(
            "/api/assessment-engine/proposals",
            params={"source_poam_id": poam_id},
            headers=_auth(token),
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["proposed_finding"] == "satisfied"
    assert body[0]["assessment_id"] == assessment_id


async def test_another_tenants_poam_id_404s_not_403s(monkeypatch: pytest.MonkeyPatch) -> None:
    token_a, _org_a = await _mk_user("reeval-b-a@ae-api.test", "Reeval API Org B-A")
    _token_b, org_b = await _mk_user("reeval-b-b@ae-api.test", "Reeval API Org B-B")
    assessment_b = await _assessment_for(org_b, "reeval-b")
    poam_b = await _poam_for_org(org_b, "reeval-b-poam")
    await _reevaluation_proposal_for(poam_b, org_b, assessment_b)

    async with _client() as client:
        response = await client.get(
            "/api/assessment-engine/proposals",
            params={"source_poam_id": poam_b},
            headers=_auth(token_a),
        )
    assert response.status_code == 404


async def test_a_nonexistent_poam_id_also_404s(monkeypatch: pytest.MonkeyPatch) -> None:
    token, _org_id = await _mk_user("reeval-c@ae-api.test", "Reeval API Org C")
    async with _client() as client:
        response = await client.get(
            "/api/assessment-engine/proposals",
            params={"source_poam_id": 999_999_999},
            headers=_auth(token),
        )
    assert response.status_code == 404
