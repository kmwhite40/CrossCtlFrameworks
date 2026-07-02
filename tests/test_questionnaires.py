"""Vendor security questionnaires: scoring logic + full assessment lifecycle."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import tprm
from ccf.models import Organization, Task, Vendor

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# --- scoring unit tests ------------------------------------------------------


def test_score_all_yes_is_100_low_risk() -> None:
    resp = [{"answer": "yes", "weight": 3, "question_id": q["id"]}
            for q in tprm.DEFAULT_TEMPLATE["questions"]]
    out = tprm.score_responses(resp)
    assert out["score"] == 100.0
    assert out["rating"] == "low"
    assert out["flagged"] == []


def test_score_weighted_and_flags_no() -> None:
    resp = [
        {"answer": "yes", "weight": 1, "question_id": "A"},
        {"answer": "no", "weight": 3, "question_id": "B"},
        {"answer": "partial", "weight": 2, "question_id": "C"},
        {"answer": "na", "weight": 5, "question_id": "D"},  # excluded from denominator
    ]
    out = tprm.score_responses(resp)
    # earned = 1*1 + 0*3 + 0.5*2 = 2 ; possible = 1+3+2 = 6 → 33.3
    assert out["score"] == 33.3
    assert out["rating"] == "critical"
    assert out["flagged"] == ["B"]


def test_rating_bands() -> None:
    assert tprm.rating_for(95) == "low"
    assert tprm.rating_for(80) == "moderate"
    assert tprm.rating_for(60) == "high"
    assert tprm.rating_for(10) == "critical"


# --- lifecycle integration ---------------------------------------------------


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _vendor(name: str = "Acme SaaS") -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "QnrOrg"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="QnrOrg")
            s.add(org)
            await s.flush()
        v = Vendor(organization_id=org.id, name=name, criticality="high")
        s.add(v)
        await s.flush()
        return v.id


@pytest.mark.asyncio
async def test_builtin_template_available() -> None:
    async with _client() as c:
        templates = (await c.get("/api/questionnaire-templates")).json()
        keys = {t["key"] for t in templates}
        assert tprm.DEFAULT_TEMPLATE["key"] in keys
        builtin = next(t for t in templates if t["key"] == tprm.DEFAULT_TEMPLATE["key"])
        assert builtin["builtin"] is True
        assert len(builtin["questions"]) == 10


@pytest.mark.asyncio
async def test_full_questionnaire_lifecycle_updates_vendor_and_opens_tasks() -> None:
    vid = await _vendor()
    async with _client() as c:
        inst = await c.post(f"/api/vendors/{vid}/questionnaires", json={})
        assert inst.status_code == 201, inst.text
        q = inst.json()
        assert q["status"] == "sent"
        assert len(q["responses"]) == 10
        qid = q["id"]

        # Answer all yes except one high-weight 'no' (GOV-02, weight 3).
        for r in q["responses"]:
            ans = "no" if r["question_id"] == "GOV-02" else "yes"
            resp = await c.patch(
                f"/api/questionnaires/{qid}/responses/{r['id']}",
                json={"answer": ans, "detail": "attested"},
            )
            assert resp.status_code == 200

        submitted = (await c.post(f"/api/questionnaires/{qid}/submit")).json()
        assert submitted["status"] == "submitted"
        assert 0 < submitted["score"] < 100
        assert submitted["flagged"] == ["GOV-02"]

        reviewed = (
            await c.post(
                f"/api/questionnaires/{qid}/review",
                json={"reviewer": "TPRM Lead", "open_tasks": True},
            )
        ).json()
        assert reviewed["status"] == "reviewed"
        assert reviewed["tasks_opened"] == 1

        # Vendor risk rating is updated from the assessment.
        vendor = next(v for v in (await c.get("/api/vendors")).json() if v["id"] == vid)
        assert vendor["risk_rating"] == reviewed["rating"]

    # A high-priority remediation task exists for the flagged gap, deduped.
    async with session_scope() as s:
        tasks = (
            await s.execute(
                select(Task).where(Task.dedupe_key == f"vendorq-gap:{qid}:GOV-02")
            )
        ).scalars().all()
        assert len(tasks) == 1
        assert tasks[0].priority == "high"
        assert tasks[0].entity_type == "vendor"


@pytest.mark.asyncio
async def test_review_requires_submission_and_unknown_ids_404() -> None:
    vid = await _vendor("Beta Corp")
    async with _client() as c:
        qid = (await c.post(f"/api/vendors/{vid}/questionnaires", json={})).json()["id"]
        # Draft/sent → in_progress once answered, but review needs submitted; a
        # freshly-instantiated (status 'sent') questionnaire cannot be reviewed.
        blocked = await c.post(f"/api/questionnaires/{qid}/review", json={})
        assert blocked.status_code == 409

        assert (await c.get("/api/questionnaires/999999")).status_code == 404
        assert (
            await c.post("/api/vendors/999999/questionnaires", json={})
        ).status_code == 404
