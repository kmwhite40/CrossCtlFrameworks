"""Personnel & Access: onboarding automation, training, access reviews, summary."""

from __future__ import annotations

from datetime import date

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import digest
from ccf.models import Notification, Organization, Task, Vendor
from ccf.models_people import AccessReview, Person, TrainingRecord
from ccf.models_tprm import VendorQuestionnaire

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_onboarding_assigns_training_and_screening_task() -> None:
    async with _client() as c:
        r = await c.post(
            "/api/personnel",
            json={
                "full_name": "Dana Analyst",
                "email": "dana@example.gov",
                "position": "Security Analyst",
                "risk_designation": "high",
            },
        )
        assert r.status_code == 201, r.text
        pid = r.json()["id"]
        assert r.json()["status"] == "active"

        detail = (await c.get(f"/api/personnel/{pid}")).json()
        courses = {t["course"]: t for t in detail["training"]}
        assert "Security Awareness Training" in courses
        assert courses["Security Awareness Training"]["control_ref"] == "AT-2"
        assert courses["Security Awareness Training"]["due_on"] is not None

    # A high-risk hire with no screening opens a high-priority onboarding task.
    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"onboard-screen:{pid}"))
        ).scalar_one_or_none()
        assert task is not None
        assert task.priority == "high"
        assert task.kind == "onboarding"


@pytest.mark.asyncio
async def test_offboarding_opens_revocation_task() -> None:
    async with _client() as c:
        pid = (
            await c.post("/api/personnel", json={"full_name": "Lee Contractor"})
        ).json()["id"]
        r = await c.post(f"/api/personnel/{pid}/offboard", json={})
        assert r.status_code == 200
        assert r.json()["status"] == "offboarded"
        assert r.json()["end_date"] is not None

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"offboard-revoke:{pid}"))
        ).scalar_one_or_none()
        assert task is not None and task.priority == "high" and task.kind == "offboarding"


@pytest.mark.asyncio
async def test_training_completion_and_summary_counts() -> None:
    async with _client() as c:
        pid = (
            await c.post("/api/personnel", json={"full_name": "Sam Overdue"})
        ).json()["id"]
        # Assign a training already past due.
        t = (
            await c.post(
                f"/api/personnel/{pid}/training",
                json={"course": "Privileged User Training", "kind": "role_based",
                      "control_ref": "AT-3", "due_on": "2020-01-01"},
            )
        ).json()
        summary = (await c.get("/api/personnel/summary")).json()
        assert summary["training_overdue"] >= 1
        assert summary["screening_incomplete"] >= 1  # default not_started

        # Completing it clears the overdue count for that record.
        done = await c.post(f"/api/training/{t['id']}/complete", json={"evidence_ref": "LMS#42"})
        assert done.json()["status"] == "completed"
        assert done.json()["completed_on"] is not None

    async with session_scope() as s:
        rec = (
            await s.execute(select(TrainingRecord).where(TrainingRecord.id == t["id"]))
        ).scalar_one()
        assert rec.status == "completed"
        assert rec.evidence_ref == "LMS#42"


@pytest.mark.asyncio
async def test_access_review_lifecycle_blocks_completion_until_decided() -> None:
    async with _client() as c:
        pid = (await c.post("/api/personnel", json={"full_name": "Ada Reviewer"})).json()["id"]
        rid = (
            await c.post(
                "/api/access-reviews",
                json={"name": "Q3 Prod Access", "reviewer": "ISSO"},
            )
        ).json()["id"]
        item = (
            await c.post(
                f"/api/access-reviews/{rid}/items",
                json={"subject": "ada@example.gov", "person_id": pid,
                      "resource": "Prod DB", "access_level": "admin"},
            )
        ).json()

        # Cannot complete while an item is pending.
        blocked = await c.post(f"/api/access-reviews/{rid}/complete")
        assert blocked.status_code == 409

        decided = await c.patch(
            f"/api/access-review-items/{item['id']}",
            json={"decision": "revoke", "note": "left team"},
        )
        assert decided.json()["decision"] == "revoke"
        assert decided.json()["decided_on"] is not None

        done = await c.post(f"/api/access-reviews/{rid}/complete")
        assert done.status_code == 200
        assert done.json()["status"] == "completed"
        assert done.json()["item_decided"] == 1


@pytest.mark.asyncio
async def test_person_404_for_unknown_id() -> None:
    async with _client() as c:
        assert (await c.get("/api/personnel/999999")).status_code == 404
        assert (await c.post("/api/personnel/999999/offboard", json={})).status_code == 404


@pytest.mark.asyncio
async def test_digest_flags_personnel_and_tprm_overdue() -> None:
    past = date(2020, 1, 1)
    today = date(2026, 7, 1)
    async with session_scope() as s:
        org = Organization(name="DigestPeopleOrg")
        s.add(org)
        await s.flush()
        person = Person(
            organization_id=org.id, full_name="Overdue Person",
            status="active", background_check_status="not_started",
        )
        s.add(person)
        await s.flush()
        s.add(
            TrainingRecord(
                person_id=person.id, course="Security Awareness Training",
                status="assigned", due_on=past,
            )
        )
        s.add(AccessReview(organization_id=org.id, name="Stale Review", status="open", due_on=past))
        vendor = Vendor(organization_id=org.id, name="Late Vendor")
        s.add(vendor)
        await s.flush()
        s.add(
            VendorQuestionnaire(
                organization_id=org.id, vendor_id=vendor.id, name="Late Qnr",
                status="sent", due_on=past,
            )
        )
        await s.flush()
        org_id = org.id

    async with session_scope() as s:
        counts = await digest.run(s, today=today, org_id=org_id)
        assert counts["training"] >= 1
        assert counts["screening"] >= 1
        assert counts["access_review"] >= 1
        assert counts["questionnaire"] >= 1

        cats = {
            n.category
            for n in (
                await s.execute(select(Notification).where(Notification.organization_id == org_id))
            ).scalars().all()
        }
        assert {"training", "screening", "access_review", "questionnaire"} <= cats
