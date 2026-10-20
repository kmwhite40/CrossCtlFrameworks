"""Findings from the independent review of the tier-0 gate fixes.

Each test names the review finding it pins. They are kept together because
they share fixtures; the behaviour each one describes lives in its own module.
"""

from __future__ import annotations

import io
import os
from collections.abc import Iterator
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import scheduler
from ccf.ingest.scanners import ScanFinding, reconcile_findings
from ccf.models import (
    POAM,
    AssessmentControlResult,
    Notification,
    Organization,
    SSPProject,
    System,
    User,
)
from ccf.models_evidence import EvidenceObject
from ccf.scoring.seed import seed_scoring_controls
from tests.test_scan_ingest import IMPROVED_NESSUS_XML, NESSUS_XML

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str, roles: tuple[str, ...] = ()) -> tuple[int, int, list[dict]]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        users = []
        for i, role in enumerate(roles):
            u = User(
                email=f"u{i}@{name.lower()}.example",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            users.append(u)
        await s.flush()
        return org.id, sysm.id, [{"Authorization": f"Bearer {u.api_token}"} for u in users]


# --- H1: the HTML assessment form enforces independence too ------------------


@pytest.mark.asyncio
async def test_the_ui_result_form_refuses_a_control_owner_on_a_3pao(_auth_enabled: None) -> None:
    async with session_scope() as s:
        await seed_scoring_controls(s)
    _o, sys_id, (owner, assessor) = await _org("FollowupOrgH1", ("control_owner", "assessor"))
    async with _client() as c:
        aid = (
            await c.post(
                "/api/assessments", json={"system_id": sys_id, "kind": "3pao"}, headers=owner
            )
        ).json()["id"]
        async with session_scope() as s:
            rid = (
                await s.execute(
                    select(AssessmentControlResult.id)
                    .where(AssessmentControlResult.assessment_id == aid)
                    .limit(1)
                )
            ).scalar_one()
        form = {"finding": "satisfied"}
        own = await c.post(f"/assessments/{aid}/result/{rid}", data=form, headers=owner)
        assert own.status_code == 403, own.text
        ok = await c.post(f"/assessments/{aid}/result/{rid}", data=form, headers=assessor)
        assert ok.status_code == 200, ok.text


# --- H2: a scan with no findings proves nothing absent -----------------------


@pytest.mark.asyncio
async def test_a_scan_with_no_findings_closes_nothing() -> None:
    _o, sys_id, _ = await _org("FollowupOrgH2")
    open_one = ScanFinding(
        scanner="qualys", native_id="4242", title="Open weakness", severity="high", asset="h1"
    )
    async with session_scope() as s:
        await reconcile_findings(s, system_id=sys_id, scanner="qualys", findings=[open_one])
    async with session_scope() as s:
        res = await reconcile_findings(s, system_id=sys_id, scanner="qualys", findings=[])
        assert res.closed == 0
    async with session_scope() as s:
        rows = (await s.execute(select(POAM).where(POAM.system_id == sys_id))).scalars().all()
        assert [p.status for p in rows] == ["open"]


@pytest.mark.asyncio
async def test_a_scan_that_closes_poams_says_so() -> None:
    _o, sys_id, _ = await _org("FollowupOrgH2b")

    def nessus(content: bytes) -> dict:
        return {"file": ("scan.nessus", io.BytesIO(content), "text/xml")}

    async with _client() as c:
        await c.post(
            "/api/scans/ingest",
            data={"system_id": sys_id, "scanner": "nessus"},
            files=nessus(NESSUS_XML),
        )
        second = await c.post(
            "/api/scans/ingest",
            data={"system_id": sys_id, "scanner": "nessus"},
            files=nessus(IMPROVED_NESSUS_XML),
        )
        assert second.status_code == 201, second.text
        assert second.json()["closed"] == 1
        ingestion_id = second.json()["id"]
    async with session_scope() as s:
        note = (
            await s.execute(
                select(Notification).where(
                    Notification.entity_type == "scan_ingestion",
                    Notification.entity_id == str(ingestion_id),
                )
            )
        ).scalar_one_or_none()
        assert note is not None
        assert "closed" in note.title


# --- security review: a version uploaded after submission needs resubmission -


@pytest.mark.asyncio
async def test_a_new_version_on_submitted_evidence_returns_it_to_draft() -> None:
    _o, sys_id, _ = await _org("FollowupOrgSwap")
    async with _client() as c:
        oid = (await c.post("/api/evidence-repo", json={"title": "E", "system_id": sys_id})).json()[
            "id"
        ]

        async def upload(body: bytes) -> None:
            r = await c.post(
                f"/api/evidence-repo/{oid}/versions",
                files={"file": ("e.txt", io.BytesIO(body), "text/plain")},
            )
            assert r.status_code == 201, r.text

        await upload(b"what the reviewer was asked to look at")
        assert (await c.post(f"/api/evidence-repo/{oid}/submit")).status_code == 200
        await upload(b"something else entirely")
        assert (await c.get(f"/api/evidence-repo/{oid}")).json()["status"] == "draft"
        r = await c.post(f"/api/evidence-repo/{oid}/review", json={"decision": "approved"})
        assert r.status_code == 409, r.text


# --- M1: an approved SSP can be withdrawn and approved again ------------------


@pytest.mark.asyncio
async def test_an_approved_ssp_withdrawn_to_draft_can_be_reapproved() -> None:
    async with session_scope() as s:
        org = Organization(name="FollowupOrgM1")
        s.add(org)
        await s.flush()
        proj = SSPProject(organization_id=org.id, customer_name="M1 customer")
        s.add(proj)
        await s.flush()
        pid = proj.id
    async with _client() as c:
        assert (await c.post(f"/api/approvals/ssp_project/{pid}/submit")).status_code == 200
        assert (
            await c.post(f"/api/approvals/ssp_project/{pid}/approve", json={})
        ).status_code == 200

        # A whole-form client re-sends the status it was given.
        resend = await c.patch(f"/api/ssp/projects/{pid}", json={"status": "approved"})
        assert resend.status_code == 200, resend.text
        assert resend.json()["status"] == "approved"

        withdrawn = await c.patch(f"/api/ssp/projects/{pid}", json={"status": "draft"})
        assert withdrawn.status_code == 200, withdrawn.text
        assert withdrawn.json()["status"] == "draft"
        again = await c.post(f"/api/approvals/ssp_project/{pid}/submit")
        assert again.status_code == 200, again.text


# --- M2: evidence with no organization still expires --------------------------


@pytest.mark.asyncio
async def test_unowned_evidence_expires_too() -> None:
    today = date(2026, 10, 20)
    async with session_scope() as s:
        obj = EvidenceObject(
            organization_id=None,
            title="Single-operator evidence",
            status="approved",
            expires_on=today - timedelta(days=1),
        )
        s.add(obj)
        await s.flush()
        oid = obj.id
    async with session_scope() as s:
        await scheduler._run_per_tenant_cycle(s, [], today=today)
    async with session_scope() as s:
        row = await s.get(EvidenceObject, oid)
        assert row is not None
        assert row.status == "expired"


# --- M3: the closure proposal fires on the transition, not on every save -----


@pytest.mark.asyncio
async def test_resaving_a_satisfied_practice_does_not_repeat_the_note() -> None:
    async with session_scope() as s:
        await seed_scoring_controls(s)
    _o, sys_id, _ = await _org("FollowupOrgM3")
    practice = "AC.L2-3.1.2"
    async with _client() as c:
        pid = (
            await c.post("/api/poams", json={"system_id": sys_id, "title": f"{practice} — gap"})
        ).json()["id"]
        url = f"/api/scoring/systems/{sys_id}/controls/{practice}"
        assert (await c.put(url, json={"state": "implemented"})).status_code == 200
        assert (
            await c.put(url, json={"state": "implemented", "notes": "edited"})
        ).status_code == 200
        plan = (await c.get(f"/api/poams/{pid}")).json()["remediation_plan"] or ""
    assert plan.count("review for closure") == 1


# --- Low: closing an already-closed POA&M keeps its real closure date ---------


@pytest.mark.asyncio
async def test_closing_a_closed_poam_keeps_its_closure_date() -> None:
    _o, sys_id, _ = await _org("FollowupOrgLow")
    closed_on = date(2026, 1, 15)
    async with session_scope() as s:
        p = POAM(system_id=sys_id, title="Long closed", status="completed", closed_on=closed_on)
        s.add(p)
        await s.flush()
        pid = p.id
    async with _client() as c:
        r = await c.post(f"/api/poams/{pid}/close")
        assert r.status_code == 200, r.text
        assert r.json()["closed_on"] == closed_on.isoformat()
        assert r.json()["status"] == "completed"
