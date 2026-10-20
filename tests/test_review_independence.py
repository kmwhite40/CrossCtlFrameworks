"""Evidence and independent assessments are reviewed by someone other than their author.

Evidence repository:
* ``review_object`` accepted any state, so a draft nobody had submitted could
  be "approved" (and WORM-locked) in one call.
* The uploader could approve their own evidence.
* ``mark_expired`` had no caller, so expired evidence stayed ``approved`` and
  was sealed into packages as current.

Assessments: any author could record results on a 3PAO, IG or audit
assessment, so a control owner could score their own controls in an
assessment presented as independent. Self and internal assessments stay open
to authors -- a CMMC self-assessment is the organization assessing itself.
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

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import scheduler
from ccf.models import Organization, System, User
from ccf.models_evidence import EvidenceObject
from ccf.scoring.seed import seed_scoring_controls

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


async def _org(name: str, roles: tuple[str, ...]) -> tuple[int, int, list[dict]]:
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


async def _evidence_with_version(c: AsyncClient, sys_id: int, headers: dict) -> int:
    oid = (
        await c.post(
            "/api/evidence-repo", json={"title": "E", "system_id": sys_id}, headers=headers
        )
    ).json()["id"]
    up = await c.post(
        f"/api/evidence-repo/{oid}/versions",
        files={"file": ("e.txt", io.BytesIO(b"evidence body"), "text/plain")},
        headers=headers,
    )
    assert up.status_code == 201, up.text
    return oid


# --- evidence -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_draft_cannot_be_approved() -> None:
    _org_id, sys_id, _ = await _org("ReviewIndepOrgA", ())
    async with _client() as c:
        oid = await _evidence_with_version(c, sys_id, {})
        r = await c.post(f"/api/evidence-repo/{oid}/review", json={"decision": "approved"})
        assert r.status_code == 409, r.text
        assert (await c.get(f"/api/evidence-repo/{oid}")).json()["status"] == "draft"


@pytest.mark.asyncio
async def test_the_uploader_cannot_approve_their_own_evidence(_auth_enabled: None) -> None:
    _org_id, sys_id, (owner, assessor) = await _org(
        "ReviewIndepOrgB", ("control_owner", "assessor")
    )
    async with _client() as c:
        oid = await _evidence_with_version(c, sys_id, owner)
        assert (await c.post(f"/api/evidence-repo/{oid}/submit", headers=owner)).status_code == 200

        own = await c.post(
            f"/api/evidence-repo/{oid}/review", json={"decision": "approved"}, headers=owner
        )
        assert own.status_code == 403, own.text

        other = await c.post(
            f"/api/evidence-repo/{oid}/review", json={"decision": "approved"}, headers=assessor
        )
        assert other.status_code == 200, other.text
        assert other.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_the_scheduler_expires_evidence_past_its_date() -> None:
    org_id, sys_id, _ = await _org("ReviewIndepOrgC", ())
    today = date(2026, 10, 20)
    async with session_scope() as s:
        obj = EvidenceObject(
            organization_id=org_id,
            system_id=sys_id,
            title="Stale",
            status="approved",
            expires_on=today - timedelta(days=1),
        )
        s.add(obj)
        await s.flush()
        oid = obj.id

    async with session_scope() as s:
        summary = await scheduler._run_per_tenant_cycle(s, [org_id], today=today)
    assert not [f for f in summary["step_failures"] if f["step"] == "evidence_expiry"]

    async with session_scope() as s:
        row = await s.get(EvidenceObject, oid)
        assert row is not None
        assert row.status == "expired"


# --- assessments --------------------------------------------------------------


async def _assessment(c: AsyncClient, sys_id: int, kind: str, headers: dict) -> tuple[int, str]:
    a = await c.post("/api/assessments", json={"system_id": sys_id, "kind": kind}, headers=headers)
    assert a.status_code == 201, a.text
    aid = a.json()["id"]
    results = (await c.get(f"/api/assessments/{aid}", headers=headers)).json()
    rows = results.get("results") or results.get("controls") or []
    assert rows, results
    return aid, rows[0]["control_id"]


@pytest.mark.asyncio
async def test_a_control_owner_cannot_record_3pao_results(_auth_enabled: None) -> None:
    async with session_scope() as s:
        await seed_scoring_controls(s)
    _org_id, sys_id, (owner, assessor) = await _org(
        "ReviewIndepOrgD", ("control_owner", "assessor")
    )
    async with _client() as c:
        aid, ctrl = await _assessment(c, sys_id, "3pao", owner)
        body = {"finding": "satisfied"}
        own = await c.put(f"/api/assessments/{aid}/controls/{ctrl}", json=body, headers=owner)
        assert own.status_code == 403, own.text
        ok = await c.put(f"/api/assessments/{aid}/controls/{ctrl}", json=body, headers=assessor)
        assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_a_control_owner_can_record_a_self_assessment(_auth_enabled: None) -> None:
    async with session_scope() as s:
        await seed_scoring_controls(s)
    _org_id, sys_id, (owner,) = await _org("ReviewIndepOrgE", ("control_owner",))
    async with _client() as c:
        aid, ctrl = await _assessment(c, sys_id, "self", owner)
        r = await c.put(
            f"/api/assessments/{aid}/controls/{ctrl}", json={"finding": "satisfied"}, headers=owner
        )
        assert r.status_code == 200, r.text
