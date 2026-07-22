"""ISSM-08/09 governance gates: POA&M closure and risk acceptance must pass
validation and (auth-on) a separation-of-duties approval before the terminal
status transition is allowed.

Covers both the dedicated ``/close`` route and the generic PATCH routes, since
POAMUpdate/RiskUpdate accept the terminal status directly and would otherwise
let a caller bypass the gate entirely.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    Control,
    ControlImplementation,
    Evidence,
    Organization,
    System,
    User,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


# --- POA&M closure gate (auth disabled / single-operator) -------------------


@pytest.mark.asyncio
async def test_close_poam_rejected_with_no_milestones_and_no_evidence() -> None:
    _org_id, sys_id = await _make_system("PoamGateOrg1")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]

        r = await c.post(f"/api/poams/{pid}/close")
        assert r.status_code == 409, r.text

        got = await c.get(f"/api/poams/{pid}")
        assert got.json()["status"] == "open"  # unchanged


@pytest.mark.asyncio
async def test_close_poam_rejected_with_incomplete_milestone() -> None:
    _org_id, sys_id = await _make_system("PoamGateOrg2")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]
        await c.post(f"/api/poams/{pid}/milestones", json={"description": "patch it"})

        r = await c.post(f"/api/poams/{pid}/close")
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_close_poam_succeeds_with_all_milestones_completed() -> None:
    _org_id, sys_id = await _make_system("PoamGateOrg3")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]
        ms = await c.post(f"/api/poams/{pid}/milestones", json={"description": "patch it"})
        mid = ms.json()["id"]
        await c.patch(f"/api/poams/{pid}/milestones/{mid}", json={"status": "completed"})

        r = await c.post(f"/api/poams/{pid}/close")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "closed"
        assert r.json()["closed_on"] is not None


@pytest.mark.asyncio
async def test_close_poam_succeeds_with_linked_evidence_and_no_milestones() -> None:
    _org_id, sys_id = await _make_system("PoamGateOrg4")
    async with session_scope() as s:
        ctrl = Control(identifier="AC-EVID-1", control_name="Test control")
        s.add(ctrl)
        await s.flush()
        impl = ControlImplementation(system_id=sys_id, control_id=ctrl.id, status="implemented")
        s.add(impl)
        await s.flush()
        s.add(
            Evidence(
                implementation_id=impl.id,
                kind="attestation",
                title="re-test after patch",
                collected_on=date.today(),
            )
        )
        await s.flush()
        control_id = ctrl.id

    async with _client() as c:
        created = await c.post(
            "/api/poams",
            json={"system_id": sys_id, "control_id": control_id, "title": "Weak spot"},
        )
        pid = created.json()["id"]

        r = await c.post(f"/api/poams/{pid}/close")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_close_poam_rejected_when_evidence_predates_the_weakness() -> None:
    """Pre-existing evidence that predates the POA&M's identified_on does not
    demonstrate remediation and must not satisfy the closure gate (review finding)."""
    _org_id, sys_id = await _make_system("PoamGateOrg4b")
    async with session_scope() as s:
        ctrl = Control(identifier="AC-EVID-OLD-1", control_name="Test control old")
        s.add(ctrl)
        await s.flush()
        impl = ControlImplementation(system_id=sys_id, control_id=ctrl.id, status="implemented")
        s.add(impl)
        await s.flush()
        s.add(
            Evidence(
                implementation_id=impl.id,
                kind="attestation",
                title="stale attestation collected before the weakness",
                collected_on=date(2020, 1, 1),
            )
        )
        await s.flush()
        control_id = ctrl.id

    async with _client() as c:
        created = await c.post(
            "/api/poams",
            json={
                "system_id": sys_id,
                "control_id": control_id,
                "title": "Weak spot",
                "identified_on": date.today().isoformat(),
            },
        )
        pid = created.json()["id"]
        # only pre-dated evidence exists → closure must be rejected
        r = await c.post(f"/api/poams/{pid}/close")
        assert r.status_code == 409, r.text
        assert (await c.get(f"/api/poams/{pid}")).json()["status"] == "open"


@pytest.mark.asyncio
async def test_patch_poam_to_closed_is_gated_same_as_close_route() -> None:
    """PATCH /api/poams/{id} {"status": "closed"} must not bypass the gate that
    guards the dedicated /close route."""
    _org_id, sys_id = await _make_system("PoamGateOrg5")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]

        r = await c.patch(f"/api/poams/{pid}", json={"status": "closed"})
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_patch_poam_non_terminal_edit_still_works_without_gate() -> None:
    """Non-terminal edits (no status change to closed) must keep working even
    with no milestones/evidence — only the terminal transition is gated."""
    _org_id, sys_id = await _make_system("PoamGateOrg6")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]

        r = await c.patch(f"/api/poams/{pid}", json={"severity": "critical"})
        assert r.status_code == 200, r.text
        assert r.json()["severity"] == "critical"

        r2 = await c.patch(f"/api/poams/{pid}", json={"status": "in_progress"})
        assert r2.status_code == 200, r2.text
        assert r2.json()["status"] == "in_progress"


# --- Risk acceptance gate (auth disabled / single-operator) -----------------


@pytest.mark.asyncio
async def test_accept_risk_rejected_without_owner_or_expiry() -> None:
    _org_id, sys_id = await _make_system("RiskGateOrg1")
    async with _client() as c:
        created = await c.post("/api/risks", json={"system_id": sys_id, "title": "Some risk"})
        rid = created.json()["id"]

        r = await c.patch(f"/api/risks/{rid}", json={"status": "accepted"})
        assert r.status_code == 409, r.text

        got = await c.get(f"/api/risks/{rid}")
        assert got.json()["status"] == "open"


@pytest.mark.asyncio
async def test_accept_risk_rejected_with_owner_but_no_expiry() -> None:
    _org_id, sys_id = await _make_system("RiskGateOrg2")
    async with _client() as c:
        created = await c.post("/api/risks", json={"system_id": sys_id, "title": "Some risk"})
        rid = created.json()["id"]

        r = await c.patch(
            f"/api/risks/{rid}", json={"status": "accepted", "owner_user_id": 999999}
        )
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_accept_risk_succeeds_with_owner_and_expiry() -> None:
    org_id, sys_id = await _make_system("RiskGateOrg3")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@riskgateorg3.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        created = await c.post("/api/risks", json={"system_id": sys_id, "title": "Some risk"})
        rid = created.json()["id"]

        r = await c.patch(
            f"/api/risks/{rid}",
            json={
                "status": "accepted",
                "owner_user_id": owner_id,
                "next_review_on": str(date.today() + timedelta(days=180)),
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "accepted"


@pytest.mark.asyncio
async def test_create_risk_with_status_accepted_is_gated_too() -> None:
    """A caller cannot skip the PATCH gate by setting status='accepted' at
    creation time — RiskCreate exposes the same field."""
    _org_id, sys_id = await _make_system("RiskGateOrg4")
    async with _client() as c:
        r = await c.post(
            "/api/risks", json={"system_id": sys_id, "title": "Born accepted", "status": "accepted"}
        )
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_patch_risk_non_terminal_edit_still_works_without_gate() -> None:
    _org_id, sys_id = await _make_system("RiskGateOrg5")
    async with _client() as c:
        created = await c.post("/api/risks", json={"system_id": sys_id, "title": "Some risk"})
        rid = created.json()["id"]

        r = await c.patch(f"/api/risks/{rid}", json={"likelihood": "high", "impact": "high"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "open"


# --- Auth-enabled: separation-of-duties approval required -------------------


@pytest.fixture
def _auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _mk_user(org_id: int, email: str, role: str) -> str:
    async with session_scope() as s:
        user = User(
            email=email,
            organization_id=org_id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        assert user.api_token is not None
        return user.api_token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_close_poam_blocked_without_approval_when_auth_enabled(_auth_enabled: None) -> None:
    org_id, sys_id = await _make_system("PoamGateAuthOrg1")
    preparer = await _mk_user(org_id, "prep1@authorg1.example", "control_owner")

    async with _client() as c:
        created = await c.post(
            "/api/poams",
            json={"system_id": sys_id, "title": "Weak spot"},
            headers=_auth(preparer),
        )
        pid = created.json()["id"]
        ms = await c.post(
            f"/api/poams/{pid}/milestones",
            json={"description": "patch it"},
            headers=_auth(preparer),
        )
        mid = ms.json()["id"]
        await c.patch(
            f"/api/poams/{pid}/milestones/{mid}",
            json={"status": "completed"},
            headers=_auth(preparer),
        )

        # Validation gate passes (milestones complete) but no approval exists yet.
        r = await c.post(f"/api/poams/{pid}/close", headers=_auth(preparer))
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_close_poam_blocked_when_approver_is_same_as_submitter(_auth_enabled: None) -> None:
    org_id, sys_id = await _make_system("PoamGateAuthOrg2")
    preparer = await _mk_user(org_id, "prep2@authorg2.example", "admin")

    async with _client() as c:
        created = await c.post(
            "/api/poams",
            json={"system_id": sys_id, "title": "Weak spot"},
            headers=_auth(preparer),
        )
        pid = created.json()["id"]
        ms = await c.post(
            f"/api/poams/{pid}/milestones",
            json={"description": "patch it"},
            headers=_auth(preparer),
        )
        mid = ms.json()["id"]
        await c.patch(
            f"/api/poams/{pid}/milestones/{mid}",
            json={"status": "completed"},
            headers=_auth(preparer),
        )

        await c.post(f"/api/approvals/poam/{pid}/submit", headers=_auth(preparer))
        # Same principal tries to approve their own submission — SoD blocks it.
        approve = await c.post(f"/api/approvals/poam/{pid}/approve", headers=_auth(preparer))
        assert approve.status_code == 403, approve.text

        r = await c.post(f"/api/poams/{pid}/close", headers=_auth(preparer))
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_close_poam_succeeds_with_distinct_approver_when_auth_enabled(
    _auth_enabled: None,
) -> None:
    org_id, sys_id = await _make_system("PoamGateAuthOrg3")
    preparer = await _mk_user(org_id, "prep3@authorg3.example", "control_owner")
    approver = await _mk_user(org_id, "appr3@authorg3.example", "admin")

    async with _client() as c:
        created = await c.post(
            "/api/poams",
            json={"system_id": sys_id, "title": "Weak spot"},
            headers=_auth(preparer),
        )
        pid = created.json()["id"]
        ms = await c.post(
            f"/api/poams/{pid}/milestones",
            json={"description": "patch it"},
            headers=_auth(preparer),
        )
        mid = ms.json()["id"]
        await c.patch(
            f"/api/poams/{pid}/milestones/{mid}",
            json={"status": "completed"},
            headers=_auth(preparer),
        )

        await c.post(f"/api/approvals/poam/{pid}/submit", headers=_auth(preparer))
        approve = await c.post(f"/api/approvals/poam/{pid}/approve", headers=_auth(approver))
        assert approve.status_code == 200, approve.text

        r = await c.post(f"/api/poams/{pid}/close", headers=_auth(preparer))
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_accept_risk_blocked_without_approval_when_auth_enabled(_auth_enabled: None) -> None:
    org_id, sys_id = await _make_system("RiskGateAuthOrg1")
    preparer = await _mk_user(org_id, "rprep1@rauthorg1.example", "control_owner")

    async with _client() as c:
        created = await c.post(
            "/api/risks", json={"system_id": sys_id, "title": "Some risk"}, headers=_auth(preparer)
        )
        rid = created.json()["id"]

        r = await c.patch(
            f"/api/risks/{rid}",
            json={
                "status": "accepted",
                "owner_user_id": None,
            },
            headers=_auth(preparer),
        )
        # owner not supplied at all -> still a validation 409 (checked first)
        assert r.status_code == 409

        r2 = await c.patch(
            f"/api/risks/{rid}",
            json={
                "status": "accepted",
                "owner_user_id": 1,
                "next_review_on": str(date.today() + timedelta(days=90)),
            },
            headers=_auth(preparer),
        )
        assert r2.status_code == 409, r2.text  # validation OK, but no approval yet


@pytest.mark.asyncio
async def test_accept_risk_succeeds_with_ao_approval_when_auth_enabled(_auth_enabled: None) -> None:
    org_id, sys_id = await _make_system("RiskGateAuthOrg2")
    preparer = await _mk_user(org_id, "rprep2@rauthorg2.example", "control_owner")
    ao = await _mk_user(org_id, "rao2@rauthorg2.example", "admin")

    async with session_scope() as s:
        owner = User(
            organization_id=org_id,
            email="rowner2@rauthorg2.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(owner)
        await s.flush()
        owner_id = owner.id

    async with _client() as c:
        created = await c.post(
            "/api/risks", json={"system_id": sys_id, "title": "Some risk"}, headers=_auth(preparer)
        )
        rid = created.json()["id"]

        await c.post(f"/api/approvals/risk/{rid}/submit", headers=_auth(preparer))
        approve = await c.post(f"/api/approvals/risk/{rid}/approve", headers=_auth(ao))
        assert approve.status_code == 200, approve.text

        r = await c.patch(
            f"/api/risks/{rid}",
            json={
                "status": "accepted",
                "owner_user_id": owner_id,
                "next_review_on": str(date.today() + timedelta(days=90)),
            },
            headers=_auth(preparer),
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "accepted"
