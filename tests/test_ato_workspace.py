"""The authorization workflow, driven through the real API with auth enabled.

Covers what ``ccf.ato`` adds on top of the existing records: who signs for a
system, a package's ISSO → ISSM → AO review and its effect on
``System.ato_status``, the blockers an authorization enforces, POA&M extension
requests, AO-only risk acceptance, scheduler expiry, and the /ato pages.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.api.routes.ui_ato import _system
from ccf.ato import lifecycle
from ccf.ato import roles as system_roles
from ccf.auth import SYSTEM_PRINCIPAL, Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, System, User
from ccf.models_packages import AuthorizationPackage

pytestmark = pytest.mark.usefixtures("fresh_engine")

PEOPLE = ("prep", "isso", "issm", "ao", "admin", "other", "viewer")


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


class World:
    def __init__(self, name: str) -> None:
        self.name = name
        self.ids: dict[str, int] = {}
        self.hdr: dict[str, dict[str, str]] = {}

    @property
    def sys(self) -> int:
        return self.ids["system"]

    @property
    def org(self) -> int:
        return self.ids["org"]


async def _world(name: str) -> World:
    w = World(name)
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        await s.flush()
        w.ids.update(org=org.id, system=sysm.id)
        for key in PEOPLE:
            role = {"admin": "admin", "viewer": "viewer"}.get(key, "control_owner")
            u = User(
                email=f"{key}@{name.lower()}.example", organization_id=org.id, role=role,
                active=True, password_hash=hash_password("pw"), api_token=new_api_token(),
            )
            s.add(u)
            await s.flush()
            w.ids[key] = u.id
            w.hdr[key] = {"Authorization": f"Bearer {u.api_token}"}
    return w


async def _assign(c: AsyncClient, w: World, roles: dict[str, str]) -> None:
    for role, who in roles.items():
        r = await c.post(
            f"/ato/{w.sys}/roles", data={"role": role, "user_id": str(w.ids[who])},
            headers=w.hdr["admin"],
        )
        assert r.status_code == 303 and "error" not in r.headers["location"], r.headers


async def _signers(c: AsyncClient, w: World) -> None:
    await _assign(c, w, {"isso": "isso", "issm": "issm", "authorizing_official": "ao"})


async def _package(c: AsyncClient, w: World) -> int:
    r = await c.post(
        "/api/authorization-packages", json={"system_id": w.sys}, headers=w.hdr["prep"]
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "draft"
    return r.json()["id"]


async def _act(
    c: AsyncClient, pid: int, action: str, hdr: dict[str, str], **body: str
) -> tuple[int, dict]:
    r = await c.post(
        f"/api/authorization-packages/{pid}/actions/{action}", json=body, headers=hdr
    )
    return r.status_code, r.json()


async def _ato(w: World) -> tuple[str | None, date | None]:
    async with session_scope() as s:
        sysm = (await s.execute(select(System).where(System.id == w.sys))).scalar_one()
        return sysm.ato_status, sysm.ato_expires_on


# ── signing roles ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_only_an_admin_can_assign_and_a_viewer_cannot_hold_a_role(
    _auth_enabled: None,
) -> None:
    w = await _world("AtoRolesA")
    async with _client() as c:
        r = await c.post(
            f"/ato/{w.sys}/roles", data={"role": "isso", "user_id": str(w.ids["isso"])},
            headers=w.hdr["prep"],
        )
        assert "error" in r.headers["location"]
        r = await c.post(
            f"/ato/{w.sys}/roles", data={"role": "isso", "user_id": str(w.ids["viewer"])},
            headers=w.hdr["admin"],
        )
        assert "viewer" in r.headers["location"]


@pytest.mark.asyncio
async def test_another_tenants_user_cannot_be_assigned(_auth_enabled: None) -> None:
    w = await _world("AtoRolesB")
    other = await _world("AtoRolesB2")
    async with _client() as c:
        r = await c.post(
            f"/ato/{w.sys}/roles", data={"role": "isso", "user_id": str(other.ids["isso"])},
            headers=w.hdr["admin"],
        )
        assert "no%20such%20user" in r.headers["location"]


# ── package review ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_package_cannot_be_submitted_before_its_signers_exist(
    _auth_enabled: None,
) -> None:
    w = await _world("AtoPkgA")
    async with _client() as c:
        pid = await _package(c, w)
        code, body = await _act(c, pid, "submit", w.hdr["prep"])
        assert code == 409 and "assign" in body["detail"]


@pytest.mark.asyncio
async def test_the_full_review_authorizes_the_system(_auth_enabled: None) -> None:
    w = await _world("AtoPkgB")
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        assert (await _act(c, pid, "submit", w.hdr["prep"]))[0] == 200
        assert (await _ato(w))[0] == "in_progress"
        assert (await _act(c, pid, "isso_approve", w.hdr["isso"]))[0] == 200
        assert (await _act(c, pid, "issm_approve", w.hdr["issm"]))[0] == 200
        until = str(date.today() + timedelta(days=200))
        code, body = await _act(c, pid, "authorize", w.hdr["ao"], expires_on=until)
        assert code == 200, body
        assert body["status"] == "authorized"
        assert body["manifest_sha256"] and len(body["manifest_sha256"]) == 64
        events = (
            await c.get(f"/api/authorization-packages/{pid}/events", headers=w.hdr["prep"])
        ).json()
    assert [e["acted_as"] for e in events] == [None, "isso", "issm", "authorizing_official"]
    assert len({e["manifest_sha256"] for e in events}) == 1
    status, expires = await _ato(w)
    assert status == "authorized" and str(expires) == until


@pytest.mark.asyncio
async def test_each_stage_belongs_to_its_holder(_auth_enabled: None) -> None:
    w = await _world("AtoPkgC")
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        await _act(c, pid, "submit", w.hdr["prep"])
        code, body = await _act(c, pid, "isso_approve", w.hdr["issm"])
        assert code == 403 and "ISSO" in body["detail"]
        code, _ = await _act(c, pid, "isso_approve", w.hdr["other"])
        assert code == 403


@pytest.mark.asyncio
async def test_one_person_cannot_sign_two_stages(_auth_enabled: None) -> None:
    w = await _world("AtoPkgD")
    async with _client() as c:
        await _assign(c, w, {"isso": "isso", "issm": "isso", "authorizing_official": "ao"})
        pid = await _package(c, w)
        await _act(c, pid, "submit", w.hdr["prep"])
        assert (await _act(c, pid, "isso_approve", w.hdr["isso"]))[0] == 200
        code, body = await _act(c, pid, "issm_approve", w.hdr["isso"])
        assert code == 403 and "separation of duties" in body["detail"]


@pytest.mark.asyncio
async def test_the_submitter_cannot_approve_their_own_package(_auth_enabled: None) -> None:
    w = await _world("AtoPkgE")
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        await _act(c, pid, "submit", w.hdr["isso"])
        code, body = await _act(c, pid, "isso_approve", w.hdr["isso"])
        assert code == 403 and "separation of duties" in body["detail"]


@pytest.mark.asyncio
async def test_return_needs_a_reason_and_resets_the_system(_auth_enabled: None) -> None:
    w = await _world("AtoPkgF")
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        await _act(c, pid, "submit", w.hdr["prep"])
        assert (await _act(c, pid, "return", w.hdr["isso"]))[0] == 409
        code, body = await _act(c, pid, "return", w.hdr["isso"], reason="SSP stale")
        assert code == 200 and body["status"] == "returned"
    assert (await _ato(w))[0] == "none"


@pytest.mark.asyncio
async def test_an_open_high_poam_blocks_the_ao(_auth_enabled: None) -> None:
    w = await _world("AtoPkgG")
    async with session_scope() as s:
        s.add(POAM(system_id=w.sys, title="unpatched", severity="high", status="open"))
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        await _act(c, pid, "submit", w.hdr["prep"])
        await _act(c, pid, "isso_approve", w.hdr["isso"])
        await _act(c, pid, "issm_approve", w.hdr["issm"])
        code, body = await _act(c, pid, "authorize", w.hdr["ao"])
        assert code == 409 and "critical/high POA&M" in body["detail"]
        # Deny is still open to the AO: blockers stop a yes, never a no.
        code, body = await _act(c, pid, "deny", w.hdr["ao"], reason="weakness open")
        assert code == 200 and body["status"] == "denied"


@pytest.mark.asyncio
async def test_an_expired_risk_acceptance_blocks_the_ao(_auth_enabled: None) -> None:
    w = await _world("AtoPkgH")
    async with session_scope() as s:
        s.add(POAM(
            system_id=w.sys, title="accepted", severity="moderate", status="risk_accepted",
            due_on=date.today() - timedelta(days=1), acceptance_rationale="compensated",
        ))
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        await _act(c, pid, "submit", w.hdr["prep"])
        await _act(c, pid, "isso_approve", w.hdr["isso"])
        await _act(c, pid, "issm_approve", w.hdr["issm"])
        code, body = await _act(c, pid, "authorize", w.hdr["ao"])
        assert code == 409 and "past expiry" in body["detail"]


@pytest.mark.asyncio
async def test_a_conditional_authorization_needs_an_end_date(_auth_enabled: None) -> None:
    w = await _world("AtoPkgI")
    async with _client() as c:
        await _signers(c, w)
        pid = await _package(c, w)
        for action, who in (("submit", "prep"), ("isso_approve", "isso"),
                            ("issm_approve", "issm")):
            await _act(c, pid, action, w.hdr[who])
        code, _ = await _act(c, pid, "authorize_conditional", w.hdr["ao"], reason="limits")
        assert code == 409
        until = str(date.today() + timedelta(days=90))
        code, body = await _act(
            c, pid, "authorize_conditional", w.hdr["ao"], reason="limits", expires_on=until
        )
        assert code == 200 and body["status"] == "conditional"


@pytest.mark.asyncio
async def test_a_new_authorization_supersedes_the_old_one(_auth_enabled: None) -> None:
    w = await _world("AtoPkgJ")
    async with _client() as c:
        await _signers(c, w)
        ids = []
        for _ in range(2):
            pid = await _package(c, w)
            for action, who in (("submit", "prep"), ("isso_approve", "isso"),
                                ("issm_approve", "issm"), ("authorize", "ao")):
                code, body = await _act(c, pid, action, w.hdr[who])
                assert code == 200, body
            ids.append(pid)
        first = (await c.get(f"/api/authorization-packages/{ids[0]}", headers=w.hdr["prep"]))
    assert first.json()["status"] == "superseded"


@pytest.mark.asyncio
async def test_direct_authorize_is_refused_when_auth_is_on(_auth_enabled: None) -> None:
    w = await _world("AtoPkgK")
    async with _client() as c:
        r = await c.post(f"/api/systems/{w.sys}/authorize", headers=w.hdr["admin"])
    assert r.status_code == 409 and "authorization package" in r.json()["detail"]


@pytest.mark.asyncio
async def test_the_scheduler_expires_a_lapsed_authorization() -> None:
    w = await _world("AtoPkgL")
    async with session_scope() as s:
        sysm = (await s.execute(select(System).where(System.id == w.sys))).scalar_one()
        sysm.ato_status = "authorized"
        sysm.ato_expires_on = date.today() - timedelta(days=1)
        pkg = AuthorizationPackage(
            organization_id=w.org, system_id=w.sys, label="old", status="authorized",
            authorization_expires_on=date.today() - timedelta(days=1),
        )
        s.add(pkg)
        await s.flush()
        result = await lifecycle.expire_due(s, org_id=w.org)
        pkg_id = pkg.id
    assert result == {"packages_expired": 1, "systems_expired": 1}
    assert (await _ato(w))[0] == "expired"
    async with session_scope() as s:
        p = (await s.execute(
            select(AuthorizationPackage).where(AuthorizationPackage.id == pkg_id)
        )).scalar_one()
        assert p.status == "expired"


# ── POA&M extensions and risk acceptance ─────────────────────────────────


async def _poam(c: AsyncClient, w: World, due: date) -> int:
    r = await c.post(
        "/api/poams",
        json={"system_id": w.sys, "title": "late fix", "severity": "moderate",
              "due_on": str(due)},
        headers=w.hdr["prep"],
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


@pytest.mark.asyncio
async def test_a_later_due_date_needs_an_approved_extension(_auth_enabled: None) -> None:
    w = await _world("AtoExtA")
    due = date.today() + timedelta(days=10)
    later = due + timedelta(days=30)
    async with _client() as c:
        await _signers(c, w)
        pid = await _poam(c, w, due)
        r = await c.patch(f"/api/poams/{pid}", json={"due_on": str(later)}, headers=w.hdr["prep"])
        assert r.status_code == 409 and "extension" in r.json()["detail"]
        # Shortening is free.
        r = await c.patch(
            f"/api/poams/{pid}", json={"due_on": str(due - timedelta(days=1))},
            headers=w.hdr["prep"],
        )
        assert r.status_code == 200, r.text
        r = await c.post(
            f"/api/poams/{pid}/extensions",
            json={"requested_due_on": str(later), "reason": "vendor patch slips"},
            headers=w.hdr["prep"],
        )
        assert r.status_code == 201, r.text
        eid = r.json()["id"]
        # The requester cannot decide, and neither can the ISSO.
        for who in ("prep", "isso"):
            r = await c.post(f"/api/poams/{pid}/extensions/{eid}/approve", headers=w.hdr[who])
            assert r.status_code == 403, (who, r.text)
        r = await c.post(f"/api/poams/{pid}/extensions/{eid}/approve", headers=w.hdr["issm"])
        assert r.status_code == 200, r.text
        got = (await c.get(f"/api/poams/{pid}", headers=w.hdr["prep"])).json()
    assert got["due_on"] == str(later)
    assert got["original_due_on"] == str(due)


@pytest.mark.asyncio
async def test_an_isso_approval_cannot_accept_risk(_auth_enabled: None) -> None:
    w = await _world("AtoRiskA")
    async with _client() as c:
        await _signers(c, w)
        pid = await _poam(c, w, date.today() + timedelta(days=10))
        accept = {
            "status": "risk_accepted", "owner_user_id": w.ids["prep"],
            "due_on": str(date.today() + timedelta(days=60)),
            "acceptance_rationale": "compensating control in place",
        }
        await c.post(f"/api/approvals/poam/{pid}/submit", headers=w.hdr["prep"])
        r = await c.post(f"/api/approvals/poam/{pid}/approve", headers=w.hdr["isso"])
        assert r.status_code == 200, r.text
        r = await c.patch(f"/api/poams/{pid}", json=accept, headers=w.hdr["prep"])
        assert r.status_code == 409 and "Authorizing Official" in r.json()["detail"]
        # Ask again -- the ISSO's unspent approval is voided, not spent -- and
        # the same request goes through once the AO decides.
        r = await c.post(f"/api/approvals/poam/{pid}/submit", headers=w.hdr["prep"])
        assert r.status_code == 200, r.text
        r = await c.post(f"/api/approvals/poam/{pid}/approve", headers=w.hdr["ao"])
        assert r.status_code == 200, r.text
        r = await c.patch(f"/api/poams/{pid}", json=accept, headers=w.hdr["prep"])
        assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_the_spend_refuses_an_approval_regranted_after_the_ao_check(
    _auth_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The AO check is a read and the spend is a write. If, between them, the
    AO's approval was spent and the ISSO re-approved, an unpinned spend would
    accept risk on the ISSO's approval. The spend is pinned to the reviewer
    the check saw. The interleaving is staged: the check reports the AO while
    the stored approval is the ISSO's."""
    from ccf.governance import approvals  # noqa: PLC0415

    w = await _world("AtoRiskPin")
    async with _client() as c:
        await _signers(c, w)
        pid = await _poam(c, w, date.today() + timedelta(days=10))
        await c.post(f"/api/approvals/poam/{pid}/submit", headers=w.hdr["prep"])
        r = await c.post(f"/api/approvals/poam/{pid}/approve", headers=w.hdr["isso"])
        assert r.status_code == 200, r.text

        async def saw_the_ao(*_a: object, **_k: object) -> str:
            return f"ao@{w.name.lower()}.example"

        monkeypatch.setattr(approvals, "authorized_reviewer", saw_the_ao)
        r = await c.patch(f"/api/poams/{pid}", json={
            "status": "risk_accepted", "owner_user_id": w.ids["prep"],
            "due_on": str(date.today() + timedelta(days=60)),
            "acceptance_rationale": "compensating control in place",
        }, headers=w.hdr["prep"])
        assert r.status_code == 409, r.text
        state = (await c.get(f"/api/approvals/poam/{pid}", headers=w.hdr["prep"])).json()
    assert state["state"] == "approved"  # the ISSO's approval was not spent


@pytest.mark.asyncio
async def test_extending_an_acceptance_spends_only_the_aos_approval(
    _auth_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same pin on the other gate that spends a POA&M approval as a risk
    decision: pushing an accepted weakness's expiry later."""
    from ccf.governance import approvals  # noqa: PLC0415

    w = await _world("AtoExtPin")
    accepted_until = date.today() + timedelta(days=60)
    async with _client() as c:
        await _signers(c, w)
        pid = await _poam(c, w, date.today() + timedelta(days=10))
        await c.post(f"/api/approvals/poam/{pid}/submit", headers=w.hdr["prep"])
        await c.post(f"/api/approvals/poam/{pid}/approve", headers=w.hdr["ao"])
        r = await c.patch(f"/api/poams/{pid}", json={
            "status": "risk_accepted", "owner_user_id": w.ids["prep"],
            "due_on": str(accepted_until),
            "acceptance_rationale": "compensating control in place",
        }, headers=w.hdr["prep"])
        assert r.status_code == 200, r.text
        await c.post(f"/api/approvals/poam/{pid}/submit", headers=w.hdr["prep"])
        r = await c.post(f"/api/approvals/poam/{pid}/approve", headers=w.hdr["isso"])
        assert r.status_code == 200, r.text

        async def saw_the_ao(*_a: object, **_k: object) -> str:
            return f"ao@{w.name.lower()}.example"

        monkeypatch.setattr(approvals, "authorized_reviewer", saw_the_ao)
        r = await c.patch(
            f"/api/poams/{pid}", json={"due_on": str(accepted_until + timedelta(days=90))},
            headers=w.hdr["prep"],
        )
        assert r.status_code == 409, r.text
        got = (await c.get(f"/api/poams/{pid}", headers=w.hdr["prep"])).json()
    assert got["due_on"] == str(accepted_until)


@pytest.mark.asyncio
async def test_the_ao_of_one_system_cannot_approve_for_another(_auth_enabled: None) -> None:
    w = await _world("AtoRiskB")
    async with session_scope() as s:
        second = System(organization_id=w.org, name="second")
        s.add(second)
        await s.flush()
        poam = POAM(system_id=second.id, title="other system weakness")
        s.add(poam)
        await s.flush()
        poam_id = poam.id
    async with _client() as c:
        await _signers(c, w)
        await c.post(f"/api/approvals/poam/{poam_id}/submit", headers=w.hdr["prep"])
        r = await c.post(f"/api/approvals/poam/{poam_id}/approve", headers=w.hdr["ao"])
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_another_tenants_poam_cannot_be_submitted(_auth_enabled: None) -> None:
    w = await _world("AtoRiskC")
    other = await _world("AtoRiskC2")
    async with session_scope() as s:
        poam = POAM(system_id=other.sys, title="theirs")
        s.add(poam)
        await s.flush()
        poam_id = poam.id
    async with _client() as c:
        r = await c.post(f"/api/approvals/poam/{poam_id}/submit", headers=w.hdr["prep"])
    assert r.status_code == 404


# ── pages ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_workspace_and_briefs_render_from_real_records() -> None:
    w = await _world("AtoPageA")
    async with session_scope() as s:
        s.add(POAM(system_id=w.sys, title="Overdue thing", severity="high", status="open",
                   due_on=date.today() - timedelta(days=3)))
    async with _client() as c:
        page = await c.get(f"/ato/{w.sys}")
        assert page.status_code == 200
        assert "Overdue thing" in page.text
        assert "1 open critical/high POA&amp;M" in page.text
        # Nothing behind ConMon health: the page must say so, not print 0% or 100%.
        assert "no data" in page.text
        for audience in ("authorizing_official", "issm", "isso", "system_owner"):
            brief = await c.get(f"/ato/{w.sys}/brief?audience={audience}")
            assert brief.status_code == 200, audience
            assert "1 overdue" in brief.text
        index = await c.get("/ato")
        assert index.status_code == 200 and f"/ato/{w.sys}" in index.text


@pytest.mark.asyncio
async def test_another_tenants_workspace_is_not_found(_auth_enabled: None) -> None:
    w = await _world("AtoPageB")
    other = await _world("AtoPageB2")
    async with _client() as c:
        r = await c.get(f"/ato/{other.sys}", headers=w.hdr["prep"])
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_an_issm_cannot_decide_their_own_extension(_auth_enabled: None) -> None:
    w = await _world("AtoExtB")
    async with _client() as c:
        await _signers(c, w)
        pid = await _poam(c, w, date.today() + timedelta(days=5))
        r = await c.post(
            f"/api/poams/{pid}/extensions",
            json={"requested_due_on": str(date.today() + timedelta(days=40)), "reason": "x"},
            headers=w.hdr["issm"],
        )
        eid = r.json()["id"]
        r = await c.post(f"/api/poams/{pid}/extensions/{eid}/approve", headers=w.hdr["issm"])
        assert r.status_code == 403 and "separation of duties" in r.json()["detail"]
        r = await c.post(f"/api/poams/{pid}/extensions/{eid}/approve", headers=w.hdr["ao"])
        assert r.status_code == 200, r.text


# RLS hides another tenant's rows from a scoped request, so the org checks
# below never run through the API -- the check could be deleted and every API
# test would still pass. Pin them on an unscoped session, where RLS is not
# doing the work for them.


@pytest.mark.asyncio
async def test_assign_refuses_another_tenants_user_without_rls() -> None:
    w = await _world("AtoPinA")
    other = await _world("AtoPinA2")
    async with session_scope() as s:
        sysm = (await s.execute(select(System).where(System.id == w.sys))).scalar_one()
        with pytest.raises(system_roles.RoleError, match="no such user"):
            await system_roles.assign(
                s, system=sysm, role="isso", user_id=other.ids["isso"],
                principal=SYSTEM_PRINCIPAL,
            )


@pytest.mark.asyncio
async def test_workspace_lookup_refuses_another_tenant_without_rls() -> None:
    w = await _world("AtoPinB")
    other = await _world("AtoPinB2")
    request = SimpleNamespace(
        state=SimpleNamespace(principal=Principal(w.ids["prep"], "p@x", w.org, "control_owner"))
    )
    async with session_scope() as s:
        assert (await _system(s, w.sys, request)).id == w.sys  # type: ignore[arg-type]
        with pytest.raises(HTTPException) as exc:
            await _system(s, other.sys, request)  # type: ignore[arg-type]
    assert exc.value.status_code == 404
