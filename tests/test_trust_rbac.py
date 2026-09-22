"""Trust Center under real auth: role gate, UI/API parity, tenant isolation.

``tests/test_grc_integration.py`` exercises these routes with auth *disabled*,
so every request is ``SYSTEM_PRINCIPAL`` — ``is_global``, which short-circuits
``require_role`` entirely (``auth_deps.py``) and leaves ``org_id`` ``None`` so
no tenant predicate ever narrows anything. That file therefore pins nothing
about who may reach the trust routes. This one uses real role-bearing
principals, the same harness ``tests/test_waivers_api_rbac.py`` established
(module autouse ``_auth_enabled``, ``_client()``, ``_mk_user``, ``_auth``),
with unique org/email names per test since the DB isn't truncated between them.

What it pins:

* profile edit and approve/deny are **admin**, on both the API and the
  server-rendered UI — ``viewer`` and ``control_owner`` get 403;
* every role can still *read* the trust page, the profile and the request
  list, and any member can *ask* for access (asking is not approving);
* a decision made through the UI leaves the same audit record as the same
  decision made through the API — asserted by equality, not by shape;
* another tenant's request is not decidable, 404 rather than 403.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.api.routes.grc import _load_access_request
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Event, Organization, User
from ccf.models_grc import TrustAccessRequest, TrustProfile

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

#: Every role a User may hold (``models.User.role``'s enum). Reads must work
#: for all of them — a fix that locks out readers is a worse bug than the
#: missing gate.
ALL_ROLES = ("admin", "control_owner", "assessor", "viewer")

#: The roles the mapping deliberately refuses on a write. ``control_owner`` is
#: the party a trust request usually concerns, the same conflict of interest
#: ``waivers.APPROVER_ROLES`` excludes it for.
NON_ADMIN_ROLES = ("viewer", "control_owner")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _tag() -> str:
    return str(next(_SEQ))


async def _mk_org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


async def _mk_user(org_id: int, email: str, role: str) -> str:
    """A user with ``role`` in ``org_id``; returns the bearer token."""
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
        return user.api_token


async def _mk_request(org_id: int, requester: str) -> int:
    async with session_scope() as s:
        r = TrustAccessRequest(organization_id=org_id, requester_name=requester)
        s.add(r)
        await s.flush()
        return r.id


async def _load_request(req_id: int) -> TrustAccessRequest:
    async with session_scope() as s:
        return (
            await s.execute(
                select(TrustAccessRequest).where(TrustAccessRequest.id == req_id)
            )
        ).scalar_one()


async def _profile_headline(org_id: int) -> str | None:
    async with session_scope() as s:
        row = (
            await s.execute(select(TrustProfile).where(TrustProfile.organization_id == org_id))
        ).scalar_one_or_none()
        return None if row is None else row.headline


async def _decision_events(req_id: int) -> list[Event]:
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(Event)
                    .where(
                        Event.entity_type == "trust_access_request",
                        Event.entity_id == str(req_id),
                        Event.verb == "decided",
                    )
                    .order_by(Event.id)
                )
            ).scalars().all()
        )


# --- writes are admin-only --------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
async def test_non_admin_cannot_edit_the_trust_profile(role: str) -> None:
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Profile {role} Org {tag}")
    token = await _mk_user(org, f"{role}-{tag}@trust-rbac.test", role)
    async with _client() as c:
        api = await c.put(
            "/api/trust/profile", json={"headline": "pwned"}, headers=_auth(token)
        )
        assert api.status_code == 403, api.text
        ui = await c.post("/trust", data={"headline": "pwned", "summary": ""},
                          headers=_auth(token))
        assert ui.status_code == 403, ui.text
    # The row, not just the status code: nothing was written either way.
    assert await _profile_headline(org) != "pwned"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
async def test_non_admin_cannot_decide_an_access_request(role: str) -> None:
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Decide {role} Org {tag}")
    token = await _mk_user(org, f"{role}-decide-{tag}@trust-rbac.test", role)
    req_id = await _mk_request(org, f"Acme {tag}")
    async with _client() as c:
        api = await c.post(
            f"/api/trust/access-requests/{req_id}/decide?approve=true", headers=_auth(token)
        )
        assert api.status_code == 403, api.text
        ui = await c.post(
            f"/trust/access-requests/{req_id}/decide", data={"approve": "1"},
            headers=_auth(token),
        )
        assert ui.status_code == 403, ui.text
    row = await _load_request(req_id)
    assert row.status == "pending"  # the stored row, not just the refusal
    assert row.decided_by is None
    assert row.decided_at is None
    assert await _decision_events(req_id) == []


@pytest.mark.asyncio
async def test_admin_can_edit_the_profile_and_decide() -> None:
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Admin Org {tag}")
    token = await _mk_user(org, f"admin-{tag}@trust-rbac.test", "admin")
    req_id = await _mk_request(org, f"Acme {tag}")
    async with _client() as c:
        api = await c.put(
            "/api/trust/profile", json={"headline": f"Posture {tag}"}, headers=_auth(token)
        )
        assert api.status_code == 200, api.text
        decided = await c.post(
            f"/api/trust/access-requests/{req_id}/decide?approve=true", headers=_auth(token)
        )
        assert decided.status_code == 200, decided.text
    assert await _profile_headline(org) == f"Posture {tag}"
    row = await _load_request(req_id)
    assert row.status == "approved"
    assert row.decided_by == f"admin-{tag}@trust-rbac.test"


@pytest.mark.asyncio
async def test_admin_can_save_the_profile_through_the_ui() -> None:
    tag = _tag()
    org = await _mk_org(f"Trust RBAC UI Save Org {tag}")
    token = await _mk_user(org, f"admin-uisave-{tag}@trust-rbac.test", "admin")
    async with _client() as c:
        saved = await c.post(
            "/trust", data={"headline": f"UI posture {tag}", "summary": "s"},
            headers=_auth(token), follow_redirects=False,
        )
        assert saved.status_code == 303, saved.text
    assert await _profile_headline(org) == f"UI posture {tag}"


# --- reads stay open to every role -----------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ALL_ROLES)
async def test_every_role_can_read_the_trust_center(role: str) -> None:
    """Including ``GET /trust``, which was not smoke-tested for rendering."""
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Read {role} Org {tag}")
    token = await _mk_user(org, f"{role}-read-{tag}@trust-rbac.test", role)
    await _mk_request(org, f"Reader Co {tag}")
    async with _client() as c:
        page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert "text/html" in page.headers["content-type"]
        assert f"Reader Co {tag}" in page.text  # it actually rendered the data

        profile = await c.get("/api/trust/profile", headers=_auth(token))
        assert profile.status_code == 200, profile.text
        assert "headline" in profile.json()

        listed = await c.get("/api/trust/access-requests", headers=_auth(token))
        assert listed.status_code == 200, listed.text
        assert [r["requester_name"] for r in listed.json()] == [f"Reader Co {tag}"]

        pkg = await c.get("/api/trust/package", headers=_auth(token))
        assert pkg.status_code == 200, pkg.text


@pytest.mark.asyncio
@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
async def test_any_member_may_ask_for_access(role: str) -> None:
    """Logging that someone asked is not an approval, so it is not gated."""
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Ask {role} Org {tag}")
    token = await _mk_user(org, f"{role}-ask-{tag}@trust-rbac.test", role)
    async with _client() as c:
        api = await c.post(
            "/api/trust/access-requests",
            json={"requester_name": f"Asker {tag}"},
            headers=_auth(token),
        )
        assert api.status_code == 201, api.text
        ui = await c.post(
            "/trust/access-requests",
            data={"requester_name": f"UI Asker {tag}"},
            headers=_auth(token), follow_redirects=False,
        )
        assert ui.status_code == 303, ui.text
    row = await _load_request(api.json()["id"])
    assert row.status == "pending"  # asking decides nothing


# --- the UI decision records what the API decision records ------------------


@pytest.mark.asyncio
async def test_a_ui_decision_records_exactly_what_the_api_decision_records() -> None:
    """Asserted by equality against the API path, not by shape.

    The UI handler used to set ``status`` and ``decided_at`` and nothing else:
    no ``decided_by``, no bus event. The same decision through the two paths
    must be indistinguishable in the record it leaves.
    """
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Parity Org {tag}")
    email = f"admin-parity-{tag}@trust-rbac.test"
    token = await _mk_user(org, email, "admin")
    via_api = await _mk_request(org, f"Parity Co {tag}")
    via_ui = await _mk_request(org, f"Parity Co {tag}")
    async with _client() as c:
        a = await c.post(
            f"/api/trust/access-requests/{via_api}/decide?approve=true", headers=_auth(token)
        )
        assert a.status_code == 200, a.text
        u = await c.post(
            f"/trust/access-requests/{via_ui}/decide", data={"approve": "1"},
            headers=_auth(token), follow_redirects=False,
        )
        assert u.status_code == 303, u.text

    api_row, ui_row = await _load_request(via_api), await _load_request(via_ui)
    assert ui_row.status == api_row.status == "approved"
    assert ui_row.decided_by == api_row.decided_by == email
    assert ui_row.decided_at is not None

    api_events, ui_events = await _decision_events(via_api), await _decision_events(via_ui)
    assert len(ui_events) == len(api_events) == 1
    api_ev, ui_ev = api_events[0], ui_events[0]
    assert (ui_ev.verb, ui_ev.entity_type, ui_ev.actor, ui_ev.organization_id, ui_ev.summary) == (
        api_ev.verb, api_ev.entity_type, api_ev.actor, api_ev.organization_id, api_ev.summary
    )
    assert ui_ev.actor == email


@pytest.mark.asyncio
async def test_a_ui_denial_is_recorded_as_a_denial() -> None:
    """The event summary carries the decision, so an approval and a denial are
    not the same audit record."""
    tag = _tag()
    org = await _mk_org(f"Trust RBAC Deny Org {tag}")
    email = f"admin-deny-{tag}@trust-rbac.test"
    token = await _mk_user(org, email, "admin")
    req_id = await _mk_request(org, f"Denied Co {tag}")
    async with _client() as c:
        u = await c.post(
            f"/trust/access-requests/{req_id}/decide", data={"approve": "0"},
            headers=_auth(token), follow_redirects=False,
        )
        assert u.status_code == 303, u.text
    row = await _load_request(req_id)
    assert row.status == "denied"
    assert row.decided_by == email
    events = await _decision_events(req_id)
    assert len(events) == 1
    assert "denied" in events[0].summary


# --- cross-tenant -----------------------------------------------------------


@pytest.mark.asyncio
async def test_another_organizations_request_is_not_decidable() -> None:
    """404 rather than 403, the distinction ``test_waivers_api_rbac`` keeps:
    confirming an id exists in another tenant is itself a disclosure."""
    tag = _tag()
    org_a = await _mk_org(f"Trust RBAC CrossTenant OrgA {tag}")
    org_b = await _mk_org(f"Trust RBAC CrossTenant OrgB {tag}")
    outsider = await _mk_user(org_b, f"outsider-{tag}@trust-rbac.test", "admin")
    req_id = await _mk_request(org_a, f"OrgA Co {tag}")
    async with _client() as c:
        api = await c.post(
            f"/api/trust/access-requests/{req_id}/decide?approve=true", headers=_auth(outsider)
        )
        assert api.status_code == 404, api.text
        ui = await c.post(
            f"/trust/access-requests/{req_id}/decide", data={"approve": "1"},
            headers=_auth(outsider), follow_redirects=False,
        )
        assert ui.status_code == 404, ui.text
    row = await _load_request(req_id)
    assert row.status == "pending"  # untouched
    assert row.decided_by is None
    assert await _decision_events(req_id) == []


@pytest.mark.asyncio
async def test_another_organizations_request_is_not_listed_or_rendered() -> None:
    tag = _tag()
    org_a = await _mk_org(f"Trust RBAC Listing OrgA {tag}")
    org_b = await _mk_org(f"Trust RBAC Listing OrgB {tag}")
    outsider = await _mk_user(org_b, f"outsider-list-{tag}@trust-rbac.test", "viewer")
    await _mk_request(org_a, f"Hidden Co {tag}")
    async with _client() as c:
        listed = await c.get("/api/trust/access-requests", headers=_auth(outsider))
        assert listed.status_code == 200, listed.text
        assert all(f"Hidden Co {tag}" != r["requester_name"] for r in listed.json())
        page = await c.get("/trust", headers=_auth(outsider))
        assert page.status_code == 200
        assert f"Hidden Co {tag}" not in page.text


@pytest.mark.asyncio
async def test_the_org_predicate_is_the_only_defense_on_an_unscoped_session() -> None:
    """Asserted where the predicate actually bears weight.

    Over HTTP ``deps.get_session`` already sets the RLS tenant from the
    principal, so the explicit predicate is a backstop *beneath* that and
    deleting it does not fail the HTTP cross-tenant test above — it is a
    surviving mutation by construction, not a gap in that test. Where it is
    the only defense is the unscoped ``session_scope()`` the CLI and scheduler
    use, which bypasses RLS by design; ``capability/derive.py`` gives the same
    reason for its own explicit predicate. So it is pinned there.
    """
    tag = _tag()
    org_a = await _mk_org(f"Trust RBAC Unscoped OrgA {tag}")
    org_b = await _mk_org(f"Trust RBAC Unscoped OrgB {tag}")
    req_id = await _mk_request(org_a, f"Unscoped Co {tag}")
    outsider = Principal(
        user_id=None, email=f"outsider-unscoped-{tag}@trust-rbac.test",
        org_id=org_b, role="admin",
    )
    owner = Principal(
        user_id=None, email=f"owner-unscoped-{tag}@trust-rbac.test",
        org_id=org_a, role="admin",
    )
    async with session_scope() as s:  # unscoped: RLS is not filtering here
        assert (
            await s.execute(
                select(TrustAccessRequest).where(TrustAccessRequest.id == req_id)
            )
        ).scalar_one_or_none() is not None  # the row IS visible without the predicate

        with pytest.raises(HTTPException) as exc:
            await _load_access_request(s, req_id, outsider)
        assert exc.value.status_code == 404  # 404, not 403 — no id disclosure

        found = await _load_access_request(s, req_id, owner)
        assert found.id == req_id  # and the owning org is not locked out
