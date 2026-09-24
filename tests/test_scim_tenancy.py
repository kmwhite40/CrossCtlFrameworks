"""SCIM provisioning is one deployment-wide token, and it must not cross tenants.

`_scim_org` authorizes on a single bearer token configured for the whole
deployment and returns no principal, so `get_session` binds no tenant and the
RLS policies treat the request as bypass. Every query SCIM makes therefore sees
every organization's rows. That is the condition these tests are written
against -- an HTTP-only assertion here would prove nothing about scoping, so
each check reads the victim organization back on an unscoped `session_scope()`.

`User.email` is globally unique, so the same address cannot exist in two
organizations. A SCIM payload naming an email that belongs to another tenant is
therefore never an update -- it is a conflict, and SCIM has a status for it.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

TOKEN = "scim-tenancy-token"
HDR = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


async def _user(org_id: int, email: str, name: str) -> int:
    async with session_scope() as s:
        u = User(organization_id=org_id, email=email, full_name=name, active=True)
        s.add(u)
        await s.flush()
        return u.id


@pytest.fixture
def _scim(monkeypatch):
    """SCIM enabled with a token; the target org is set per test."""
    monkeypatch.setenv("CCF_SCIM_ENABLED", "true")
    monkeypatch.setenv("CCF_SCIM_BEARER_TOKEN", TOKEN)

    def target(org_id: int | None) -> None:
        if org_id is None:
            monkeypatch.delenv("CCF_SCIM_ORGANIZATION_ID", raising=False)
        else:
            monkeypatch.setenv("CCF_SCIM_ORGANIZATION_ID", str(org_id))
        get_settings.cache_clear()

    target(None)
    yield target
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_scim_never_mutates_a_user_in_another_organization(_scim) -> None:
    """The defect: one IdP renaming and deactivating another tenant's user.

    The lookup was `select(User).where(User.email == email)` with no org
    predicate, on a session with RLS cleared. A payload carrying a foreign
    tenant's email reached that tenant's row and wrote `full_name` and
    `active` to it, then audited the write against the victim's own org.
    """
    victim_org = await _org("SCIM Victim Org")
    caller_org = await _org("SCIM Caller Org")
    victim_id = await _user(victim_org, "shared@tenant.gov", "Victim Original Name")
    _scim(caller_org)

    async with _client() as c:
        resp = await c.post(
            "/api/scim/v2/Users",
            headers=HDR,
            json={
                "userName": "shared@tenant.gov",
                "displayName": "Attacker Renamed Them",
                "active": False,
            },
        )

    assert resp.status_code == 409, resp.text

    # Unscoped read: RLS is already bypassed for SCIM, so this asserts the
    # app-layer refusal rather than re-testing the policy.
    async with session_scope() as s:
        victim = (await s.execute(select(User).where(User.id == victim_id))).scalar_one()
        assert victim.organization_id == victim_org
        assert victim.full_name == "Victim Original Name"
        assert victim.active is True


@pytest.mark.asyncio
async def test_scim_still_updates_a_user_of_its_own_organization(_scim) -> None:
    """A fix that refuses everything is not a fix. The idempotent update stays."""
    org = await _org("SCIM Own Org")
    uid = await _user(org, "own@tenant.gov", "Original Name")
    _scim(org)

    async with _client() as c:
        resp = await c.post(
            "/api/scim/v2/Users",
            headers=HDR,
            json={"userName": "own@tenant.gov", "displayName": "Renamed By IdP", "active": False},
        )

    assert resp.status_code == 201, resp.text
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == uid))).scalar_one()
        assert user.full_name == "Renamed By IdP"
        assert user.active is False


@pytest.mark.asyncio
async def test_scim_provisions_into_the_configured_organization_not_the_lowest_id(_scim) -> None:
    """`_default_org_id` returned `ORDER BY id LIMIT 1` -- the oldest org.

    With one deployment-wide token and several tenants, that silently routed
    every provisioned user into whichever organization happened to be created
    first, whatever the IdP behind the token represented.
    """
    first = await _org("SCIM Oldest Org")
    second = await _org("SCIM Intended Org")
    assert first < second
    _scim(second)

    async with _client() as c:
        resp = await c.post(
            "/api/scim/v2/Users", headers=HDR, json={"userName": "routed@tenant.gov"}
        )

    assert resp.status_code == 201, resp.text
    async with session_scope() as s:
        user = (
            await s.execute(select(User).where(User.email == "routed@tenant.gov"))
        ).scalar_one()
        assert user.organization_id == second


@pytest.mark.asyncio
async def test_scim_refuses_when_the_target_organization_is_ambiguous(_scim) -> None:
    """Two tenants, one token, no configured target: there is no right answer.

    Refuse and say why, the rule `ssp/seed.py` already applies to a missing
    baseline. Guessing writes a real user into a real tenant on no evidence.
    """
    await _org("SCIM Ambiguous A")
    await _org("SCIM Ambiguous B")
    _scim(None)

    async with _client() as c:
        resp = await c.post(
            "/api/scim/v2/Users", headers=HDR, json={"userName": "ambiguous@tenant.gov"}
        )

    assert resp.status_code == 500, resp.text
    assert "ambiguous" in resp.text.lower()
    async with session_scope() as s:
        assert (
            await s.execute(select(User).where(User.email == "ambiguous@tenant.gov"))
        ).scalar_one_or_none() is None


# ── the other doors into the same defect ────────────────────────────────────
#
# The create path was the one that looked like a provisioning bug. The read,
# update and delete paths take a `user_id` (or no filter at all) and act on
# whatever organization owns the row, which is the same cross-tenant reach
# through an route that never looked like provisioning.


@pytest.mark.asyncio
async def test_scim_list_does_not_enumerate_another_organizations_users(_scim) -> None:
    """`select(User).order_by(User.id)` with RLS cleared returns every tenant."""
    other = await _org("SCIM List Other")
    mine = await _org("SCIM List Mine")
    await _user(other, "listed-other@tenant.gov", "Other Tenant User")
    await _user(mine, "listed-mine@tenant.gov", "My User")
    _scim(mine)

    async with _client() as c:
        resp = await c.get("/api/scim/v2/Users", headers=HDR)

    assert resp.status_code == 200, resp.text
    emails = {r["userName"] for r in resp.json()["Resources"]}
    assert "listed-mine@tenant.gov" in emails
    assert "listed-other@tenant.gov" not in emails, emails


@pytest.mark.asyncio
async def test_scim_get_does_not_read_another_organizations_user(_scim) -> None:
    other = await _org("SCIM Get Other")
    mine = await _org("SCIM Get Mine")
    victim = await _user(other, "read-other@tenant.gov", "Other Tenant User")
    _scim(mine)

    async with _client() as c:
        resp = await c.get(f"/api/scim/v2/Users/{victim}", headers=HDR)

    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_scim_patch_does_not_deactivate_another_organizations_user(_scim) -> None:
    """`org_id = user.organization_id` took the victim's own org as authority."""
    other = await _org("SCIM Patch Other")
    mine = await _org("SCIM Patch Mine")
    victim = await _user(other, "patch-other@tenant.gov", "Other Tenant User")
    _scim(mine)

    async with _client() as c:
        resp = await c.patch(
            f"/api/scim/v2/Users/{victim}",
            headers=HDR,
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        )

    assert resp.status_code == 404, resp.text
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == victim))).scalar_one()
        assert user.active is True


@pytest.mark.asyncio
async def test_scim_delete_does_not_deactivate_another_organizations_user(_scim) -> None:
    other = await _org("SCIM Delete Other")
    mine = await _org("SCIM Delete Mine")
    victim = await _user(other, "delete-other@tenant.gov", "Other Tenant User")
    _scim(mine)

    async with _client() as c:
        resp = await c.delete(f"/api/scim/v2/Users/{victim}", headers=HDR)

    assert resp.status_code == 404, resp.text
    async with session_scope() as s:
        user = (await s.execute(select(User).where(User.id == victim))).scalar_one()
        assert user.active is True


@pytest.mark.asyncio
async def test_scim_groups_does_not_list_another_organizations_mappings(_scim) -> None:
    """The fifth door, missed when the other four were fixed.

    This file's own section header above names "the read, update and delete
    paths ... (or no filter at all)" -- and the one route matching "no filter at
    all" was the one left uncovered. `scim_list_groups` bound the resolved
    organization to `_org_id` and discarded it, on a session RLS treats as
    bypass.

    An IdP group name is not nothing: it carries a tenant's internal
    organizational structure, and the mapping says which of those groups
    confers admin.
    """
    from ccf.models_identity import GroupRoleMapping  # noqa: PLC0415

    other = await _org("SCIM Groups Other")
    mine = await _org("SCIM Groups Mine")
    async with session_scope() as s:
        s.add(GroupRoleMapping(organization_id=other, group="OTHER-TENANT-GROUP", role="admin"))
        s.add(GroupRoleMapping(organization_id=mine, group="MY-GROUP", role="viewer"))
    _scim(mine)

    async with _client() as c:
        resp = await c.get("/api/scim/v2/Groups", headers=HDR)

    assert resp.status_code == 200, resp.text
    names = {r["displayName"] for r in resp.json()["Resources"]}
    assert "MY-GROUP" in names
    assert "OTHER-TENANT-GROUP" not in names, names
