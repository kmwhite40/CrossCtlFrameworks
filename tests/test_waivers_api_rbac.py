"""Waiver API under real auth: role gate, tenant isolation, and self-approval.

``tests/test_waivers_api.py`` runs with auth disabled, so every request is
``SYSTEM_PRINCIPAL`` (``org_id=None``, unconditionally global): ``require_role``
short-circuits, ``can_approve(..., is_global=True)`` returns True
unconditionally, and ``_load``'s tenant check is skipped. None of the
authorization branches in ``api/routes/waivers.py`` are exercised there --
including self-approval, which that file's ``test_approve_records_who_and_when``
incidentally performs and passes for exactly that reason.

Mirrors ``tests/test_audit_rbac.py``'s (and ``tests/test_boundary_api.py``'s)
auth-enabled harness exactly (module autouse ``_auth_enabled`` fixture,
``_client()``, ``_mk_user``/``_mk_user_and_system``, ``_auth``) -- this repo's
tests use unique org/email names per test since the DB isn't truncated between
tests.
"""

from __future__ import annotations

import itertools
import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user_and_system(
    email: str, org_name: str, role: str, sys_name: str
) -> tuple[str, int]:
    """Create an org + a user with the given role + a System in that org.

    Returns ``(bearer_token, system_id)``.
    """
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        sysrow = System(organization_id=org.id, name=sys_name)
        s.add(sysrow)
        await s.flush()
        return user.api_token, sysrow.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _body(system_id: int, **kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "system_id": system_id,
        "check_key": "m365.identity.mfa_registered",
        "rationale": "Break-glass account exempt by design; compensating control in place.",
    }
    base.update(kw)
    return base


def _tag() -> str:
    return str(next(_SEQ))


# --- non-approver roles get 403 on approve/revoke ---------------------------


@pytest.mark.asyncio
async def test_control_owner_cannot_approve() -> None:
    """control_owner is typically the party a finding belongs to -- the same
    conflict of interest separation-of-duties exists to police -- so it is
    deliberately excluded from APPROVER_ROLES."""
    tag = _tag()
    token, sys_id = await _mk_user_and_system(
        f"co-{tag}@waivers-rbac.test", f"Waivers RBAC ControlOwner Org {tag}",
        "control_owner", f"CO Sys {tag}",
    )
    async with _client() as c:
        created = await c.post("/api/waivers", json=_body(sys_id), headers=_auth(token))
        assert created.status_code == 201, created.text
        wid = created.json()["id"]

        approve = await c.post(f"/api/waivers/{wid}/approve", headers=_auth(token))
        assert approve.status_code == 403, approve.text
        revoke = await c.post(f"/api/waivers/{wid}/revoke", headers=_auth(token))
        assert revoke.status_code == 403, revoke.text


@pytest.mark.asyncio
async def test_assessor_cannot_approve() -> None:
    """assessor evaluates whether a control works; accepting the risk of it
    not working is a separate responsibility FedRAMP keeps independent of
    assessment, so assessor is also excluded from APPROVER_ROLES."""
    tag = _tag()
    token, sys_id = await _mk_user_and_system(
        f"assessor-{tag}@waivers-rbac.test", f"Waivers RBAC Assessor Org {tag}",
        "assessor", f"Assessor Sys {tag}",
    )
    async with _client() as c:
        created = await c.post("/api/waivers", json=_body(sys_id), headers=_auth(token))
        assert created.status_code == 201, created.text
        wid = created.json()["id"]

        approve = await c.post(f"/api/waivers/{wid}/approve", headers=_auth(token))
        assert approve.status_code == 403, approve.text


@pytest.mark.asyncio
async def test_viewer_cannot_approve() -> None:
    tag = _tag()
    admin_token, sys_id = await _mk_user_and_system(
        f"admin-{tag}@waivers-rbac.test", f"Waivers RBAC Viewer Org {tag}",
        "admin", f"Viewer Sys {tag}",
    )
    async with session_scope() as s:
        org_id = (
            await s.execute(
                select(System.organization_id).where(System.id == sys_id)
            )
        ).scalar_one()
        viewer = User(
            email=f"viewer-{tag}@waivers-rbac.test",
            organization_id=org_id,
            role="viewer",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(viewer)
        await s.flush()
        viewer_token = viewer.api_token

    async with _client() as c:
        created = await c.post("/api/waivers", json=_body(sys_id), headers=_auth(admin_token))
        assert created.status_code == 201, created.text
        wid = created.json()["id"]

        approve = await c.post(f"/api/waivers/{wid}/approve", headers=_auth(viewer_token))
        assert approve.status_code == 403, approve.text


@pytest.mark.asyncio
async def test_admin_can_approve() -> None:
    tag = _tag()
    requester_token, sys_id = await _mk_user_and_system(
        f"req-{tag}@waivers-rbac.test", f"Waivers RBAC Admin Org {tag}",
        "control_owner", f"Admin Sys {tag}",
    )
    async with session_scope() as s:
        org_id = (
            await s.execute(
                select(System.organization_id).where(System.id == sys_id)
            )
        ).scalar_one()
        admin = User(
            email=f"admin-{tag}@waivers-rbac.test",
            organization_id=org_id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(admin)
        await s.flush()
        admin_token = admin.api_token

    async with _client() as c:
        created = await c.post(
            "/api/waivers", json=_body(sys_id), headers=_auth(requester_token)
        )
        assert created.status_code == 201, created.text
        wid = created.json()["id"]

        approved = await c.post(f"/api/waivers/{wid}/approve", headers=_auth(admin_token))
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"


# --- self-approval is refused even for an approver role ---------------------


@pytest.mark.asyncio
async def test_self_approval_is_refused() -> None:
    """The prior (auth-disabled) test suite's ``test_approve_records_who_and_when``
    approves the waiver it just created and passes -- because SYSTEM_PRINCIPAL
    is global and can_approve's separation-of-duties check exempts global
    principals by design. Under real auth, an admin approving their own
    request must be refused."""
    tag = _tag()
    token, sys_id = await _mk_user_and_system(
        f"selfapprove-{tag}@waivers-rbac.test", f"Waivers RBAC SelfApprove Org {tag}",
        "admin", f"SelfApprove Sys {tag}",
    )
    async with _client() as c:
        created = await c.post("/api/waivers", json=_body(sys_id), headers=_auth(token))
        assert created.status_code == 201, created.text
        wid = created.json()["id"]

        approve = await c.post(f"/api/waivers/{wid}/approve", headers=_auth(token))
        assert approve.status_code == 403, approve.text


# --- cross-tenant: a waiver from another org is 404, not visible/approvable -


@pytest.mark.asyncio
async def test_cross_tenant_waiver_is_not_found() -> None:
    """404 rather than 403 (``_load``'s own rationale): confirming an id
    exists in another tenant is itself a disclosure."""
    tag = _tag()
    _owner_token, org_a_sys = await _mk_user_and_system(
        f"owner-{tag}@waivers-rbac.test", f"Waivers RBAC CrossTenant OrgA {tag}",
        "admin", f"OrgA Sys {tag}",
    )
    outsider_token, _org_b_sys = await _mk_user_and_system(
        f"outsider-{tag}@waivers-rbac.test", f"Waivers RBAC CrossTenant OrgB {tag}",
        "admin", f"OrgB Sys {tag}",
    )
    async with _client() as c:
        created = await c.post(
            "/api/waivers", json=_body(org_a_sys), headers=_auth(_owner_token)
        )
        assert created.status_code == 201, created.text
        wid = created.json()["id"]

        approve = await c.post(f"/api/waivers/{wid}/approve", headers=_auth(outsider_token))
        assert approve.status_code == 404, approve.text
        revoke = await c.post(f"/api/waivers/{wid}/revoke", headers=_auth(outsider_token))
        assert revoke.status_code == 404, revoke.text


@pytest.mark.asyncio
async def test_cross_tenant_system_is_not_found_on_create() -> None:
    """Requesting a waiver against another org's system is refused the same
    way -- 404, matching the system-scoping check already in create_waiver."""
    tag = _tag()
    _owner_token, org_a_sys = await _mk_user_and_system(
        f"owner2-{tag}@waivers-rbac.test", f"Waivers RBAC CrossTenant2 OrgA {tag}",
        "admin", f"OrgA2 Sys {tag}",
    )
    outsider_token, _org_b_sys = await _mk_user_and_system(
        f"outsider2-{tag}@waivers-rbac.test", f"Waivers RBAC CrossTenant2 OrgB {tag}",
        "admin", f"OrgB2 Sys {tag}",
    )
    async with _client() as c:
        created = await c.post(
            "/api/waivers", json=_body(org_a_sys), headers=_auth(outsider_token)
        )
        assert created.status_code == 404, created.text


# --- unauthenticated is refused ----------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_refused() -> None:
    async with _client() as c:
        r = await c.get("/api/waivers")
        assert r.status_code == 401
