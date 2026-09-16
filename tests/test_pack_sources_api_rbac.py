"""Pack-source API under real auth: the ADOPTER_ROLES gate, both directions.

``tests/test_pack_sources_api.py`` (like ``tests/test_waivers_api.py`` before
it) used to run every request as ``SYSTEM_PRINCIPAL`` (global,
``org_id=None``): ``require_role`` short-circuits for a global principal, so
neither ``/adopt``'s existing role gate nor the ``auto_install`` gate added at
registration (PR #17 security review, IMPORTANT 5) ever saw a caller who
*should* be refused. IMPORTANT 5 explicitly calls this out: "ADOPTER_ROLES has
no failing-direction test at all, because every API test runs as a global
principal."

Mirrors ``tests/test_waivers_api_rbac.py``'s harness exactly (module autouse
``_auth_enabled`` fixture, ``_client()``, ``_mk_user``, ``_auth()``) -- unique
org/email names per test since the DB isn't truncated between tests.
"""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.api.routes.packs import PackSourceIn, adopt_source, register_source
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User
from ccf.models_packs import PackSource
from ccf.packs.sync import check_pack_source
from tests.conftest import pack_source_url

pytestmark = pytest.mark.usefixtures("fresh_engine", "local_pack_source_fetch")

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


async def _mk_user(email: str, org_name: str, role: str) -> tuple[str, int]:
    """An org + a user with the given role in it. Returns ``(token, org_id)``."""
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
        await s.flush()
        return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _tag() -> str:
    return str(next(_SEQ))


def _manifest(pack_id: str, version: str = "1.0.0") -> dict:
    return {
        "id": pack_id,
        "name": "RBAC Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2"}],
    }


async def _register(client: AsyncClient, token: str, pack_key: str, url: str, **extra: object):
    resp = await client.post(
        f"/api/packs/{pack_key}/sources", json={"url": url, **extra}, headers=_auth(token)
    )
    return resp


# --- auto_install at registration requires an adopter role ------------------


@pytest.mark.asyncio
async def test_a_viewer_cannot_register_with_auto_install(tmp_path: Path) -> None:
    tag = _tag()
    token, _org = await _mk_user(
        f"viewer-{tag}@pack-rbac.test", f"PackRBAC Viewer Org {tag}", "viewer"
    )
    path = tmp_path / f"viewer-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with _client() as c:
        resp = await _register(
            c, token, f"pack-{tag}", pack_source_url(path), auto_install=True
        )
        assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_a_control_owner_cannot_register_with_auto_install(tmp_path: Path) -> None:
    """control_owner is excluded from ADOPTER_ROLES for the same
    separation-of-duties reason waivers excludes it from APPROVER_ROLES."""
    tag = _tag()
    token, _org = await _mk_user(
        f"co-{tag}@pack-rbac.test", f"PackRBAC ControlOwner Org {tag}", "control_owner"
    )
    path = tmp_path / f"co-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with _client() as c:
        resp = await _register(
            c, token, f"pack-{tag}", pack_source_url(path), auto_install=True
        )
        assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_a_viewer_can_still_register_without_auto_install(tmp_path: Path) -> None:
    """The gate is specifically on auto_install=True -- ordinary (reviewed)
    registration stays open to any authenticated principal, matching
    "detection is automatic; adoption is not"."""
    tag = _tag()
    token, _org = await _mk_user(
        f"viewer2-{tag}@pack-rbac.test", f"PackRBAC Viewer2 Org {tag}", "viewer"
    )
    path = tmp_path / f"viewer2-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with _client() as c:
        resp = await _register(c, token, f"pack-{tag}", pack_source_url(path))
        assert resp.status_code == 201, resp.text
        assert resp.json()["auto_install"] is False


@pytest.mark.asyncio
async def test_an_admin_can_register_with_auto_install(tmp_path: Path) -> None:
    tag = _tag()
    token, _org = await _mk_user(
        f"admin-{tag}@pack-rbac.test", f"PackRBAC Admin Org {tag}", "admin"
    )
    path = tmp_path / f"admin-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with _client() as c:
        resp = await _register(
            c, token, f"pack-{tag}", pack_source_url(path), auto_install=True
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["auto_install"] is True


@pytest.mark.asyncio
async def test_an_issm_can_register_with_auto_install(tmp_path: Path) -> None:
    """``issm``/``isso`` are not yet values ``ccf.user_role`` (the Postgres
    enum backing ``User.role``) accepts, so there is no way to mint a real
    bearer token with one of these roles through the HTTP/DB path -- exercised
    directly against the route function instead, exactly like
    ``test_pack_sources_api.py``'s cross-tenant and global-principal tests
    already do for the same reason (a ``Principal`` is a plain dataclass, not
    constrained by that enum)."""
    tag = _tag()
    path = tmp_path / f"issm-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with session_scope() as session:
        org = Organization(name=f"PackRBAC ISSM Org {tag}")
        session.add(org)
        await session.flush()
        issm = Principal(user_id=1, email="issm@pack-rbac.test", org_id=org.id, role="issm")
        body = PackSourceIn(url=pack_source_url(path), auto_install=True)
        out = await register_source(f"pack-{tag}", body, session, issm)
        assert out["auto_install"] is True


# --- /adopt requires an adopter role (pre-existing gate, previously untested
#     in the failing direction) -----------------------------------------------


@pytest.mark.asyncio
async def test_a_viewer_cannot_adopt(tmp_path: Path) -> None:
    tag = _tag()
    token, _org = await _mk_user(
        f"adoptviewer-{tag}@pack-rbac.test", f"PackRBAC AdoptViewer Org {tag}", "viewer"
    )
    path = tmp_path / f"adopt-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with _client() as c:
        created = await _register(c, token, f"pack-{tag}", pack_source_url(path))
        source_id = created.json()["id"]
        synced = await c.post(
            f"/api/pack-sources/{source_id}/sync", headers=_auth(token)
        )
        assert synced.json()["status"] == "pending"

        resp = await c.post(
            f"/api/pack-sources/{source_id}/adopt", headers=_auth(token)
        )
        assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_a_control_owner_cannot_adopt(tmp_path: Path) -> None:
    tag = _tag()
    token, _org = await _mk_user(
        f"adoptco-{tag}@pack-rbac.test", f"PackRBAC AdoptCO Org {tag}", "control_owner"
    )
    path = tmp_path / f"adoptco-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with _client() as c:
        created = await _register(c, token, f"pack-{tag}", pack_source_url(path))
        source_id = created.json()["id"]
        await c.post(f"/api/pack-sources/{source_id}/sync", headers=_auth(token))

        resp = await c.post(
            f"/api/pack-sources/{source_id}/adopt", headers=_auth(token)
        )
        assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_an_isso_can_adopt(tmp_path: Path) -> None:
    """``isso`` is not yet a value ``ccf.user_role`` accepts -- see
    ``test_an_issm_can_register_with_auto_install``'s docstring -- so this is
    exercised directly against the route functions with a hand-built
    ``Principal`` rather than through a real bearer token."""
    tag = _tag()
    path = tmp_path / f"isso-{tag}.json"
    path.write_text(json.dumps(_manifest(path.stem)), encoding="utf-8")
    async with session_scope() as session:
        org = Organization(name=f"PackRBAC ISSO Org {tag}")
        session.add(org)
        await session.flush()
        isso = Principal(user_id=1, email="isso@pack-rbac.test", org_id=org.id, role="isso")

        body = PackSourceIn(url=pack_source_url(path))
        created = await register_source(f"pack-{tag}", body, session, isso)
        source_id = created["id"]

        src = (
            await session.execute(select(PackSource).where(PackSource.id == source_id))
        ).scalar_one()
        out = await check_pack_source(session, src, actor=isso.email)
        assert out["status"] == "pending"

        pack = await adopt_source(source_id, session, isso)
        assert pack["status"] == "installed"


# --- unauthenticated is refused ----------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_registration_is_refused() -> None:
    async with _client() as c:
        resp = await c.post(
            "/api/packs/whatever/sources",
            json={"url": "https://raw.githubusercontent.com/acme/pack/main/pack.json"},
        )
        assert resp.status_code == 401
