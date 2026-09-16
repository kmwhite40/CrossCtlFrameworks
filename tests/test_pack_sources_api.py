"""Pack-source endpoints: register, poll, review, adopt, and divergence.

Runs under real auth (mirrors ``tests/test_waivers_api_rbac.py``'s harness):
registration now requires an organization-scoped principal (PR #17 security
review, IMPORTANT 6 -- a source registered by a global/unscoped principal is
never polled by the scheduler or CLI, which both iterate real
``Organization.id``), so the SYSTEM_PRINCIPAL default this file used before
that fix can no longer exercise it. ``test_pack_sources_api_rbac.py`` covers
the ADOPTER_ROLES gate itself (including the failing direction).
"""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.api.routes.packs import PackSourceIn, _require_source, register_source
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import AuditLog, Organization, User
from ccf.models_packs import CompliancePack, PackSource
from tests.conftest import pack_source_url

pytestmark = [pytest.mark.usefixtures("fresh_engine", "local_pack_source_fetch")]

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
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


async def _mk_admin(org_name: str) -> tuple[str, int]:
    """An org + an admin user in it (admin is an ADOPTER_ROLES member).
    Returns ``(bearer_token, org_id)``."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=f"admin-{next(_SEQ)}@pack-sources.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _manifest(pack_id: str, version: str = "1.0.0") -> dict:
    return {
        "id": pack_id,
        "name": "Source Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2"}],
    }


def _tag() -> str:
    return str(next(_SEQ))


@pytest.mark.asyncio
async def test_openapi_lists_the_source_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/packs/{pack_key}/sources" in paths
        assert "/api/pack-sources/{source_id}/sync" in paths
        assert "/api/pack-sources/{source_id}/adopt" in paths
        assert "/api/pack-sources/{source_id}/divergence" in paths


@pytest.mark.asyncio
async def test_register_poll_review_and_adopt(tmp_path: Path) -> None:
    """The whole GitOps loop through HTTP, gate included."""
    tag = _tag()
    token, _org_id = await _mk_admin(f"PackSrcOrg-{tag}")
    pack_key = f"api-src-{tag}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")

    async with _client() as client:
        created = await client.post(
            f"/api/packs/{pack_key}/sources",
            json={"url": pack_source_url(path), "ref": "main"},
            headers=_auth(token),
        )
        assert created.status_code == 201, created.text
        assert created.json()["auto_install"] is False, "the gate is the default"
        source_id = created.json()["id"]

        listed = await client.get(f"/api/packs/{pack_key}/sources", headers=_auth(token))
        assert [s["id"] for s in listed.json()] == [source_id]

        # Never polled: divergence is unknown, not in sync.
        assert (
            await client.get(
                f"/api/pack-sources/{source_id}/divergence", headers=_auth(token)
            )
        ).json()["state"] == "unknown"

        synced = await client.post(
            f"/api/pack-sources/{source_id}/sync", headers=_auth(token)
        )
        assert synced.json()["status"] == "pending"
        assert (
            await client.get(
                f"/api/pack-sources/{source_id}/divergence", headers=_auth(token)
            )
        ).json()["state"] == "pending_change"

    # Nothing installed while the change is merely pending.
    async with session_scope() as session:
        assert (
            await session.execute(
                select(CompliancePack).where(CompliancePack.pack_key == pack_key)
            )
        ).scalar_one_or_none() is None

    async with _client() as client:
        adopted = await client.post(
            f"/api/pack-sources/{source_id}/adopt", headers=_auth(token)
        )
        assert adopted.status_code == 200, adopted.text
        assert adopted.json()["version"] == "1.0.0"
        assert (
            await client.get(
                f"/api/pack-sources/{source_id}/divergence", headers=_auth(token)
            )
        ).json()["state"] == "in_sync"

    async with session_scope() as session:
        rows = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "pack_source",
                    AuditLog.entity_id == str(source_id),
                )
            )
        ).scalars().all()
        events = [r.diff.get("event") for r in rows]
        assert events == ["registered", "adopted"], events
        assert all(r.row_hash for r in rows)


@pytest.mark.asyncio
async def test_adopting_with_nothing_pending_is_a_conflict(tmp_path: Path) -> None:
    tag = _tag()
    token, _org_id = await _mk_admin(f"PackSrcOrg-{tag}")
    pack_key = f"api-src-{tag}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")
    async with _client() as client:
        source_id = (
            await client.post(
                f"/api/packs/{pack_key}/sources",
                json={"url": pack_source_url(path)},
                headers=_auth(token),
            )
        ).json()["id"]
        resp = await client.post(
            f"/api/pack-sources/{source_id}/adopt", headers=_auth(token)
        )
        assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_a_url_is_required() -> None:
    token, _org_id = await _mk_admin(f"PackSrcOrg-{_tag()}")
    async with _client() as client:
        resp = await client.post(
            "/api/packs/whatever/sources", json={"url": "   "}, headers=_auth(token)
        )
        assert resp.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "/etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/admin",
        "https://192.168.1.1/internal",
        "ftp://example.test/pack.json",
    ],
)
async def test_an_unsafe_url_is_rejected_at_registration(url: str) -> None:
    """CRITICAL 1: SSRF / local-file-read shapes are refused with a clear
    400, not silently stored for the scheduler to poll unattended."""
    token, _org_id = await _mk_admin(f"PackSrcOrg-{_tag()}")
    async with _client() as client:
        resp = await client.post(
            "/api/packs/whatever/sources", json={"url": url}, headers=_auth(token)
        )
        assert resp.status_code == 400, resp.text


@pytest.mark.asyncio
async def test_an_unknown_source_is_not_found() -> None:
    token, _org_id = await _mk_admin(f"PackSrcOrg-{_tag()}")
    async with _client() as client:
        for suffix in ("sync", "adopt"):
            resp = await client.post(
                f"/api/pack-sources/9999999/{suffix}", headers=_auth(token)
            )
            assert resp.status_code == 404, suffix
        assert (
            await client.get(
                "/api/pack-sources/9999999/divergence", headers=_auth(token)
            )
        ).status_code == 404


@pytest.mark.asyncio
async def test_listing_excludes_another_packs_sources(tmp_path: Path) -> None:
    """Two sources under different pack keys: the filter must exclude."""
    token, _org_id = await _mk_admin(f"PackSrcOrg-{_tag()}")
    mine = f"api-src-{_tag()}"
    theirs = f"api-src-{_tag()}"
    async with _client() as client:
        for key in (mine, theirs):
            p = tmp_path / f"{key}.json"
            p.write_text(json.dumps(_manifest(key)), encoding="utf-8")
            await client.post(
                f"/api/packs/{key}/sources",
                json={"url": pack_source_url(p)},
                headers=_auth(token),
            )
        listed = (
            await client.get(f"/api/packs/{mine}/sources", headers=_auth(token))
        ).json()
        assert [s["pack_key"] for s in listed] == [mine]


@pytest.mark.asyncio
async def test_an_organization_id_in_the_body_is_ignored(tmp_path: Path) -> None:
    """Tenancy comes from the principal, never the request."""
    token, org_id = await _mk_admin(f"PackSrcOrg-{_tag()}")
    pack_key = f"api-src-{_tag()}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")
    async with _client() as client:
        created = await client.post(
            f"/api/packs/{pack_key}/sources",
            json={"url": pack_source_url(path), "organization_id": 424_242},
            headers=_auth(token),
        )
        assert created.status_code == 201
        source_id = created.json()["id"]
    async with session_scope() as session:
        src = (
            await session.execute(select(PackSource).where(PackSource.id == source_id))
        ).scalar_one()
        assert src.organization_id == org_id
        assert src.organization_id != 424_242


@pytest.mark.asyncio
async def test_a_scoped_principal_cannot_reach_another_tenants_source(
    tmp_path: Path,
) -> None:
    """Exercised directly against ``_require_source``, matching the pattern
    used for the RLS/ownership check in ``test_waivers_api_rbac.py``."""
    pack_key = f"api-src-{_tag()}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")
    async with session_scope() as session:
        org = Organization(name=f"PackSrcApiOrg-{_tag()}")
        session.add(org)
        await session.flush()
        src = PackSource(
            organization_id=org.id, pack_key=pack_key, url=pack_source_url(path)
        )
        session.add(src)
        await session.flush()
        source_id, owning_org = src.id, org.id

        intruder = Principal(
            user_id=1, email="other@example.gov", org_id=owning_org + 1000, role="admin"
        )
        with pytest.raises(HTTPException) as caught:
            await _require_source(session, source_id, intruder)
        assert caught.value.status_code == 404, "never confirm existence across tenants"

        owner = Principal(
            user_id=2, email="owner@example.gov", org_id=owning_org, role="admin"
        )
        assert (await _require_source(session, source_id, owner)).id == source_id


@pytest.mark.asyncio
async def test_a_global_principal_cannot_register_a_source(tmp_path: Path) -> None:
    """IMPORTANT 6: a source registered with organization_id=NULL is never
    polled -- the scheduler and CLI both iterate real Organization.id -- so
    it would sit at "unknown" forever. Exercised directly against the route
    function (the same pattern the cross-tenant test above uses) since a real
    HTTP request under auth always carries a real user's org."""
    path = tmp_path / f"global-{_tag()}.json"
    body = PackSourceIn(url=pack_source_url(path))
    global_principal = Principal(user_id=None, email="system", org_id=None, role="admin")
    async with session_scope() as session:
        with pytest.raises(HTTPException) as caught:
            await register_source("whatever", body, session, global_principal)
        assert caught.value.status_code == 400


@pytest.mark.asyncio
async def test_last_error_is_scrubbed_but_status_and_invalid_reason_survive(
    tmp_path: Path,
) -> None:
    """CRITICAL 1: last_error must not become a file-existence/internal-port
    oracle through the API. A transport failure (``error``) is scrubbed to a
    generic message; an ``invalid`` reason (a config/content problem in the
    source itself, not what the fetch touched) stays informative."""
    token, _org_id = await _mk_admin(f"PackSrcOrg-{_tag()}")
    pack_key = f"api-src-{_tag()}"
    path = tmp_path / f"{pack_key}.json"  # never written -- every poll fails
    async with _client() as client:
        source_id = (
            await client.post(
                f"/api/packs/{pack_key}/sources",
                json={"url": pack_source_url(path)},
                headers=_auth(token),
            )
        ).json()["id"]
        synced = await client.post(
            f"/api/pack-sources/{source_id}/sync", headers=_auth(token)
        )
        assert synced.json()["status"] == "error"
        assert str(path) not in synced.json().get("reason", "")

        got = await client.get(
            f"/api/packs/{pack_key}/sources", headers=_auth(token)
        )
        row = next(s for s in got.json() if s["id"] == source_id)
        assert row["last_status"] == "error"
        assert str(path) not in (row["last_error"] or "")
        assert row["consecutive_failures"] == 1
