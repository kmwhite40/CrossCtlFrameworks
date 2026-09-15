"""Pack-source endpoints: register, poll, review, adopt, and divergence."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.models import AuditLog
from ccf.models_packs import CompliancePack, PackSource

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


def _manifest(pack_id: str, version: str = "1.0.0") -> dict:
    return {
        "id": pack_id,
        "name": "Source Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2"}],
    }


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
    pack_key = f"api-src-{next(_SEQ)}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")

    async with _client() as client:
        created = await client.post(
            f"/api/packs/{pack_key}/sources",
            json={"url": f"file://{path}", "ref": "main"},
        )
        assert created.status_code == 201, created.text
        assert created.json()["auto_install"] is False, "the gate is the default"
        source_id = created.json()["id"]

        listed = await client.get(f"/api/packs/{pack_key}/sources")
        assert [s["id"] for s in listed.json()] == [source_id]

        # Never polled: divergence is unknown, not in sync.
        assert (
            await client.get(f"/api/pack-sources/{source_id}/divergence")
        ).json()["state"] == "unknown"

        synced = await client.post(f"/api/pack-sources/{source_id}/sync")
        assert synced.json()["status"] == "pending"
        assert (
            await client.get(f"/api/pack-sources/{source_id}/divergence")
        ).json()["state"] == "pending_change"

    # Nothing installed while the change is merely pending.
    async with session_scope() as session:
        assert (
            await session.execute(
                select(CompliancePack).where(CompliancePack.pack_key == pack_key)
            )
        ).scalar_one_or_none() is None

    async with _client() as client:
        adopted = await client.post(f"/api/pack-sources/{source_id}/adopt")
        assert adopted.status_code == 200, adopted.text
        assert adopted.json()["version"] == "1.0.0"
        assert (
            await client.get(f"/api/pack-sources/{source_id}/divergence")
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
    pack_key = f"api-src-{next(_SEQ)}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")
    async with _client() as client:
        source_id = (
            await client.post(
                f"/api/packs/{pack_key}/sources", json={"url": f"file://{path}"}
            )
        ).json()["id"]
        resp = await client.post(f"/api/pack-sources/{source_id}/adopt")
        assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_a_url_is_required() -> None:
    async with _client() as client:
        resp = await client.post("/api/packs/whatever/sources", json={"url": "   "})
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_an_unknown_source_is_not_found() -> None:
    async with _client() as client:
        for suffix in ("sync", "adopt"):
            resp = await client.post(f"/api/pack-sources/9999999/{suffix}")
            assert resp.status_code == 404, suffix
        assert (
            await client.get("/api/pack-sources/9999999/divergence")
        ).status_code == 404


@pytest.mark.asyncio
async def test_listing_excludes_another_packs_sources(tmp_path: Path) -> None:
    """Two sources under different pack keys: the filter must exclude."""
    mine = f"api-src-{next(_SEQ)}"
    theirs = f"api-src-{next(_SEQ)}"
    async with _client() as client:
        for key in (mine, theirs):
            p = tmp_path / f"{key}.json"
            p.write_text(json.dumps(_manifest(key)), encoding="utf-8")
            await client.post(f"/api/packs/{key}/sources", json={"url": f"file://{p}"})
        listed = (await client.get(f"/api/packs/{mine}/sources")).json()
        assert [s["pack_key"] for s in listed] == [mine]


@pytest.mark.asyncio
async def test_an_organization_id_in_the_body_is_ignored(tmp_path: Path) -> None:
    """Tenancy comes from the principal, never the request."""
    pack_key = f"api-src-{next(_SEQ)}"
    path = tmp_path / f"{pack_key}.json"
    path.write_text(json.dumps(_manifest(pack_key)), encoding="utf-8")
    async with _client() as client:
        created = await client.post(
            f"/api/packs/{pack_key}/sources",
            json={"url": f"file://{path}", "organization_id": 424_242},
        )
        assert created.status_code == 201
        source_id = created.json()["id"]
    async with session_scope() as session:
        src = (
            await session.execute(select(PackSource).where(PackSource.id == source_id))
        ).scalar_one()
        assert src.organization_id != 424_242
