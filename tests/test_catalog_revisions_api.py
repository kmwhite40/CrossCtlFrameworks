"""Revision endpoints: listing, diff, impact, and the 409 adoption gate."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.catalog.revisions import adopt_revision, materialize_revision
from ccf.db import session_scope
from ccf.models import (
    CatalogRevision,
    CatalogSource,
    Organization,
    SSPControlEntry,
    SSPProject,
)
from tests.test_catalog_materialize import _documents

_ORG_SEQ = itertools.count()
_EMPTY_CATALOG = json.dumps({"catalog": {"metadata": {"version": "5.3.0"}, "groups": []}}).encode()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


async def _source(session, key: str) -> CatalogSource:
    s = CatalogSource(
        key=key, name=key, kind="oscal_catalog", url="https://example.test/catalog.json"
    )
    session.add(s)
    await session.flush()
    return s


@pytest.mark.asyncio
async def test_openapi_lists_revision_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/catalog/sources/{source_id}/revisions" in paths
        assert "/api/catalog/revisions/{revision_id}/diff" in paths
        assert "/api/catalog/revisions/{revision_id}/impact" in paths
        assert "/api/catalog/revisions/{revision_id}/adopt" in paths


@pytest.mark.asyncio
async def test_lists_revisions_newest_first(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "api_list")
        await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = _EMPTY_CATALOG
        await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="b" * 40, data_root=tmp_path
        )
        await session.commit()
        source_id = src.id

    async with _client() as client:
        r = await client.get(f"/api/catalog/sources/{source_id}/revisions")
        assert r.status_code == 200
        rows = r.json()
        assert [x["revision"] for x in rows] == ["b" * 12, "a" * 12]


@pytest.mark.asyncio
async def test_diff_and_impact_endpoints(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "api_diff")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        await session.commit()
        rev_id = rev.id

    async with _client() as client:
        d = await client.get(f"/api/catalog/revisions/{rev_id}/diff")
        assert d.status_code == 200
        assert "diff" in d.json()

        i = await client.get(f"/api/catalog/revisions/{rev_id}/impact")
        assert i.status_code == 200
        assert "impact" in i.json()


@pytest.mark.asyncio
async def test_unknown_revision_is_404() -> None:
    async with _client() as client:
        assert (await client.get("/api/catalog/revisions/999999/diff")).status_code == 404


@pytest.mark.asyncio
async def test_adopt_returns_409_with_impact_when_unacknowledged(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "api_409")
        first = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="d" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=first.id, actor="seed")

        org = Organization(name=f"ApiOrg-{next(_ORG_SEQ)}")
        session.add(org)
        await session.flush()
        proj = SSPProject(organization_id=org.id, customer_name="Acme")
        session.add(proj)
        await session.flush()
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-1", nist_id="AC-1"))

        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = _EMPTY_CATALOG
        second = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="e" * 40, data_root=tmp_path
        )
        await session.commit()
        second_id = second.id

    async with _client() as client:
        r = await client.post(f"/api/catalog/revisions/{second_id}/adopt")
        assert r.status_code == 409
        detail = r.json()["detail"]
        assert detail["impact"]["empty"] is False
        assert detail["impact"]["orphaned_entries"]

        ok = await client.post(
            f"/api/catalog/revisions/{second_id}/adopt",
            json={"acknowledge_impact": True},
        )
        assert ok.status_code == 200
        assert ok.json()["status"] == "adopted"

    async with session_scope() as session:
        row = await session.get(CatalogRevision, second_id)
        assert row is not None
        assert row.status == "adopted"


@pytest.mark.asyncio
async def test_adopting_a_rejected_revision_is_400(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "api_400")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = b'{"catalog": "bad"}'
        rev = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="f" * 40, data_root=tmp_path
        )
        await session.commit()
        rev_id = rev.id

    async with _client() as client:
        r = await client.post(f"/api/catalog/revisions/{rev_id}/adopt")
        assert r.status_code == 400
