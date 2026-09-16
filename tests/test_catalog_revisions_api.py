"""Revision endpoints: listing, diff, impact, and the 409 adoption gate."""

from __future__ import annotations

import itertools
import json
import os
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.catalog.revisions import adopt_revision, materialize_revision
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    CatalogRevision,
    CatalogSource,
    Organization,
    SSPControlEntry,
    SSPProject,
    User,
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


async def _mk_admin(session, email: str, org_name: str) -> tuple[str, int]:
    """Create an org + an admin user in it; return (bearer token, org id)."""
    org = Organization(name=org_name)
    session.add(org)
    await session.flush()
    user = User(
        email=email,
        organization_id=org.id,
        role="admin",
        active=True,
        password_hash=hash_password("pw"),
        api_token=new_api_token(),
    )
    session.add(user)
    await session.flush()
    return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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
        await adopt_revision(
            session, revision_id=first.id, actor="seed", acknowledge_impact=True
        )

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
async def test_impact_is_platform_wide_not_caller_org_scoped(tmp_path: Path) -> None:
    """CRITICAL 2 regression: adoption moves a single global catalog pointer,
    but the impact used to be computed on the caller's tenant-scoped session.
    An org admin with no SSP content of their own would see an empty impact
    -- no 409, no acknowledgement -- while a *different* org's authored
    content, which this revision actually orphans, was invisible to them.

    Both ``/impact`` and the ``/adopt`` 409 gate must reflect the true
    platform-wide consequence regardless of which org the caller belongs to.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        async with session_scope() as session:
            src = await _source(session, "api_tenant_scope")
            first = await materialize_revision(
                session,
                source=src,
                documents=_documents(),
                upstream_commit_sha="1" * 40,
                data_root=tmp_path,
            )
            await adopt_revision(
                session, revision_id=first.id, actor="seed", acknowledge_impact=True
            )

            # Org B holds the SSP content that the next revision will orphan.
            org_b = Organization(name=f"ImpactOrgB-{next(_ORG_SEQ)}")
            session.add(org_b)
            await session.flush()
            proj = SSPProject(organization_id=org_b.id, customer_name="Acme")
            session.add(proj)
            await session.flush()
            session.add(SSPControlEntry(project_id=proj.id, control_id="AC-1", nist_id="AC-1"))

            # Org A is the caller below -- it has no SSP content of its own.
            token_a, _org_a_id = await _mk_admin(
                session, "admin-a@tenant-scope.test", f"ImpactOrgA-{next(_ORG_SEQ)}"
            )

            docs = _documents()
            docs["NIST_SP-800-53_rev5_catalog.json"] = _EMPTY_CATALOG
            second = await materialize_revision(
                session,
                source=src,
                documents=docs,
                upstream_commit_sha="2" * 40,
                data_root=tmp_path,
            )
            await session.commit()
            second_id = second.id

        async with _client() as client:
            # A tenant-scoped impact computation would see none of org B's
            # content and report empty -- assert it does not.
            r = await client.get(
                f"/api/catalog/revisions/{second_id}/impact", headers=_auth(token_a)
            )
            assert r.status_code == 200
            impact = r.json()["impact"]
            assert impact["empty"] is False
            assert impact["orphaned_entries"]

            # The adoption gate must refuse for the same reason: org A's admin
            # cannot adopt straight past org B's impact just because org A's
            # own (empty) slice would have shown nothing.
            gate = await client.post(
                f"/api/catalog/revisions/{second_id}/adopt", headers=_auth(token_a)
            )
            assert gate.status_code == 409
            assert gate.json()["detail"]["impact"]["empty"] is False
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()


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
