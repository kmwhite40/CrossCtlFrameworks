"""Evidence repository — versioning, digests, review lock, download, expiry, RLS."""

from __future__ import annotations

import hashlib
import io
from datetime import date
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.evidence import service
from ccf.models import Organization
from ccf.models_evidence import EvidenceAccessEvent, EvidenceObject

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _upload(content: bytes, name: str = "e.txt") -> dict:
    return {"file": (name, io.BytesIO(content), "text/plain")}


@pytest.mark.asyncio
async def test_version_digest_history_review_lock_and_download() -> None:
    async with _client() as c:
        oid = (await c.post("/api/evidence-repo", json={"title": "SOC2 report"})).json()["id"]

        v1 = await c.post(f"/api/evidence-repo/{oid}/versions", files=_upload(b"first"))
        assert v1.status_code == 201, v1.text
        assert v1.json()["version"] == 1
        assert v1.json()["sha256"] == hashlib.sha256(b"first").hexdigest()

        # A second upload preserves history as version 2.
        v2 = await c.post(f"/api/evidence-repo/{oid}/versions", files=_upload(b"second"))
        assert v2.json()["version"] == 2
        detail = (await c.get(f"/api/evidence-repo/{oid}")).json()
        assert len(detail["versions"]) == 2

        # Submit → review approved → immutable lock; further versions rejected.
        assert (await c.post(f"/api/evidence-repo/{oid}/submit")).json()["status"] == "submitted"
        reviewed = await c.post(
            f"/api/evidence-repo/{oid}/review", json={"decision": "approved", "note": "ok"}
        )
        assert reviewed.json()["status"] == "approved"
        assert reviewed.json()["immutable_lock"] is True
        locked = await c.post(f"/api/evidence-repo/{oid}/versions", files=_upload(b"third"))
        assert locked.status_code == 409

        # Download returns the latest content and records an access event.
        dl = await c.get(f"/api/evidence-repo/{oid}/download")
        assert dl.status_code == 200
        assert dl.content == b"second"

    async with session_scope() as s:
        events = (
            await s.execute(
                select(EvidenceAccessEvent).where(EvidenceAccessEvent.evidence_object_id == oid)
            )
        ).scalars().all()
        assert len(events) == 1 and events[0].action == "download"


@pytest.mark.asyncio
async def test_submit_requires_a_version() -> None:
    async with _client() as c:
        oid = (await c.post("/api/evidence-repo", json={"title": "empty"})).json()["id"]
        assert (await c.post(f"/api/evidence-repo/{oid}/submit")).status_code == 409


@pytest.mark.asyncio
async def test_expired_evidence_is_flagged() -> None:
    async with session_scope() as s:
        org = Organization(name="EvExpireOrg")
        s.add(org)
        await s.flush()
        obj = await service.create_object(
            s, org_id=org.id, title="Stale", expires_on=date(2020, 1, 1)
        )
        oid, org_id = obj.id, org.id
    async with session_scope() as s:
        n = await service.mark_expired(s, org_id=org_id)
        assert n == 1
    async with session_scope() as s:
        obj = await s.get(EvidenceObject, oid)
        assert obj.status == "expired"


@pytest.mark.asyncio
async def test_read_version_returns_untampered_bytes() -> None:
    async with session_scope() as s:
        org = Organization(name="EvIntegrityOkOrg")
        s.add(org)
        await s.flush()
        obj = await service.create_object(s, org_id=org.id, title="Integrity ok")
        await service.add_version(s, obj, data=b"authentic bytes")
        obj_id = obj.id

    async with session_scope() as s:
        obj = await s.get(EvidenceObject, obj_id)
        ver, data = await service.read_version(s, obj)
        assert data == b"authentic bytes"
        assert ver.sha256 == hashlib.sha256(b"authentic bytes").hexdigest()


@pytest.mark.asyncio
async def test_read_version_detects_tampered_bytes_on_disk() -> None:
    """A real local-storage round trip: corrupt the on-disk blob, then verify
    ``read_version`` recomputes the digest and refuses to serve it silently."""
    async with session_scope() as s:
        org = Organization(name="EvIntegrityTamperOrg")
        s.add(org)
        await s.flush()
        obj = await service.create_object(s, org_id=org.id, title="Integrity tamper")
        version = await service.add_version(s, obj, data=b"authentic bytes")
        obj_id, version_id, storage_ref = obj.id, version.id, version.storage_ref

    # Corrupt the stored blob directly on disk — same length, different content,
    # so this can't be caught by anything other than a digest re-check.
    path = Path(storage_ref[len("file://") :])
    assert path.is_file()
    path.write_bytes(b"tampered bytes!")

    async with session_scope() as s:
        obj = await s.get(EvidenceObject, obj_id)
        with pytest.raises(service.EvidenceIntegrityError):
            await service.read_version(s, obj, version_id=version_id)


@pytest.mark.asyncio
async def test_rls_blocks_cross_tenant_reads() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:  # unscoped seed
        ids = {}
        for name in ("EvRlsA", "EvRlsB"):
            org = Organization(name=name)
            s.add(org)
            await s.flush()
            obj = await service.create_object(s, org_id=org.id, title=f"{name}-ev")
            ids[name] = (org.id, obj.id)
    (org_a, obj_a), (_org_b, obj_b) = ids["EvRlsA"], ids["EvRlsB"]
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        visible = (await s.execute(select(EvidenceObject.id))).scalars().all()
        assert obj_a in visible
        assert obj_b not in visible
