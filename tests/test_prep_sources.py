"""Metadata-only source resolution — no storage fetch for a system id lookup."""

from __future__ import annotations

import pytest

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, Policy, PolicyVersion, System
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.prep.sources import SourceMissing, resolve_source_system_id

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
    # No test here calls the storage backend, but keeping the same isolated,
    # per-test backend configuration as the other prep-source tests avoids any
    # accidental dependency on a real backend being configured.
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_resolve_source_system_id_returns_the_system_for_evidence_version() -> None:
    org_id = await _org("prep-src-meta-ev")
    async with session_scope() as s:
        system = System(organization_id=org_id, name="Test System")
        s.add(system)
        await s.flush()
        obj = EvidenceObject(organization_id=org_id, title="p.txt", system_id=system.id)
        s.add(obj)
        await s.flush()
        # storage_ref points at content that was never written to the backend
        # — resolve_source_system_id must not care, because it never calls
        # get_backend(). This is what distinguishes it from resolve_source().
        ver = EvidenceVersion(
            evidence_object_id=obj.id, version=1, sha256="deadbeef", media_type="text/plain",
            size_bytes=0, filename="p.txt", storage_backend="local",
            storage_ref="never/written/to/disk",
        )
        s.add(ver)
        await s.flush()
        system_id = int(system.id)
        version_id = int(ver.id)

    async with session_scope() as s:
        result = await resolve_source_system_id(s, "evidence_version", version_id)
    assert result == system_id


async def test_resolve_source_system_id_returns_none_for_policy_version() -> None:
    org_id = await _org("prep-src-meta-pol")
    async with session_scope() as s:
        policy = Policy(organization_id=org_id, name="Access Control Policy")
        s.add(policy)
        await s.flush()
        ver = PolicyVersion(policy_id=policy.id, version="1.0", body="Accounts are reviewed.")
        s.add(ver)
        await s.flush()
        version_id = int(ver.id)

    async with session_scope() as s:
        result = await resolve_source_system_id(s, "policy_version", version_id)
    assert result is None


async def test_resolve_source_system_id_raises_source_missing_for_a_deleted_source() -> None:
    async with session_scope() as s:
        with pytest.raises(SourceMissing):
            await resolve_source_system_id(s, "evidence_version", 999_999)
