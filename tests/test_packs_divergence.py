"""Is what is running what the repository declares?"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_packs import PackSource
from ccf.packs.service import install_pack
from ccf.packs.sync import DIVERGENCE_STATES, adopt_pending, check_pack_source, divergence
from tests.conftest import pack_source_url

_SEQ = itertools.count()

pytestmark = pytest.mark.usefixtures("local_pack_source_fetch")


def _manifest(*, pack_id: str, version: str = "1.0.0", control: str = "AC-2") -> dict:
    return {
        "id": pack_id,
        "name": "Diverge Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": control}],
    }


async def _org(session) -> Organization:
    org = Organization(name=f"DivergeOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def _source(session, org, path: Path) -> PackSource:
    src = PackSource(
        organization_id=org.id, pack_key=path.stem, url=pack_source_url(path), ref="main"
    )
    session.add(src)
    await session.flush()
    return src


def test_the_state_vocabulary_is_closed() -> None:
    assert sorted(DIVERGENCE_STATES) == ["diverged", "in_sync", "pending_change", "unknown"]


@pytest.mark.asyncio
async def test_a_source_never_polled_is_unknown(tmp_path: Path) -> None:
    """Not "in sync" -- nothing has been compared."""
    path = tmp_path / f"never-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        out = await divergence(session, src)
        assert out["state"] == "unknown"
        assert out["reason"] == "source has never been polled"
        assert out["source_sha"] is None


@pytest.mark.asyncio
async def test_a_source_that_only_ever_failed_is_unknown_with_a_distinct_reason(
    tmp_path: Path,
) -> None:
    """IMPORTANT 7: ``last_manifest_sha is None`` alone was used to mean
    "never polled", which is also true for a source that HAS been polled --
    repeatedly, possibly for weeks -- and every time came back ``invalid`` or
    ``error``. That text can reach an authorization artifact, so the two
    situations get different reasons, keyed on ``last_checked_at``."""
    path = tmp_path / f"failing-{next(_SEQ)}.json"  # never written -- every poll fails
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        assert src.last_checked_at is not None
        assert src.last_manifest_sha is None
        out = await divergence(session, src)
        assert out["state"] == "unknown"
        assert out["reason"] != "source has never been polled"
        assert "last poll did not succeed" in out["reason"]
        assert src.last_status in out["reason"]


@pytest.mark.asyncio
async def test_a_fetched_but_unadopted_change_is_pending(tmp_path: Path) -> None:
    path = tmp_path / f"pend-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        path.write_text(json.dumps(_manifest(pack_id=path.stem)), encoding="utf-8")
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        out = await divergence(session, src)
        assert out["state"] == "pending_change"


@pytest.mark.asyncio
async def test_an_adopted_manifest_is_in_sync(tmp_path: Path) -> None:
    path = tmp_path / f"sync-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        path.write_text(json.dumps(_manifest(pack_id=path.stem)), encoding="utf-8")
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        await adopt_pending(session, src, actor="ao@acme.gov")
        out = await divergence(session, src)
        assert out["state"] == "in_sync"
        assert out["installed_sha"] == out["source_sha"]


@pytest.mark.asyncio
async def test_a_manifest_installed_behind_the_sources_back_is_diverged(
    tmp_path: Path,
) -> None:
    """The state nobody asks for, and the one that matters: a pack pushed
    through the API while a source is configured is how a deployment quietly
    stops matching its own repository."""
    path = tmp_path / f"behind-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        path.write_text(json.dumps(_manifest(pack_id=path.stem)), encoding="utf-8")
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        await adopt_pending(session, src, actor="ao@acme.gov")
        assert (await divergence(session, src))["state"] == "in_sync"

        # Someone installs a different manifest directly.
        await install_pack(
            session,
            org_id=org.id,
            manifest=_manifest(pack_id=path.stem, version="9.9.9", control="AC-6"),
            source="manual",
            actor="someone@acme.gov",
        )
        out = await divergence(session, src)
        assert out["state"] == "diverged"
        assert out["installed_sha"] != out["source_sha"]


@pytest.mark.asyncio
async def test_a_source_declaring_an_uninstalled_pack_is_diverged(
    tmp_path: Path,
) -> None:
    """Polled, adopted nowhere: the repository declares a pack this deployment
    does not run."""
    path = tmp_path / f"absent-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        path.write_text(json.dumps(_manifest(pack_id=path.stem)), encoding="utf-8")
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        # Clear the pending flag without installing, as an operator declining
        # the change would.
        src.pending_manifest = {}
        src.pending_sha256 = None
        await session.flush()
        out = await divergence(session, src)
        assert out["state"] == "diverged"
        assert out["installed_sha"] is None


@pytest.mark.asyncio
async def test_divergence_ignores_another_tenants_pack_of_the_same_key(
    tmp_path: Path,
) -> None:
    """Two organizations install the same pack key; each source compares against
    its own."""
    path = tmp_path / f"shared-{next(_SEQ)}.json"
    async with session_scope() as session:
        mine, theirs = await _org(session), await _org(session)
        path.write_text(json.dumps(_manifest(pack_id=path.stem)), encoding="utf-8")
        src = await _source(session, mine, path)
        await check_pack_source(session, src)
        # Their install must not make my source look in sync.
        await install_pack(
            session,
            org_id=theirs.id,
            manifest=_manifest(pack_id=path.stem),
            source="manual",
            actor="them@acme.gov",
        )
        src.pending_manifest = {}
        src.pending_sha256 = None
        await session.flush()
        out = await divergence(session, src)
        assert out["state"] == "diverged"
        assert out["installed_sha"] is None, "another tenant's pack was compared"
