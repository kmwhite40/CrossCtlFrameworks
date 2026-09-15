"""Polling a desired-state repository: five outcomes, and the gate."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import AuditLog, Organization
from ccf.models_packs import CompliancePack, PackSource
from ccf.packs.sync import SYNC_OUTCOMES, adopt_pending, check_pack_source, sync_for_org

_SEQ = itertools.count()


def _manifest(version: str = "1.0.0", *, pack_id: str) -> dict:
    return {
        "id": pack_id,
        "name": "Synced Pack",
        "version": version,
        "schema_version": "1",
        "controls": [{"control_id": "AC-2", "title": "Account Management"}],
    }


async def _org(session) -> Organization:
    org = Organization(name=f"SyncOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def _source(session, org, path: Path, *, auto_install: bool = False) -> PackSource:
    src = PackSource(
        organization_id=org.id,
        pack_key=path.stem,
        url=f"file://{path}",
        ref="main",
        auto_install=auto_install,
    )
    session.add(src)
    await session.flush()
    return src


def _write(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest), encoding="utf-8")


async def _installed(session, org_id: int, pack_key: str) -> CompliancePack | None:
    return (
        await session.execute(
            select(CompliancePack).where(
                CompliancePack.organization_id == org_id,
                CompliancePack.pack_key == pack_key,
            )
        )
    ).scalar_one_or_none()


# ── the five outcomes ────────────────────────────────────────────────────────


def test_the_outcome_vocabulary_is_closed() -> None:
    assert sorted(SYNC_OUTCOMES) == [
        "error", "installed", "invalid", "pending", "unchanged",
    ]


@pytest.mark.asyncio
async def test_a_new_manifest_is_stored_pending_and_installs_nothing(tmp_path: Path) -> None:
    """auto_install is off by default; adoption is an act."""
    path = tmp_path / f"pending-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        out = await check_pack_source(session, src)
        assert out["status"] == "pending"
        assert src.pending_manifest["version"] == "1.0.0"
        assert src.pending_sha256
        assert await _installed(session, org.id, src.pack_key) is None


@pytest.mark.asyncio
async def test_auto_install_installs_and_audits_the_commit(tmp_path: Path) -> None:
    path = tmp_path / f"auto-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path, auto_install=True)
        out = await check_pack_source(session, src)
        assert out["status"] == "installed"
        pack = await _installed(session, org.id, src.pack_key)
        assert pack is not None
        assert pack.version == "1.0.0"
        assert src.pending_manifest == {}, "nothing is left pending once installed"

        rows = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "pack_source",
                    AuditLog.entity_id == str(src.id),
                )
            )
        ).scalars().all()
        assert rows, "an install through a source must be audited"
        assert "sha256" in rows[-1].diff, "provenance is lost without the content sha"
        assert all(r.row_hash for r in rows), "the audit chain must be intact"


@pytest.mark.asyncio
async def test_an_invalid_manifest_is_invalid_not_error_and_installs_nothing(
    tmp_path: Path,
) -> None:
    """A repository whose manifest does not validate is a content problem
    someone must fix in git; a transport failure is transient. Conflating them
    sends an operator to the wrong place."""
    path = tmp_path / f"invalid-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        bad = _manifest(pack_id=path.stem)
        bad["controls"] = []  # a pack must define at least one control
        _write(path, bad)
        src = await _source(session, org, path, auto_install=True)
        out = await check_pack_source(session, src)
        assert out["status"] == "invalid"
        assert src.last_status == "invalid"
        assert src.last_error and "control" in src.last_error
        assert src.pending_manifest == {}
        assert await _installed(session, org.id, src.pack_key) is None


@pytest.mark.asyncio
async def test_unparseable_json_is_invalid_not_a_crash(tmp_path: Path) -> None:
    path = tmp_path / f"broken-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        path.write_text("{not json", encoding="utf-8")
        src = await _source(session, org, path)
        out = await check_pack_source(session, src)
        assert out["status"] == "invalid"


@pytest.mark.asyncio
async def test_a_transport_failure_is_error_and_keeps_the_previous_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / f"gone-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        good_sha = src.pending_sha256
        assert good_sha

        path.unlink()  # the repository moved or the network failed
        out = await check_pack_source(session, src)
        assert out["status"] == "error"
        assert src.last_status == "error"
        assert src.pending_sha256 == good_sha, "a failed poll must not discard state"


@pytest.mark.asyncio
async def test_polling_unchanged_content_twice_is_a_no_op(tmp_path: Path) -> None:
    path = tmp_path / f"same-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        first = await check_pack_source(session, src)
        second = await check_pack_source(session, src)
        assert first["status"] == "pending"
        assert second["status"] == "unchanged"


@pytest.mark.asyncio
async def test_a_disabled_source_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / f"off-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        src.enabled = False
        await session.flush()
        out = await check_pack_source(session, src)
        assert out["status"] == "unchanged"
        assert out["reason"] == "source disabled"
        assert src.last_checked_at is None, "a skipped source was never checked"


# ── adoption ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adopting_pending_installs_it_and_clears_the_pending_fields(
    tmp_path: Path,
) -> None:
    path = tmp_path / f"adopt-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        pack = await adopt_pending(session, src, actor="ao@acme.gov")
        assert pack.version == "1.0.0"
        assert src.pending_manifest == {}
        assert src.pending_sha256 is None
        assert src.last_status == "installed"


@pytest.mark.asyncio
async def test_adopting_with_nothing_pending_is_refused(tmp_path: Path) -> None:
    path = tmp_path / f"nothing-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        with pytest.raises(ValueError, match="nothing pending"):
            await adopt_pending(session, src, actor="ao@acme.gov")


@pytest.mark.asyncio
async def test_adopting_twice_is_refused(tmp_path: Path) -> None:
    """The second adopt has nothing to apply; silently re-installing would
    write a fresh version record for a decision nobody made."""
    path = tmp_path / f"twice-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        await adopt_pending(session, src, actor="ao@acme.gov")
        with pytest.raises(ValueError, match="nothing pending"):
            await adopt_pending(session, src, actor="ao@acme.gov")


# ── scoping ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sync_for_org_skips_another_tenants_source(tmp_path: Path) -> None:
    """Two sources, one per organization: the filter must exclude, not merely
    include."""
    mine = tmp_path / f"mine-{next(_SEQ)}.json"
    theirs = tmp_path / f"theirs-{next(_SEQ)}.json"
    async with session_scope() as session:
        org_a, org_b = await _org(session), await _org(session)
        _write(mine, _manifest(pack_id=mine.stem))
        _write(theirs, _manifest(pack_id=theirs.stem))
        src_a = await _source(session, org_a, mine)
        src_b = await _source(session, org_b, theirs)

        out = await sync_for_org(session, org_a.id)
        assert [r["source_id"] for r in out["results"]] == [src_a.id]
        await session.refresh(src_b)
        assert src_b.last_checked_at is None, "another tenant's source was polled"
