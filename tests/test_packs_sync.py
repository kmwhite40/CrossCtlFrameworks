"""Polling a desired-state repository: six outcomes, and the gate."""

from __future__ import annotations

import asyncio
import itertools
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.etl.sources import FetchTooLargeError
from ccf.models import AuditLog, Organization
from ccf.models_packs import CompliancePack, PackSource
from ccf.packs import sync as sync_mod
from ccf.packs.sync import (
    PACK_SOURCE_MAX_BYTES,
    SYNC_OUTCOMES,
    PackSourceRejectedError,
    adopt_pending,
    check_pack_source,
    sync_for_org,
    validate_pack_source_url,
)
from tests.conftest import pack_source_url

_SEQ = itertools.count()

#: Every test that touches a PackSource's fetch gets the local-file stub by
#: default; individual tests still override ``sync_mod.fetch_conditional``
#: further (304, redirect, oversized-body, backoff) where they need a
#: different fake -- monkeypatch's stack makes a second setattr in the same
#: test safe.
pytestmark = pytest.mark.usefixtures("local_pack_source_fetch")


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
        url=pack_source_url(path),
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


# ── the six outcomes ─────────────────────────────────────────────────────────


def test_the_outcome_vocabulary_is_closed() -> None:
    assert sorted(SYNC_OUTCOMES) == [
        "backoff", "error", "installed", "invalid", "pending", "unchanged",
    ]


@pytest.mark.asyncio
async def test_a_new_manifest_is_stored_pending_and_installs_nothing(
    tmp_path: Path, local_pack_source_fetch
) -> None:
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
async def test_auto_install_installs_and_audits_the_commit(
    tmp_path: Path, local_pack_source_fetch
) -> None:
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
    tmp_path: Path, local_pack_source_fetch
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
async def test_unparseable_json_is_invalid_not_a_crash(
    tmp_path: Path, local_pack_source_fetch
) -> None:
    path = tmp_path / f"broken-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        path.write_text("{not json", encoding="utf-8")
        src = await _source(session, org, path)
        out = await check_pack_source(session, src)
        assert out["status"] == "invalid"


@pytest.mark.asyncio
async def test_deeply_nested_json_is_invalid_not_a_recursion_crash(
    tmp_path: Path, local_pack_source_fetch
) -> None:
    """IMPORTANT 4: ``_parse`` used to catch only UnicodeDecodeError and
    JSONDecodeError, so pathological nesting raised RecursionError straight
    out of check_pack_source instead of being recorded."""
    path = tmp_path / f"nested-{next(_SEQ)}.json"
    nested = "1"
    for _ in range(4000):
        nested = f"[{nested}]"
    path.write_text(nested, encoding="utf-8")
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        out = await check_pack_source(session, src)
        assert out["status"] == "invalid"


@pytest.mark.asyncio
async def test_a_transport_failure_is_error_and_previous_state_survives(
    tmp_path: Path, local_pack_source_fetch
) -> None:
    """The prior version of this test asserted ``pending_sha256`` unchanged --
    a field ``_record_error`` never touches whether or not the bug it named
    exists, so it passed by construction. Assert fields that a poll's success
    path DOES set (``last_sha256``/``last_manifest_sha``), so a regression
    that let ``_record_error`` clobber them would actually fail this."""
    path = tmp_path / f"gone-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        await check_pack_source(session, src)
        good_sha256 = src.last_sha256
        good_manifest_sha = src.last_manifest_sha
        good_pending_sha256 = src.pending_sha256
        assert good_sha256 and good_manifest_sha and good_pending_sha256

        path.unlink()  # the repository moved or the network failed
        out = await check_pack_source(session, src)
        assert out["status"] == "error"
        assert src.last_status == "error"
        assert src.consecutive_failures == 1
        assert src.last_sha256 == good_sha256, "a failed poll must not discard state"
        assert src.last_manifest_sha == good_manifest_sha
        assert src.pending_sha256 == good_pending_sha256


@pytest.mark.asyncio
async def test_polling_unchanged_content_twice_is_a_no_op(
    tmp_path: Path, local_pack_source_fetch
) -> None:
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
async def test_a_disabled_source_is_skipped(tmp_path: Path, local_pack_source_fetch) -> None:
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


@pytest.mark.asyncio
async def test_a_304_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The conditional-request branch.

    Every other test polls a fetch stub that always returns 200, so this
    branch was unreachable -- which is how it escaped mutation testing. The
    fetch is stubbed rather than a server stood up: what is under test is the
    branch, not httpx.
    """
    path = tmp_path / f"nm-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        src.etag = 'W/"abc"'
        await session.flush()

        async def _not_modified(url: str, etag: str | None, **_kwargs: object):
            assert etag == 'W/"abc"', "the stored ETag must be sent"
            return 304, None, etag

        monkeypatch.setattr(sync_mod, "fetch_conditional", _not_modified)
        out = await check_pack_source(session, src)
        assert out["status"] == "unchanged"
        assert out["reason"] == "not modified"
        assert src.last_checked_at is not None


@pytest.mark.asyncio
async def test_a_successful_poll_always_records_that_it_happened(
    tmp_path: Path, local_pack_source_fetch
) -> None:
    """last_checked_at is how an operator tells a healthy source from a stuck
    one, so every poll that looked must set it -- not just the first, and not
    just on the same outcome. The prior version of this test only compared
    two timestamps with ``>=``, which passes even if a later poll never
    re-stamps at all (equal still satisfies ``>=``); this asserts strict
    monotonic progress across three different outcomes."""
    path = tmp_path / f"stamped-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(path, _manifest(pack_id=path.stem))
        src = await _source(session, org, path)
        assert src.last_checked_at is None

        await check_pack_source(session, src)  # -> pending
        first = src.last_checked_at
        assert first is not None

        await asyncio.sleep(0.01)
        await check_pack_source(session, src)  # -> unchanged
        second = src.last_checked_at
        assert second is not None and second > first

        await asyncio.sleep(0.01)
        path.unlink()
        await check_pack_source(session, src)  # -> error
        third = src.last_checked_at
        assert third is not None and third > second


# ── SSRF / local-file-read rejection (CRITICAL 1) ────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "/etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin",
        "https://localhost/admin",
        "https://127.0.0.1/admin",
        "https://10.0.0.5/internal",
        "https://172.16.0.5/internal",
        "https://192.168.1.1/internal",
        "ftp://example.test/pack.json",
        "git://example.test/pack.json",
    ],
)
def test_validate_pack_source_url_rejects_each_unsafe_shape(url: str) -> None:
    with pytest.raises(PackSourceRejectedError):
        validate_pack_source_url(url)


def test_validate_pack_source_url_accepts_a_normal_https_url() -> None:
    validate_pack_source_url("https://raw.githubusercontent.com/acme/pack/main/pack.json")


@pytest.mark.asyncio
async def test_a_row_with_an_unsafe_url_is_rejected_at_fetch_time_too(
    tmp_path: Path,
) -> None:
    """CRITICAL 1 requires re-validation at fetch, not just at registration --
    a row written before this validation existed (or by any future path that
    bypasses the API route) must not be fetchable either."""
    async with session_scope() as session:
        org = await _org(session)
        src = PackSource(
            organization_id=org.id, pack_key="bypass", url="file:///etc/passwd",
        )
        session.add(src)
        await session.flush()
        out = await check_pack_source(session, src)
        assert out["status"] == "invalid"
        assert src.last_status == "invalid"


@pytest.mark.asyncio
async def test_an_oversized_body_is_invalid_not_buffered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CRITICAL 3: the pack-source path must record ``invalid`` (and never
    buffer the whole thing) when a source's body exceeds the byte cap."""
    path = tmp_path / f"huge-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)

        async def _huge(url: str, etag: str | None, **_kwargs: object):
            raise FetchTooLargeError(f"response body exceeded {PACK_SOURCE_MAX_BYTES} byte cap")

        monkeypatch.setattr(sync_mod, "fetch_conditional", _huge)
        out = await check_pack_source(session, src)
        assert out["status"] == "invalid"
        assert src.last_status == "invalid"


# ── backoff (IMPORTANT 8) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_repeatedly_failing_source_backs_off_instead_of_refetching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / f"backoff-{next(_SEQ)}.json"
    calls = 0

    async def _always_fails(url: str, etag: str | None, **_kwargs: object):
        nonlocal calls
        calls += 1
        raise RuntimeError("connection refused")

    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        monkeypatch.setattr(sync_mod, "fetch_conditional", _always_fails)

        first = await check_pack_source(session, src)
        assert first["status"] == "error"
        assert calls == 1
        assert src.consecutive_failures == 1

        # Immediately polling again must not re-fetch: the source is inside
        # its backoff window.
        second = await check_pack_source(session, src)
        assert second["status"] == "backoff"
        assert calls == 1, "a source in backoff must not be re-fetched"

        # Once the backoff window has elapsed, it is fetched again.
        src.last_checked_at = datetime.now(UTC) - timedelta(hours=1)
        await session.flush()
        third = await check_pack_source(session, src)
        assert third["status"] == "error"
        assert calls == 2
        assert src.consecutive_failures == 2


@pytest.mark.asyncio
async def test_a_success_after_failures_resets_the_backoff_counter(
    tmp_path: Path, local_pack_source_fetch
) -> None:
    path = tmp_path / f"recover-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        # Not yet backed off: no prior checks, so the first (failing) poll
        # still runs.
        out = await check_pack_source(session, src)
        assert out["status"] == "error", "the file does not exist yet"
        assert src.consecutive_failures == 1

        _write(path, _manifest(pack_id=path.stem))
        src.last_checked_at = datetime.now(UTC) - timedelta(hours=1)
        await session.flush()
        out = await check_pack_source(session, src)
        assert out["status"] == "pending"
        assert src.consecutive_failures == 0


# ── adoption ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adopting_pending_installs_it_and_clears_the_pending_fields(
    tmp_path: Path, local_pack_source_fetch
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
async def test_adopting_with_nothing_pending_is_refused(
    tmp_path: Path, local_pack_source_fetch
) -> None:
    path = tmp_path / f"nothing-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        src = await _source(session, org, path)
        with pytest.raises(ValueError, match="nothing pending"):
            await adopt_pending(session, src, actor="ao@acme.gov")


@pytest.mark.asyncio
async def test_adopting_twice_is_refused(tmp_path: Path, local_pack_source_fetch) -> None:
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
async def test_sync_for_org_skips_another_tenants_source(
    tmp_path: Path, local_pack_source_fetch
) -> None:
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


@pytest.mark.asyncio
async def test_sync_for_org_survives_one_source_raising_unexpectedly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """IMPORTANT 4: one bad source must not abort the cycle for the rest of
    that org's sources. Forces an exception past check_pack_source's own
    guards to exercise sync_for_org's belt-and-braces catch."""
    ok_path = tmp_path / f"ok-{next(_SEQ)}.json"
    bad_path = tmp_path / f"bad-{next(_SEQ)}.json"
    async with session_scope() as session:
        org = await _org(session)
        _write(ok_path, _manifest(pack_id=ok_path.stem))
        _write(bad_path, _manifest(pack_id=bad_path.stem))
        ok_src = await _source(session, org, ok_path)
        bad_src = await _source(session, org, bad_path)

        real_check = sync_mod.check_pack_source

        async def _flaky(session_, source, **kw):
            if source.id == bad_src.id:
                raise RuntimeError("boom")
            return await real_check(session_, source, **kw)

        monkeypatch.setattr(sync_mod, "check_pack_source", _flaky)
        out = await sync_for_org(session, org.id)
        statuses = {r["source_id"]: r["status"] for r in out["results"]}
        assert statuses[ok_src.id] == "pending"
        assert statuses[bad_src.id] == "error"
