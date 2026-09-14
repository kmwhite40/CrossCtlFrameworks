"""Polling captures revisions without changing existing drift behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

import ccf.etl.sources as mod
from ccf.db import session_scope
from ccf.etl.sources import check_source, parse_commit_url, resolve_commit_sha
from ccf.models import CatalogRevision, CatalogSource
from tests.test_catalog_materialize import CATALOG

_BODY = json.dumps(CATALOG).encode()


def test_parse_commit_url_extracts_repo_ref_and_path() -> None:
    repo, ref, path = parse_commit_url(
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    )
    assert repo == "usnistgov/oscal-content"
    assert ref == "main"
    assert path == "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"


def test_parse_commit_url_returns_none_for_non_github() -> None:
    assert parse_commit_url("file:///data/local.xlsx") == (None, None, None)
    assert parse_commit_url("https://example.test/c.json") == (None, None, None)


async def test_resolve_commit_sha_returns_none_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Commit resolution is best-effort: a failure must never break a poll."""

    async def boom(*a: object, **k: object) -> object:
        raise RuntimeError("network down")

    monkeypatch.setattr(mod, "_get_json", boom)
    assert await resolve_commit_sha("https://raw.githubusercontent.com/o/r/main/x.json") is None


async def test_resolve_commit_sha_reads_the_first_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake(url: str) -> object:
        return [{"sha": "f" * 40}]

    monkeypatch.setattr(mod, "_get_json", fake)
    got = await resolve_commit_sha("https://raw.githubusercontent.com/o/r/main/x.json")
    assert got == "f" * 40


async def _src(session, key: str, **kw: object) -> CatalogSource:
    s = CatalogSource(
        key=key, name=key, kind="oscal_catalog", url="https://example.test/c.json", **kw
    )
    session.add(s)
    await session.flush()
    return s


async def _revisions(session, source_id: int) -> list[CatalogRevision]:
    return list(
        (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == source_id)
            )
        ).scalars().all()
    )


async def test_unchanged_304_poll_captures_no_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 304, None, etag

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    async with session_scope() as session:
        src = await _src(session, "poll_304", last_sha256="deadbeef")
        check = await check_source(session, src, revision_data_root=tmp_path)
        assert check.status == "unchanged"
        assert await _revisions(session, src.id) == []


async def test_identical_sha_poll_captures_no_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 200, _BODY, "etag-1"

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    async with session_scope() as session:
        src = await _src(session, "poll_same", last_sha256=mod._sha256_bytes(_BODY))
        check = await check_source(session, src, revision_data_root=tmp_path)
        assert check.status == "unchanged"
        assert await _revisions(session, src.id) == []


async def test_changed_poll_captures_an_available_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 200, _BODY, "etag-1"

    async def no_commit(url: str) -> str | None:
        return None

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    monkeypatch.setattr(mod, "resolve_commit_sha", no_commit)
    async with session_scope() as session:
        src = await _src(session, "poll_new")
        check = await check_source(session, src, revision_data_root=tmp_path)
        assert check.status == "changed"
        rows = await _revisions(session, src.id)
        assert len(rows) == 1
        # Never adopted by the poller -- that stays a human decision.
        assert rows[0].status in {"available", "rejected"}
        assert rows[0].status != "adopted"


async def test_capture_is_skipped_when_no_revision_root_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing callers that pass no root keep today's behaviour exactly."""

    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 200, _BODY, "etag-1"

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    async with session_scope() as session:
        src = await _src(session, "poll_noroot")
        check = await check_source(session, src)
        assert check.status == "changed"  # drift still detected
        assert await _revisions(session, src.id) == []  # but nothing captured


async def test_non_oscal_source_captures_no_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 200, b"not json at all", "etag-1"

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    async with session_scope() as session:
        src = await _src(session, "poll_generic")
        src.kind = "generic"
        await session.flush()
        await check_source(session, src, revision_data_root=tmp_path)
        assert await _revisions(session, src.id) == []
