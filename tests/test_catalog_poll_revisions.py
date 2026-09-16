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
from tests.test_catalog_materialize import CATALOG, PROFILE

_BODY = json.dumps(CATALOG).encode()
_PROFILE_BODY = json.dumps(PROFILE).encode()


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
    kw.setdefault("url", "https://example.test/c.json")
    s = CatalogSource(key=key, name=key, kind="oscal_catalog", **kw)
    session.add(s)
    await session.flush()
    return s


async def _reuse_800_53_source(session, **overrides: object) -> CatalogSource:
    """The real 800-53 catalog source key is migration-seeded and globally
    unique (see migrations/versions/0066_catalog_revisions.py's bundled-
    revision seed), so tests that need that exact key must reuse-and-reset
    that row rather than inserting a duplicate. Only the given fields are
    overridden; a fresh, correctly-shaped ``url`` is always set since the
    seed's own ``url`` is a human-readable provenance string, not a fetchable
    per-file URL."""
    src = (
        await session.execute(
            select(CatalogSource).where(CatalogSource.key == mod._800_53_CATALOG_KEY)
        )
    ).scalars().first()
    assert src is not None, "expected migration 0066 to have seeded this source"
    src.url = mod._default_source_url(mod._800_53_CATALOG_KEY)
    for k, v in overrides.items():
        setattr(src, k, v)
    await session.flush()
    return src


async def _revisions(session, source_id: int) -> list[CatalogRevision]:
    return list(
        (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == source_id)
            )
        ).scalars().all()
    )


async def _revision_by_label(session, source_id: int, label: str) -> CatalogRevision | None:
    """The 800-53 source is a shared singleton row (see _reuse_800_53_source),
    so tests using it must look up their own revision by label rather than
    assuming they're the only row for that source_id."""
    return (
        await session.execute(
            select(CatalogRevision).where(
                CatalogRevision.source_id == source_id, CatalogRevision.revision == label
            )
        )
    ).scalars().first()


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
    """The 800-53 catalog source must capture all four files _verify needs.

    ``materialize_revision``'s parse-check requires the catalog *and* its
    three baseline profiles (see ccf.catalog.oscal._verify) -- so the fetch
    mock has to answer each of the four URLs with the right shape of content,
    the way real polling of ``DEFAULT_SOURCES`` would.
    """

    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        body = _BODY if url.endswith("_catalog.json") else _PROFILE_BODY
        return 200, body, "etag-1"

    async def no_commit(url: str) -> str | None:
        return None

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    monkeypatch.setattr(mod, "resolve_commit_sha", no_commit)
    async with session_scope() as session:
        src = await _reuse_800_53_source(session, etag=None, last_sha256=None)
        check = await check_source(session, src, revision_data_root=tmp_path)
        assert check.status == "changed"
        label = f"sha-{mod._sha256_bytes(_BODY)[:8]}"
        row = await _revision_by_label(session, src.id, label)
        assert row is not None
        # Never adopted by the poller -- that stays a human decision.
        assert row.status == "available"
        assert row.status != "adopted"
        # An available revision means the source's digest legitimately advances.
        assert src.last_sha256 == mod._sha256_bytes(_BODY)


async def test_other_oscal_catalog_sources_skip_capture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CSF 2.0 / 800-171 are also ``oscal_catalog`` sources materialize_revision
    can't handle (it's hard-wired to the 800-53 filenames) -- capture must be
    skipped for them rather than manufacturing a doomed-to-reject row, and
    drift detection/last_sha256 advancement must still work normally."""

    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 200, _BODY, "etag-1"

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    async with session_scope() as session:
        src = await _src(session, "nist_csf_2_0_catalog")
        check = await check_source(session, src, revision_data_root=tmp_path)
        assert check.status == "changed"
        assert check.detail.get("capture_skipped")
        assert await _revisions(session, src.id) == []
        assert src.last_sha256 == mod._sha256_bytes(_BODY)


async def test_rejected_capture_does_not_advance_last_sha256(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Losing the only copy of drifted content is worse than re-fetching it.

    Every URL here answers with catalog-shaped content, so the "baseline
    profiles" aren't real OSCAL profiles and materialize_revision's
    parse-check rejects the capture. When that happens, last_sha256 (and
    etag) must stay exactly as they were, so the next poll gets a genuine 200
    -- not a 304 against the new etag -- and sees this same drift again.
    """

    async def fake_fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
        return 200, _BODY, "new-etag"

    async def fake_commit(url: str) -> str | None:
        # A commit sha distinct from other tests' labels, so this capture
        # attempt is never short-circuited by a prior test's already-
        # committed revision for the same (source, revision-label) pair.
        return "b" * 40

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    monkeypatch.setattr(mod, "resolve_commit_sha", fake_commit)
    async with session_scope() as session:
        src = await _reuse_800_53_source(
            session, last_sha256="original-sha", etag="original-etag"
        )
        check = await check_source(session, src, revision_data_root=tmp_path)
        row = await _revision_by_label(session, src.id, "b" * 12)
        assert row is not None
        assert row.status == "rejected"
        # Drift was real and must still be reported...
        assert check.status == "changed"
        # ...but the recorded digest/etag must be untouched.
        assert src.last_sha256 == "original-sha"
        assert src.etag == "original-etag"


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
