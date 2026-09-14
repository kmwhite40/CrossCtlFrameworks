"""Resolution precedence, and the loader's no-database guarantee."""

from __future__ import annotations

import inspect
from pathlib import Path

from ccf.catalog import oscal as oscal_mod
from ccf.catalog.revisions import resolve_adopted_dir
from ccf.db import session_scope
from ccf.models import CatalogRevision, CatalogSource


async def _source_with_adopted(session, key: str, content_dir: str | None) -> CatalogSource:
    s = CatalogSource(key=key, name=key, url="https://example.test/x.json")
    session.add(s)
    await session.flush()
    session.add(
        CatalogRevision(source_id=s.id, revision="rev1", status="adopted", content_dir=content_dir)
    )
    await session.flush()
    return s


async def test_returns_adopted_directory_when_present(tmp_path: Path) -> None:
    d = tmp_path / "rev1"
    d.mkdir()
    (d / "MANIFEST.json").write_text("{}", encoding="utf-8")
    async with session_scope() as session:
        await _source_with_adopted(session, "res_ok", str(d))
        assert await resolve_adopted_dir(session, source_key="res_ok") == d


async def test_returns_none_for_packaged_bundled_revision() -> None:
    async with session_scope() as session:
        await _source_with_adopted(session, "res_bundled", None)
        assert await resolve_adopted_dir(session, source_key="res_bundled") is None


async def test_returns_none_when_adopted_directory_is_missing(tmp_path: Path) -> None:
    """A container that lost its volume must fall back, not crash."""
    async with session_scope() as session:
        await _source_with_adopted(session, "res_gone", str(tmp_path / "vanished"))
        assert await resolve_adopted_dir(session, source_key="res_gone") is None


async def test_returns_none_for_unknown_source() -> None:
    async with session_scope() as session:
        assert await resolve_adopted_dir(session, source_key="nope") is None


async def test_ignores_non_adopted_revisions(tmp_path: Path) -> None:
    d = tmp_path / "avail"
    d.mkdir()
    (d / "MANIFEST.json").write_text("{}", encoding="utf-8")
    async with session_scope() as session:
        s = CatalogSource(key="res_avail", name="x", url="https://example.test/x.json")
        session.add(s)
        await session.flush()
        session.add(
            CatalogRevision(
                source_id=s.id, revision="r1", status="available", content_dir=str(d)
            )
        )
        await session.flush()
        assert await resolve_adopted_dir(session, source_key="res_avail") is None


def test_load_oscal_catalog_performs_no_database_access() -> None:
    """catalog/report.py and ssp/nist80053.py depend on this staying DB-free."""
    src = inspect.getsource(oscal_mod)
    for forbidden in ("AsyncSession", "session_scope", "sqlalchemy", "await "):
        assert forbidden not in src, f"{forbidden!r} leaked into the pure catalog loader"
