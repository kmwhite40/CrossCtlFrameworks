"""The single-adopted-revision invariant is enforced by the database."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import CatalogRevision, CatalogSource

# Rows in catalog_sources / pack_sources are polled by scheduler.run_cycle(),
# so they must not outlive the test that made them -- see the fixture.
pytestmark = pytest.mark.usefixtures("isolate_source_rows")


async def _source(session, key: str) -> CatalogSource:
    s = CatalogSource(key=key, name=key, url="https://example.test/x.json")
    session.add(s)
    await session.flush()
    return s


async def test_one_adopted_revision_per_source() -> None:
    async with session_scope() as session:
        src = await _source(session, "src_a")
        session.add(CatalogRevision(source_id=src.id, revision="aaaaaaaaaaaa", status="adopted"))
        await session.flush()
        session.add(CatalogRevision(source_id=src.id, revision="bbbbbbbbbbbb", status="adopted"))
        with pytest.raises(IntegrityError):
            await session.flush()
        # The session is poisoned after a failed flush; roll back so the
        # surrounding session_scope can exit without a PendingRollbackError.
        await session.rollback()


async def test_many_available_revisions_allowed() -> None:
    async with session_scope() as session:
        src = await _source(session, "src_b")
        for rev in ("aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"):
            session.add(CatalogRevision(source_id=src.id, revision=rev, status="available"))
        await session.flush()  # no constraint violation


async def test_revision_unique_per_source() -> None:
    async with session_scope() as session:
        src = await _source(session, "src_c")
        session.add(CatalogRevision(source_id=src.id, revision="dupdupdupdup", status="available"))
        await session.flush()
        session.add(CatalogRevision(source_id=src.id, revision="dupdupdupdup", status="available"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_same_revision_label_allowed_across_sources() -> None:
    async with session_scope() as session:
        a = await _source(session, "src_d")
        b = await _source(session, "src_e")
        session.add(CatalogRevision(source_id=a.id, revision="shared0000aa", status="adopted"))
        session.add(CatalogRevision(source_id=b.id, revision="shared0000aa", status="adopted"))
        await session.flush()  # the invariant is per-source, not global


async def test_bundled_revision_is_seeded_and_adopted() -> None:
    """Migration 0066 must leave the shipped catalog as the adopted revision."""
    async with session_scope() as session:
        row = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.revision == "bundled")
            )
        ).scalars().first()
        assert row is not None
        assert row.status == "adopted"
        # content_dir NULL means "resolve to the packaged in-wheel directory".
        assert row.content_dir is None
        assert row.files, "bundled revision should carry the manifest's file hashes"
