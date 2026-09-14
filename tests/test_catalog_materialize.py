"""Materializing a revision: parse-check before commit, idempotence, rejection."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import select

from ccf.catalog.oscal import load_oscal_catalog
from ccf.catalog.revisions import import_revision, materialize_revision, revision_root
from ccf.db import session_scope
from ccf.models import CatalogRevision, CatalogSource

CATALOG = {
    "catalog": {
        "metadata": {"version": "5.2.0"},
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "ac-1",
                        "title": "Policy",
                        "parts": [{"name": "statement", "prose": "Develop policy"}],
                    }
                ],
            }
        ],
    }
}
PROFILE = {"profile": {"imports": [{"include-controls": [{"with-ids": ["ac-1"]}]}]}}


def _documents() -> dict[str, bytes]:
    docs = {"NIST_SP-800-53_rev5_catalog.json": json.dumps(CATALOG).encode()}
    for name in (
        "NIST_SP-800-53_rev5_LOW-baseline_profile.json",
        "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
        "NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
    ):
        docs[name] = json.dumps(PROFILE).encode()
    return docs


async def _source(session, key: str) -> CatalogSource:
    s = CatalogSource(
        key=key, name=key, kind="oscal_catalog", url="https://example.test/catalog.json"
    )
    session.add(s)
    await session.flush()
    return s


async def test_materialize_lands_available_and_loadable(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_ok")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        assert rev.status == "available"
        assert rev.revision == "a" * 12
        assert rev.oscal_version == "5.2.0"
        # content_index is in parse_oscal_catalog's shape.
        assert "ac-1" in rev.content_index
        # And the directory is loadable by the real, unmodified loader.
        d = revision_root(tmp_path, "mat_ok", rev.revision)
        assert (d / "MANIFEST.json").is_file()
        assert load_oscal_catalog(d).exists("AC-1")


async def test_non_parsing_revision_is_rejected_and_leaves_no_directory(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_bad")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = b'{"catalog": "not-an-object"}'
        rev = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="b" * 40, data_root=tmp_path
        )
        assert rev.status == "rejected"
        assert rev.notes
        assert not revision_root(tmp_path, "mat_bad", rev.revision).exists()


async def test_materialize_is_idempotent_on_same_commit(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_idem")
        first = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        second = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        assert first.id == second.id
        rows = (
            await session.execute(
                select(CatalogRevision).where(CatalogRevision.source_id == src.id)
            )
        ).scalars().all()
        assert len(rows) == 1


async def test_materialize_never_touches_the_adopted_revision(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _source(session, "mat_keep")
        adopted = CatalogRevision(source_id=src.id, revision="bundled", status="adopted")
        session.add(adopted)
        await session.flush()
        await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="d" * 40,
            data_root=tmp_path,
        )
        await session.refresh(adopted)
        assert adopted.status == "adopted"


async def test_unpinned_revision_gets_a_content_addressed_label(tmp_path: Path) -> None:
    """A host with no commit concept still yields a stable, reproducible label."""
    async with session_scope() as session:
        src = await _source(session, "mat_nopin")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha=None,
            data_root=tmp_path,
        )
        assert rev.revision.startswith("sha-")
        assert rev.upstream_commit_sha is None


async def test_import_from_directory(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.mkdir()
    for name, body in _documents().items():
        (payload / name).write_bytes(body)

    async with session_scope() as session:
        await _source(session, "imp_dir")
        rev = await import_revision(
            session,
            source_key="imp_dir",
            payload=payload,
            data_root=tmp_path / "root",
            notes="sneakernet from IL5",
        )
        assert rev.status == "available"
        assert rev.upstream_commit_sha is None
        assert rev.notes and "IL5" in rev.notes


async def test_import_from_zip(tmp_path: Path) -> None:
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, body in _documents().items():
            zf.writestr(name, body)

    async with session_scope() as session:
        await _source(session, "imp_zip")
        rev = await import_revision(
            session, source_key="imp_zip", payload=archive, data_root=tmp_path / "root"
        )
        assert rev.status == "available"


async def test_import_rejects_unknown_source(tmp_path: Path) -> None:
    payload = tmp_path / "p"
    payload.mkdir()
    (payload / "x.json").write_bytes(b"{}")
    async with session_scope() as session:
        with pytest.raises(ValueError, match="unknown catalog source"):
            await import_revision(
                session, source_key="nope", payload=payload, data_root=tmp_path / "root"
            )


async def test_import_rejects_empty_payload(tmp_path: Path) -> None:
    payload = tmp_path / "empty"
    payload.mkdir()
    async with session_scope() as session:
        await _source(session, "imp_empty")
        with pytest.raises(ValueError, match="no OSCAL JSON"):
            await import_revision(
                session, source_key="imp_empty", payload=payload, data_root=tmp_path / "root"
            )
