"""Adoption is human, audited, and refuses an unreviewed non-empty impact."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from ccf.catalog.revisions import AdoptionRefusedError, adopt_revision, materialize_revision
from ccf.db import session_scope
from ccf.models import (
    AuditLog,
    CatalogSource,
    Organization,
    SSPControlEntry,
    SSPProject,
)
from tests.test_catalog_materialize import _documents

_ORG_SEQ = itertools.count()

_EMPTY_CATALOG = json.dumps({"catalog": {"metadata": {"version": "5.3.0"}, "groups": []}}).encode()


async def _src(session, key: str) -> CatalogSource:
    s = CatalogSource(
        key=key, name=key, kind="oscal_catalog", url="https://example.test/catalog.json"
    )
    session.add(s)
    await session.flush()
    return s


async def test_adopts_when_impact_is_empty(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_clean")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        adopted = await adopt_revision(session, revision_id=rev.id, actor="kevin")
        assert adopted.status == "adopted"
        assert adopted.adopted_by == "kevin"
        assert adopted.adopted_at is not None


async def test_refuses_non_empty_impact_without_acknowledgement(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_impact")
        first = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="a" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=first.id, actor="kevin")

        # Authored content that the next revision would orphan.
        org = Organization(name=f"AdOrg-{next(_ORG_SEQ)}")
        session.add(org)
        await session.flush()
        proj = SSPProject(organization_id=org.id, customer_name="Acme")
        session.add(proj)
        await session.flush()
        session.add(SSPControlEntry(project_id=proj.id, control_id="AC-1", nist_id="AC-1"))
        await session.flush()

        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = _EMPTY_CATALOG
        second = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="b" * 40, data_root=tmp_path
        )

        with pytest.raises(AdoptionRefusedError) as exc:
            await adopt_revision(session, revision_id=second.id, actor="kevin")
        assert not exc.value.impact.is_empty()
        # Refusal must not have adopted anything.
        await session.refresh(second)
        assert second.status == "available"

        adopted = await adopt_revision(
            session, revision_id=second.id, actor="kevin", acknowledge_impact=True
        )
        assert adopted.status == "adopted"
        assert adopted.adoption_impact["empty"] is False


async def test_previous_revision_is_superseded(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_supersede")
        first = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="c" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=first.id, actor="kevin")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = _EMPTY_CATALOG
        second = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="d" * 40, data_root=tmp_path
        )
        await adopt_revision(
            session, revision_id=second.id, actor="kevin", acknowledge_impact=True
        )
        await session.refresh(first)
        assert first.status == "superseded"
        assert second.status == "adopted"


async def test_adoption_writes_a_chained_audit_entry(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_audit")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="e" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=rev.id, actor="kevin")
        rows = (
            await session.execute(
                select(AuditLog).where(AuditLog.entity_type == "catalog_revision")
            )
        ).scalars().all()
        entry = next(r for r in rows if r.entity_id == str(rev.id))
        assert entry.action == "adopt"
        assert entry.diff["revision"] == rev.revision
        # The chain must be intact -- record_event populates both hashes.
        assert entry.prev_hash and entry.row_hash


async def test_rejected_revision_cannot_be_adopted(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_rejected")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = b'{"catalog": "bad"}'
        rev = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="f" * 40, data_root=tmp_path
        )
        assert rev.status == "rejected"
        with pytest.raises(ValueError, match="rejected"):
            await adopt_revision(session, revision_id=rev.id, actor="kevin")


async def test_adopting_an_already_adopted_revision_is_a_noop(tmp_path: Path) -> None:
    async with session_scope() as session:
        src = await _src(session, "ad_noop")
        rev = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="1" * 40,
            data_root=tmp_path,
        )
        once = await adopt_revision(session, revision_id=rev.id, actor="kevin")
        stamp = once.adopted_at
        twice = await adopt_revision(session, revision_id=rev.id, actor="someone-else")
        assert twice.adopted_at == stamp
        assert twice.adopted_by == "kevin"


async def test_unknown_revision_raises(tmp_path: Path) -> None:
    async with session_scope() as session:
        with pytest.raises(ValueError, match="unknown catalog revision"):
            await adopt_revision(session, revision_id=999999, actor="kevin")


async def test_rollback_to_an_earlier_revision(tmp_path: Path) -> None:
    """Rolling back is adopting an earlier revision, through the same gate."""
    async with session_scope() as session:
        src = await _src(session, "ad_rollback")
        first = await materialize_revision(
            session,
            source=src,
            documents=_documents(),
            upstream_commit_sha="2" * 40,
            data_root=tmp_path,
        )
        await adopt_revision(session, revision_id=first.id, actor="kevin")
        docs = _documents()
        docs["NIST_SP-800-53_rev5_catalog.json"] = _EMPTY_CATALOG
        second = await materialize_revision(
            session, source=src, documents=docs, upstream_commit_sha="3" * 40, data_root=tmp_path
        )
        await adopt_revision(
            session, revision_id=second.id, actor="kevin", acknowledge_impact=True
        )
        # Back to the first.
        again = await adopt_revision(
            session, revision_id=first.id, actor="kevin", acknowledge_impact=True
        )
        assert again.status == "adopted"
        await session.refresh(second)
        assert second.status == "superseded"
