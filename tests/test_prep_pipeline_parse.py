"""Source resolution and the parse stage, including resumption semantics."""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import storage
from ccf.models import Organization, Policy, PolicyVersion, System
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_prep import PrepLine, PrepRun
from ccf.prep import pipeline
from ccf.prep.sources import SourceMissing, resolve_source

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
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


async def _evidence_version(org_id: int, payload: bytes, filename: str) -> tuple[int, int]:
    """Store bytes through the real backend and return (version_id, system_id).

    ``media_type`` is derived from the filename rather than hardcoded: a stored
    version with a *known* media type (e.g. ``text/plain``) always wins over
    extension sniffing in ``resolve_media_type``, so hardcoding it here would
    make it impossible to exercise the unsupported-format path for a filename
    like ``diagram.vsdx`` — dispatch would happily "parse" the raw bytes as text
    instead of raising ``UnsupportedMediaType``.
    """
    digest = hashlib.sha256(payload).hexdigest()
    media_type = "text/plain" if filename.endswith(".txt") else None
    ref = storage.get_backend().put(digest, payload, media_type or "application/octet-stream")
    async with session_scope() as s:
        system = System(organization_id=org_id, name="Test System")
        s.add(system)
        await s.flush()
        obj = EvidenceObject(organization_id=org_id, title=filename, system_id=system.id)
        s.add(obj)
        await s.flush()
        ver = EvidenceVersion(
            evidence_object_id=obj.id, version=1, sha256=digest, media_type=media_type,
            size_bytes=len(payload), filename=filename, storage_backend="local", storage_ref=ref,
        )
        s.add(ver)
        await s.flush()
        return int(ver.id), int(system.id)


async def test_resolve_evidence_version_returns_bytes_and_system() -> None:
    org_id = await _org("prep-src-ev")
    version_id, system_id = await _evidence_version(org_id, b"MFA is required.", "p.txt")
    async with session_scope() as s:
        resolved = await resolve_source(s, "evidence_version", version_id)
    assert resolved.data == b"MFA is required."
    assert resolved.organization_id == org_id
    assert resolved.system_id == system_id
    assert resolved.filename == "p.txt"


async def test_resolve_policy_version_uses_inline_body() -> None:
    org_id = await _org("prep-src-pol")
    async with session_scope() as s:
        policy = Policy(organization_id=org_id, name="Access Control Policy")
        s.add(policy)
        await s.flush()
        ver = PolicyVersion(policy_id=policy.id, version="1.0", body="Accounts are reviewed.")
        s.add(ver)
        await s.flush()
        version_id = int(ver.id)
    async with session_scope() as s:
        resolved = await resolve_source(s, "policy_version", version_id)
    assert b"Accounts are reviewed." in resolved.data
    assert resolved.organization_id == org_id
    assert resolved.system_id is None


async def test_resolve_raises_source_missing_for_a_deleted_source() -> None:
    async with session_scope() as s:
        with pytest.raises(SourceMissing):
            await resolve_source(s, "evidence_version", 999_999)


async def test_parse_stage_persists_lines_and_marks_stage_complete() -> None:
    org_id = await _org("prep-parse")
    version_id, _ = await _evidence_version(org_id, b"One.\nTwo.\n", "p.txt")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        count = await pipeline.run_stage_parse(s, run)
        assert count == 2
        assert run.stage_parse == "complete"
        assert run.lines_parsed == 2
        assert run.parser_name == "text"
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert sorted(x.content for x in lines) == ["One.", "Two."]
        assert all(x.organization_id == org_id for x in lines)


async def test_unsupported_media_type_marks_the_run_unsupported_not_failed() -> None:
    org_id = await _org("prep-unsupported")
    version_id, _ = await _evidence_version(org_id, b"\x00\x01", "diagram.vsdx")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        await pipeline.run_stage_parse(s, run)
        assert run.status == "unsupported"
        assert run.stage_parse == "skipped"
        assert run.error_stage is None


async def test_reparsing_replaces_prior_lines_rather_than_duplicating() -> None:
    """Re-running a stage must be idempotent — a resumed run cannot double-write."""
    org_id = await _org("prep-reparse")
    version_id, _ = await _evidence_version(org_id, b"One.\nTwo.\n", "p.txt")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        await pipeline.run_stage_parse(s, run)
        await pipeline.run_stage_parse(s, run)
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert len(lines) == 2


async def test_next_stage_reports_the_first_incomplete_stage() -> None:
    org_id = await _org("prep-next")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()
        assert pipeline.next_stage(run) == "parse"
        run.stage_parse = "complete"
        assert pipeline.next_stage(run) == "screen"
        for stage in ("screen", "expand", "classify", "embed"):
            setattr(run, f"stage_{stage}", "complete")
        assert pipeline.next_stage(run) is None


async def test_config_snapshot_records_the_thresholds_in_force() -> None:
    org_id = await _org("prep-snapshot")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=1
        )
        assert run.config_snapshot["screen_threshold"] == get_settings().prep_screen_threshold
        assert run.config_snapshot["expand_window"] == get_settings().prep_expand_window
