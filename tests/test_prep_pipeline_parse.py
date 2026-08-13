"""Source resolution and the parse stage, including resumption semantics."""

from __future__ import annotations

import hashlib

import fitz
import pytest
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import storage
from ccf.models import Organization, Policy, PolicyVersion, System
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_prep import PrepLine, PrepRun
from ccf.prep import pipeline
from ccf.prep.parsers import ParsedBlock, ParsedDocument, ParsedPage
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


async def test_nul_byte_in_text_source_is_stripped_not_crashed() -> None:
    """A NUL byte is valid UTF-8 but illegal in a Postgres ``text`` column.

    Without sanitization this reaches ``PrepLine.content`` and the flush raises
    an unhandled ``CharacterNotInRepertoireError`` instead of completing the
    stage — see task-8-report.md Finding 1.
    """
    org_id = await _org("prep-nul-text")
    version_id, _ = await _evidence_version(org_id, b"One.\nHas a NUL: \x00 in it.\n", "p.txt")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        count = await pipeline.run_stage_parse(s, run)
        assert count == 2
        assert run.status != "failed"
        assert run.stage_parse == "complete"
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert all("\x00" not in x.content for x in lines)
        assert any(x.content == "Has a NUL:  in it." for x in lines)


async def test_nul_byte_in_pdf_source_is_stripped_not_crashed() -> None:
    """The same NUL-byte hazard via a binary parser, not just the text parser.

    DOCX/PPTX cannot carry a literal NUL through to their parser at all: both are
    XML-based and lxml refuses to parse (or even build, via python-docx/pptx) a
    document containing one — confirmed empirically
    (``lxml.etree.XMLSyntaxError: Invalid character: Char 0x0 out of allowed
    range``). PDF text objects have no such well-formedness constraint, so PDF
    (via PyMuPDF) is the binary format that actually exercises this path.
    """
    org_id = await _org("prep-nul-pdf")
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Has a NUL: \x00 marker.")
    payload: bytes = doc.tobytes()
    doc.close()
    version_id, _ = await _evidence_version(org_id, payload, "policy.pdf")
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        count = await pipeline.run_stage_parse(s, run)
        assert count == 1
        assert run.status != "failed"
        assert run.stage_parse == "complete"
        assert run.parser_name == "pdf"
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert all("\x00" not in x.content for x in lines)
        assert any("Has a NUL:" in x.content and "marker" in x.content for x in lines)


async def test_persistence_failure_marks_the_run_failed_not_raised() -> None:
    """A persistence error during the write must not escape as an exception.

    Forces a real Postgres failure independent of the NUL-byte case above (an
    out-of-range ``page_number`` — ``prep_lines.page_number`` is a 32-bit
    ``Integer``) by monkeypatching ``dispatch`` to return a document with a bad
    value, then asserts the run lands in ``failed``/``error_stage="parse"`` and
    that the session is still usable afterward (the query below would raise
    ``PendingRollbackError`` if the failed flush had poisoned it).
    """
    org_id = await _org("prep-persist-fail")
    version_id, _ = await _evidence_version(org_id, b"One.\n", "p.txt")

    bad_doc = ParsedDocument(
        filename="p.txt",
        media_type="text/plain",
        parser_name="text",
        pages=[
            ParsedPage(
                page_number=99_999_999_999,  # exceeds Postgres INTEGER range
                blocks=[ParsedBlock(block_id="p1", block_type="paragraph", text="x")],
            )
        ],
    )

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        original_dispatch = pipeline.dispatch
        pipeline.dispatch = lambda *_a, **_kw: bad_doc  # type: ignore[assignment]
        try:
            count = await pipeline.run_stage_parse(s, run)
        finally:
            pipeline.dispatch = original_dispatch  # type: ignore[assignment]
        assert count == 0
        assert run.status == "failed"
        assert run.stage_parse == "failed"
        assert run.error_stage == "parse"
        assert run.error
        assert run.lines_parsed == 0
        # The session must still be usable — a poisoned session would raise
        # PendingRollbackError here instead of returning an empty result.
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert lines == []


async def test_rerun_after_source_deleted_clears_prior_lines_and_resets_counts() -> None:
    """Idempotency must hold when a rerun's outcome *changes*, not just repeats.

    Parse successfully once (N rows persisted), delete the source out from under
    the run, then re-run: the run must end up ``orphaned`` with its own
    ``PrepLine`` rows gone and ``lines_parsed`` reset to 0 — not left claiming N
    lines that no longer exist for it.
    """
    org_id = await _org("prep-rerun-orphan")
    version_id, _ = await _evidence_version(org_id, b"One.\nTwo.\n", "p.txt")

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        run_id = int(run.id)
        count = await pipeline.run_stage_parse(s, run)
        assert count == 2
        assert run.lines_parsed == 2

    async with session_scope() as s:
        await s.execute(delete(EvidenceVersion).where(EvidenceVersion.id == version_id))

    async with session_scope() as s:
        run = await pipeline.load_run(s, run_id)
        assert run is not None
        await pipeline.run_stage_parse(s, run)
        assert run.status == "orphaned"
        assert run.stage_parse == "skipped"
        assert run.lines_parsed == 0
        lines = (
            await s.execute(select(PrepLine).where(PrepLine.run_id == run.id))
        ).scalars().all()
        assert lines == []
