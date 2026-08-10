"""Prep pipeline tables — round-trip, cascade, and traceability chain."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_prep import (
    PREP_STAGES,
    PrepClassification,
    PrepEmbedding,
    PrepLine,
    PrepRun,
    PrepScreen,
    PrepUnit,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def test_server_default_timestamps_are_not_null_in_live_schema() -> None:
    """The ORM declares these ``Mapped[datetime]`` (non-Optional); the migration
    must match with an explicit ``nullable=False``, not just a server default.
    Checked against ``information_schema`` — not the ORM — since the ORM would
    pass this assertion regardless of what the migration actually created."""
    expected = {
        ("prep_runs", "created_at"),
        ("prep_runs", "updated_at"),
        ("prep_screens", "screened_at"),
        ("prep_units", "created_at"),
        ("prep_classifications", "classified_at"),
        ("prep_embeddings", "embedded_at"),
        ("prep_jobs", "created_at"),
        ("prep_jobs", "updated_at"),
    }
    async with session_scope() as s:
        rows = (
            await s.execute(
                text(
                    """
                    SELECT table_name, column_name, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'ccf' AND table_name LIKE 'prep_%'
                    """
                )
            )
        ).all()
    nullability = {(r.table_name, r.column_name): r.is_nullable for r in rows}
    assert expected <= nullability.keys(), "expected column(s) missing from live schema"
    for key in expected:
        assert nullability[key] == "NO", f"{key} is nullable in the live schema"


async def test_run_defaults_every_stage_to_pending() -> None:
    org_id = await _org("prep-defaults")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()
        assert run.status == "pending"
        for stage in PREP_STAGES:
            assert getattr(run, f"stage_{stage}") == "pending"


async def test_traceability_chain_resolves_page_and_cell() -> None:
    """A unit must resolve back to the page and table cell it came from."""
    org_id = await _org("prep-trace")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="evidence_version", source_id=1)
        s.add(run)
        await s.flush()
        line = PrepLine(
            run_id=run.id,
            organization_id=org_id,
            line_number=7,
            page_number=3,
            section_path="Access Control > Account Management",
            block_type="table_cell",
            table_id="t1",
            row_index=2,
            col_index=1,
            cell_label="Review Frequency",
            content="Accounts are reviewed quarterly.",
        )
        s.add(line)
        await s.flush()
        unit = PrepUnit(
            run_id=run.id,
            organization_id=org_id,
            trigger_line_id=line.id,
            source_line_ids=[line.id],
            content="Accounts are reviewed quarterly.",
            page_numbers=[3],
            section_path="Access Control > Account Management",
            table_coordinates={"table_id": "t1", "row_index": 2, "col_index": 1},
            token_count=8,
        )
        s.add(unit)
        await s.flush()
        unit_id = unit.id

    async with session_scope() as s:
        unit = (await s.execute(select(PrepUnit).where(PrepUnit.id == unit_id))).scalar_one()
        origin = (
            await s.execute(select(PrepLine).where(PrepLine.id.in_(unit.source_line_ids)))
        ).scalars().all()
        assert [o.page_number for o in origin] == [3]
        assert origin[0].cell_label == "Review Frequency"


async def test_deleting_a_run_cascades_to_all_children() -> None:
    org_id = await _org("prep-cascade")
    async with session_scope() as s:
        run = PrepRun(organization_id=org_id, source_kind="policy_version", source_id=9)
        s.add(run)
        await s.flush()
        line = PrepLine(
            run_id=run.id, organization_id=org_id, line_number=1, content="MFA is required."
        )
        s.add(line)
        await s.flush()
        s.add(PrepScreen(line_id=line.id, run_id=run.id, organization_id=org_id,
                         relevance_score=0.9, candidate_controls=["IA-2"], above_threshold=True))
        unit = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                        source_line_ids=[line.id], content="MFA is required.", token_count=4)
        s.add(unit)
        await s.flush()
        s.add(PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org_id,
                                 control_identifiers=["IA-2"], artifact_type="policy",
                                 evidence_strength="strong", model_confidence=0.8))
        s.add(PrepEmbedding(unit_id=unit.id, run_id=run.id, organization_id=org_id,
                            model_name="text-embedding-3-small", embedding=[0.1] * 1024))
        await s.flush()
        run_id = run.id

    async with session_scope() as s:
        run = (await s.execute(select(PrepRun).where(PrepRun.id == run_id))).scalar_one()
        await s.delete(run)

    async with session_scope() as s:
        assert (await s.execute(select(PrepLine).where(PrepLine.run_id == run_id))).first() is None
        assert (await s.execute(select(PrepUnit).where(PrepUnit.run_id == run_id))).first() is None
