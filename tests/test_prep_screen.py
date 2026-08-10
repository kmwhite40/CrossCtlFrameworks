"""Catalog-driven relevance screening against ccf.controls."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, Organization
from ccf.models_prep import PrepLine, PrepScreen
from ccf.prep import pipeline
from ccf.prep.screen import run_stage_screen, score_line

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _seed_controls() -> int:
    """Seed two catalog controls and refresh the tsvector the screen relies on.

    Called once per test in this module, and the shared test database is only
    reset once per session (see ``clean_migrated_db``) — other test modules
    (e.g. ``test_fedramp20x.py``) also commit a real ``Control(identifier="IA-2")``
    row, and every test here reuses this same helper. Deleting these two
    identifiers first, and getting-or-creating the organization below, keeps
    every call idempotent regardless of what already ran earlier in the
    session.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.identifier.in_(["IA-2", "CP-9"])))
        s.add(
            Control(
                identifier="IA-2",
                control_name="Identification and Authentication (Organizational Users)",
                description=(
                    "Uniquely identify and authenticate organizational users and associate "
                    "that unique identification with processes acting on behalf of those users."
                ),
                assessment_objective="multifactor authentication is implemented for network access",
            )
        )
        s.add(
            Control(
                identifier="CP-9",
                control_name="System Backup",
                description=(
                    "Conduct backups of user-level information and system-level information "
                    "contained in the system."
                ),
                assessment_objective="backups of system documentation are conducted",
            )
        )
        await s.flush()
        await s.execute(
            text(
                "UPDATE ccf.controls SET search_vector = "
                "to_tsvector('english', coalesce(control_name,'') || ' ' || "
                "coalesce(description,'') || ' ' || coalesce(assessment_objective,''))"
            )
        )
        # get-or-create: this module's tests each call _seed_controls(), and the
        # shared test database only resets once per session (see
        # clean_migrated_db), so a second call in the same session must not
        # collide on the unique organization name.
        org = (
            await s.execute(select(Organization).where(Organization.name == "screen-org"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="screen-org")
            s.add(org)
            await s.flush()
        return int(org.id)


async def test_score_line_ranks_the_right_control_first() -> None:
    await _seed_controls()
    async with session_scope() as s:
        ranked = await score_line(
            s, content="All administrators must use multifactor authentication."
        )
    assert ranked, "expected at least one candidate control"
    assert ranked[0][0] == "IA-2"
    assert ranked[0][1] > 0


async def test_score_line_distinguishes_unrelated_subject_matter() -> None:
    await _seed_controls()
    async with session_scope() as s:
        ranked = await score_line(s, content="Nightly backups are written to offsite storage.")
    assert ranked[0][0] == "CP-9"


async def test_score_line_returns_empty_for_text_with_no_catalog_signal() -> None:
    await _seed_controls()
    async with session_scope() as s:
        ranked = await score_line(s, content="The quick brown fox jumped.")
    assert ranked == []


async def test_screen_stage_flags_relevant_lines_above_threshold() -> None:
    org_id = await _seed_controls()
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content="Administrators must use multifactor authentication."))
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=2,
                       content="The quick brown fox jumped."))
        await s.flush()

        above = await run_stage_screen(s, run)
        assert above == 1
        assert run.stage_screen == "complete"
        assert run.lines_above_threshold == 1

        screens = (
            await s.execute(
                select(PrepScreen, PrepLine)
                .join(PrepLine, PrepLine.id == PrepScreen.line_id)
                .where(PrepScreen.run_id == run.id)
                .order_by(PrepLine.line_number)
            )
        ).all()
        assert [x.PrepScreen.above_threshold for x in screens] == [True, False]
        assert "IA-2" in screens[0].PrepScreen.candidate_controls
        assert screens[0].PrepScreen.method == "catalog_fts"


async def test_screen_stage_is_idempotent_on_rerun() -> None:
    org_id = await _seed_controls()
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content="Multifactor authentication is required."))
        await s.flush()
        await run_stage_screen(s, run)
        await run_stage_screen(s, run)
        rows = (
            await s.execute(select(PrepScreen).where(PrepScreen.run_id == run.id))
        ).scalars().all()
        assert len(rows) == 1


async def test_threshold_is_read_from_the_run_snapshot_not_live_settings() -> None:
    """A settings change mid-flight must not silently reinterpret an open run."""
    org_id = await _seed_controls()
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        run.config_snapshot = {**run.config_snapshot, "screen_threshold": 99.0}
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content="Multifactor authentication is required."))
        await s.flush()
        above = await run_stage_screen(s, run)
    assert above == 0, "an impossibly high snapshot threshold must gate everything out"
    assert get_settings().prep_screen_threshold < 99.0
