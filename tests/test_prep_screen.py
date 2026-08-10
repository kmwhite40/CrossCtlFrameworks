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


#: The same weighting the real ETL applies after every workbook ingest
#: (``ccf.etl.pipeline``: identifier/control_name at 'A', assessment_objective
#: at 'B', description at 'C', discussion at 'D'). A prior version of this
#: helper built an unweighted vector (every lexeme at the default weight),
#: which scored roughly an order of magnitude lower than real catalog rows for
#: the same term overlap and would have made ``prep_screen_threshold`` — tuned
#: against the real catalog, see task-9-report.md — look uncrossable in this
#: tiny fixture even though the design behind it is sound at real scale.
_SEARCH_VECTOR_SQL = (
    "UPDATE ccf.controls SET search_vector = "
    "setweight(to_tsvector('english', coalesce(identifier,'')), 'A') || "
    "setweight(to_tsvector('english', coalesce(control_name,'')), 'A') || "
    "setweight(to_tsvector('english', coalesce(assessment_objective,'')), 'B') || "
    "setweight(to_tsvector('english', coalesce(description,'')), 'C') || "
    "setweight(to_tsvector('english', coalesce(discussion,'')), 'D')"
)


async def _seed_controls() -> int:
    """Seed two catalog controls and refresh the tsvector the screen relies on.

    Called once per test in this module, and the shared test database is only
    reset once per session (see ``clean_migrated_db``) — other test modules
    (e.g. ``test_fedramp20x.py``) also commit a real ``Control(identifier="IA-2")``
    row, and every test here reuses this same helper. Deleting these two
    identifiers first, and getting-or-creating the organization below, keeps
    every call idempotent regardless of what already ran earlier in the
    session.

    The description/assessment_objective/discussion text below is longer than
    a minimal fixture needs, deliberately: ``prep_screen_threshold`` is
    calibrated against real catalog rows, which typically carry several
    sentences across these fields (see ``test_prep_screen_realistic_scale.py``
    for the full-size validation). A single eight-word fixture row can't reach
    that threshold at all — not because the design is wrong, but because a
    real IA-02/CP-09 catalog entry simply contains more matchable text than a
    one-line stub does. Sizing these two rows closer to real entries keeps
    this fixture representative instead of accidentally re-hiding the exact
    scale problem this task was revised to fix.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.identifier.in_(["IA-2", "CP-9"])))
        s.add(
            Control(
                identifier="IA-2",
                control_name="Identification and Authentication (Organizational Users)",
                description=(
                    "Uniquely identify and authenticate organizational users and associate "
                    "that unique identification with processes acting on behalf of those "
                    "users. Multifactor authentication is required for network access to "
                    "privileged and non-privileged accounts."
                ),
                assessment_objective=(
                    "multifactor authentication is implemented for network access to "
                    "privileged accounts; multifactor authentication is implemented for "
                    "network access to non-privileged accounts"
                ),
                discussion=(
                    "Organizational users include employees or individuals considered to "
                    "have equivalent status. Authentication of user identities is "
                    "accomplished through passwords, tokens, or multifactor authentication "
                    "mechanisms such as personal identity verification cards."
                ),
            )
        )
        s.add(
            Control(
                identifier="CP-9",
                control_name="System Backup",
                description=(
                    "Conduct backups of user-level information and system-level information "
                    "contained in the system. Backups are stored offsite and protected from "
                    "unauthorized disclosure or modification."
                ),
                assessment_objective=(
                    "backups of system-level information are conducted; backups of "
                    "user-level information are conducted; backup information is protected "
                    "at storage locations"
                ),
                discussion=(
                    "System-level information includes system state, operating system "
                    "software, and other installed software. Backups of information system "
                    "documentation are also part of the contingency planning process."
                ),
            )
        )
        await s.flush()
        await s.execute(text(_SEARCH_VECTOR_SQL))
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


# --- realistic-scale regression -------------------------------------------
#
# The six tests above seed two controls. That is exactly why the original
# query construction (websearch_to_tsquery + ts_rank, then OR-lexemes +
# ts_rank_cd unnormalized) looked fine here and then broke down against the
# real catalog: at ~1,200 real base/enhancement controls, ts_rank_cd's raw
# scale is dominated by document richness rather than topical relevance, and
# nearly every substantive sentence cleared the old 0.15 threshold regardless
# of which control it was actually about (measured directly against the fully
# ingested "NIST Cross Mappings" workbook — see task-9-report.md). A fixture
# this small cannot catch that; it has nothing to get lost among. This test
# seeds several hundred synthetic-but-plausible controls spanning many
# families with overlapping, realistic compliance vocabulary, so the two
# properties that broke at scale are pinned down here too.

_SYNTHETIC_FAMILIES = [
    "AC", "AU", "CA", "CM", "IR", "MA", "PE", "PL",
    "PS", "RA", "SA", "SC", "SI", "SR", "PM", "MP",
]

#: Plausible-sounding control topics, deliberately reusing generic compliance
#: vocabulary ("organization", "system", "review", "annually", "documented",
#: "authorized", "access", "process") that also appears in the two target
#: controls below — the same kind of incidental overlap that diluted OR-only
#: matching against the real catalog.
_SYNTHETIC_TOPICS = [
    "access control list management", "audit trail generation and review",
    "configuration baseline maintenance", "contingency plan testing",
    "incident response coordination", "maintenance record keeping",
    "physical entry authorization", "system security plan documentation",
    "personnel screening procedures", "risk assessment methodology",
    "acquisition process security review", "boundary protection device management",
    "system integrity monitoring", "supply chain risk evaluation",
    "program management oversight", "media protection and handling",
]


async def _seed_realistic_scale_catalog() -> None:
    """Seed ~320 synthetic-but-plausible controls plus two real, richly-worded
    targets (IA-02, CP-09), weighted exactly as the real ETL weights
    ``search_vector`` after every workbook ingest.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.identifier.like("ZS-%")))
        await s.execute(delete(Control).where(Control.identifier.in_(["IA-02", "CP-09"])))

        rows: list[Control] = []
        for family in _SYNTHETIC_FAMILIES:
            for i in range(1, 21):
                topic = _SYNTHETIC_TOPICS[(len(rows)) % len(_SYNTHETIC_TOPICS)]
                rows.append(
                    Control(
                        identifier=f"ZS-{family}-{i:02d}",
                        control_name=f"{family} Synthetic Control {i}: {topic.title()}",
                        description=(
                            f"The organization implements {topic} as part of its {family} "
                            f"family of controls. Personnel review and document these "
                            f"procedures annually to ensure the system remains compliant "
                            f"with authorized access requirements."
                        ),
                        assessment_objective=(
                            f"the {topic} process is documented and reviewed by authorized "
                            f"personnel on an annual basis"
                        ),
                    )
                )
        rows.append(
            Control(
                identifier="IA-02",
                control_name="Identification and Authentication (Organizational Users)",
                description=(
                    "Uniquely identify and authenticate organizational users and associate "
                    "that unique identification with processes acting on behalf of those "
                    "users. Multifactor authentication is required for network access to "
                    "privileged and non-privileged accounts."
                ),
                assessment_objective=(
                    "multifactor authentication is implemented for network access to "
                    "privileged accounts; multifactor authentication is implemented for "
                    "network access to non-privileged accounts"
                ),
                discussion=(
                    "Organizational users include employees or individuals considered to "
                    "have equivalent status. Authentication of user identities is "
                    "accomplished through passwords, tokens, or multifactor authentication "
                    "mechanisms such as personal identity verification cards."
                ),
            )
        )
        rows.append(
            Control(
                identifier="CP-09",
                control_name="System Backup",
                description=(
                    "Conduct backups of user-level information and system-level information "
                    "contained in the system. Backups are stored offsite and protected from "
                    "unauthorized disclosure or modification."
                ),
                assessment_objective=(
                    "backups of system-level information are conducted; backups of "
                    "user-level information are conducted; backup information is protected "
                    "at storage locations"
                ),
                discussion=(
                    "System-level information includes system state, operating system "
                    "software, and other installed software. Backups of information system "
                    "documentation are also part of the contingency planning process."
                ),
            )
        )
        s.add_all(rows)
        await s.flush()
        await s.execute(text(_SEARCH_VECTOR_SQL))


async def test_score_line_ranks_the_right_control_in_top5_at_realistic_scale() -> None:
    """Ranking precision: against ~320 plausible competing controls, the
    obviously-correct control is still reachable within the candidate window
    Task 12's classifier is handed (``_MAX_CANDIDATES`` = 5)."""
    await _seed_realistic_scale_catalog()
    async with session_scope() as s:
        mfa = await score_line(
            s, content="All administrators must use multifactor authentication for network access."
        )
        backups = await score_line(
            s, content="The organization conducts nightly backups of system-level information."
        )
    assert "IA-02" in [identifier for identifier, _ in mfa], (
        f"IA-02 not reachable in top-5 candidates: {mfa}"
    )
    assert "CP-09" in [identifier for identifier, _ in backups], (
        f"CP-09 not reachable in top-5 candidates: {backups}"
    )


async def test_irrelevant_line_stays_below_threshold_at_realistic_scale() -> None:
    """Selectivity: a clearly irrelevant, boilerplate line must not clear the
    default (settings-derived) threshold even with ~320 competing controls
    sharing generic compliance vocabulary ("organization", "review",
    "documented", "annually") that could otherwise create incidental overlap."""
    await _seed_realistic_scale_catalog()
    threshold = get_settings().prep_screen_threshold
    async with session_scope() as s:
        ranked = await score_line(
            s, content="The quarterly newsletter will be distributed via email next Friday."
        )
    top_score = ranked[0][1] if ranked else 0.0
    assert top_score < threshold, (
        f"irrelevant line scored {top_score} >= threshold {threshold}: {ranked}"
    )
