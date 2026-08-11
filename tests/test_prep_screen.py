"""Catalog-driven relevance screening against ccf.controls."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import delete, select, text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, Organization
from ccf.models_prep import PrepLine, PrepScreen
from ccf.prep import pipeline
from ccf.prep.screen import normalize_control_identifier, run_stage_screen, score_line

pytestmark = pytest.mark.usefixtures("fresh_engine")


# --- control identifier normalization (Finding C1) -------------------------
#
# The real ingested catalog is not consistently formatted -- confirmed live
# against the test DB: "AC-01, AC-02, AC-99, AC.L2-3.1.1, AC.L2-3.1.2, CP-9"
# all coexist. These are plain unit tests (no DB needed) pinning down the
# normalization rule itself, ahead of the integration-level proof in
# test_prep_retriever.py that it actually reconnects a padded catalog
# identifier with an unpadded query.


def test_normalize_control_identifier_folds_zero_padding() -> None:
    assert normalize_control_identifier("AC-02") == "AC-2"
    assert normalize_control_identifier("AC-2") == "AC-2"


def test_normalize_control_identifier_leaves_already_unpadded_forms_alone() -> None:
    assert normalize_control_identifier("CP-9") == "CP-9"


def test_normalize_control_identifier_still_strips_an_enhancement_suffix() -> None:
    assert normalize_control_identifier("AC-6(2)") == "AC-6"
    assert normalize_control_identifier("AC-06(02)") == "AC-6"


def test_normalize_control_identifier_leaves_cmmc_style_identifiers_untouched() -> None:
    """CMMC-style identifiers have a dot before the hyphen and dotted segments
    after it -- they must round-trip unchanged, not be mistaken for a padded
    NIST-style family-number identifier."""
    assert normalize_control_identifier("AC.L2-3.1.1") == "AC.L2-3.1.1"
    assert normalize_control_identifier("AC.L2-3.1.2") == "AC.L2-3.1.2"


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


async def test_screen_stage_skips_a_pathologically_oversized_line_without_failing_the_run() -> None:
    """``score_line`` ORs every lexeme of a line into one ``to_tsquery``. A
    line dense enough with distinct lexemes reliably reproduces Postgres's
    real ``StatementTooComplexError`` ("stack depth limit exceeded") --
    confirmed directly against this test DB at ~30,000 distinct lexemes, well
    within reach of a minified JSON export, a newline-free CSV, or a base64
    blob, none of which anything upstream caps the length of. Before the fix,
    that error aborted the whole transaction: the whole stage failed, and
    every ``PrepScreen`` row already added earlier in this loop (for a
    multi-page document, screened line by line) would be lost with it. The
    fix isolates each line's own query in a savepoint, so this line gets zero
    candidates and the run keeps going.
    """
    org_id = await _seed_controls()
    pathological_content = " ".join(f"word{i}" for i in range(30_000))
    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="policy_version", source_id=1
        )
        run.stage_parse = "complete"
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=1,
                       content=pathological_content))
        s.add(PrepLine(run_id=run.id, organization_id=org_id, line_number=2,
                       content="Administrators must use multifactor authentication."))
        await s.flush()

        above = await run_stage_screen(s, run)

        assert run.stage_screen == "complete", "one bad line must not fail the whole stage"
        assert above == 1, "the second, well-formed line must still be screened normally"

        screens = (
            await s.execute(
                select(PrepScreen, PrepLine)
                .join(PrepLine, PrepLine.id == PrepScreen.line_id)
                .where(PrepScreen.run_id == run.id)
                .order_by(PrepLine.line_number)
            )
        ).all()
    assert len(screens) == 2, "the pathological line must be recorded, not silently dropped"
    pathological, normal = screens[0].PrepScreen, screens[1].PrepScreen
    assert pathological.candidate_controls == []
    assert pathological.above_threshold is False
    assert normal.above_threshold is True


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


#: Boilerplate phrasing that stands in for the real catalog's per-AO/per-ODP
#: fragment rows ("Determine if: ..."), which carry no ``control_name`` of
#: their own. Deliberately generic/procedural, like the real ones.
_FRAGMENT_PHRASES = [
    "Determine if: the {topic} is documented and reviewed by authorized personnel.",
    "Determine if: the organization defines the frequency for {topic}.",
    "Determine if: {topic} records are retained for the period defined by the organization.",
    "Determine if: personnel responsible for {topic} are identified and trained.",
]

#: Two fragment rows with no thematic connection to any named control, whose
#: vocabulary is chosen to overlap with the irrelevant test line below
#: ("quarterly newsletter ... distributed ... email ... staff"). This is not
#: implausible: unnamed AO/ODP fragments in the real catalog cover a very wide
#: range of procedural minutiae, and it only takes one incidental match in an
#: unfiltered candidate pool of thousands to push an irrelevant line's score
#: above a low, unbounded threshold — which is exactly the failure mode this
#: fixture needs to reproduce (see the module-level comment above).
_POISON_FRAGMENTS = [
    (
        "ZSF-POISON-01",
        "Determine if: a quarterly newsletter summarizing organizational "
        "activity is distributed to staff via email.",
    ),
    (
        "ZSF-POISON-02",
        "Determine if: distribution lists used to email staff newsletters "
        "and quarterly bulletins are reviewed and kept current.",
    ),
]

#: Unnamed "shadow" fragments for IA-02 and CP-09 specifically — paraphrases
#: of the base control's own assessment objective, close enough in vocabulary
#: to compete directly with IA-02/CP-09 on the same lexemes rather than being
#: pure noise (measured: they don't outscore the two named, richly-worded
#: rows here — that took the real catalog's scale and diversity, not eight
#: synthetic rows — but they are still exactly the shape of row the
#: ``control_name`` filter exists to remove, and they exercise the filter
#: having *something* topically relevant to filter out rather than only
#: unrelated poison).
_SHADOW_FRAGMENTS = [
    (
        "ZSF-IA02-01",
        "multifactor authentication is implemented for network access to privileged accounts",
    ),
    ("ZSF-IA02-02", "administrators use multifactor authentication for network access"),
    ("ZSF-IA02-03", "all network access requires multifactor authentication for administrators"),
    (
        "ZSF-IA02-04",
        "multifactor authentication for network access is enforced for privileged "
        "and non-privileged accounts",
    ),
    ("ZSF-CP09-01", "nightly backups of system-level information are written to offsite storage"),
    ("ZSF-CP09-02", "the organization conducts backups of system-level information nightly"),
    ("ZSF-CP09-03", "system-level information backups are conducted and stored offsite nightly"),
    ("ZSF-CP09-04", "backups of system-level information are conducted nightly and stored offsite"),
]

#: Named enhancement rows for IA-02 and CP-09.
#: ``(identifier, name_suffix, description, assessment_objective, discussion)``.
#:
#: IMPORTANT — what this fixture is and is not evidence of. These rows are
#: deliberately amplified: the target sentence's own phrase ("multifactor
#: authentication ... network access" / "nightly backups ... system-level
#: information") is repeated two or three times per row, including in
#: ``discussion`` — a field real catalog rows use for mechanism and parameter
#: explanation, not phrase restatement. That amplification is intentional and
#: necessary to reproduce, in a ten-row synthetic fixture, the *shape* of
#: Finding 2's enhancement-crowding bug (base control outscored by its own
#: enhancements, pushed out of the candidate window).
#:
#: It is NOT a claim that IA-02/CP-09 exhibit this crowding with genuine
#: catalog text. Checked directly: the real ``IA-02(01)``/``(02)``/``(06)``/
#: ``(08)``/``(12)`` and ``CP-09(01)``/``(02)``/``(05)``/``(06)``/``(08)``
#: rows, scored with the production ``setweight`` formula against these same
#: two sentences, all score *below* their base row (IA-02 base 5.5 vs.
#: enhancements 4.1/4.1/3.1/2.9/1.5; CP-09 base 9.0 vs. enhancements
#: 4.9/4.1/3.5/3.4/3.1) — no crowding occurs in these two families with real
#: text. The organically-occurring instances of this bug, verified separately
#: against the full real catalog, are AC-06 (fell to rank 27 behind its own
#: ten enhancements) and IR-06 (fell to rank 9) — see task-9-report.md.
#: IA-02/CP-09 were kept as the fixture's targets purely because they were
#: already the two richly-worded base rows this module builds elsewhere; the
#: crowding they exhibit here is manufactured, not observed.
_ENHANCEMENTS = [
    (
        "IA-02(01)",
        "Multifactor Authentication to Privileged Accounts",
        "Implement multifactor authentication for network access to privileged accounts. "
        "Administrators and other privileged users must use multifactor authentication "
        "for network access.",
        "multifactor authentication is implemented for network access to privileged "
        "accounts; administrators use multifactor authentication for network access",
        "Network access to privileged accounts requires multifactor authentication; "
        "administrators must use multifactor authentication before network access is "
        "granted.",
    ),
    (
        "IA-02(02)",
        "Multifactor Authentication to Non-privileged Accounts",
        "Implement multifactor authentication for network access to non-privileged "
        "accounts. All users, including administrators, must use multifactor "
        "authentication for network access.",
        "multifactor authentication is implemented for network access to non-privileged "
        "accounts; administrators use multifactor authentication for network access",
        "Network access to non-privileged accounts requires multifactor authentication; "
        "administrators must use multifactor authentication before network access is "
        "granted.",
    ),
    (
        "IA-02(06)",
        "Access to Accounts - Separate Device",
        "Implement multifactor authentication for network access using a device separate "
        "from the system gaining access. Administrators must use multifactor "
        "authentication for network access.",
        "multifactor authentication for network access is implemented using a separate "
        "device; administrators use multifactor authentication for network access",
        "Administrators must use multifactor authentication for network access via a "
        "device separate from the system.",
    ),
    (
        "IA-02(08)",
        "Access to Accounts - Replay Resistant",
        "Implement replay-resistant multifactor authentication mechanisms for network "
        "access. Administrators must use multifactor authentication for network access.",
        "replay-resistant multifactor authentication is implemented for network access; "
        "administrators use multifactor authentication for network access",
        "Administrators must use replay-resistant multifactor authentication for network "
        "access.",
    ),
    (
        "IA-02(12)",
        "Acceptance of PIV Credentials",
        "Accept and verify PIV credentials for multifactor authentication of network "
        "access. Administrators must use multifactor authentication for network access.",
        "multifactor authentication using PIV credentials is accepted for network access; "
        "administrators use multifactor authentication for network access",
        "Administrators must use multifactor authentication with PIV credentials for "
        "network access.",
    ),
    (
        "CP-09(01)",
        "Testing for Reliability and Integrity",
        "Test nightly backups of system-level information periodically for reliability "
        "and integrity. The organization conducts nightly backups of system-level "
        "information.",
        "nightly backups of system-level information are tested for reliability and "
        "integrity; the organization conducts nightly backups of system-level "
        "information",
        "Nightly backups of system-level information are conducted and tested for "
        "reliability.",
    ),
    (
        "CP-09(02)",
        "Test Restoration Using Sampling",
        "Test restoration of nightly backups of system-level information using a "
        "sample. The organization conducts nightly backups of system-level information.",
        "nightly backups of system-level information are conducted and restoration is "
        "tested; the organization conducts nightly backups of system-level information",
        "Nightly backups of system-level information are conducted and sample "
        "restorations are tested.",
    ),
    (
        "CP-09(05)",
        "Transfer to Alternate Storage Site",
        "Transfer nightly backups of system-level information to an alternate storage "
        "site. The organization conducts nightly backups of system-level information.",
        "nightly backups of system-level information are transferred to an alternate "
        "storage site; the organization conducts nightly backups of system-level "
        "information",
        "Nightly backups of system-level information are conducted and transferred "
        "offsite.",
    ),
    (
        "CP-09(06)",
        "Redundant Secondary System",
        "Conduct nightly backups of system-level information to a redundant secondary "
        "system. The organization conducts nightly backups of system-level information.",
        "nightly backups of system-level information are conducted to a redundant "
        "secondary system; the organization conducts nightly backups of system-level "
        "information",
        "Nightly backups of system-level information are conducted to a secondary "
        "system.",
    ),
    (
        "CP-09(08)",
        "Cryptographic Protection",
        "Protect nightly backups of system-level information using cryptographic "
        "mechanisms. The organization conducts nightly backups of system-level "
        "information.",
        "nightly backups of system-level information are cryptographically protected; "
        "the organization conducts nightly backups of system-level information",
        "Nightly backups of system-level information are conducted and cryptographically "
        "protected.",
    ),
]


async def _seed_realistic_scale_catalog() -> None:
    """Seed ~320 synthetic-but-plausible *named* controls, ~1,280 synthetic
    *unnamed* AO/ODP-style fragment rows (roughly the real catalog's ~4:1
    ratio of fragment rows to named base/enhancement controls), ten *named
    enhancement* rows (five each for IA-02 and CP-09), plus the two real,
    richly-worded named base targets (IA-02, CP-09) — all weighted exactly as
    the real ETL weights ``search_vector`` after every workbook ingest.

    The unnamed fragment rows matter for the ``control_name`` filter: a prior
    version of this fixture seeded only named rows, so the filter had nothing
    to remove and the selectivity test passed identically against the pre-fix
    query.

    The named enhancement rows matter for the base-control collapse
    separately: Finding 2's bug was never fragment dilution, it was a
    control's *own* named enhancements — filling every candidate slot and
    pushing the base identifier itself out — measured on the real catalog:
    AC-06 fell to rank 27, crowded out entirely by its own
    AC-06(01)/(02)/.../(10); IR-06 fell to rank 9. Unnamed fragments cannot
    reproduce that specific failure because they don't outscore a
    richly-worded base row; only enhancement-shaped rows can. The
    IA-02/CP-09 enhancement rows below reproduce that *shape* with
    deliberately amplified synthetic text — see the correction in the
    ``_ENHANCEMENTS`` comment for exactly what that does and does not claim
    about how real IA-02/CP-09 enhancements score.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.identifier.like("ZS%")))
        await s.execute(delete(Control).where(Control.identifier.like("IA-02(%")))
        await s.execute(delete(Control).where(Control.identifier.like("CP-09(%")))
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
                # ~4 unnamed AO/ODP-style fragments per named row, matching the
                # real catalog's rough 4:1 fragment-to-named-control ratio.
                for j, phrase in enumerate(_FRAGMENT_PHRASES, start=1):
                    rows.append(
                        Control(
                            identifier=f"ZSF-{family}-{i:02d}-{j:02d}",
                            control_name=None,
                            assessment_objective=phrase.format(topic=topic),
                        )
                    )
        for ident, phrase in _POISON_FRAGMENTS:
            rows.append(Control(identifier=ident, control_name=None, assessment_objective=phrase))
        for ident, phrase in _SHADOW_FRAGMENTS:
            rows.append(Control(identifier=ident, control_name=None, assessment_objective=phrase))
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
        for ident, name_suffix, description, objective, discussion in _ENHANCEMENTS:
            base = ident.split("(")[0]
            base_name = (
                "Identification and Authentication (Organizational Users)"
                if base == "IA-02"
                else "System Backup"
            )
            rows.append(
                Control(
                    identifier=ident,
                    control_name=f"{base_name} | {name_suffix}",
                    description=description,
                    assessment_objective=objective,
                    discussion=discussion,
                )
            )
        s.add_all(rows)
        await s.flush()
        await s.execute(text(_SEARCH_VECTOR_SQL))


@pytest.fixture
async def realistic_scale_catalog() -> AsyncIterator[None]:
    """Seed the ~1,600-row synthetic catalog and always remove it afterward —
    this fixture is the only thing in this module that writes more than a
    couple of rows, and nothing else in the shared ``ccf_test`` schema should
    have to account for a stray 'ZS%'-prefixed control left behind by a
    failed assertion or an interrupted run."""
    await _seed_realistic_scale_catalog()
    try:
        yield
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.identifier.like("ZS%")))
            await s.execute(delete(Control).where(Control.identifier.like("IA-02(%")))
            await s.execute(delete(Control).where(Control.identifier.like("CP-09(%")))
            await s.execute(delete(Control).where(Control.identifier.in_(["IA-02", "CP-09"])))


async def test_score_line_ranks_the_right_control_in_top5_at_realistic_scale(
    realistic_scale_catalog: None,
) -> None:
    """Ranking precision *and* the base-control collapse, together — the two
    properties Finding 2 actually requires:

    1. The base control (IA-02, CP-09) is reachable within the candidate
       window Task 12's classifier is handed (``_MAX_CANDIDATES`` = 5).
    2. No two candidates in that window come from the same base family.

    Five named enhancement rows per target (``IA-02(01)``, ``IA-02(02)``,
    ...; ``CP-09(01)``, ``CP-09(02)``, ...) restate each base control's own
    vocabulary in an 'A'-weighted ``control_name``, so pre-collapse they
    outscore the bare base identifier and fill the entire candidate window
    among themselves — reproducing the *shape* of Finding 2's bug (a control
    crowded out by its own enhancements). This is a manufactured fixture, not
    a claim that IA-02/CP-09 crowd out with real catalog text — they don't
    (checked directly; see the ``_ENHANCEMENTS`` comment). The organically
    occurring instances, measured on the real catalog, are AC-06 (crowded to
    rank 27 by its own ten enhancements) and IR-06 (rank 9). Property 2 is
    impossible to satisfy without the collapse regardless: with five
    same-family enhancements outscoring their own base row, a pre-collapse
    top-5 is, by construction, either all one family or missing the base
    control entirely.
    """
    async with session_scope() as s:
        mfa = await score_line(
            s, content="All administrators must use multifactor authentication for network access."
        )
        backups = await score_line(
            s, content="The organization conducts nightly backups of system-level information."
        )
    # Catalog rows are seeded padded ("IA-02", "CP-09" -- see module docstring
    # for why); score_line's return is normalized (Finding C1), so the
    # expected candidate is the canonical unpadded form.
    for label, ranked, expected_base in [("mfa", mfa, "IA-2"), ("backups", backups, "CP-9")]:
        candidates = [identifier for identifier, _ in ranked]
        assert expected_base in candidates, (
            f"{expected_base} not reachable in top-5 candidates ({label}): {ranked}"
        )
        families = [c.split("(")[0] for c in candidates]
        assert len(families) == len(set(families)), (
            f"two or more candidates share a base family ({label}), the base-control "
            f"collapse did not run: {ranked}"
        )


async def test_irrelevant_line_stays_below_threshold_at_realistic_scale(
    realistic_scale_catalog: None,
) -> None:
    """Selectivity: a clearly irrelevant, boilerplate line must not clear the
    default (settings-derived) threshold. Two of the ~1,280 unnamed fragment
    rows share heavy incidental vocabulary with this exact line ("quarterly",
    "newsletter", "distributed", "email", "staff") and would, on their own,
    have cleared the *old* unfiltered/unnormalized default (0.15) easily —
    that is the specific failure this test pins down: filtering to named
    controls removes them from consideration entirely, so the remaining ~320
    named rows (none of which mention any of that vocabulary) leave this line
    with nothing to match."""
    threshold = get_settings().prep_screen_threshold
    async with session_scope() as s:
        ranked = await score_line(
            s, content="The quarterly newsletter will be distributed via email next Friday."
        )
    top_score = ranked[0][1] if ranked else 0.0
    assert top_score < threshold, (
        f"irrelevant line scored {top_score} >= threshold {threshold}: {ranked}"
    )
