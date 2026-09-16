"""Objective extraction — reads ccf.controls sub-clause rows, materialises nothing."""

from __future__ import annotations

import pytest
from sqlalchemy import delete

from ccf.assessment.engine.objectives import (
    ObjectiveExtractionError,
    _ordinal_label,
    objective_sha256,
    objectives_for,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = "ZQ-01"


@pytest.fixture(autouse=True)
async def _catalog_rows():
    """Seed one addressable control plus three sub-clause objective rows.

    Mirrors the real workbook's shape: the parent row carries control_name and a
    bare "Determine if:" objective header; the sub-clause rows carry the actual
    objective text with control_name NULL, and ap_acronym is sparse.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
                control_name="Test Policy And Procedures",
                assessment_objective="Determine if:",
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                ap_acronym="ZQ-01a",
                assessment_objective="personnel to whom the policy is disseminated are defined;",
                source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2",
                sequence_control=_SEQ,
                assessment_objective="an official to manage the policy is defined;",
                source_row=3,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao3",
                sequence_control=_SEQ,
                assessment_objective="the review frequency is defined;",
                source_row=4,
            )
        )
    yield
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


async def test_returns_only_sub_clause_rows_in_catalog_order() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert [o.text for o in objectives] == [
        "personnel to whom the policy is disseminated are defined;",
        "an official to manage the policy is defined;",
        "the review frequency is defined;",
    ]
    assert [o.sort_order for o in objectives] == [0, 1, 2]


async def test_the_parent_control_row_is_not_an_objective() -> None:
    """The parent row's 'Determine if:' header is a heading, not an objective."""
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert all(not o.text.startswith("Determine if:") for o in objectives)


async def test_default_fixture_labels_are_each_rows_own_identifier() -> None:
    """Task 10: identifier now wins over both ap_acronym and the ordinal
    fallback.

    Before Task 10 this test was named
    ``test_label_prefers_ap_acronym_then_falls_back_to_ordinal`` and asserted
    ``objectives[0].label == "ZQ-01a"`` (from ``ap_acronym``, present only on
    the first sub-clause row), then ``"ZQ-01b"`` and ``"ZQ-01c"`` (both
    derived by ``_ordinal_label`` since the other two rows carry no
    ``ap_acronym``). ``identifier`` is populated on every row in this fixture
    -- as it is NOT NULL on every real catalog row -- so it is now the label
    on all three, and ``ap_acronym``/the ordinal derivation are never
    consulted even though the first row still carries an ``ap_acronym``.
    """
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert objectives[0].label == f"{_SEQ}-ao1"
    assert objectives[1].label == f"{_SEQ}-ao2"
    assert objectives[2].label == f"{_SEQ}-ao3"


async def test_text_hash_is_stable_and_detects_a_reword() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert objectives[0].text_sha256 == objective_sha256(objectives[0].text)
    assert objective_sha256("a") != objective_sha256("b")


async def test_padded_and_unpadded_identifiers_both_resolve() -> None:
    """The catalog mixes AC-02 and CP-9 forms; both must find the same objectives."""
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-07"))
        s.add(Control(identifier="ZQ-07", sequence_control="ZQ-07", control_name="Padded",
                      assessment_objective="Determine if:", source_row=1))
        s.add(Control(identifier="ZQ-07-ao1", sequence_control="ZQ-07",
                      assessment_objective="a padded-family objective;", source_row=2))
        await s.flush()
        by_padded = await objectives_for(s, "ZQ-07")
        by_unpadded = await objectives_for(s, "ZQ-7")
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-07"))
    assert len(by_padded) == 1
    assert [o.text for o in by_unpadded] == [o.text for o in by_padded]


async def test_labels_are_identical_regardless_of_caller_spelling() -> None:
    """Task 5's orchestration passes the canonical (unpadded) form; a legacy or

    manual caller might still spell the padded form. Both must derive the same
    labels -- the ordinal suffix must not depend on how the caller spelled the
    query.
    """
    async with session_scope() as s:
        padded = await objectives_for(s, "ZQ-01")
        unpadded = await objectives_for(s, "ZQ-1")
    assert [o.label for o in padded] == [o.label for o in unpadded]


async def test_ap_acronym_no_longer_surfaces_as_a_label_even_when_present() -> None:
    """Before Task 10 this test was named ``test_no_control_yields_a_mixed_label_set``
    and asserted every ordinal-derived label in a group shared the
    ap_acronym-supplied label's prefix -- guarding against a caller-spelling
    bug in the ordinal derivation (``_ordinal_label`` must use the row's own
    stored ``sequence_control``, not the caller's query spelling). identifier
    is now the label source on every row (it is NOT NULL), so no label in
    this fixture is ever ap_acronym- or ordinal-derived any more; the mixed
    ordinal/ap_acronym label set this test used to guard against cannot occur
    through any real Control row. What remains true, and worth asserting: the
    row carrying ``ap_acronym="ZQ-01a"`` does not surface it as a label, and
    every label in the group is still that row's own identifier.
    """
    async with session_scope() as s:
        objectives = await objectives_for(s, "ZQ-1")
    assert not any(o.label == "ZQ-01a" for o in objectives)
    assert [o.label for o in objectives] == [f"{_SEQ}-ao1", f"{_SEQ}-ao2", f"{_SEQ}-ao3"]


async def test_a_repeated_ap_acronym_within_a_group_produces_distinct_identifier_labels() -> None:
    """CRITICAL 3: confirmed live on AC-1, which carries two sub-clause rows
    both stamped ap_acronym "AC-01a" -- but with distinct identifiers
    ("AC-01_ODP[01]" and "AC-01a.[01]"; see
    tests/test_assessment_engine_real_catalog.py).

    Before Task 10, this test asserted ``objectives[0].label == "ZQ-11a"``
    (the shared ap_acronym) and ``objectives[1].label != "ZQ-11a"`` (the
    dedup fallback's ordinal derivation kicking in for the second row) --
    that was CRITICAL 3's actual fix: two rows sharing an ap_acronym would
    otherwise violate uq_objective_proposal_label the moment both were
    persisted as AssessmentObjectiveProposal rows for the same control
    proposal.

    Task 10 makes label selection prefer each row's own identifier, which is
    UNIQUE at the database level -- so two rows sharing an ap_acronym can no
    longer collide on label at all; there is nothing left for the dedup
    fallback to catch here. The fallback lower in objectives_for is retained
    as defense-in-depth regardless (uniqueness by construction is a property
    of the current schema, not a promise), but it is no longer reachable
    through this scenario, or through any real Control row: identifier is
    UNIQUE, so two rows can never insert with the same identifier in the
    first place, and label = row.identifier when identifier is present (which
    it always is).
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-11"))
        s.add(Control(identifier="ZQ-11", sequence_control="ZQ-11",
                      control_name="Dup Acronym", assessment_objective="Determine if:",
                      source_row=1))
        s.add(Control(identifier="ZQ-11-ao1", sequence_control="ZQ-11", ap_acronym="ZQ-11a",
                      assessment_objective="the first colliding objective is met;",
                      source_row=2))
        s.add(Control(identifier="ZQ-11-ao2", sequence_control="ZQ-11", ap_acronym="ZQ-11a",
                      assessment_objective="the second colliding objective is met;",
                      source_row=3))
        await s.flush()
        objectives = await objectives_for(s, "ZQ-11")
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-11"))

    assert len(objectives) == 2
    labels = [o.label for o in objectives]
    assert len(labels) == len(set(labels)), f"duplicate labels survived: {labels}"
    assert objectives[0].label == "ZQ-11-ao1"
    assert objectives[1].label == "ZQ-11-ao2"
    assert objectives[1].text == "the second colliding objective is met;"


def test_ordinal_label_derives_letter_suffixes_from_position() -> None:
    """``_ordinal_label`` itself, called directly rather than through
    ``objectives_for``.

    Task 10's brief requires ``_ordinal_label`` to "remain reachable and
    tested." But identifier is NOT NULL and UNIQUE on every Control row, and
    label selection now tries identifier first -- so no real Control row can
    ever reach this function through ``objectives_for`` (see this module's
    other Task-10-updated tests, and
    ``test_a_row_deduplicated_identifier_is_used_verbatim_as_the_label``'s
    docstring, which documents the same gap for the dedup fallback). Direct
    coverage keeps the function honestly tested rather than silently
    unreachable.
    """
    assert _ordinal_label("AC-02", 0) == "AC-02a"
    assert _ordinal_label("AC-02", 1) == "AC-02b"
    assert _ordinal_label("AC-02", 25) == "AC-02z"
    assert _ordinal_label("AC-02", 26) == "AC-02aa"
    assert _ordinal_label("AC-02", 27) == "AC-02ab"


async def test_a_control_with_no_sub_clauses_yields_none() -> None:
    async with session_scope() as s:
        assert await objectives_for(s, "ZQ-99-does-not-exist") == []


async def test_absurd_objective_count_raises_rather_than_fanning_out() -> None:
    """A grouping bug must fail loudly, not spawn hundreds of model calls.

    Seeds strictly more rows than the configured guard, whatever that guard
    currently is, rather than a hardcoded row count -- the guard was raised
    from 60 to 150 (see test_assessment_engine_models.py) precisely because
    real controls exceed small fixed counts, so this test must not pin one
    either.
    """
    limit = get_settings().assessment_engine_max_objectives_per_control
    row_count = limit + 5
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-08"))
        for n in range(row_count):
            s.add(
                Control(
                    identifier=f"ZQ-08-ao{n}",
                    sequence_control="ZQ-08",
                    assessment_objective=f"objective number {n};",
                    source_row=n + 1,
                )
            )
        await s.flush()
        with pytest.raises(ObjectiveExtractionError) as exc:
            await objectives_for(s, "ZQ-08")
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-08"))
    assert str(row_count) in str(exc.value)


@pytest.mark.asyncio
async def test_label_prefers_the_rows_own_identifier(clean_migrated_db) -> None:
    """The workbook's identifier IS the item path (AC-02a.[01]) and is UNIQUE,
    so it beats both the near-empty ap_acronym column (4 populated rows in
    5,435) and an ordinal derived from position."""
    try:
        async with session_scope() as s:
            s.add_all(
                [
                    Control(
                        identifier="ZZ-01a.[01]", sequence_control="ZZ-01",
                        control_name=None, assessment_objective="first objective",
                        source_row=1,
                    ),
                    Control(
                        identifier="ZZ-01b.", sequence_control="ZZ-01",
                        control_name=None, assessment_objective="second objective",
                        source_row=2,
                    ),
                ]
            )
        async with session_scope() as s:
            got = await objectives_for(s, "ZZ-01")
        assert [o.label for o in got] == ["ZZ-01a.[01]", "ZZ-01b."]
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.sequence_control == "ZZ-01"))


@pytest.mark.asyncio
async def test_identifier_wins_even_when_ap_acronym_is_also_populated(
    clean_migrated_db,
) -> None:
    """identifier must be tried BEFORE ap_acronym, not merely be present in the
    fallback chain: a row with both populated must still label from identifier.
    ``test_label_prefers_the_rows_own_identifier`` leaves ap_acronym unset on
    both rows, so it can't tell ``identifier or ap_acronym`` apart from
    ``ap_acronym or identifier`` -- this uses two different, both-truthy values."""
    try:
        async with session_scope() as s:
            s.add(
                Control(
                    identifier="ZZ-02a.[01]", sequence_control="ZZ-02",
                    ap_acronym="ZZ-02-WRONG", control_name=None,
                    assessment_objective="an objective", source_row=1,
                )
            )
        async with session_scope() as s:
            got = await objectives_for(s, "ZZ-02")
        assert [o.label for o in got] == ["ZZ-02a.[01]"]
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.sequence_control == "ZZ-02"))


@pytest.mark.asyncio
async def test_a_row_deduplicated_identifier_is_not_used_as_the_label(
    clean_migrated_db,
) -> None:
    """A "#rowN" identifier -- the loader's own de-duplication scheme (see
    ``ccf.etl.pipeline``, which renames a repeated workbook identifier to
    ``f"{identifier}#row{row_idx}"`` with ``row_idx`` the physical
    spreadsheet row number) must NOT be used verbatim as the objective
    label. That suffix is an ETL artifact, not part of the catalog's item-
    path vocabulary: it is unstable (inserting one row upstream shifts every
    later index) and, used as a label, would land an internal loader detail
    in a federal authorization artifact (SAR/SSP part labels).

    A row carrying that shape must fall through to ``ap_acronym`` (absent
    here) and then ``_ordinal_label``, exactly as if ``identifier`` were
    absent -- so this also confirms ``_ordinal_label`` is reachable through
    the database again, which the previous (buggy) behaviour prevented.

    A second row in the same control carries an ordinary, non-suffixed
    identifier and must still be labelled from it verbatim: the fallback
    only engages for the ``#rowN`` shape, and normal identifiers are not
    regressed by this change. (``test_label_prefers_the_rows_own_identifier``
    covers that behaviour on its own in more detail.)"""
    try:
        async with session_scope() as s:
            s.add_all(
                [
                    Control(
                        identifier="ZZ-02#row9", sequence_control="ZZ-02",
                        control_name=None, assessment_objective="first objective",
                        source_row=1,
                    ),
                    Control(
                        identifier="ZZ-02b.[01]", sequence_control="ZZ-02",
                        control_name=None, assessment_objective="second objective",
                        source_row=2,
                    ),
                ]
            )
        async with session_scope() as s:
            got = await objectives_for(s, "ZZ-02")
        assert got[0].label != "ZZ-02#row9"
        assert got[0].label == "ZZ-02a"
        assert got[1].label == "ZZ-02b.[01]"
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.sequence_control == "ZZ-02"))
