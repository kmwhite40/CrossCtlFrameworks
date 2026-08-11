"""Objective extraction — reads ccf.controls sub-clause rows, materialises nothing."""

from __future__ import annotations

import pytest
from sqlalchemy import delete

from ccf.assessment.engine.objectives import (
    ObjectiveExtractionError,
    objective_sha256,
    objectives_for,
)
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


async def test_label_prefers_ap_acronym_then_falls_back_to_ordinal() -> None:
    async with session_scope() as s:
        objectives = await objectives_for(s, _SEQ)
    assert objectives[0].label == "ZQ-01a"
    assert objectives[1].label == "ZQ-01b"
    assert objectives[2].label == "ZQ-01c"


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


async def test_no_control_yields_a_mixed_label_set() -> None:
    """Every derived (ordinal) label must share the prefix of the

    ap_acronym-supplied label in the same group -- otherwise a catalog-supplied
    label like ``ZQ-01a`` sits next to a derived ``ZQ-1b``, a silent mismatch
    that only shows up later as objective rows disagreeing with the catalog's
    own labelling convention.
    """
    async with session_scope() as s:
        objectives = await objectives_for(s, "ZQ-1")
    catalog_supplied = [o for o in objectives if o.label == "ZQ-01a"]
    assert catalog_supplied, "fixture must include the ap_acronym-supplied row"
    prefix = catalog_supplied[0].label[:-1]
    assert all(o.label.startswith(prefix) for o in objectives)


async def test_a_control_with_no_sub_clauses_yields_none() -> None:
    async with session_scope() as s:
        assert await objectives_for(s, "ZQ-99-does-not-exist") == []


async def test_absurd_objective_count_raises_rather_than_fanning_out() -> None:
    """A grouping bug must fail loudly, not spawn hundreds of model calls."""
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == "ZQ-08"))
        for n in range(70):
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
    assert "70" in str(exc.value)
