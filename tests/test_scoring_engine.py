"""Unit tests for the SPRS scoring engine, parser, and SSP generator (no DB)."""

from __future__ import annotations

import io

from docx import Document

from ccf.scoring.engine import (
    MAX_SPRS_SCORE,
    SPRS_FLOOR,
    SSP_CONTROL_ID,
    credit_for,
    deduction_for,
    score_system,
)
from ccf.scoring.parser import load_seed, split_objectives
from ccf.ssp.generator import generate_ssp_docx


def test_deduction_weights() -> None:
    # Full miss subtracts the point value.
    assert deduction_for("5", "not_implemented") == 5
    assert deduction_for("3", "not_implemented") == 3
    assert deduction_for("1", "not_implemented") == 1
    # Met-like states never deduct.
    for state in ("implemented", "inherited", "not_applicable"):
        assert deduction_for("5", state) == 0
    # Partial credit only on the 3/5 rows; others lose the full value.
    assert deduction_for("3/5", "partial") == 3
    assert deduction_for("3/5", "not_implemented") == 5
    assert deduction_for("5", "partial") == 5
    # Special (SSP) carries no numeric weight.
    assert deduction_for("Special", "not_implemented") == 0


def test_seed_has_110_controls() -> None:
    seed = load_seed()
    assert len(seed) == 110
    assert {r["point_value"] for r in seed} <= {"1", "3", "3/5", "5", "Special"}
    assert all(r["control_id"] for r in seed)


def test_split_objectives_parts() -> None:
    parts = split_objectives("[a] foo is identified;\n[b] bar is controlled.")
    assert [p["label"] for p in parts] == ["a", "b"]
    assert parts[0]["text"] == "foo is identified"
    # No markers → a single unlabeled part.
    assert split_objectives("plain text")[0]["label"] == ""


def test_score_system_extremes_and_floor() -> None:
    seed = load_seed()
    # Everything implemented → perfect 110.
    perfect = score_system(seed, {r["control_id"]: "implemented" for r in seed})
    assert perfect.score == MAX_SPRS_SCORE
    assert perfect.met_controls == 110
    # Nothing assessed → maximum deduction, clamped at the SPRS floor.
    worst = score_system(seed, {})
    assert worst.score == SPRS_FLOOR
    assert worst.deductions_total == 313
    assert worst.ssp_present is False


def test_score_recomputes_per_control() -> None:
    seed = load_seed()
    states = {r["control_id"]: "implemented" for r in seed}
    five = next(r["control_id"] for r in seed if r["point_value"] == "5")
    states[five] = "not_implemented"
    summary = score_system(seed, states)
    assert summary.score == MAX_SPRS_SCORE - 5
    assert summary.by_domain  # populated breakdown


def test_generate_ssp_docx_roundtrips() -> None:
    project = {"customer_name": "Acme", "system_name": "Enclave", "version": "0.1"}
    entries = [
        {
            "control_id": "AC.L2-3.1.1",
            "nist_id": "3.1.1",
            "domain": "AC",
            "title": "Authorized Access Control",
            "responsible_role": "Access Control Lead",
            "implementation_status": ["Implemented"],
            "control_origination": ["Shared"],
            "part_narratives": [{"label": "a", "text": "users are identified."}],
        }
    ]
    data = generate_ssp_docx(project, entries)
    doc = Document(io.BytesIO(data))
    para_text = "\n".join(p.text for p in doc.paragraphs)
    assert "System Security Plan" in para_text
    cell_text = "\n".join(c.text for t in doc.tables for row in t.rows for c in row.cells)
    assert "AC.L2-3.1.1" in cell_text
    assert "users are identified" in cell_text


# ---------------------------------------------------------------------------
# Provenance: which of a score's points nobody assessed
# ---------------------------------------------------------------------------


def test_credit_for_is_what_a_state_keeps_relative_to_not_assessed() -> None:
    # The honest measure of a state's worth: what an unassessed practice
    # would have cost, minus what this one costs.
    assert credit_for("5", "implemented") == 5
    assert credit_for("3", "inherited") == 3
    assert credit_for("1", "not_applicable") == 1
    # Partial credit exists only on the three 3/5 requirements, so a partial
    # on any other row keeps nothing at all.
    assert credit_for("3/5", "partial") == 2
    assert credit_for("5", "partial") == 0
    assert credit_for("3", "not_implemented") == 0
    assert credit_for("Special", "implemented") == 0


def test_derived_states_are_reported_without_changing_the_score() -> None:
    """SPRS is self-attested, so the math must not move; the reader must know.

    A derivation credits practices from an intake answer and a vendor placemat.
    Those points count -- and a view that cannot tell them from assessed ones
    shows a questionnaire's output as an assessment.
    """
    seed = load_seed()
    states = {r["control_id"]: "implemented" for r in seed}
    derived_ids = {r["control_id"] for r in seed[:5]}
    sources = {cid: "derived" for cid in derived_ids}

    assessed_only = score_system(seed, states)
    mixed = score_system(seed, states, sources=sources)

    assert mixed.score == assessed_only.score == MAX_SPRS_SCORE
    assert mixed.derived_controls == 5
    assert mixed.assessed_controls == 105
    assert assessed_only.derived_controls == 0
    assert assessed_only.assessed_controls == 110
    # The credited points are exactly those five rows' point values.
    expected = sum(
        credit_for(r["point_value"], "implemented")
        for r in seed
        if r["control_id"] in derived_ids
    )
    assert mixed.derived_credit == expected
    assert assessed_only.derived_credit == 0


def test_an_unrecognised_or_absent_source_counts_as_assessed() -> None:
    """Never overstate the derived share -- that would be its own false claim."""
    seed = load_seed()[:3]
    states = {r["control_id"]: "implemented" for r in seed}
    for value in ("", "platform", "DERIVED", "unknown"):
        s = score_system(seed, states, sources={r["control_id"]: value for r in seed})
        assert s.derived_controls == 0, value
        assert s.derived_credit == 0, value
        assert s.assessed_controls == 3, value


def test_a_control_nobody_recorded_is_neither_assessed_nor_derived() -> None:
    """With no state there is no decision to attribute to anyone."""
    seed = load_seed()[:4]
    s = score_system(seed, {}, sources={r["control_id"]: "derived" for r in seed})
    assert s.derived_controls == 0
    assert s.assessed_controls == 0
    assert s.state_counts["not_assessed"] == 4


def test_a_derived_ssp_prerequisite_is_not_reported_as_satisfied_outright() -> None:
    """CA.L2-3.12.4 is the one prerequisite an assessment cannot proceed without.

    The m365 placemat marks it "Shared Coverage", which the derivation turns
    into ``partial`` -- and ``ssp_present`` reads ``partial`` as present. So
    answering "Microsoft 365 GCC High" on the intake form asserted that an SSP
    exists. The assertion still stands (it is the customer's claim to make),
    but the source is now on the record beside it.
    """
    seed = load_seed()
    states = {SSP_CONTROL_ID: "partial"}

    derived = score_system(seed, states, sources={SSP_CONTROL_ID: "derived"})
    assert derived.ssp_present is True
    assert derived.ssp_present_source == "derived"

    assessed = score_system(seed, states)
    assert assessed.ssp_present is True
    assert assessed.ssp_present_source == "assessed"

    # An absent SSP is not a claim anyone relies on, so it carries no source --
    # "no SSP" must not render as "an SSP asserted by a placemat".
    missing = score_system(seed, {}, sources={SSP_CONTROL_ID: "derived"})
    assert missing.ssp_present is False
    assert missing.ssp_present_source is None


def test_the_summary_dict_carries_provenance_to_its_consumers() -> None:
    """`as_dict` is what the API, the analytics and the templates actually read."""
    seed = load_seed()
    d = score_system(
        seed,
        {r["control_id"]: "inherited" for r in seed},
        sources={seed[0]["control_id"]: "derived"},
    ).as_dict()
    for key in ("derived_credit", "derived_controls", "assessed_controls", "ssp_present_source"):
        assert key in d, key
    assert d["derived_controls"] == 1
