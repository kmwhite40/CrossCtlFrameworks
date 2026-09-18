"""The KSI merge: authored narrative survives, derived facts refresh.

ksiImplementation is the one field the platform cannot derive. Everything else
is a fact about the system that changes as scans and reviews run, so it must be
refreshed on every seed -- and an indicator with no authored narrative is
omitted entirely rather than emitted with an empty array, which would satisfy
the schema while saying nothing.
"""

from __future__ import annotations

import pytest

from ccf.cr26.sdr import merge_indicators

_DERIVED = {
    "KSI-IAM-01": {
        "ksiImplementationStatus": "implemented",
        "ksiValidation": ["passed 2026-09-17 (scan)"],
        "ksiAssessment": ["accepted by assessor@3pao.example"],
        "ksiTests": ["automated: mfa_registered"],
        "ksiEvidence": [{"evidenceType": "scan", "evidenceDescription": "47 users"}],
    },
    "KSI-CNA-02": {
        "ksiImplementationStatus": "planned",
        "ksiValidation": [],
        "ksiAssessment": [],
        "ksiTests": [],
        "ksiEvidence": [],
    },
}


def test_an_indicator_with_no_authored_narrative_is_omitted() -> None:
    merged, omitted = merge_indicators([], _DERIVED)
    assert merged == []
    assert sorted(omitted) == ["KSI-CNA-02", "KSI-IAM-01"]


def test_an_authored_narrative_is_kept_and_the_derived_fields_refresh() -> None:
    """The central property. Both halves matter: asserting only that the
    narrative survives would pass against a seeder that ignores the database
    entirely and echoes the authored document back."""
    authored = [
        {
            "ksiId": "KSI-IAM-01",
            "ksiImplementation": ["We enforce MFA via Entra Conditional Access."],
            "ksiValidation": ["STALE -- from a previous seed"],
            "ksiTests": ["STALE"],
            "ksiEvidence": [],
            "ksiAssessment": [],
            "ksiImplementationStatus": "planned",
        }
    ]
    merged, omitted = merge_indicators(authored, _DERIVED)

    assert omitted == ["KSI-CNA-02"]
    assert len(merged) == 1
    entry = merged[0]
    assert entry["ksiImplementation"] == [
        "We enforce MFA via Entra Conditional Access."
    ]
    assert entry["ksiValidation"] == ["passed 2026-09-17 (scan)"]
    assert entry["ksiTests"] == ["automated: mfa_registered"]
    assert entry["ksiImplementationStatus"] == "implemented"
    assert entry["ksiEvidence"] == [
        {"evidenceType": "scan", "evidenceDescription": "47 users"}
    ]
    assert entry["ksiAssessment"] == ["accepted by assessor@3pao.example"]


def test_an_empty_authored_narrative_does_not_count() -> None:
    """``ksiImplementation: []`` satisfies the schema, which is exactly why it
    must not be treated as authored."""
    merged, omitted = merge_indicators(
        [{"ksiId": "KSI-IAM-01", "ksiImplementation": []}], _DERIVED
    )
    assert merged == []
    assert "KSI-IAM-01" in omitted


def test_an_authored_indicator_the_platform_no_longer_knows_is_kept() -> None:
    """A narrative is human work. If the KSI catalog drops an identifier, the
    entry stays with whatever derived fields it last had, rather than being
    silently deleted -- the merge must never destroy authored text, and must
    not blank the derived fields it can no longer refresh.
    """
    authored = [
        {
            "ksiId": "KSI-GONE-99",
            "ksiImplementation": ["Still true."],
            "ksiValidation": ["last scan 2026-03-01"],
            "ksiImplementationStatus": "Implemented",
        }
    ]
    merged, _omitted = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-GONE-99"]
    entry = merged[0]
    assert entry["ksiImplementation"] == ["Still true."]
    assert entry["ksiValidation"] == ["last scan 2026-03-01"]  # last carried, not blanked
    assert entry["ksiImplementationStatus"] == "Implemented"  # an authored value survives


def test_an_unrecognised_indicator_with_nothing_carried_gets_required_defaults() -> None:
    """``ksiImplementationStatus`` is optional and enum-constrained in the
    schema (``Implemented`` / ``Not Implemented`` / ``Partially
    Implemented``), unlike the four array fields, which are required and
    ``type: array``. Inventing ``""`` for it would produce a value outside the
    enum -- a document that fails validation -- so the key must be absent
    entirely rather than defaulted, while the four array fields still default
    to ``[]``.
    """
    bare, _omitted = merge_indicators(
        [{"ksiId": "KSI-GONE-98", "ksiImplementation": ["x"]}], _DERIVED
    )
    entry = bare[0]
    assert entry["ksiValidation"] == []
    assert entry["ksiAssessment"] == []
    assert entry["ksiTests"] == []
    assert entry["ksiEvidence"] == []
    assert "ksiImplementationStatus" not in entry


def test_a_real_narrative_survives_a_later_empty_duplicate() -> None:
    """``keySecurityIndicators`` carries no ``uniqueItems`` constraint, so
    duplicate ``ksiId``s are legal input. A later duplicate with no narrative
    must not evict an earlier real one -- that would both destroy human work
    and misreport it as never having existed (the id would land in
    ``omitted``)."""
    authored = [
        {"ksiId": "KSI-IAM-01", "ksiImplementation": ["REAL"]},
        {"ksiId": "KSI-IAM-01", "ksiImplementation": []},
    ]
    merged, omitted = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-IAM-01"]
    assert merged[0]["ksiImplementation"] == ["REAL"]
    assert omitted == ["KSI-CNA-02"]  # _DERIVED's other, unauthored indicator


def test_a_real_narrative_wins_over_an_earlier_empty_duplicate() -> None:
    """The opposite ordering must still work: a real narrative that arrives
    after an empty duplicate is not itself evicted by the guard above."""
    authored = [
        {"ksiId": "KSI-IAM-01", "ksiImplementation": []},
        {"ksiId": "KSI-IAM-01", "ksiImplementation": ["REAL"]},
    ]
    merged, omitted = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-IAM-01"]
    assert merged[0]["ksiImplementation"] == ["REAL"]
    assert omitted == ["KSI-CNA-02"]  # _DERIVED's other, unauthored indicator


def test_a_non_list_narrative_does_not_count() -> None:
    """``ksiImplementation`` is ``type: array`` -- a bare string is not a
    valid narrative even though it is truthy."""
    merged, omitted = merge_indicators(
        [{"ksiId": "KSI-IAM-01", "ksiImplementation": "We enforce MFA."}], _DERIVED
    )
    assert merged == []
    assert "KSI-IAM-01" in omitted


def test_a_narrative_of_only_blank_strings_does_not_count() -> None:
    """``[""]`` is schema-valid and says nothing about the implementation --
    the same invisible gap the omission rule exists to prevent, one level
    down."""
    merged, omitted = merge_indicators(
        [{"ksiId": "KSI-IAM-01", "ksiImplementation": ["", "   "]}], _DERIVED
    )
    assert merged == []
    assert "KSI-IAM-01" in omitted


def test_a_derived_mapping_missing_a_required_field_names_the_indicator() -> None:
    """A bare ``KeyError`` naming no KSI is a debugging trap in a catalog with
    hundreds of indicators; the failure must say which one is short a
    field."""
    broken_derived = {"KSI-IAM-01": {"ksiImplementationStatus": "implemented"}}
    authored = [{"ksiId": "KSI-IAM-01", "ksiImplementation": ["x"]}]
    with pytest.raises(KeyError, match="KSI-IAM-01"):
        merge_indicators(authored, broken_derived)


def test_derived_list_fields_are_copied_not_aliased() -> None:
    """Task 3 post-processes this result. If a merged entry shared list
    identity with the derived facts, mutating the document downstream would
    silently mutate the derived-facts cache underneath it."""
    authored = [{"ksiId": "KSI-IAM-01", "ksiImplementation": ["x"]}]
    merged, _omitted = merge_indicators(authored, _DERIVED)
    assert merged[0]["ksiEvidence"] == _DERIVED["KSI-IAM-01"]["ksiEvidence"]
    assert merged[0]["ksiEvidence"] is not _DERIVED["KSI-IAM-01"]["ksiEvidence"]


def test_entries_are_ordered_by_ksi_id() -> None:
    """Stable order, so re-seeding produces no spurious document diff.

    The authored input is deliberately given as IAM, CNA -- the REVERSE of
    sorted order -- so that insertion order and sorted order disagree. Do not
    "tidy" this back into sorted input: KSI-CNA-02 before KSI-IAM-01 would make
    insertion order and sorted order the same sequence again, and the
    assertion would pass whether or not the implementation actually sorts.
    """
    authored = [
        {"ksiId": "KSI-IAM-01", "ksiImplementation": ["a"]},
        {"ksiId": "KSI-CNA-02", "ksiImplementation": ["b"]},
    ]
    merged, _ = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-CNA-02", "KSI-IAM-01"]


def test_an_authored_entry_without_a_ksi_id_is_omitted_not_crashed() -> None:
    merged, omitted = merge_indicators(
        [{"ksiImplementation": ["orphaned"]}], _DERIVED
    )
    assert merged == []
    assert sorted(omitted) == ["KSI-CNA-02", "KSI-IAM-01"]
