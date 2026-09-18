"""The KSI merge: authored narrative survives, derived facts refresh.

ksiImplementation is the one field the platform cannot derive. Everything else
is a fact about the system that changes as scans and reviews run, so it must be
refreshed on every seed -- and an indicator with no authored narrative is
omitted entirely rather than emitted with an empty array, which would satisfy
the schema while saying nothing.
"""

from __future__ import annotations

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
    silently deleted -- the merge must never destroy authored text.
    """
    authored = [{"ksiId": "KSI-GONE-99", "ksiImplementation": ["Still true."]}]
    merged, _omitted = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-GONE-99"]
    assert merged[0]["ksiImplementation"] == ["Still true."]


def test_entries_are_ordered_by_ksi_id() -> None:
    """Stable order, so re-seeding produces no spurious document diff."""
    authored = [
        {"ksiId": "KSI-CNA-02", "ksiImplementation": ["b"]},
        {"ksiId": "KSI-IAM-01", "ksiImplementation": ["a"]},
    ]
    merged, _ = merge_indicators(authored, _DERIVED)
    assert [e["ksiId"] for e in merged] == ["KSI-CNA-02", "KSI-IAM-01"]


def test_an_authored_entry_without_a_ksi_id_is_omitted_not_crashed() -> None:
    merged, omitted = merge_indicators(
        [{"ksiImplementation": ["orphaned"]}], _DERIVED
    )
    assert merged == []
    assert sorted(omitted) == ["KSI-CNA-02", "KSI-IAM-01"]
