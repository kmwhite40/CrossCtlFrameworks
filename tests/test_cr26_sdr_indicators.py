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

#: What ``seed_sdr``'s producer actually emits, in the shapes the vendored
#: schema actually accepts.
#:
#: This fixture used to carry ``ksiImplementationStatus: "implemented"`` and
#: ``evidenceType: "scan"``, neither of which is a valid enum member. They
#: were harmless here -- these are pure-function tests -- but the identical
#: mistake in ``tests/test_cr26_sdr_controls.py``'s fixture hid a real defect
#: through a full review (spec 1.2.1), so invalid values are not left lying
#: about in a fixture any more, whatever the excuse.
#:
#: ``KSI-CNA-02`` omits ``ksiImplementationStatus`` entirely, which is what
#: the producer emits for an indicator whose verdict is ``warn``,
#: ``not_tested``, ``manual_review_required`` or ``not_applicable`` -- spec
#: 1.3: only ``pass`` and ``fail`` map to a defensible claim.
_DERIVED = {
    "KSI-IAM-01": {
        "ksiImplementationStatus": "Implemented",
        "ksiValidation": ["passed 2026-09-17 (scan)"],
        "ksiAssessment": ["accepted by assessor@3pao.example"],
        "ksiTests": ["automated: mfa_registered"],
        "ksiEvidence": [
            {"evidenceDescription": "47 users", "lastUpdated": "2026-09-17"}
        ],
    },
    "KSI-CNA-02": {
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
            # Deliberately junk, like the "STALE" strings above: this is INPUT
            # being overwritten, not a shape anything is expected to produce.
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
    assert entry["ksiImplementationStatus"] == "Implemented"
    assert entry["ksiEvidence"] == [
        {"evidenceDescription": "47 users", "lastUpdated": "2026-09-17"}
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
    broken_derived = {"KSI-IAM-01": {"ksiImplementationStatus": "Implemented"}}
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


def test_nested_evidence_dicts_are_copied_not_aliased() -> None:
    """``ksiEvidence`` is the one derived field that is a list of dicts --
    exactly the shape Task 3 is most likely to post-process. A shallow
    ``list(...)`` copy alone breaks aliasing of the outer list but leaves the
    dicts inside it shared with the caller's derived mapping."""
    authored = [{"ksiId": "KSI-IAM-01", "ksiImplementation": ["x"]}]
    merged, _omitted = merge_indicators(authored, _DERIVED)
    merged_item = merged[0]["ksiEvidence"][0]
    derived_item = _DERIVED["KSI-IAM-01"]["ksiEvidence"][0]
    assert merged_item == derived_item
    assert merged_item is not derived_item


def test_a_carried_forward_authored_list_is_copied_not_aliased() -> None:
    """The fallback branch used to reuse the authored entry's own list
    object for a carried-forward field -- mutating the merged document would
    have mutated the caller's authored input underneath it."""
    validation = ["last scan 2026-03-01"]
    authored = [
        {
            "ksiId": "KSI-GONE-97",
            "ksiImplementation": ["Still true."],
            "ksiValidation": validation,
        }
    ]
    merged, _omitted = merge_indicators(authored, _DERIVED)
    assert merged[0]["ksiValidation"] == validation
    assert merged[0]["ksiValidation"] is not validation


def test_a_carried_forward_invalid_status_is_dropped() -> None:
    """``seed_sdr`` (Task 3) feeds a previously-seeded document's own
    ``keySecurityIndicators`` back in as ``authored`` -- so an invalid status
    an earlier defect wrote (or any other producer wrote) must not round-trip
    forever. Dropping it here is what lets the next document validate."""
    merged, _omitted = merge_indicators(
        [
            {
                "ksiId": "KSI-GONE-96",
                "ksiImplementation": ["x"],
                "ksiImplementationStatus": "",
            }
        ],
        _DERIVED,
    )
    assert "ksiImplementationStatus" not in merged[0]


def test_a_non_scalar_carried_forward_status_is_dropped_not_raised() -> None:
    """Live defect on ``main`` prior to this fix, verified reachable through
    ``PUT /cr26-documents/sdr`` (an unvalidated ``dict[str, Any]``):
    ``_implementation_status_enum()`` is a ``frozenset``, and
    membership-testing an unhashable authored value (a dict or a list) raised
    ``TypeError`` here instead of being recognised as invalid and dropped.
    Once such a value was stored, every future seed crashed instead of
    self-healing -- exactly the failure this drop exists to prevent."""
    for bad_status in ({}, []):
        merged, _omitted = merge_indicators(
            [
                {
                    "ksiId": "KSI-GONE-93",
                    "ksiImplementation": ["x"],
                    "ksiImplementationStatus": bad_status,
                }
            ],
            _DERIVED,
        )
        assert "ksiImplementationStatus" not in merged[0], bad_status


def test_a_carried_forward_valid_status_survives() -> None:
    """The other half of the same guard: a mistyped enum list must not
    silently discard a status that is actually valid."""
    merged, _omitted = merge_indicators(
        [
            {
                "ksiId": "KSI-GONE-95",
                "ksiImplementation": ["x"],
                "ksiImplementationStatus": "Partially Implemented",
            }
        ],
        _DERIVED,
    )
    assert merged[0]["ksiImplementationStatus"] == "Partially Implemented"


def test_a_derived_field_with_a_none_value_names_the_indicator() -> None:
    """A present-but-``None`` derived value is as much a broken contract as
    an absent key -- it would put a wrongly-typed value into a required
    ``type: array`` field, with no hint which producer wrote it."""
    broken_derived = {"KSI-IAM-01": {**_DERIVED["KSI-IAM-01"], "ksiValidation": None}}
    authored = [{"ksiId": "KSI-IAM-01", "ksiImplementation": ["x"]}]
    with pytest.raises(KeyError, match="KSI-IAM-01"):
        merge_indicators(authored, broken_derived)


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


def test_derived_facts_may_omit_the_optional_status_and_a_stale_one_is_dropped() -> None:
    """Spec 1.3: only ``pass`` and ``fail`` map to an implementation status, so
    the producer omits the key for the four ambiguous verdicts.

    The derived half is refreshed WHOLESALE, not patched -- so a status the
    authored entry carried from an earlier seed (here a perfectly valid enum
    member, which the self-healing guard would not touch) must be dropped
    rather than left asserting a claim the platform no longer makes. The four
    required array fields must still refresh in the same pass, which is what
    the last assertion pins.
    """
    derived = {
        "KSI-IAM-01": {
            k: v
            for k, v in _DERIVED["KSI-IAM-01"].items()
            if k != "ksiImplementationStatus"
        }
    }
    authored = [
        {
            "ksiId": "KSI-IAM-01",
            "ksiImplementation": ["x"],
            "ksiImplementationStatus": "Implemented",  # from an earlier seed
        }
    ]
    merged, _omitted = merge_indicators(authored, derived)
    assert "ksiImplementationStatus" not in merged[0], merged[0]
    assert merged[0]["ksiValidation"] == ["passed 2026-09-17 (scan)"]


def test_a_carried_forward_non_list_is_replaced_not_carried() -> None:
    """The array fields got a default but not a type check.

    ``seed_sdr`` feeds a previously-stored document's own entries back in as
    ``authored``, so an authored ``ksiValidation: null`` on a ksiId the catalog
    no longer knows would be carried forward verbatim into a field that is
    ``required`` and ``type: array`` -- and would round-trip through every
    future seed, exactly like the invalid enum value the guard below it exists
    for. The document could never validate again.
    """
    merged, _omitted = merge_indicators(
        [
            {
                "ksiId": "KSI-GONE-94",
                "ksiImplementation": ["x"],
                "ksiValidation": None,
                "ksiTests": "not a list either",
            }
        ],
        _DERIVED,
    )
    assert merged[0]["ksiValidation"] == []
    assert merged[0]["ksiTests"] == []
    # A genuine list is still carried, not blanked along with them.
    assert merged[0]["ksiImplementation"] == ["x"]
