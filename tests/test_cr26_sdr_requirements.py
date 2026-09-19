"""The FedRAMP-requirements merge: entirely authored narrative, no derived half.

``fedRampRequirements`` has no machine-readable ruleset to check an ``frrID``
against and no derived facts to refresh -- unlike ``keySecurityIndicators``,
every field here is something only a human can supply. So
``merge_requirements`` has no ``derived`` argument at all; it only decides
which authored entries are honest enough to keep, mirroring
``merge_indicators``' omit-and-name discipline.
"""

from __future__ import annotations

import json

from ccf.cr26.sdr import _implementation_status_enum, merge_requirements
from ccf.cr26.validation import schema_path


def test_frr_implementation_status_enum_agrees_with_the_shared_constant() -> None:
    """``merge_requirements`` reuses ``_implementation_status_enum`` rather
    than hand-typing a third copy of the enum, per the design instruction --
    this pins that the vendored schema's ``frrImplementationStatus`` enum
    really is the same three members the shared constant already reads for
    ``controlImplementationStatus`` and ``ksiImplementationStatus``, so
    reusing it is correct rather than coincidentally passing today."""
    path = schema_path("sdr")
    assert path is not None
    schema = json.loads(path.read_text(encoding="utf-8"))
    frr = schema["properties"]["fedRampRequirements"]["items"]["properties"][
        "frrImplementationStatus"
    ]["enum"]
    assert set(frr) == _implementation_status_enum()


def test_a_valid_authored_entry_survives_unchanged() -> None:
    authored = [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["We meet it."]}]
    merged, omitted = merge_requirements(authored)
    assert merged == authored
    assert omitted == []


def test_a_non_object_entry_is_omitted_by_locator() -> None:
    """An entry that is not even a dict has no ``frrID`` to report it by, so
    it is named by its position in the array."""
    merged, omitted = merge_requirements(["not a dict", {"frrID": "X", "frrImplementation": ["y"]}])
    assert [e["frrID"] for e in merged] == ["X"]
    assert omitted == [("fedRampRequirements[0]", "not an object")]


def test_a_blank_frr_id_is_omitted_by_locator() -> None:
    merged, omitted = merge_requirements(
        [{"frrID": "", "frrImplementation": ["We meet it."]}]
    )
    assert merged == []
    assert omitted == [("fedRampRequirements[0]", "no frrID")]


def test_a_whitespace_only_frr_id_is_omitted() -> None:
    """``frrID: "   "`` validates cleanly against the vendored schema -- a
    requirement that identifies nothing -- so it must not survive the merge
    just because the schema lets it through."""
    merged, omitted = merge_requirements(
        [{"frrID": "   ", "frrImplementation": ["We meet it."]}]
    )
    assert merged == []
    assert omitted == [("fedRampRequirements[0]", "no frrID")]


def test_a_missing_frr_id_is_omitted() -> None:
    merged, omitted = merge_requirements([{"frrImplementation": ["We meet it."]}])
    assert merged == []
    assert omitted == [("fedRampRequirements[0]", "no frrID")]


def test_a_non_string_frr_id_is_omitted() -> None:
    """``frrID`` is ``type: string``; a non-string value cannot be used as the
    id an operator would look the entry up by, so it is reported the same way
    a blank one is."""
    merged, omitted = merge_requirements(
        [{"frrID": 42, "frrImplementation": ["We meet it."]}]
    )
    assert merged == []
    assert omitted == [("fedRampRequirements[0]", "no frrID")]


def test_a_non_list_implementation_is_omitted_by_frr_id() -> None:
    """``frrImplementation`` is ``type: array`` -- a bare string would satisfy
    naive truthiness while violating the schema, the same shape
    ``_has_narrative`` guards for ``ksiImplementation``. This entry HAS a real
    ``frrID``, so it is reported by that id, not by locator."""
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": "We meet it."}]
    )
    assert merged == []
    assert omitted == [("SDR-CSO-FRR", "frrImplementation is not a list")]


def test_a_missing_implementation_is_treated_as_not_a_list() -> None:
    merged, omitted = merge_requirements([{"frrID": "SDR-CSO-FRR"}])
    assert merged == []
    assert omitted == [("SDR-CSO-FRR", "frrImplementation is not a list")]


def test_an_empty_implementation_array_is_omitted() -> None:
    """``frrImplementation: []`` validates cleanly -- "we address this" with
    no statement of how -- so it must not survive the merge."""
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": []}]
    )
    assert merged == []
    assert omitted == [("SDR-CSO-FRR", "no implementation statement")]


def test_only_blank_statements_are_omitted() -> None:
    """``["", "   "]`` validates cleanly -- statements that say nothing."""
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["", "   "]}]
    )
    assert merged == []
    assert omitted == [("SDR-CSO-FRR", "no implementation statement")]


def test_blank_statements_are_stripped_and_the_rest_kept() -> None:
    """A repair, not an omission: the entry survives with only its real
    statements."""
    merged, omitted = merge_requirements(
        [
            {
                "frrID": "SDR-CSO-FRR",
                "frrImplementation": ["", "We meet it.", "   ", "And this too."],
            }
        ]
    )
    assert omitted == []
    assert len(merged) == 1
    assert merged[0]["frrImplementation"] == ["We meet it.", "And this too."]


def test_a_non_string_statement_is_dropped_like_a_blank_one() -> None:
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["We meet it.", 42, None]}]
    )
    assert omitted == []
    assert merged[0]["frrImplementation"] == ["We meet it."]


def test_an_invalid_implementation_status_is_dropped_not_left_standing() -> None:
    """The self-heal ``merge_indicators`` applies to ``ksiImplementationStatus``,
    mirrored here: ``seed_sdr`` feeds a previously-seeded document's own
    ``fedRampRequirements`` back in as ``authored``, so an invalid value must
    not round-trip forever."""
    merged, omitted = merge_requirements(
        [
            {
                "frrID": "SDR-CSO-FRR",
                "frrImplementation": ["We meet it."],
                "frrImplementationStatus": "implemented",  # not a schema enum member
            }
        ]
    )
    assert omitted == []
    assert "frrImplementationStatus" not in merged[0]


def test_a_valid_implementation_status_survives() -> None:
    merged, omitted = merge_requirements(
        [
            {
                "frrID": "SDR-CSO-FRR",
                "frrImplementation": ["We meet it."],
                "frrImplementationStatus": "Partially Implemented",
            }
        ]
    )
    assert omitted == []
    assert merged[0]["frrImplementationStatus"] == "Partially Implemented"


def test_entries_are_ordered_by_frr_id() -> None:
    """Stable order, so re-seeding produces no spurious document diff. Input
    is given in reverse-sorted order so insertion order and sorted order
    disagree -- do not "tidy" this back into sorted input."""
    authored = [
        {"frrID": "SDR-CSO-IAM", "frrImplementation": ["b"]},
        {"frrID": "SDR-CSO-AUD", "frrImplementation": ["a"]},
    ]
    merged, _omitted = merge_requirements(authored)
    assert [e["frrID"] for e in merged] == ["SDR-CSO-AUD", "SDR-CSO-IAM"]


def test_every_reason_that_applies_is_reported_once_per_entry() -> None:
    """Multiple bad entries each get their own reason, in walk order before
    sorting is applied to the survivors."""
    merged, omitted = merge_requirements(
        [
            {"frrID": "", "frrImplementation": ["x"]},
            "not a dict",
            {"frrID": "GOOD", "frrImplementation": ["ok"]},
            {"frrID": "BAD-SHAPE", "frrImplementation": "not a list"},
        ]
    )
    assert [e["frrID"] for e in merged] == ["GOOD"]
    assert omitted == [
        ("fedRampRequirements[0]", "no frrID"),
        ("fedRampRequirements[1]", "not an object"),
        ("BAD-SHAPE", "frrImplementation is not a list"),
    ]


def test_a_merged_entry_does_not_alias_the_caller() -> None:
    """Mutating the returned document must not reach back into the caller's
    ``authored`` list -- the same guarantee ``merge_indicators`` gives via
    ``_copied``, here via ``copy.deepcopy``."""
    implementation = ["We meet it."]
    authored = [{"frrID": "SDR-CSO-FRR", "frrImplementation": implementation}]
    merged, _omitted = merge_requirements(authored)
    merged[0]["frrImplementation"].append("mutated")
    assert implementation == ["We meet it."]
    assert authored[0]["frrImplementation"] == ["We meet it."]


def test_an_empty_authored_list_produces_an_empty_result() -> None:
    merged, omitted = merge_requirements([])
    assert merged == []
    assert omitted == []


def test_extra_fields_survive_a_valid_entry_untouched() -> None:
    """``frrValidation`` and ``frrAssessment`` are optional array fields this
    module does not derive or constrain -- a merge that dropped them would be
    destroying authored content nobody asked it to touch."""
    authored = [
        {
            "frrID": "SDR-CSO-FRR",
            "frrImplementation": ["We meet it."],
            "frrValidation": ["Validated via scan."],
            "frrAssessment": ["Assessed by 3PAO."],
        }
    ]
    merged, omitted = merge_requirements(authored)
    assert omitted == []
    assert merged[0]["frrValidation"] == ["Validated via scan."]
    assert merged[0]["frrAssessment"] == ["Assessed by 3PAO."]
