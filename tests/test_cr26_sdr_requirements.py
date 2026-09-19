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

from ccf.cr26.sdr import _STATUS_ENUM_PATHS, _implementation_status_enum, merge_requirements
from ccf.cr26.validation import schema_path


def test_the_third_status_enum_path_targets_frr_implementation_status() -> None:
    """Reverting to two paths (dropping FRR's) leaves ``_implementation_status_enum``'s
    answer unchanged, because the drift guard only fires on DISAGREEMENT
    between paths -- it can raise, but it can never assert False when a path
    is simply missing. So the third path is pinned directly rather than
    through the constant's behaviour, which cannot detect its absence."""
    assert (
        "properties", "fedRampRequirements", "items", "properties",
        "frrImplementationStatus", "enum",
    ) in _STATUS_ENUM_PATHS


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


def test_a_non_string_statement_is_dropped_and_reported() -> None:
    """Unlike a blank statement, a non-string one (``42``, ``None``) is real
    authored content of a shape this function cannot render -- destroying it
    silently would be the same invisible-repair gap as the status drop
    below, so it is named."""
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["We meet it.", 42, None]}]
    )
    assert merged[0]["frrImplementation"] == ["We meet it."]
    assert omitted == [
        ("SDR-CSO-FRR", "frrImplementation entry dropped: not a string")
    ]


def test_a_kept_statement_is_not_stripped_of_surrounding_whitespace() -> None:
    """The schema says these fields 'May use Markdown' -- an authored indented
    code block must survive verbatim, not be silently reformatted into a
    plain paragraph. Only the BLANK-ness test strips; the stored value must
    not."""
    indented = "    def example():\n        pass"
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": [indented]}]
    )
    assert omitted == []
    assert merged[0]["frrImplementation"] == [indented]


def test_an_invalid_implementation_status_is_dropped_and_reported() -> None:
    """The self-heal ``merge_indicators`` applies to ``ksiImplementationStatus``,
    mirrored here: ``seed_sdr`` feeds a previously-seeded document's own
    ``fedRampRequirements`` back in as ``authored``, so an invalid value must
    not round-trip forever. Unlike ``merge_indicators`` (whose derived half is
    refreshed wholesale every seed, making silence defensible), this function
    has no derived half at all -- so the drop is a destructive repair on
    entirely authored content, and it is named."""
    merged, omitted = merge_requirements(
        [
            {
                "frrID": "SDR-CSO-FRR",
                "frrImplementation": ["We meet it."],
                "frrImplementationStatus": "implemented",  # not a schema enum member
            }
        ]
    )
    assert "frrImplementationStatus" not in merged[0]
    assert omitted == [
        ("SDR-CSO-FRR", "implementation status dropped: not a schema enum member")
    ]


def test_an_absent_implementation_status_is_not_reported() -> None:
    """Absence is not a repair: only a PRESENT, invalid value is dropped and
    named -- an entry that never claimed a status must not be flagged as if
    one had been silently erased."""
    merged, omitted = merge_requirements(
        [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["We meet it."]}]
    )
    assert "frrImplementationStatus" not in merged[0]
    assert omitted == []


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


def test_valid_optional_arrays_survive_a_valid_entry_untouched() -> None:
    """``frrValidation`` and ``frrAssessment`` are optional array fields this
    module does not derive -- a merge that dropped a schema-valid one would be
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


def test_a_schema_invalid_optional_array_is_repaired_and_reported() -> None:
    """Unlike ``frrID`` and ``frrImplementation``, ``frrValidation`` and
    ``frrAssessment`` are optional -- but ``PUT /cr26-documents/sdr`` takes an
    unvalidated ``dict[str, Any]``, so a stray edit (a bare string or ``null``
    instead of an array, or a non-string element inside one) must not
    round-trip through every future seed as an invalid document with no
    signal. ``merge_indicators`` applies exactly this discipline to every
    array field it carries; this closes the same gap here."""
    merged, omitted = merge_requirements(
        [
            {
                "frrID": "SDR-CSO-A",
                "frrImplementation": ["ok"],
                "frrValidation": "not a list",
            },
            {
                "frrID": "SDR-CSO-B",
                "frrImplementation": ["ok"],
                "frrValidation": None,
            },
            {
                "frrID": "SDR-CSO-C",
                "frrImplementation": ["ok"],
                "frrAssessment": [42],
            },
        ]
    )
    by_id = {e["frrID"]: e for e in merged}
    assert "frrValidation" not in by_id["SDR-CSO-A"]
    assert "frrValidation" not in by_id["SDR-CSO-B"]
    assert by_id["SDR-CSO-C"]["frrAssessment"] == []
    assert omitted == [
        ("SDR-CSO-A", "frrValidation dropped: not a list"),
        ("SDR-CSO-B", "frrValidation dropped: not a list"),
        ("SDR-CSO-C", "frrAssessment dropped: contains a non-string entry"),
    ]


def test_a_blank_entry_in_an_optional_array_is_dropped_silently() -> None:
    """Matching ``frrImplementation``'s asymmetry: a blank string inside an
    otherwise-valid optional array is dropped without a report -- nothing was
    lost, unlike a non-string element."""
    merged, omitted = merge_requirements(
        [
            {
                "frrID": "SDR-CSO-FRR",
                "frrImplementation": ["ok"],
                "frrValidation": ["Validated via scan.", "   "],
            }
        ]
    )
    assert omitted == []
    assert merged[0]["frrValidation"] == ["Validated via scan."]


def test_a_clean_optional_array_is_not_aliased_to_the_caller() -> None:
    """The deepcopy at the top of the walk is what protects an untouched
    optional array -- ``frrImplementation`` is always rebuilt fresh via its
    own comprehension regardless of copy depth, so it cannot tell a
    ``copy.deepcopy`` from a shallow ``dict(raw_entry)`` apart. An
    already-valid ``frrValidation`` IS left as the object the deep copy
    produced (see the docstring), so mutating it must not reach the caller's
    list -- a shallow copy would leave the two aliased and this would fail."""
    validation = ["We validated via scan."]
    authored = [
        {
            "frrID": "SDR-CSO-FRR",
            "frrImplementation": ["ok"],
            "frrValidation": validation,
        }
    ]
    merged, omitted = merge_requirements(authored)
    assert omitted == []
    merged[0]["frrValidation"].append("mutated")
    assert validation == ["We validated via scan."]
    assert authored[0]["frrValidation"] == ["We validated via scan."]


def test_frr_id_is_stored_stripped() -> None:
    """The id is stripped before it is used for anything, including storage
    -- an authored ``"  SDR-CSO-FRR  "`` must not ship with its whitespace, or
    a consumer that trims before matching would fail to find it and one that
    does not would group it separately from the trimmed form."""
    merged, omitted = merge_requirements(
        [{"frrID": "  SDR-CSO-FRR  ", "frrImplementation": ["We meet it."]}]
    )
    assert omitted == []
    assert merged[0]["frrID"] == "SDR-CSO-FRR"


def test_a_duplicate_frr_id_is_kept_not_discarded() -> None:
    """A duplicate ``frrID`` is not a duplicate KSI narrative: unlike an
    evicted authored entry, dropping either one here destroys human work,
    and unlike ``acceptedVulnerabilities``, nothing forces a choice between
    them on its own. Both survive, sorted adjacently."""
    authored = [
        {
            "frrID": "SDR-CSO-FRR",
            "frrImplementation": ["First statement."],
            "frrImplementationStatus": "Implemented",
        },
        {
            "frrID": "SDR-CSO-FRR",
            "frrImplementation": ["Second statement."],
            "frrImplementationStatus": "Not Implemented",
        },
    ]
    merged, omitted = merge_requirements(authored)
    assert [e["frrID"] for e in merged] == ["SDR-CSO-FRR", "SDR-CSO-FRR"]
    assert [e["frrImplementationStatus"] for e in merged] == [
        "Implemented",
        "Not Implemented",
    ]
    assert omitted == [("SDR-CSO-FRR", "duplicate authored entry kept")]


def test_inserting_a_last_wins_dedup_would_be_a_regression() -> None:
    """A last-wins dedup (evicting the first of a pair) is invertible with
    the rest of this module's suite green -- this is the pin that specifically
    catches it: BOTH entries, and their distinguishing content, must survive."""
    authored = [
        {"frrID": "SDR-CSO-DUP", "frrImplementation": ["Kept if not deduped."]},
        {"frrID": "SDR-CSO-DUP", "frrImplementation": ["Also kept."]},
    ]
    merged, _omitted = merge_requirements(authored)
    assert len(merged) == 2
    statements = [e["frrImplementation"][0] for e in merged]
    assert "Kept if not deduped." in statements
    assert "Also kept." in statements
