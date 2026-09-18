"""securityControls: the SSP's content in CR26's shape.

Three of the four fields need a shape conversion rather than a copy -- the SDR
wants strings where the platform holds JSONB -- and the joins are the ones
ssp/nist80053_docx.py already uses, so the Word SSP and the JSON SDR cannot
disagree about the same control.
"""

from __future__ import annotations

from ccf.cr26.sdr import render_controls
from ccf.models import SSPControlEntry


def _entry(**kw: object) -> SSPControlEntry:
    defaults: dict[str, object] = {
        "project_id": 1,
        "control_id": "AC-2",
        "implementation_status": ["implemented"],
        "part_narratives": [{"part": "a", "text": "We do the thing."}],
        "odp_values": {},
    }
    return SSPControlEntry(**{**defaults, **kw})  # type: ignore[arg-type]


def test_a_control_renders_every_field() -> None:
    out = render_controls([_entry()])
    assert out == [
        {
            "controlId": "AC-2",
            "controlImplementationStatus": "implemented",
            "controlImplementationDescription": "We do the thing.",
            "parameterValues": [],
        }
    ]


def test_several_narrative_parts_join_with_a_space() -> None:
    """Matching nist80053_docx.py:170 -- not newline, not concatenation."""
    out = render_controls(
        [_entry(part_narratives=[{"text": "First."}, {"text": "Second."}])]
    )
    assert out[0]["controlImplementationDescription"] == "First. Second."


def test_several_statuses_join_with_a_comma() -> None:
    """Matching nist80053_docx.py:173."""
    out = render_controls([_entry(implementation_status=["planned", "partial"])])
    assert out[0]["controlImplementationStatus"] == "planned, partial"


def test_an_answered_parameter_is_rendered() -> None:
    out = render_controls([_entry(odp_values={"ac-2_prm_1": "30 days"})])
    assert out[0]["parameterValues"] == [
        {"parameterId": "ac-2_prm_1", "parameterValue": "30 days"}
    ]


def test_an_UNANSWERED_parameter_is_dropped_not_stringified() -> None:  # noqa: N802
    """ssp/nist80053.py:71 scaffolds odp_values as {param.id: None} for every
    parameter in the control, so an unanswered ODP is present with a None
    value. str(None) would emit "None" as the provider's chosen parameter --
    a document that validates and is wrong.
    """
    out = render_controls(
        [_entry(odp_values={"answered": "7", "unanswered": None})]
    )
    assert out[0]["parameterValues"] == [
        {"parameterId": "answered", "parameterValue": "7"}
    ]


def test_a_non_string_parameter_value_becomes_a_string() -> None:
    """parameterValue is type: string, so a number or bool must be coerced --
    but coercion must not resurrect None (see the test above)."""
    out = render_controls([_entry(odp_values={"count": 30, "flag": True})])
    values = {p["parameterId"]: p["parameterValue"] for p in out[0]["parameterValues"]}
    assert values == {"count": "30", "flag": "True"}


def test_empty_columns_render_as_empty_not_missing() -> None:
    """Every key must be present even when the source is empty -- a caller
    reading controlImplementationStatus must not have to handle KeyError."""
    out = render_controls(
        [_entry(implementation_status=[], part_narratives=[], odp_values={})]
    )
    assert out[0] == {
        "controlId": "AC-2",
        "controlImplementationStatus": "",
        "controlImplementationDescription": "",
        "parameterValues": [],
    }


def test_controls_keep_their_input_order() -> None:
    out = render_controls([_entry(control_id="AC-1"), _entry(control_id="AU-2")])
    assert [c["controlId"] for c in out] == ["AC-1", "AU-2"]
