"""securityControls: the SSP's content in CR26's shape.

Three of the four fields need a shape conversion rather than a copy -- the SDR
wants strings where the platform holds JSONB -- and the joins are the ones
ssp/nist80053_docx.py already uses, so the Word SSP and the JSON SDR cannot
disagree about the same control.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ccf.cr26.sdr import latest_project_id, render_controls
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System


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


# ``latest_project_id`` is a real DB query with two disagreeing precedents in
# the codebase -- oscal.py orders by ``id.desc()``, reports.py by
# ``updated_at.desc()`` -- so a sign flip or a dropped ``.where()`` would
# silently change which SSP a customer's SDR is seeded from. These need a
# session, unlike the eight above; the helper style follows
# tests/test_cr26_cpo_seed.py's ``_system``.


async def _system(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=f"{name} Org")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} System")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _project(system_id: int, updated_at: datetime) -> int:
    async with session_scope() as s:
        proj = SSPProject(system_id=system_id, customer_name="Acme", updated_at=updated_at)
        s.add(proj)
        await s.flush()
        return proj.id


async def test_the_more_recently_updated_project_wins() -> None:
    """Matching reports.py:184 -- not oscal.py:996's id.desc().

    The newer project is inserted first (so it gets the LOWER id) and the
    older one second (so it gets the HIGHER id). That arrangement is
    deliberate: an ``id.desc()`` mistake (oscal.py's ordering) would return
    the older project here, so this test fails under that mistake instead of
    passing it by insertion-order coincidence.
    """
    system_id = await _system("Recency")
    newer_id = await _project(system_id, datetime(2024, 6, 1, tzinfo=UTC))
    older_id = await _project(system_id, datetime(2023, 1, 1, tzinfo=UTC))
    assert older_id > newer_id  # pin the arrangement the docstring above relies on

    async with session_scope() as s:
        assert await latest_project_id(s, system_id) == newer_id


async def test_a_system_with_no_project_returns_none() -> None:
    system_id = await _system("Empty")
    async with session_scope() as s:
        assert await latest_project_id(s, system_id) is None


async def test_a_project_belonging_to_a_different_system_is_not_returned() -> None:
    """Pins the ``.where(SSPProject.system_id == system_id)`` clause: system
    B's project is the more recently updated one, so a dropped ``.where()``
    would return it instead of system A's."""
    system_a = await _system("A")
    system_b = await _system("B")
    a_id = await _project(system_a, datetime(2023, 1, 1, tzinfo=UTC))
    await _project(system_b, datetime(2024, 6, 1, tzinfo=UTC))

    async with session_scope() as s:
        assert await latest_project_id(s, system_a) == a_id
