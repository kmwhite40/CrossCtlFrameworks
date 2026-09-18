"""securityControls: the SSP's content in CR26's shape.

Three of the four fields need a shape conversion rather than a copy -- the SDR
wants strings where the platform holds JSONB -- and the joins are the ones
ssp/nist80053_docx.py already uses, so the Word SSP and the JSON SDR cannot
disagree about the same control.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ccf.cr26.sdr import (
    _implementation_status_enum,
    latest_project_id,
    render_controls,
)
from ccf.cr26.validation import schema_path
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System


def _entry(**kw: object) -> SSPControlEntry:
    defaults: dict[str, object] = {
        "project_id": 1,
        "control_id": "AC-2",
        # ssp.constants.IMPLEMENTATION_STATUS_OPTIONS is title-cased, so this
        # is what the platform actually writes -- and it is an exact member of
        # the schema's enum. The lowercase "implemented" this fixture used to
        # carry is a value no column ever holds, and it disguised the fact
        # that the rendered status was failing enum validation (spec 1.2.1).
        "implementation_status": ["Implemented"],
        "part_narratives": [{"part": "a", "text": "We do the thing."}],
        "odp_values": {},
    }
    return SSPControlEntry(**{**defaults, **kw})  # type: ignore[arg-type]


def test_the_status_enum_is_read_from_the_vendored_schema_not_retyped() -> None:
    """The constant this module gates on must BE the schema's enum, not a
    hand-copy of it. A copy goes silently stale when a schema bump widens the
    enum -- the seeder would start omitting a status FedRAMP had just begun to
    accept -- and this spec has already produced four claim-versus-rendering
    defects without adding a fifth hiding place.

    Read independently here, straight off disk, so this fails if the module's
    lookup path drifts from where the value actually lives.
    """
    path = schema_path("sdr")
    assert path is not None
    schema = json.loads(path.read_text(encoding="utf-8"))
    from_schema = set(
        schema["properties"]["securityControls"]["items"]["properties"][
            "controlImplementationStatus"
        ]["enum"]
    )
    assert from_schema == {"Implemented", "Not Implemented", "Partially Implemented"}
    assert _implementation_status_enum() == from_schema


def test_both_schema_locations_of_the_status_enum_still_agree() -> None:
    """One derived constant serves both ``controlImplementationStatus`` (spec
    1.2.1) and ``ksiImplementationStatus`` (spec 1.3) because the vendored
    schema gives them the same three members. If a future vendoring splits
    them, one constant silently applied to both would be wrong for one of
    them -- so the module raises, and this is the test that says why."""
    path = schema_path("sdr")
    assert path is not None
    schema = json.loads(path.read_text(encoding="utf-8"))
    control = schema["properties"]["securityControls"]["items"]["properties"][
        "controlImplementationStatus"
    ]["enum"]
    ksi = schema["properties"]["keySecurityIndicators"]["items"]["properties"][
        "ksiImplementationStatus"
    ]["enum"]
    assert set(control) == set(ksi), (control, ksi)


def test_a_control_renders_every_field() -> None:
    out = render_controls([_entry()])
    assert out == [
        {
            "controlId": "AC-2",
            "controlImplementationStatus": "Implemented",
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


def test_several_statuses_omit_the_key_rather_than_joining() -> None:
    """Spec 1.2.1. ``controlImplementationStatus`` is enum-constrained
    (``Implemented`` / ``Not Implemented`` / ``Partially Implemented``), so a
    ``", ".join(...)`` of two values can NEVER be a member -- "planned,
    partial" is not a status, it is a sentence. nist80053_docx.py:173 joins
    them because it writes into a Word table cell where any string is fine.

    The key is optional, so omitting it validates; the narrative join is
    unaffected, which is what the second assertion pins.
    """
    out = render_controls(
        [_entry(implementation_status=["Implemented", "Partially Implemented"])]
    )
    assert "controlImplementationStatus" not in out[0], out[0]
    assert out[0]["controlImplementationDescription"] == "We do the thing."


def test_a_single_valid_status_is_still_emitted() -> None:
    """The other half of the same rule: omitting is not the answer to
    everything. ``Implemented`` and ``Partially Implemented`` are exact
    members of BOTH the platform's vocabulary
    (ssp.constants.IMPLEMENTATION_STATUS_OPTIONS) and the schema's enum, so
    genuine single-valued data must still reach the document."""
    out = render_controls([_entry(implementation_status=["Partially Implemented"])])
    assert out[0]["controlImplementationStatus"] == "Partially Implemented"


def test_a_platform_status_with_no_fedramp_equivalent_is_omitted_not_translated() -> None:
    """``Planned``, ``Alternative Implementation`` and ``Not Applicable`` are
    real members of the platform's vocabulary with no member of FedRAMP's to
    map to. Translating ``Planned`` to ``Not Implemented`` would tell a
    regulator something harsher than the provider said -- the same
    claim-versus-rendering defect as 1.3's, facing the other way."""
    for status in ("Planned", "Alternative Implementation", "Not Applicable"):
        out = render_controls([_entry(implementation_status=[status])])
        assert "controlImplementationStatus" not in out[0], (status, out[0])


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


def test_empty_columns_render_as_empty_except_the_enum_which_is_omitted() -> None:
    """The three unconstrained fields must be present even when the source is
    empty, so a caller never handles KeyError for them.

    ``controlImplementationStatus`` is the exception and spec 1.2.1 is why:
    it is enum-constrained, so ``""`` is not "empty", it is a value outside
    the enum that fails validation. The key is optional, so absence is the
    correct rendering of "nothing to say" -- exactly as it is for
    ``ksiImplementationStatus``.
    """
    out = render_controls(
        [_entry(implementation_status=[], part_narratives=[], odp_values={})]
    )
    assert out[0] == {
        "controlId": "AC-2",
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


async def test_a_tie_on_updated_at_is_broken_by_id_not_left_to_chance() -> None:
    """``ssp_project_id`` is the one value :class:`SdrSeedResult` exists to
    make VISIBLE, so it must not depend on whatever order Postgres happens to
    return. Two projects can share ``updated_at`` easily -- ``now()`` is
    transaction-scoped in Postgres, so two rows created in one transaction get
    the identical server default.

    The newer-by-id project is inserted SECOND, so ordering by ``updated_at``
    alone returns the other one in physical-scan order and this fails.
    """
    system_id = await _system("Tie")
    same_moment = datetime(2026, 6, 1, tzinfo=UTC)
    first_id = await _project(system_id, same_moment)
    second_id = await _project(system_id, same_moment)
    assert second_id > first_id

    async with session_scope() as s:
        assert await latest_project_id(s, system_id) == second_id
