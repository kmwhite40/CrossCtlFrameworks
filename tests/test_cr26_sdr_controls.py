"""securityControls: the SSP's content in CR26's shape.

Three of the four fields need a shape conversion rather than a copy -- the SDR
wants strings where the platform holds JSONB -- and the joins are the ones
ssp/nist80053_docx.py already uses, so the Word SSP and the JSON SDR cannot
disagree about the same control.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ccf.cr26 import sdr as sdr_module
from ccf.cr26.sdr import (
    _control_gaps,
    _implementation_status_enum,
    latest_project_id,
    render_controls,
)
from ccf.cr26.validation import schema_path
from ccf.db import session_scope
from ccf.models import Organization, SSPControlEntry, SSPProject, System
from ccf.ssp.completeness import is_draft_or_placeholder


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


def test_an_entry_with_nothing_in_it_renders_only_what_is_true() -> None:
    """This test used to assert ``controlImplementationDescription: ""``, on
    the grounds that "every key must be present so a caller never handles
    KeyError". Spec 1.2.2 reverses that: ``required`` is absent from
    ``securityControls.items``, so every property there is optional, and
    ``""`` does not mean "no description" -- it asserts to FedRAMP that the
    provider's description of this control IS blank. Convenience for our
    callers is not worth a false statement in a federal deliverable, and it is
    the same defect this module already refuses for the two status enums.

    ``parameterValues: []`` stays, and the difference is the point: an empty
    list of *answered* parameters is a true statement about a control nobody
    has filled in. An empty description is not.
    """
    out = render_controls(
        [_entry(implementation_status=[], part_narratives=[], odp_values={})]
    )
    assert out[0] == {"controlId": "AC-2", "parameterValues": []}


def test_a_draft_scaffolded_narrative_is_dropped_not_shipped() -> None:
    """The exact text ssp/nist80053.py:83-91 writes into EVERY control of
    EVERY new 800-53 project, with ``draft: True`` beside it.

    A scaffolded-but-unwritten SSP is the state of every new project and the
    state an operator is most likely to press "seed" in. Rendering this would
    tell FedRAMP that the provider's implementation description is an
    instruction to write one -- and spec 1.2.1 omits the scaffolded ``Planned``
    status, so nothing else in the document would have signalled it.
    """
    out = render_controls(
        [
            _entry(
                implementation_status=["Planned"],
                part_narratives=[
                    {
                        "label": "",
                        "text": (
                            "[DRAFT] AC control AC-2 is the responsibility of "
                            "System Owner. Describe the implementation."
                        ),
                        "draft": True,
                    }
                ],
            )
        ]
    )
    assert out[0] == {"controlId": "AC-2", "parameterValues": []}


def test_the_draft_marker_is_caught_even_without_the_draft_flag() -> None:
    """Both gates are load-bearing. ``draft: True`` is nist80053.py's flag;
    the text predicate catches the same marker from a producer that sets no
    flag, and dropping either check alone lets one of the two through."""
    out = render_controls(
        [_entry(part_narratives=[{"text": "[DRAFT] Describe the implementation."}])]
    )
    assert "controlImplementationDescription" not in out[0], out[0]


def test_an_unresolved_odp_placeholder_is_dropped() -> None:
    """ssp/statements.py:65 and ssp/platforms.py:145-161 leave
    ``[ORGANIZATION-DEFINED: ...]``, and ssp/odp.py leaves ``[Assignment: ...]``
    / ``[Selection ...]``, in narrative text with no ``draft`` flag at all.
    ssp/completeness.py already refuses to count these as written."""
    for placeholder in (
        "Key custody is [ORGANIZATION-DEFINED: FIPS 140-2 certificate number].",
        "Accounts are reviewed [Assignment: organization-defined frequency].",
        "The system enforces [Selection (one or more): a; b].",
    ):
        out = render_controls([_entry(part_narratives=[{"text": placeholder}])])
        assert "controlImplementationDescription" not in out[0], (placeholder, out[0])


def test_written_parts_survive_while_scaffolded_ones_beside_them_are_dropped() -> None:
    """The other half: dropping must be surgical, not a blanket refusal of any
    entry that contains one draft part. A human who has written part (a) and
    left the generated part (b) alone keeps (a).

    And the loss must be REPORTED. A control that keeps a truncated
    description still carries a status and reads complete, so it is the drop
    most easily missed -- ``controls_missing_description`` fires only when the
    key vanishes entirely and would say nothing here.
    """
    entries = [
        _entry(
            part_narratives=[
                {"part": "a", "text": "We manage accounts in Entra ID."},
                {"part": "b", "text": "[DRAFT] Describe the implementation.",
                 "draft": True},
            ]
        )
    ]
    out = render_controls(entries)
    assert out[0]["controlImplementationDescription"] == (
        "We manage accounts in Entra ID."
    )
    missing, dropped = _control_gaps(entries)
    assert missing == []
    assert dropped == ["AC-2"]


def test_a_composed_paragraph_losing_its_frequency_clause_is_reported() -> None:
    """The realistic shape, not a contrived one. ``ssp/statements.py:88-90``
    appends ``" Frequency: {frequency}."`` -- with ``_resolved_frequency``'s
    placeholder when unset -- to the END of an otherwise-complete composed
    paragraph, so three sentences of real provider content are dropped whole
    for one trailing token.

    Keeping the placeholder is not the fix: the surviving text is defensible
    content, and the SDR is a seed a human completes, so the result object is
    the remediation channel. What is NOT acceptable is losing it silently.
    """
    entries = [
        _entry(
            implementation_status=["Implemented"],
            part_narratives=[
                {
                    "part": "a",
                    "text": (
                        "The system uses Microsoft Entra ID for account lifecycle. "
                        "Accounts are provisioned on hire and disabled automatically "
                        "on separation. Frequency: [ORGANIZATION-DEFINED: frequency]."
                    ),
                },
                {"part": "b", "text": "Privileged accounts require PIM approval and MFA."},
            ],
        )
    ]
    out = render_controls(entries)
    assert out[0]["controlImplementationDescription"] == (
        "Privileged accounts require PIM approval and MFA."
    )
    assert out[0]["controlImplementationStatus"] == "Implemented"
    missing, dropped = _control_gaps(entries)
    assert missing == []  # it kept a description -- which is exactly the trap
    assert dropped == ["AC-2"]


def test_a_control_that_loses_everything_appears_in_both_lists() -> None:
    """The two lists deliberately overlap, so an operator reading either one
    gets a complete answer to the question that list asks."""
    entries = [_entry(part_narratives=[{"text": "[DRAFT] Describe it.", "draft": True}])]
    missing, dropped = _control_gaps(entries)
    assert missing == ["AC-2"]
    assert dropped == ["AC-2"]


def test_a_control_that_never_had_a_narrative_is_missing_but_lost_nothing() -> None:
    """The complement, which is what keeps the two lists from collapsing into
    one: nothing was dropped here, so the operator is not sent looking for
    content that never existed."""
    entries = [_entry(part_narratives=[])]
    missing, dropped = _control_gaps(entries)
    assert missing == ["AC-2"]
    assert dropped == []


def test_a_draft_flagged_part_is_dropped_even_without_the_marker_in_its_text() -> None:
    """The mirror of ``test_the_draft_marker_is_caught_even_without_the_draft_flag``,
    and without it the ``draft`` gate could be deleted with the suite green:
    every other fixture that sets the flag ALSO carries ``[DRAFT]`` in its
    text, so the predicate alone caught them and the flag gate was dead weight.

    A scaffolder that sets the flag without writing the marker into the prose
    is exactly what this gate is for.
    """
    out = render_controls(
        [_entry(part_narratives=[{"text": "Accounts are managed in Entra ID.", "draft": True}])]
    )
    assert "controlImplementationDescription" not in out[0], out[0]


def test_blank_parts_never_come_back_as_a_space() -> None:
    """``" ".join(["", ""])`` is ``" "`` -- truthy, and the ``""`` this rule
    exists to eliminate wearing one character of disguise.

    Reachable: ``ssp/seed.py`` writes one part per objective part (multi-part
    is the CMMC norm) and ``api/routes/ui.py`` re-saves each with ``str(...)``
    and no strip, so a cleared textarea persists as ``""``. ``_has_narrative``
    already applies exactly this rule to KSI narratives one level down.
    """
    for narratives in (
        [{"text": ""}, {"text": ""}],
        [{"text": None}, {"text": None}],
        [{"text": " "}],
        [{"text": "\t\n"}],
        # Whitespace-only AND multiple -- the shape this test's own docstring
        # describes, and the only one that needs the blank test to run on the
        # STRIPPED value. A single whitespace part is rescued by ``or None``
        # (``" ".join([""])`` is ``""``), and empty strings are falsy raw too,
        # so neither shape alone can tell ``if not text:`` from
        # ``if not value:`` -- and that mutation puts ``" "`` back in a shipped
        # description with an ``Implemented`` status and nothing in either gap
        # list.
        [{"text": " "}, {"text": " "}],
        [{"text": "\t"}, {"text": "\n"}],
    ):
        entries = [_entry(part_narratives=narratives)]
        out = render_controls(entries)
        assert "controlImplementationDescription" not in out[0], (narratives, out[0])
        # A blank part is NOT a drop. Setting ``dropped`` here would name a
        # never-written control as having LOST parts -- a false statement in
        # the one channel that exists to be truthful. A comment saying a thing
        # deliberately does not happen is as much a claim as a guard, so it
        # gets an assertion: the rule can be INVERTED green otherwise, which
        # no delete-the-guard mutation would catch.
        assert _control_gaps(entries) == (["AC-2"], []), narratives
    # A blank part beside a written one must not add a stray separator, and
    # must not be reported as a loss either.
    entries = [_entry(part_narratives=[{"text": "  Written.  "}, {"text": ""}])]
    out = render_controls(entries)
    assert out[0]["controlImplementationDescription"] == "Written."
    assert _control_gaps(entries) == ([], [])


def test_the_draft_marker_survives_the_strip_that_kills_the_space_defect() -> None:
    """``constants.DRAFT_PREFIX`` is ``"[DRAFT] "`` -- WITH the trailing space
    -- and ``is_draft_or_placeholder`` tests it as a plain substring. So
    stripping the text before handing it to the predicate destroys the token
    whenever the marker ends the string, and the control ships ``"[DRAFT]"``
    as its description, keeps its status, and lands in NEITHER gap list:
    strictly worse than the defect the strip was added to fix, which at least
    reached ``controls_missing_description``.

    The predicate gets the raw text; the strip is for the blank test and the
    join only.

    Reachability is human editing, not scaffolding: ``api/routes/ui.py``'s
    ``ssp_save_entry`` rebuilds every part as ``{"label", "text"}`` and drops
    the ``draft`` key on every save, so for any control ever touched in that
    editor the flag gate is inert and the predicate is the only gate left --
    which is the design ``ssp/statements.py`` documents, the marker in the
    stored text being the only durable record.
    """
    for text in ("[DRAFT] ", "Accounts are managed. [DRAFT] "):
        entries = [_entry(part_narratives=[{"text": text}])]  # no draft flag
        out = render_controls(entries)
        assert "controlImplementationDescription" not in out[0], (text, out[0])
        assert _control_gaps(entries) == (["AC-2"], ["AC-2"]), text


def test_a_bare_draft_part_is_dropped_at_the_per_part_check_now() -> None:
    """Formerly ``test_the_join_cannot_manufacture_the_marker_the_parts_slipped``.

    Under the old, space-including ``DRAFT_PREFIX`` substring test, a bare
    ``"[DRAFT]"`` part slipped the per-part predicate -- and then the ``" "``
    join separator supplied the missing space, manufacturing a literal
    ``"[DRAFT] "`` in the composed string, which a *second* predicate call on
    the joined text caught, dropping the whole description even though real
    content ("Kept.") survived in another part. Measured before that guard:

        [{'text':'[DRAFT]'}, {'text':'Kept.'}] -> desc='[DRAFT] Kept.' gaps=([], [])

    Now that ``is_draft_or_placeholder`` matches ``[DRAFT]`` with or without a
    trailing space (the draft-marker widening), the bare part is caught
    directly by the PER-PART check and dropped before the join ever runs --
    the real content in the other part(s) is no longer collateral damage. The
    control keeps a truncated-but-real description and is named in
    ``dropped_parts`` (something was lost) but not ``missing_description``
    (something real survived) -- the same distinction the module docstring
    draws for any other dropped part.
    """
    for narratives in (
        [{"text": "[DRAFT]"}, {"text": "Kept."}],
        [{"text": "Accounts are managed."}, {"text": "[DRAFT]"}, {"text": "More."}],
    ):
        entries = [_entry(implementation_status=["Implemented"], part_narratives=narratives)]
        out = render_controls(entries)
        assert "[DRAFT]" not in out[0].get("controlImplementationDescription", ""), (
            narratives,
            out[0],
        )
        # Real content survived, so this is a dropped-part gap, not a
        # missing-description gap.
        assert _control_gaps(entries) == ([], ["AC-2"]), narratives


def test_a_bare_draft_token_with_nothing_after_it_is_now_caught() -> None:
    """This test used to document the hole: a lone ``"[DRAFT]"`` part with
    nothing after it composes to ``"[DRAFT]"``, which the old, space-including
    ``DRAFT_PREFIX`` substring test did not match -- so it shipped verbatim as
    the control's ``controlImplementationDescription`` to a FedRAMP deliverable,
    reported in neither gap list. That was the hole; this asserts it is closed.

    ``is_draft_or_placeholder`` now matches the marker whether or not it is
    followed by a space, so the sole part is scaffolding, the description is
    dropped entirely (nothing real survived), and the control is named in
    BOTH gap lists -- the same outcome as any control whose only narrative was
    scaffolding.
    """
    entries = [_entry(part_narratives=[{"text": "[DRAFT]"}])]
    out = render_controls(entries)
    assert "controlImplementationDescription" not in out[0]
    assert _control_gaps(entries) == (["AC-2"], ["AC-2"])


def test_a_marker_at_the_end_of_a_sentence_with_no_trailing_space_is_caught() -> None:
    """The SDR-shaped instance of the draft-marker widening: a human typing
    ``"Done. [DRAFT]"`` -- the marker ending the sentence, never followed by a
    space -- used to ship verbatim as ``controlImplementationDescription`` in
    the FedRAMP deliverable, reported in neither gap list. That was the hole
    this change closes end to end.
    """
    entries = [_entry(part_narratives=[{"text": "Done. [DRAFT]"}])]
    out = render_controls(entries)
    assert "controlImplementationDescription" not in out[0]
    assert _control_gaps(entries) == (["AC-2"], ["AC-2"])


def test_a_null_element_in_the_narrative_list_lost_nothing() -> None:
    """A literal ``null`` in the JSONB array is not a lost part -- same
    reachability class as the legacy bare-string element, which already has a
    test. Without the ``None`` clause in ``_is_blank`` this reports a loss and
    sends an operator hunting for content that never existed."""
    entries = [_entry(part_narratives=[None, {"text": "We manage accounts."}, None])]
    out = render_controls(entries)
    assert out[0]["controlImplementationDescription"] == "We manage accounts."
    assert _control_gaps(entries) == ([], [])


def test_a_non_string_text_value_is_dropped_rather_than_repr_d() -> None:
    """Same standard as the legacy bare-string part, one level down:
    ``{"text": ["a", "b"]}`` must not render as ``"['a', 'b']"``. ``None``
    stays "nothing written" rather than a loss."""
    entries = [_entry(part_narratives=[{"text": ["a", "b"]}])]
    out = render_controls(entries)
    assert "controlImplementationDescription" not in out[0], out[0]
    assert _control_gaps(entries) == (["AC-2"], ["AC-2"])

    written = [_entry(part_narratives=[{"text": {"nested": "dict"}},
                                       {"text": "Real content."}])]
    assert render_controls(written)[0]["controlImplementationDescription"] == (
        "Real content."
    )
    assert _control_gaps(written) == ([], ["AC-2"])


def test_a_legacy_bare_blank_string_lost_nothing_and_is_not_reported() -> None:
    """The ``isinstance`` guard fired before any blankness test, so ``["",
    {"text": "..."}]`` reported a loss although nothing was there to lose."""
    entries = [_entry(part_narratives=["", "   ", {"text": "We manage accounts."}])]
    out = render_controls(entries)
    assert out[0]["controlImplementationDescription"] == "We manage accounts."
    assert _control_gaps(entries) == ([], [])


def test_a_legacy_bare_string_narrative_is_dropped_and_reported() -> None:
    """No producer writes this shape today, but rendering ``str(part)`` would
    put a Python repr in a federal deliverable, and vanishing silently is the
    defect this round is about."""
    entries = [_entry(part_narratives=["We manage accounts.", {"text": "And review them."}])]
    out = render_controls(entries)
    assert out[0]["controlImplementationDescription"] == "And review them."
    missing, dropped = _control_gaps(entries)
    assert missing == []
    assert dropped == ["AC-2"]


def test_the_draft_predicate_is_the_ssp_modules_own() -> None:
    """Imported, not restated. A second copy of this rule is how this module's
    status enum went wrong twice, and ssp/completeness.py already owns the
    judgement -- it calls the same text "draft narrative -- needs review"."""
    assert sdr_module.is_draft_or_placeholder is is_draft_or_placeholder


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
