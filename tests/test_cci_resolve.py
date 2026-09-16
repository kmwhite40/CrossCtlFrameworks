"""Resolve a DISA reference onto the OSCAL catalog.

The one rule worth a test of its own: a leading "(n)" is a control
*enhancement*, not a statement item.
"""
from ccf.catalog.oscal import load_oscal_catalog
from ccf.cci.reader import DEFAULT_CCI_HTML, read_cci_html
from ccf.cci.resolve import ResolutionStatus, catalog_index, resolve_reference

CONTROLS, PARTS = catalog_index(load_oscal_catalog())


def _r(raw: str):
    return resolve_reference(raw, control_ids=CONTROLS, part_ids=PARTS)


def test_item_path_resolves_to_a_statement_part() -> None:
    r = _r("AC-1 a 1 (a)")
    assert r.canonical_control == "AC-1"
    assert r.oscal_control_id == "ac-1"
    assert r.oscal_part_id == "ac-1_smt.a.1.a"


def test_leading_parenthetical_is_an_enhancement_not_an_item() -> None:
    r = _r("AC-2 (1)")
    assert r.canonical_control == "AC-2(1)"
    assert r.oscal_control_id == "ac-2.1"
    # The bug this guards: reading (1) as an item yields ac-2_smt.1, which
    # silently mis-maps 1,860 of 3,849 references.
    assert r.oscal_part_id != "ac-2_smt.1"


def test_enhancement_then_item_path() -> None:
    # AC-2(1)'s statement has no lettered items in Rev 5 -- AC-2(3) does, so it
    # is the enhancement used here to exercise "absorb the enhancement, then
    # resolve what remains as an item path" end to end.
    r = _r("AC-2 (3) a")
    assert r.oscal_control_id == "ac-2.3"
    assert r.oscal_part_id == "ac-2.3_smt.a"


def test_control_with_no_item_path_resolves_to_the_statement_root() -> None:
    r = _r("AC-1")
    assert r.canonical_control == "AC-1"
    assert r.oscal_part_id == "ac-1_smt"


def test_unresolvable_item_keeps_its_control() -> None:
    # CCI-005020 cites SI-18 b 1, but SI-18 b has no sub-items in Rev 5.
    r = _r("SI-18 b 1")
    assert r.canonical_control == "SI-18"
    assert r.oscal_control_id == "si-18"
    assert r.oscal_part_id is None


def test_non_80053_reference_resolves_to_nothing_rather_than_guessing() -> None:
    r = _r("AC-1.1 (iii)")
    assert r.canonical_control is None
    assert r.oscal_control_id is None
    assert r.oscal_part_id is None


def test_syntactically_valid_but_uncataloged_control_resolves_to_nothing() -> None:
    # "ZZ-1" satisfies canonicalize()'s family-then-number shape, so it is not
    # caught by the non-800-53-syntax guard above -- it is caught by the
    # separate "does this control actually exist in the catalog" check.
    # Dropping that check would leave canonical_control/oscal_control_id
    # populated for a control the catalog has never heard of.
    r = _r("ZZ-1")
    assert r.canonical_control is None
    assert r.oscal_control_id is None
    assert r.oscal_part_id is None


def test_every_rev5_reference_but_one_resolves_to_a_part() -> None:
    """The measured rate. A regression here means the rule or the catalog moved."""
    items = read_cci_html(DEFAULT_CCI_HTML).items
    rev5 = [(i.cci, r.raw_index) for i in items for r in i.references if r.revision == "5"]
    assert len(rev5) == 3849
    unresolved = [
        (cci, raw) for cci, raw in rev5 if _r(raw).oscal_part_id is None
    ]
    assert unresolved == [("CCI-005020", "SI-18 b 1")]


# --- Finding 1 (PR #22): non-Rev-5 references silently resolved against
# the Rev. 5 catalog. `control_ids`/`part_ids` here are always Rev. 5's, so
# these tests exercise exactly what the real loader does for a non-Rev-5
# reference -- see ccf.cci.service.load_cci_list.


def test_800_53a_glued_enhancement_falls_back_to_base_but_is_flagged() -> None:
    # 800-53A glues the enhancement to the item with a dot ("(1).1") instead
    # of DISA's usual space-separated tokens ("(1) a"). `_ENH_TOKEN` never
    # matches that shape, so absorption stops at the base control -- measured
    # over the real list, 825 of 1,683 800-53A references do this. The base
    # control (AC-2) is real; what the fix adds is a status that says so
    # instead of looking identical to a genuine base-only reference.
    r = _r("AC-2 (1).1")
    assert r.canonical_control == "AC-2"
    assert r.status is ResolutionStatus.BASE_CONTROL_FALLBACK

    plain = _r("AC-2")
    assert plain.canonical_control == "AC-2"
    assert plain.status is ResolutionStatus.RESOLVED
    # Before the fix, `AC-2 (1).1` and `AC-2` were indistinguishable at the
    # canonical_control level -- exactly what `controls_for_cci` exposes.
    assert r.canonical_control == plain.canonical_control
    assert r.status != plain.status


def test_v3_enhancement_missing_from_rev5_falls_back_to_base_and_is_flagged() -> None:
    # SA-6 was withdrawn from Rev. 5 (folded into SA-4), so SA-6(1) is not in
    # the held catalog even though bare SA-6 still resolves as a base id.
    # The absorption loop breaks on a token that DOES match `_ENH_TOKEN`
    # syntactically -- the failure is the catalog, not the tokenizer -- and
    # that must be flagged exactly like the tokenizer failure above.
    r = _r("SA-6 (1) (a)")
    assert r.canonical_control == "SA-6"
    assert r.status is ResolutionStatus.BASE_CONTROL_FALLBACK


def test_rev4_reference_to_a_control_withdrawn_in_rev5_is_flagged_not_silent() -> None:
    # AP-1 (Appendix J) is one of the 207 Rev. 4 base controls with no Rev. 5
    # counterpart. Before the fix this was indistinguishable from a
    # reference that never parsed as a control at all.
    r = _r("AP-1")
    assert r.canonical_control is None
    assert r.oscal_control_id is None
    assert r.status is ResolutionStatus.WITHDRAWN


def test_unparseable_reference_is_flagged_distinctly_from_withdrawn() -> None:
    r = _r("AC-1.1 (iii)")
    assert r.canonical_control is None
    assert r.status is ResolutionStatus.UNPARSEABLE
    assert r.status != ResolutionStatus.WITHDRAWN
