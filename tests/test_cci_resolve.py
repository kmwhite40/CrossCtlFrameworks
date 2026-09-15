"""Resolve a DISA reference onto the OSCAL catalog.

The one rule worth a test of its own: a leading "(n)" is a control
*enhancement*, not a statement item.
"""
from ccf.catalog.oscal import load_oscal_catalog
from ccf.cci.reader import DEFAULT_CCI_HTML, read_cci_html
from ccf.cci.resolve import catalog_index, resolve_reference

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


def test_every_rev5_reference_but_one_resolves_to_a_part() -> None:
    """The measured rate. A regression here means the rule or the catalog moved."""
    items = read_cci_html(DEFAULT_CCI_HTML).items
    rev5 = [(i.cci, r.raw_index) for i in items for r in i.references if r.revision == "5"]
    assert len(rev5) == 3849
    unresolved = [
        (cci, raw) for cci, raw in rev5 if _r(raw).oscal_part_id is None
    ]
    assert unresolved == [("CCI-005020", "SI-18 b 1")]
