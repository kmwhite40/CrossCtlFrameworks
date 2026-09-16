"""OscalControl exposes its statement parts by id.

CCI references address a control *item* ("AC-1 a 1 (a)"), not a control, so
resolution needs the part ids the catalog actually defines.
"""
from ccf.catalog.oscal import load_oscal_catalog


def test_statement_parts_are_addressable_by_oscal_part_id() -> None:
    cat = load_oscal_catalog()
    ac1 = cat.get("AC-1")
    assert ac1 is not None
    # The nesting DISA references: a -> 1 -> (a)
    assert "ac-1_smt.a" in ac1.statement_parts
    assert "ac-1_smt.a.1" in ac1.statement_parts
    assert "ac-1_smt.a.1.a" in ac1.statement_parts
    assert "Addresses purpose, scope, roles" in ac1.statement_parts["ac-1_smt.a.1.a"]


def test_statement_parts_absent_where_the_control_has_none() -> None:
    cat = load_oscal_catalog()
    si18 = cat.get("SI-18")
    assert si18 is not None
    # SI-18 b has no sub-items in Rev 5 -- this is the CCI-005020 case.
    assert "si-18_smt.b" in si18.statement_parts
    assert "si-18_smt.b.1" not in si18.statement_parts


def test_statement_root_id_is_present_for_bare_control_references() -> None:
    cat = load_oscal_catalog()
    ac1 = cat.get("AC-1")
    assert ac1 is not None
    # Task 3 resolves bare control references like "AC-1" (no item path)
    # to exactly "ac-1_smt", the root statement part. This must be present
    # even though 800-53r5 has empty prose on the root part itself.
    assert "ac-1_smt" in ac1.statement_parts
