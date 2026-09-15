"""Report where the workbook and DISA disagree. Never correct either."""
from ccf.cci.reconcile import compare_cci_sets, parse_workbook_cci_value


def test_workbook_value_splits_and_strips_the_compliance_marker() -> None:
    got = parse_workbook_cci_value("CCI-003621; CCI-003622; CCI-003615")
    assert got == {"CCI-003621", "CCI-003622", "CCI-003615"}
    # '*' marks "automatically compliant" and is not part of the identifier.
    assert parse_workbook_cci_value("CCI-003624*") == {"CCI-003624"}
    assert parse_workbook_cci_value(None) == set()
    assert parse_workbook_cci_value("  ") == set()


def test_agreement_reports_nothing() -> None:
    assert compare_cci_sets("AC-02a.[01]", {"CCI-1"}, {"CCI-1"}) is None


def test_each_side_reports_what_the_other_lacks() -> None:
    d = compare_cci_sets("AC-02a.[01]", {"CCI-1", "CCI-2"}, {"CCI-2", "CCI-3"})
    assert d is not None
    assert d.workbook_only == ("CCI-1",)
    assert d.disa_only == ("CCI-3",)


def test_an_empty_workbook_cell_is_not_a_disagreement() -> None:
    # Most workbook rows carry no CCI at all; treating absence as conflict
    # would bury the real findings under thousands of empty ones.
    assert compare_cci_sets("AC-02b.", set(), {"CCI-2"}) is None
