"""Report where the workbook and DISA disagree. Never correct either."""
import pytest

from ccf.cci.reconcile import _fold_to_canonical, compare_cci_sets, parse_workbook_cci_value


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


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        # Statement-item suffixes ('a.', 'b.', '[01]', '(a)') are dropped --
        # they are not enhancements and canonicalize() would reject them.
        ("AC-01a.[01]", "AC-1"),
        ("AC-01a.01(a)[01]", "AC-1"),
        ("AC-02b.", "AC-2"),
        ("AC-02_ODP[01]", "AC-2"),
        # Numeric parenthesised groups ARE enhancements and MUST survive the
        # fold -- collapsing AC-2(1)a down to AC-2 would compare the row
        # against the wrong control's CCI set.
        ("AC-02(01)", "AC-2(1)"),
        ("AC-02(03)(a)", "AC-2(3)"),
        ("AC-02(02)_ODP[02]", "AC-2(2)"),
    ],
)
def test_the_fold_keeps_enhancements_and_drops_statement_items(
    identifier: str, expected: str
) -> None:
    got = _fold_to_canonical(identifier)
    assert got is not None
    assert got.value == expected


def test_the_fold_rejects_a_non_800_53_identifier() -> None:
    # DS-IA-13* is a DoD identifier with a five-letter family prefix --
    # canonicalize() is designed to reject anything but a two-letter family,
    # so this is a correct rejection, not a lossy one.
    assert _fold_to_canonical("DS-IA-13[04]") is None
