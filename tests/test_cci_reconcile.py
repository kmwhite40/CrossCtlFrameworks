"""Report where the workbook and DISA disagree. Never correct either."""
import pytest
from sqlalchemy import delete

from ccf.cci.reconcile import (
    WORKBOOK_COLUMN,
    _fold_to_canonical,
    compare_cci_sets,
    parse_workbook_cci_value,
    reconcile_cci,
)
from ccf.db import session_scope
from ccf.models import Control, FrameworkMapping
from ccf.models_cci import CciControlRef, CciItemRow


def test_workbook_value_splits_and_strips_the_compliance_marker() -> None:
    got = parse_workbook_cci_value("CCI-003621; CCI-003622; CCI-003615")
    assert got == {"CCI-003621", "CCI-003622", "CCI-003615"}
    # '*' marks "automatically compliant" and is not part of the identifier.
    assert parse_workbook_cci_value("CCI-003624*") == {"CCI-003624"}
    assert parse_workbook_cci_value(None) == set()
    assert parse_workbook_cci_value("  ") == set()


def test_agreement_reports_nothing() -> None:
    assert compare_cci_sets("AC-02a.[01]", {"CCI-1"}, {"CCI-1"}) is None


def test_a_row_only_cci_is_reported() -> None:
    # compare_cci_sets is now a per-ROW helper: it reports only what the row
    # itself claims that DISA doesn't map to the control at all. It no
    # longer reports "disa - workbook" -- a single row is only a slice of
    # its control's CCIs, so that half is computed once per control, in
    # reconcile_cci, against the union of every row.
    d = compare_cci_sets("AC-02a.[01]", {"CCI-1", "CCI-2"}, {"CCI-2", "CCI-3"})
    assert d is not None
    assert d.row_identifier == "AC-02a.[01]"
    assert d.workbook_only == ("CCI-1",)


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


async def test_reconcile_cci_against_seeded_rows(clean_migrated_db) -> None:
    """Exercise the join, the DISA grouping, and the fold-then-compare loop
    with real data -- the pure-helper tests above never touch a database,
    and the CLI test in test_cci_cli.py runs against an EMPTY database, so
    neither ever executed reconcile_cci's actual query and aggregation
    logic. Seeds a handful of Control/FrameworkMapping rows (the "workbook")
    and CciItemRow/CciControlRef rows (DISA) directly rather than loading
    the full 5,149-item list.

    Control ZZ-90 has three statement-item rows:
      - ZZ-90a.[01] claims CCI-990001 (DISA also maps this -- agreement)
      - ZZ-90b.     claims CCI-990002 (DISA also maps this -- agreement)
      - ZZ-90c.     claims CCI-990099 (DISA does NOT map this at all --
        a genuine per-row workbook-only finding)
    DISA maps CCI-990001, CCI-990002, and CCI-990003 to ZZ-90.
    CCI-990003 is claimed by NEITHER row -- a genuine disa-only finding.

    This is exactly Finding A's failure mode, seeded directly: under the old
    per-row-against-whole-control comparison, row ZZ-90a.[01]'s own set is
    only {CCI-990001}, so comparing it against the control's full DISA set
    {990001, 990002, 990003} would spuriously report CCI-990002 as
    disa_only for that row -- even though row ZZ-90b. claims it right
    there. The fix must NOT report CCI-990002 as disa_only anywhere, since
    a sibling row of the same control does claim it; only CCI-990003, which
    NO row claims, may appear in disa_only.
    """
    control_ids: list[int] = []
    try:
        async with session_scope() as s:
            rows = [
                Control(
                    identifier="ZZ-90a.[01]", sequence_control="ZZ-90",
                    control_name=None, source_row=1,
                ),
                Control(
                    identifier="ZZ-90b.", sequence_control="ZZ-90",
                    control_name=None, source_row=2,
                ),
                Control(
                    identifier="ZZ-90c.", sequence_control="ZZ-90",
                    control_name=None, source_row=3,
                ),
            ]
            s.add_all(rows)
            await s.flush()
            control_ids = [c.id for c in rows]
            s.add_all(
                [
                    FrameworkMapping(
                        control_id=rows[0].id, column_key=WORKBOOK_COLUMN,
                        value="CCI-990001",
                    ),
                    FrameworkMapping(
                        control_id=rows[1].id, column_key=WORKBOOK_COLUMN,
                        value="CCI-990002",
                    ),
                    FrameworkMapping(
                        control_id=rows[2].id, column_key=WORKBOOK_COLUMN,
                        value="CCI-990099",
                    ),
                ]
            )

            items = [
                CciItemRow(
                    cci=cci, status="draft", type="policy", definition="test item",
                    source_version="test", source_sha256="0" * 64,
                )
                for cci in ("CCI-990001", "CCI-990002", "CCI-990003")
            ]
            s.add_all(items)
            await s.flush()
            s.add_all(
                [
                    CciControlRef(
                        cci_id=item.id, revision="5", raw_index="ZZ-90",
                        canonical_control="ZZ-90",
                    )
                    for item in items
                ]
            )

        async with session_scope() as s:
            findings = await reconcile_cci(s)

        found = next(d for d in findings if d.control_identifier == "ZZ-90")

        # The Finding A behaviour: CCI-990002 is claimed by a sibling row
        # (ZZ-90b.), so it must NOT show up as disa_only -- only the CCI no
        # row claims at all does.
        assert found.disa_only == ("CCI-990003",)

        # workbook_only stays per row: only ZZ-90c.'s CCI-990099 is a row
        # asserting something DISA has no record of for the control.
        row_findings = {r.row_identifier: r.workbook_only for r in found.rows}
        assert row_findings == {"ZZ-90c.": ("CCI-990099",)}
    finally:
        async with session_scope() as s:
            if control_ids:
                await s.execute(
                    delete(FrameworkMapping).where(
                        FrameworkMapping.control_id.in_(control_ids)
                    )
                )
                await s.execute(delete(Control).where(Control.id.in_(control_ids)))
            await s.execute(
                delete(CciControlRef).where(CciControlRef.canonical_control == "ZZ-90")
            )
            await s.execute(
                delete(CciItemRow).where(
                    CciItemRow.cci.in_(("CCI-990001", "CCI-990002", "CCI-990003"))
                )
            )
