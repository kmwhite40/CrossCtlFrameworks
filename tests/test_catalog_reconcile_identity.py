from pathlib import Path

from ccf.catalog.oscal import load_oscal_catalog
from ccf.catalog.reconcile import ControlRow, check_baseline, check_identity

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


def _rows(*specs):
    out = []
    for s in specs:
        out.append(
            ControlRow(
                control_number=s.get("cn"),
                control_name=s.get("name"),
                description=s.get("desc"),
                discussion=s.get("disc"),
                fisma_low=s.get("low"),
                fisma_mod=s.get("mod"),
                fisma_high=s.get("high"),
                source_row=s.get("row"),
            )
        )
    return out


def test_identity_flags_unknown_unparseable_withdrawn():
    cat = load_oscal_catalog(FIX)
    rows = _rows(
        {"cn": "AC-2", "row": 2},  # ok
        {"cn": "SC-99", "row": 3},  # unknown
        {"cn": "AC.L2-3.1.1", "row": 4},  # unparseable
        {"cn": "AC-13", "row": 5},  # withdrawn
    )
    findings, crosswalk, failed = check_identity(cat, rows)
    checks = {(f.check, f.severity, f.canonical_id) for f in findings}
    assert ("identity", "high", "SC-99") in checks  # unknown_control_id
    assert any(f.detail.startswith("unparseable") or f.field == "unparseable" for f in findings)
    assert ("identity", "medium", "AC-13") in checks  # withdrawn
    assert crosswalk["AC-2"] == "AC-2"
    assert crosswalk["AC.L2-3.1.1"] is None
    assert "SC-99" in failed and "AC-2" not in failed


def test_baseline_over_and_under_claim():
    cat = load_oscal_catalog(FIX)
    # AC-2(1) is in MODERATE+HIGH per fixture, NOT in LOW
    rows = _rows(
        {"cn": "AC-2(1)", "low": True, "mod": True, "high": True, "row": 2},  # low overclaim
        # mod/high/low underclaim
        {"cn": "AC-2", "low": False, "mod": False, "high": False, "row": 3},
    )
    _, _, failed = check_identity(cat, rows)
    findings = check_baseline(cat, rows, failed)
    # AC-2(1) claimed on fisma_low but not authoritatively in the LOW baseline:
    # a medium-severity overclaim, identified by the "baseline_overclaim" detail prefix.
    overclaims = [f for f in findings if f.detail.split(":")[0] == "baseline_overclaim"]
    assert overclaims
    assert all(f.severity == "medium" and f.field == "fisma_low" for f in overclaims)
    # AC-2 is authoritatively in MODERATE+HIGH (and LOW) but marked false everywhere:
    # a high-severity underclaim on fisma_mod/fisma_high.
    underclaims = [f for f in findings if f.detail.split(":")[0] == "baseline_underclaim"]
    assert underclaims
    assert any(f.severity == "high" and f.field in {"fisma_mod", "fisma_high"} for f in underclaims)
