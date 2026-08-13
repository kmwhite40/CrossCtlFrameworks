from pathlib import Path

from ccf.catalog.oscal import load_oscal_catalog
from ccf.catalog.reconcile import (
    ControlRow,
    MappingRow,
    check_content_drift,
    check_mapping_endpoints,
    reconcile,
)

FIX = Path(__file__).parent / "fixtures" / "oscal_mini"


def test_title_and_text_drift():
    cat = load_oscal_catalog(FIX)
    rows = [
        ControlRow(
            "AC-2", "Wrong Title", "totally different text here", None, None, None, None, 2
        ),
    ]
    findings = check_content_drift(cat, rows, failed=set())
    assert any(
        f.field == "control_name" and f.severity == "medium" for f in findings
    )  # title_drift
    assert any(
        f.field in {"description", "discussion"} and f.severity == "low" for f in findings
    )  # text_drift


def test_mapping_endpoint_dangling_and_uncovered():
    cat = load_oscal_catalog(FIX)
    mappings = [
        MappingRow("A.9.2.1", "NIST 800-53r5", "NIST", "AC-2"),  # endpoint AC-2 exists
        MappingRow("A.9.2.9", "NIST 800-53r5", "NIST", "SC-99"),  # dangling
        MappingRow("x", "ISO 27001", "ISO", "A.5.1"),  # no bundled catalog
    ]
    findings, uncovered = check_mapping_endpoints(cat, mappings)
    assert any(f.check == "mapping_endpoint" and f.canonical_id == "SC-99" for f in findings)
    assert uncovered.get("ISO", 0) == 1


def test_reconcile_counts_reconcile():
    cat = load_oscal_catalog(FIX)
    rows = [
        ControlRow(
            "AC-2", "Account Management", "Manage system accounts.", "", None, None, None, 2
        ),
        ControlRow("SC-99", None, None, None, None, None, None, 3),  # fails identity
    ]
    res = reconcile(cat, rows, [])
    assert res.controls_checked == 2
    assert res.not_evaluated == 1  # SC-99
    assert res.controls_checked == len(_evaluated(res)) + res.not_evaluated
    assert set(res.summary["by_check"]) >= {
        "identity",
        "baseline",
        "content_drift",
        "mapping_endpoint",
    }


def _evaluated(res):
    # distinct canonical ids that were NOT in the failed set (see summary)
    return res.summary["evaluated_ids"]


def test_counts_reconcile_with_duplicate_spellings_one_canonical():
    # Two raw spellings of the SAME control must count as ONE checked control,
    # and the invariant checked == evaluated + not_evaluated must still hold.
    # (Regression: previously controls_checked deduped by raw while evaluated_ids
    # deduped by canonical, breaking the invariant on the common path.)
    cat = load_oscal_catalog(FIX)
    rows = [
        ControlRow("AC-2", "Account Management", None, None, None, None, None, 2),
        ControlRow("AC-02", "Account Management", None, None, None, None, None, 3),
    ]
    res = reconcile(cat, rows, [])
    assert res.controls_checked == 1
    assert res.summary["evaluated_ids"] == ["AC-2"]
    assert res.not_evaluated == 0
    assert res.controls_checked == len(res.summary["evaluated_ids"]) + res.not_evaluated


def test_failed_identity_control_is_skipped_by_baseline_and_drift():
    # A control unknown to OSCAL (fails identity) must NOT produce baseline or
    # content-drift findings even when it carries baseline claims / prose — it is
    # recorded not_evaluated. Exercises the graceful-degradation guards.
    cat = load_oscal_catalog(FIX)
    rows = [
        ControlRow("SC-99", "Bogus Title", "some prose that would drift", None,
                   True, True, True, 2),  # unknown id + non-None fields
    ]
    res = reconcile(cat, rows, [])
    assert res.controls_checked == 1
    assert res.not_evaluated == 1
    assert res.summary["evaluated_ids"] == []
    # only an identity finding for SC-99; no baseline/content_drift findings
    assert {f.check for f in res.findings} <= {"identity"}
    assert res.summary["by_check"]["baseline"] == 0
    assert res.summary["by_check"]["content_drift"] == 0
