"""NIST CSF 2.0 is resolved against the published catalog, not trusted as text.

Concord already carried CSF 2.0, but only as four free-text crosswalk columns
whose values arrive in at least five shapes — a bare id, an id with a trailing
colon, an id followed by prose, a function+category name, and semicolon-joined
lists. Nothing validated them, so a typo was indistinguishable from a real
subcategory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import ccf.catalog as catalog_pkg
from ccf.catalog.csf import (
    CSF_CATALOG_FILE,
    extract_category_ids,
    extract_ids,
    load_csf_catalog,
)
from ccf.catalog.reconcile import MappingRow, check_csf_endpoints


def test_catalog_loads_the_full_published_structure() -> None:
    c = load_csf_catalog()
    # CSF 2.0 has six Functions; the count is fixed by the standard.
    assert sorted(c.functions) == ["DE", "GV", "ID", "PR", "RC", "RS"]
    assert len(c.categories) == 34
    assert len(c.subcategories) == 185
    assert c.oscal_version.startswith("v1.")


def test_the_hierarchy_is_preserved() -> None:
    """Function -> Category -> Subcategory, which the flat 800-53 loader loses."""
    s = load_csf_catalog().get("GV.OC-01")
    assert s is not None
    assert (s.function_id, s.function_title) == ("GV", "GOVERN")
    assert (s.category_id, s.category_title) == ("GV.OC", "Organizational Context")
    assert "organizational mission" in s.statement.lower()


def test_enrichment_label_uses_the_authoritative_statement() -> None:
    """The point of enrichment: show NIST's text, not the spreadsheet's."""
    label = load_csf_catalog().get("GV.OC-01").label
    assert label.startswith("GV.OC-01 — ")
    assert len(label) > 30


def test_lookup_is_case_insensitive_but_membership_is_exact() -> None:
    c = load_csf_catalog()
    assert c.has("gv.oc-01")
    assert not c.has("GV.OC-99")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("DE.CM-01", ["DE.CM-01"]),
        ("PR.AT-04:", ["PR.AT-04"]),
        ("PR.AT-01: Personnel are provided with awareness and training", ["PR.AT-01"]),
        ("GV.RR-01; GV.RR-02", ["GV.RR-01", "GV.RR-02"]),
        ("DE.CM-09  DE.CM-09", ["DE.CM-09"]),  # deduplicated, order preserved
        # coarse references carry no subcategory id — not an error
        ("Protect: Platform Security (PR.PS)", []),
        ("Respond", []),
        ("", []),
        (None, []),
    ],
)
def test_extract_ids_handles_every_shape_the_workbook_uses(
    value: str | None, expected: list[str]
) -> None:
    assert extract_ids(value) == expected


def test_extract_category_ids_does_not_swallow_subcategories() -> None:
    assert extract_category_ids("Protect: Platform Security (PR.PS)") == ["PR.PS"]
    assert extract_category_ids("PR.PS-01") == []


def test_check_flags_an_id_that_is_not_in_the_catalog() -> None:
    """The whole point: a typo must become a finding, not silent noise."""
    rows = [
        MappingRow(control_number="AC-1", column_key="NIST CSF 2.0 Subcategory",
                   framework_code="NIST_CSF_2_0", value="GV.OC-99"),
    ]
    findings = check_csf_endpoints(rows)
    assert len(findings) == 1
    assert findings[0].check == "csf_endpoint"
    assert findings[0].canonical_id == "GV.OC-99"
    assert "not a CSF" in findings[0].detail


def test_check_accepts_real_ids_and_coarse_references() -> None:
    rows = [
        MappingRow("AC-1", "NIST CSF 2.0 Subcategory", "NIST_CSF_2_0", "GV.OC-01"),
        MappingRow("AC-2", "NIST CSF 2.0 Subcategory", "NIST_CSF_2_0", "PR.AT-01: prose here"),
        MappingRow("AC-3", "NIST CSF 2.0 Category", "NIST_CSF_2_0",
                   "Protect: Platform Security (PR.PS)"),
        MappingRow("AC-4", "NIST CSF 2.0 Function", "NIST_CSF_2_0", "Respond"),
    ]
    assert check_csf_endpoints(rows) == []


def test_check_ignores_other_frameworks() -> None:
    """It must not try to resolve an 800-53 or CMMC value as a CSF id."""
    rows = [MappingRow("AC-1", "CMMC Rev. 2L2", "CMMC", "AC.L2-3.1.1")]
    assert check_csf_endpoints(rows) == []


def test_the_catalog_is_covered_by_the_integrity_manifest() -> None:
    """It must be SHA-256 verified, not merely present.

    load_csf_catalog raises if the manifest omits the file, because an unlisted
    file would be parsed unverified.
    """
    d = Path(catalog_pkg.__file__).parent / "oscal_data"
    manifest = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    assert CSF_CATALOG_FILE in manifest["files"]
    assert len(manifest["files"][CSF_CATALOG_FILE]) == 64  # sha256 hex
