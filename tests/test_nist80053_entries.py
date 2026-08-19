# tests/test_nist80053_entries.py
from ccf.catalog.oscal import load_oscal_catalog
from ccf.ssp.nist80053 import build_80053_entries, family_of


def test_family_of() -> None:
    assert family_of("AC-2(1)") == "AC"
    assert family_of("SC-7") == "SC"


def test_moderate_baseline_entry_count_and_shape() -> None:
    cat = load_oscal_catalog()
    entries, odp_defs = build_80053_entries(cat, "moderate")

    expected = {
        cid
        for cid in cat.baselines["moderate"]
        if cat.get(cid) and not cat.get(cid).withdrawn  # type: ignore[union-attr]
    }
    assert {e["control_id"] for e in entries} == expected
    assert len(entries) == len(expected)

    ac2 = next(e for e in entries if e["control_id"] == "AC-2")
    assert ac2["domain"] == "AC"
    assert ac2["nist_id"] == "AC-2"
    assert ac2["title"]
    # `requirement` mirrors OscalControl.statement verbatim (a pre-existing catalog-
    # loader concern, not this builder's) — assert it's carried through as a string.
    assert isinstance(ac2["requirement"], str)
    assert ac2["responsible_role"]
    assert ac2["odp_values"]
    assert all(v is None for v in ac2["odp_values"].values())
    # Canonical vocabulary (ssp.constants) — this seeder used to emit a
    # lowercase/hyphenated set that existed nowhere else, so an 800-53 entry
    # matched none of the case-sensitive consumers.
    assert ac2["implementation_status"] == ["Planned"]
    assert ac2["control_origination"] == ["Organization System Specific"]
    assert ac2["part_narratives"][0]["draft"] is True
    assert "AC-2" in ac2["part_narratives"][0]["text"]

    assert odp_defs["AC-2"]
    assert odp_defs["AC-2"][0]["label"]


def test_entries_sorted_by_family_then_number() -> None:
    cat = load_oscal_catalog()
    entries, _ = build_80053_entries(cat, "moderate")

    families = [e["domain"] for e in entries]
    assert families == sorted(families)
    assert families[0] <= families[-1]

    sort_orders = [e["sort_order"] for e in entries]
    assert sort_orders == list(range(len(entries)))
