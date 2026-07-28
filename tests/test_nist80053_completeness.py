"""Unit tests for the ODP completeness dimension (Task 5, 800-53r5 SSP pipeline).

Pure ``assess()`` calls — no DB. Mirrors the style of
``tests/test_ssp_completeness.py`` / ``tests/test_boundary_completeness.py``.
Entries use ``odp_definitions=[]`` so the pre-existing per-entry "unfilled
parameter(s)" gap (driven by ``odp_definitions`` vs ``odp_values``, see
``_entry_gaps``) doesn't fire and muddy the assertions here — this suite is
about the report-level ODP dimension added on top of that.
"""

from __future__ import annotations

from typing import Any

from ccf.ssp.completeness import assess

_FULL_META = {
    "system_type": "Cloud",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "the tenant",
    "roles": {
        "system_owner": {"name": "A"},
        "isso": {"name": "B"},
        "authorizing_official": {"name": "C"},
    },
}


def _entry(**kw: Any) -> dict[str, Any]:
    base = dict(
        control_id="ac-2",
        part_narratives=[{"text": "The organization does X."}],
        responsible_role="System Owner",
        implementation_status=["Implemented"],
        control_origination=["Inherited"],
        odp_definitions=[],
        odp_values={},
        evidence_ref="s3://evidence/default-config-export.pdf",
    )
    base.update(kw)
    return base


def test_unset_odps_reported_as_gap_and_summarized() -> None:
    entry = _entry(odp_values={"ac-2_prm_1": None, "ac-2_prm_2": "30 days"})
    r = assess(_FULL_META, [entry])
    assert any(
        "organization-defined parameters (ODPs) unset" in m for m in r["missing_sections"]
    )
    assert "1 of 2" in next(
        m for m in r["missing_sections"] if "organization-defined parameters" in m
    )
    assert r["odp_summary"] == {"total": 2, "unset": 1}
    assert r["ready"] is False
    # control_pct=1.0, front-matter section_pct=1.0, odp_pct=0.5 ->
    # section_pct=(1.0+0.5)/2=0.75 -> 100*(0.8*1 + 0.2*0.75) = 95.0
    assert r["score"] == 95.0


def test_filled_odps_clear_the_gap() -> None:
    entry = _entry(odp_values={"ac-2_prm_1": "annually", "ac-2_prm_2": "30 days"})
    r = assess(_FULL_META, [entry])
    assert not any("organization-defined parameters" in m for m in r["missing_sections"])
    assert r["odp_summary"] == {"total": 2, "unset": 0}
    assert r["ready"] is True
    assert r["score"] == 100.0


def test_entries_without_odp_values_are_unaffected_backward_compat() -> None:
    """Entries with no ``odp_values`` at all (or an empty dict — pre-Keystone-2
    CMMC entries) must leave the ODP dimension entirely inert: no gap,
    ``odp_summary["total"] == 0``, and the score byte-identical to a baseline
    call with an explicit empty ``odp_values``."""
    entry_no_key = _entry()
    del entry_no_key["odp_values"]

    r = assess(_FULL_META, [entry_no_key])
    baseline = assess(_FULL_META, [_entry(odp_values={})])

    assert r["odp_summary"] == {"total": 0, "unset": 0}
    assert r["missing_sections"] == baseline["missing_sections"] == []
    assert r["score"] == baseline["score"] == 100.0
    assert r["ready"] is baseline["ready"] is True
