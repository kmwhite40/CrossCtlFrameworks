"""Unit tests for SSP completeness/readiness scoring."""

from __future__ import annotations

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


def _entry(**kw):
    base = dict(
        control_id="AC.L2-3.1.1",
        part_narratives=[{"text": "The organization does X."}],
        responsible_role="System Owner",
        implementation_status=["Implemented"],
        control_origination=["Inherited"],
        odp_definitions=[],
        odp_values={},
    )
    base.update(kw)
    return base


def test_full_ssp_is_ready() -> None:
    r = assess(_FULL_META, [_entry(), _entry(control_id="AC.L2-3.1.2")])
    assert r["controls_complete"] == 2
    assert r["missing_sections"] == []
    assert r["ready"] is True
    assert r["score"] == 100.0


def test_missing_front_matter_flagged() -> None:
    r = assess({}, [_entry()])
    assert "System Owner" in r["missing_sections"]
    assert "FIPS-199 categorization" in r["missing_sections"]
    assert r["ready"] is False


def test_control_gaps_detected() -> None:
    bad = _entry(
        control_id="AU.L2-3.3.1",
        part_narratives=[{"text": ""}],
        responsible_role=None,
        odp_definitions=[{"key": "audit_retention_period"}],
        odp_values={},
    )
    r = assess(_FULL_META, [bad])
    gaps = r["control_gaps"][0]["gaps"]
    assert "no implementation narrative" in gaps
    assert "no responsible role" in gaps
    assert any("unfilled parameter" in g for g in gaps)
