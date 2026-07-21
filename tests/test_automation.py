"""Unit tests for profile-driven derivation (pure applicability/inheritance)."""

from __future__ import annotations

from types import SimpleNamespace as N

from ccf.governance.automation import (
    _COVERAGE_TO_STATE,
    _platform_state,
    na_control_ids,
    ssp_overlay_for,
)
from ccf.scoring.engine import _MET


def _profile(**kw):
    base = dict(endpoint_scope=[], connectivity="internet", cloud_platform=None)
    base.update(kw)
    return N(**base)


def test_na_rules_mobile_and_wireless() -> None:
    # No mobile/byod and not wireless -> both mobile and wireless controls are N/A.
    na = na_control_ids(_profile())
    assert "AC.L2-3.1.18" in na  # mobile
    assert "AC.L2-3.1.16" in na  # wireless
    # With mobile endpoints and wireless connectivity, none are N/A.
    na2 = na_control_ids(_profile(endpoint_scope=["mobile"], connectivity="wireless"))
    assert na2 == set()


def test_m365_per_practice_inheritance() -> None:
    sc = N(m365_coverage_status="Microsoft Coverage", domain="PE")
    state, resp, source = _platform_state("m365_gcc_high", sc)
    assert (state, resp) == ("inherited", "inherited")
    assert "m365_gcc_high" in source
    sc2 = N(m365_coverage_status="Customer Responsibility", domain="AC")
    assert _platform_state("m365_gcc_high", sc2)[0] == "not_implemented"


def test_platform_domain_default_and_fallback() -> None:
    # Azure Gov: PE inherited by domain default; AC has no per-control or
    # per-domain coverage data for Azure, so it's flagged "unknown" (needs
    # manual responsibility assignment) rather than silently guessed as
    # "customer" (FR-12) — see ssp/constants.py needs_manual_responsibility_assignment.
    assert _platform_state("azure_gov", N(m365_coverage_status=None, domain="PE"))[0] == "inherited"
    assert _platform_state("azure_gov", N(m365_coverage_status=None, domain="AC"))[1] == "unknown"
    # No cloud platform at all -> nothing can be inherited, so "customer" is a
    # correct, non-guessed default (not the same situation as an unmapped
    # domain on a *known* cloud platform, above).
    assert _platform_state("none", N(m365_coverage_status=None, domain="PE"))[1] == "customer"


def test_coverage_states_are_scoring_met() -> None:
    # inherited + not_applicable must be states the SPRS engine treats as met.
    assert _COVERAGE_TO_STATE["Microsoft Coverage"][0] in _MET
    assert _COVERAGE_TO_STATE["Not Applicable"][0] in _MET


def test_unknown_responsibility_overlay_does_not_assert_a_confident_origination() -> None:
    """An 'unknown' control (no per-control/per-domain coverage data on this
    platform) must not have the profile-driven SSP overlay overwrite it with a
    confident customer/system-specific origination — the seed layer's
    manual-assignment flag (ssp/constants.py) must survive untouched."""
    derivation = {"AC.L2-3.1.1": {"responsibility": "unknown", "state": "not_implemented"}}
    overlay = ssp_overlay_for("AC.L2-3.1.1", derivation)
    assert overlay["control_origination"] == []
