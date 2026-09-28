"""Shared-responsibility templates feed SSP origination and live-audit scope."""

from __future__ import annotations

from ccf.ssp import constants
from ccf.ssp.responsibility import (
    TEMPLATE_VERSION,
    origination_for,
    responsibility_entry_for,
    responsibility_for,
    scan_applicability,
    template_entries,
)


def test_hyperscaler_template_entries_are_versioned() -> None:
    entries = template_entries("aws_govcloud")
    assert entries
    assert {e.version for e in entries} == {TEMPLATE_VERSION}
    pe = next(e for e in entries if e.domain == "PE")
    assert pe.responsibility == "inherited"
    assert pe.scope == "domain"
    assert pe.framework == "cmmc-800-171"


def test_existing_ssp_constants_delegate_to_templates() -> None:
    assert constants.platform_responsibility("aws_govcloud", "PE") == "inherited"
    assert constants.platform_origination("aws_govcloud", None, "PE") == ["Inherited"]
    assert constants.platform_responsibility("aws_govcloud", "AC") is None
    assert constants.needs_manual_responsibility_assignment("aws_govcloud", "AC") is True


def test_no_platform_is_customer_owned_not_unknown() -> None:
    assert responsibility_for("none", "AC") == "customer"
    assert constants.platform_responsibility("none", "AC") == "customer"
    assert scan_applicability("customer") == "scan"


def test_m365_uses_per_control_coverage_status() -> None:
    shared = responsibility_entry_for(
        "m365", "AC", coverage_status="Shared Coverage"
    )
    inherited = responsibility_entry_for(
        "m365", "PE", coverage_status="Microsoft Coverage"
    )
    assert shared.responsibility == "shared"
    assert inherited.responsibility == "inherited"
    assert origination_for(shared.responsibility) == ["Shared"]
    assert scan_applicability(inherited.responsibility) == "inherited_evidence"


def test_unknown_template_requires_manual_scope_review() -> None:
    assert responsibility_for("aws_govcloud", "IA") == "unknown"
    assert scan_applicability("unknown") == "manual_scope_review"
