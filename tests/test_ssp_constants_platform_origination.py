"""Pure unit tests for the per-platform origination vocabulary in
ccf.ssp.constants — no DB needed. See tests/test_ssp_seed_platform_origination.py
for the real-production-path integration coverage of ccf.ssp.seed."""

from __future__ import annotations

from ccf.ssp import constants


def test_m365_origination_uses_per_practice_coverage_status() -> None:
    assert constants.platform_origination("m365", "Microsoft Coverage", "PE") == ["Inherited"]
    assert constants.platform_origination("m365", "Customer Responsibility", "AC") == [
        "Configured by Customer / Business Owner"
    ]
    assert not constants.needs_manual_responsibility_assignment("m365", "AC")


def test_aws_and_azure_use_the_domain_table_not_m365_coverage() -> None:
    # m365 coverage status is irrelevant on a non-m365 platform.
    for plat in ("aws_govcloud", "azure"):
        assert constants.platform_origination(plat, "Customer Responsibility", "PE") == [
            "Inherited"
        ]
        assert constants.platform_origination(plat, "Microsoft Coverage", "CM") == ["Shared"]


def test_domain_outside_the_table_is_flagged_not_defaulted() -> None:
    for plat in ("aws_govcloud", "azure"):
        assert constants.needs_manual_responsibility_assignment(plat, "AC") is True
        assert constants.platform_origination(plat, "Shared Coverage", "AC") == []
        # Never silently default an unknown-responsibility control to a
        # customer/system-specific origination value.
        assert "Configured by Customer / Business Owner" not in constants.platform_origination(
            plat, "Shared Coverage", "AC"
        )
        assert "Organization System Specific" not in constants.platform_origination(
            plat, "Shared Coverage", "AC"
        )


def test_manual_flag_is_free_text_not_a_new_origination_vocabulary_value() -> None:
    # The flag string itself is not one of the origination options — it's a
    # separate, explicit signal (surfaced via responsible_role), never smuggled
    # into control_origination as a fabricated vocabulary term.
    assert constants.MANUAL_RESPONSIBILITY_FLAG not in constants.CONTROL_ORIGINATION_OPTIONS


def test_platform_domain_table_never_produces_a_system_specific_origination() -> None:
    """A provider-performed (inherited) or provider-shared control must never
    render as 'Organization System Specific' / a pure customer value — the
    domain table only maps to Inherited or Shared."""
    for plat, table in constants.PLATFORM_DOMAIN_RESPONSIBILITY.items():
        for domain in table:
            origination = constants.platform_origination(plat, None, domain)
            assert origination
            assert "Organization System Specific" not in origination
