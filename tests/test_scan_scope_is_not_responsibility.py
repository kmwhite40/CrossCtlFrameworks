"""Scan scope and control responsibility are different questions.

Half the AWS suite never ran -- root MFA, password policy, access key rotation,
S3 public access block -- and PuppetDB never ran at all, because one table was
answering two questions at once.

`responsibility_for` says who *owns* a control. It feeds two regulator-facing
consumers: SSP control origination (`ssp.seed`) and SPRS scoring state
(`governance.automation._platform_state`). Both deliberately refuse to guess --
an unanswered domain is flagged for a human, because a guessed origination is an
assertion inside an authorization package and a guessed SPRS responsibility
moves a score reported to the DoD. The hyperscaler template answers PE, MA, SC,
AU, CM and SI, and says nothing about AC or IA.

Scan scope asks whether a check may read the customer's own configuration
through the provider's API with the customer's own credential. Nothing about
that requires settling who owns the control: an IAM password policy is set by
the customer whoever is deemed accountable for AC.

So the fix was **not** to answer AC and IA in the responsibility table. That
would have unblocked four checks and, in the same edit, changed what every AWS
system's SSP claims about its access-control origination *and* what its SPRS
score derives from. It was to stop asking the responsibility table a question
that was never its job.

The safety property that makes the split safe is tested here: an override can
only ever turn `manual_scope_review` into `scan`. A domain the template
positively calls provider-owned or not-applicable cannot be opened from the
override table, so it is not a backdoor around the safeguard it sits beside.
"""

from __future__ import annotations

import pytest

from ccf.ssp import constants
from ccf.ssp.responsibility import (
    SCAN_SCOPE_OVERRIDES,
    responsibility_for,
    scan_applicability,
    scan_scope_for,
    scan_scope_reason,
)


def test_an_override_only_upgrades_an_unanswered_domain() -> None:
    """The safety property, stated directly over the override table."""
    for (platform, domain), reason in SCAN_SCOPE_OVERRIDES.items():
        responsibility = responsibility_for(platform, domain)
        assert responsibility == "unknown", (
            f"{platform}/{domain} is overridden to scan, but the responsibility "
            f"template already answers it ({responsibility!r}). An override may "
            "only cover a domain the template declines, never contradict one it "
            "answers."
        )
        assert scan_applicability(responsibility) == "manual_scope_review"
        assert scan_scope_for(platform, domain) == "scan"
        assert reason


def test_an_override_cannot_open_a_provider_owned_control() -> None:
    """The backdoor that must not exist, exercised rather than asserted.

    PE is `inherited` for every hyperscaler -- physical protection of the
    provider's datacentres. Adding it to the override table must not make it
    scannable, because `scan_scope_for` upgrades only `manual_scope_review`.
    """
    assert responsibility_for("aws_govcloud", "PE") == "inherited"
    assert scan_scope_for("aws_govcloud", "PE") == "inherited_evidence"

    overridden = dict(SCAN_SCOPE_OVERRIDES)
    overridden[("aws_govcloud", "PE")] = "a reason someone talked themselves into"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "ccf.ssp.responsibility.SCAN_SCOPE_OVERRIDES", overridden, raising=True
        )
        assert scan_scope_for("aws_govcloud", "PE") == "inherited_evidence", (
            "an override talked over a positive provider-owned answer"
        )


def test_a_not_applicable_control_stays_not_applicable() -> None:
    """The other positive answer an override must not reach."""
    overridden = dict(SCAN_SCOPE_OVERRIDES)
    overridden[("m365", "ZZ")] = "reason"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "ccf.ssp.responsibility.SCAN_SCOPE_OVERRIDES", overridden, raising=True
        )
        # A coverage status of Not Applicable is a positive statement.
        assert (
            scan_scope_for("m365", "ZZ", coverage_status="Not Applicable")
            == "not_applicable"
        )


def test_the_aws_checks_that_were_blocked_now_scan() -> None:
    """The regression, named by the domains the four checks live in."""
    assert scan_scope_for("aws_govcloud", "AC") == "scan"
    assert scan_scope_for("aws_govcloud", "IA") == "scan"
    assert scan_scope_for("puppetdb", "CM") == "scan"


def test_scan_scope_did_not_change_who_is_responsible() -> None:
    """The point of the split: nothing regulator-facing moved.

    If this fails, the override table has started leaking into the SSP or the
    SPRS derivation -- which is the exact change the split exists to avoid.
    """
    # The responsibility answer for the overridden domains is still "unknown".
    assert responsibility_for("aws_govcloud", "AC") == "unknown"
    assert responsibility_for("aws_govcloud", "IA") == "unknown"

    # So the SSP still declines to originate them, and still flags them for a
    # human rather than asserting a value nobody chose.
    assert constants.platform_responsibility("aws_govcloud", "AC") is None
    assert constants.platform_responsibility("aws_govcloud", "IA") is None
    assert constants.needs_manual_responsibility_assignment("aws_govcloud", "AC") is True
    assert constants.needs_manual_responsibility_assignment("aws_govcloud", "IA") is True
    assert constants.platform_origination("aws_govcloud", None, "AC") == []
    assert constants.platform_origination("aws_govcloud", None, "IA") == []


def test_the_sprs_domain_table_did_not_gain_the_overridden_domains() -> None:
    """SPRS scoring reads `PLATFORM_DOMAIN_RESPONSIBILITY`, not scan scope.

    A score reported to the DoD must not move because a check became runnable.
    """
    for platform in ("azure", "aws_govcloud", "gcp"):
        table = constants.PLATFORM_DOMAIN_RESPONSIBILITY[platform]
        assert "AC" not in table, f"{platform} gained an AC responsibility"
        assert "IA" not in table, f"{platform} gained an IA responsibility"
        # The domains it did always answer are untouched.
        assert table["PE"] == "inherited"
        assert table["SC"] == "shared"


def test_the_reason_is_available_to_a_reader() -> None:
    """A scan that happened because of an override should be able to say so."""
    assert scan_scope_reason("aws_govcloud", "IA")
    assert "customer" in scan_scope_reason("aws_govcloud", "IA")
    # A domain answered by the template normally carries no override reason.
    assert scan_scope_reason("aws_govcloud", "PE") is None
    assert scan_scope_reason("m365", "AC") is None


def test_every_override_reason_is_specific() -> None:
    """A reason is what the next reader uses to decide whether to trust it."""
    for (platform, domain), reason in SCAN_SCOPE_OVERRIDES.items():
        assert len(reason.split()) >= 8, (
            f"{platform}/{domain}: reason too thin to evaluate: {reason!r}"
        )
        assert reason[0].isupper() or reason.startswith(("IAM", "S3", "PuppetDB")), (
            f"{platform}/{domain}: {reason!r}"
        )


def test_scan_scope_agrees_with_scan_applicability_where_the_template_answers() -> None:
    """The override table is additive; it must not alter settled answers."""
    for platform, domain in (
        ("aws_govcloud", "PE"),
        ("aws_govcloud", "SC"),
        ("azure", "AU"),
        ("gcp", "CM"),
        ("m365", "AC"),
        ("m365", "PE"),
        ("none", "AC"),
    ):
        expected = scan_applicability(responsibility_for(platform, domain))
        assert scan_scope_for(platform, domain) == expected, (
            f"{platform}/{domain} diverged from the responsibility-derived answer"
        )
