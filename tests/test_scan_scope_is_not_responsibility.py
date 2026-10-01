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

from ccf.connectors.readiness import provider_readiness
from ccf.db import session_scope
from ccf.models import Organization
from ccf.posture.checks import checks_for
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


def test_an_unanswered_domain_not_on_the_list_still_needs_review() -> None:
    """The override table is a list, not a default.

    Found by mutation: replacing the membership test with a bare
    `return "scan"` -- opening *every* domain the template declines -- passed
    the entire file. That is the blanket-yes this design exists to avoid, and
    nothing was pinning against it.

    AT, CA, IR, MP, PS and RA are unanswered for the hyperscalers and are not
    overridden, because no check evidences them through a provider API. If one
    is ever written, it must arrive through a deliberate entry rather than
    inherit a default.
    """
    # RA left this list when `aws.inspector.enabled` shipped: enabling Inspector
    # is an account setting only the customer can turn on, so the domain is now
    # deliberately overridden. The rest remain unanswered and unoverridden.
    for domain in ("AT", "CA", "IR", "MP", "PS"):
        assert ("aws_govcloud", domain) not in SCAN_SCOPE_OVERRIDES
        assert responsibility_for("aws_govcloud", domain) == "unknown"
        assert scan_scope_for("aws_govcloud", domain) == "manual_scope_review", (
            f"aws_govcloud/{domain} is neither answered by the template nor "
            "overridden, so it must not be scannable"
        )
    # And a platform with no template at all is only open where listed.
    assert scan_scope_for("puppetdb", "CM") == "scan"
    assert scan_scope_for("puppetdb", "AC") == "manual_scope_review"


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


@pytest.mark.asyncio
async def test_readiness_itself_reports_the_new_scope_not_the_old_one() -> None:
    """Drive the real `provider_readiness`, because every other test stubs it.

    This is the assertion the first pass was missing. Nine tests pinned
    `scan_scope_for` directly and none of them noticed when `readiness.py` was
    reverted to `scan_applicability(responsibility.responsibility)` -- the whole
    fix backed out, all six checks dark again, suite green. Found by mutation,
    which is the only thing that finds it.

    `provider_readiness` builds its check descriptors before it looks at
    credentials, so an organization with no AWS connector still exercises the
    line under test; the status is `not_configured` and the descriptors are
    real.
    """
    async with session_scope() as session:
        org = Organization(name="ScanScopeWiring")
        session.add(org)
        await session.flush()
        readiness = await provider_readiness(
            session,
            organization_id=org.id,
            connector_key="aws_govcloud",
            persist=False,
        )
        await session.rollback()

    checks = readiness["checks"]
    # Derived from the registry, not hardcoded. This said `== 8` and broke the
    # moment two AWS checks were added -- a literal beside the thing it counts
    # measures when the suite last changed, not whether the suite is present.
    expected = len(checks_for("aws_govcloud"))
    assert expected, "the AWS provider must register checks"
    assert len(checks) == expected, (
        "readiness did not describe every registered AWS check, so the "
        "assertions below would be covering a subset"
    )

    not_scanning = [
        (c["check_key"], c["scan_applicability"])
        for c in checks
        if c["scan_applicability"] != "scan"
    ]
    assert not_scanning == [], (
        "provider_readiness is not using scan_scope_for -- these AWS checks are "
        f"still out of scope: {not_scanning}"
    )

    # Exactly the four that were blocked carry the override's reason -- both
    # directions, so neither a missing reason nor a reason spreading to checks
    # the template answers on its own can pass. `aws.s3.default_encryption` is
    # the useful negative: it is an S3 check, but its control is SC-28, which
    # the hyperscaler template answers as "shared" without any override.
    with_reason = {c["check_key"] for c in checks if c["scan_scope_reason"]}
    assert with_reason == {
        "aws.s3.public_access_blocked",
        "aws.iam.access_key_rotation",
        "aws.iam.password_policy",
        "aws.iam.root_mfa_enabled",
        "aws.inspector.enabled",
    }, f"unexpected set of override-scanned checks: {sorted(with_reason)}"


@pytest.mark.asyncio
async def test_readiness_still_withholds_a_provider_owned_domain() -> None:
    """The other direction, through the same real call path.

    M365's PE domain is Microsoft's. If a future override or a loosened default
    let it through, this is where it shows up -- at the descriptor an operator
    and the scan orchestrator both read, not at the helper.
    """
    async with session_scope() as session:
        org = Organization(name="ScanScopeWiringPE")
        session.add(org)
        await session.flush()
        readiness = await provider_readiness(
            session,
            organization_id=org.id,
            connector_key="msgraph",
            persist=False,
        )
        await session.rollback()

    # No msgraph check touches PE today, so assert the rule at the source the
    # descriptor is built from rather than inventing a check that does not exist.
    assert scan_scope_for("m365", "PE") == "inherited_evidence"
    assert all(c["scan_applicability"] == "scan" for c in readiness["checks"])
    assert all(c["scan_scope_reason"] is None for c in readiness["checks"]), (
        "M365 scans because its placemat answers the domain, not via an override"
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
