"""A registered check that can never be scanned must be named, not silent.

The M365 defect (see `test_m365_responsibility_is_answered.py`) was invisible
for as long as it existed because nothing anywhere asserted that a check Concord
ships can actually run. A check resolving to `manual_scope_review` looks
identical, in every aggregate the product reports, to a check that simply has
nothing to say yet -- and the gap only surfaced because a scheduler cycle
happened to print `checks_expected=164, checks_run=0` where a human could read
it.

Fixing M365 alone would leave that blindness in place, so this guard covers
every registered provider: each check must resolve to `scan`, or appear below
with a reason. A new check whose control domain no template answers now fails
here rather than disappearing into a manual-review count.

Two providers are currently in that state, and both are recorded rather than
fixed, because the fix is not the scan path's to make. `responsibility_for`
feeds **two** consumers: this scan-scope decision, and -- through
`ssp.constants.platform_responsibility` -- SSP control origination. The
hyperscaler template deliberately leaves a domain unanswered rather than
defaulting it (`needs_manual_responsibility_assignment`), so that an SSP flags
the control for a human instead of asserting an origination nobody chose.
Adding "AC" and "IA" to that table to unblock four AWS checks would also, and
silently, change what an AWS system's SSP claims about who originates its
access-control requirements. That is a decision about a regulator-facing
document, not about scan coverage, and it is not taken here.
"""

from __future__ import annotations

import pytest

from ccf.connectors import connector_keys
from ccf.connectors.readiness import _CONNECTOR_PLATFORM
from ccf.posture.checks import checks_for
from ccf.ssp.responsibility import (
    control_domain,
    responsibility_for,
    scan_applicability,
)

#: Checks that cannot currently be scanned, each with the reason and what would
#: change it. Anything not listed here must resolve to `scan`.
#:
#: These are *defects*, not design. A tenant that binds one of these credentials
#: gets a ready connector whose checks produce no evidence -- the exact failure
#: the M365 fix removed, still present on these two providers.
UNSCANNABLE: dict[str, str] = {
    # The hyperscaler template answers PE, MA, SC, AU, CM and SI. AC and IA are
    # unanswered, so half the AWS suite -- including root MFA, password policy
    # and key rotation, which are among the checks an assessor asks for first --
    # resolves to manual scope review on every AWS tenant.
    "aws.s3.public_access_blocked": "aws_govcloud template does not answer domain AC",
    "aws.iam.access_key_rotation": "aws_govcloud template does not answer domain IA",
    "aws.iam.password_policy": "aws_govcloud template does not answer domain IA",
    "aws.iam.root_mfa_enabled": "aws_govcloud template does not answer domain IA",
    # PuppetDB has no template at all, so *every* check it ships is filtered
    # out. It is a customer-operated config-management server rather than a
    # cloud platform, so unlike the hyperscalers there is no provider whose
    # responsibility could be in question -- but giving it a template is still a
    # deliberate addition, not a silent default.
    "puppetdb.node.last_run_succeeded": (
        "no responsibility template exists for platform 'puppetdb'"
    ),
    "puppetdb.node.reporting": (
        "no responsibility template exists for platform 'puppetdb'"
    ),
}


def _applicability(connector_key: str, check: object) -> tuple[str, str | None]:
    platform = _CONNECTOR_PLATFORM.get(connector_key, connector_key)
    control_ids = getattr(check, "control_ids", ())
    domain = control_domain(control_ids[0] if control_ids else None)
    return scan_applicability(responsibility_for(platform, domain)), domain


def _all_checks() -> list[tuple[str, object]]:
    return [(key, check) for key in sorted(connector_keys()) for check in checks_for(key)]


def test_every_registered_check_scans_or_is_named() -> None:
    """The allowlist is exhaustive: no check may quietly fail to scan."""
    unexpected: list[str] = []
    for connector_key, check in _all_checks():
        applicability, domain = _applicability(connector_key, check)
        if applicability == "scan":
            continue
        if check.key not in UNSCANNABLE:  # type: ignore[attr-defined]
            unexpected.append(
                f"{check.key} ({connector_key}, domain={domain}) -> {applicability}"  # type: ignore[attr-defined]
            )
    assert unexpected == [], (
        "these checks would never run, and nothing else would say so:\n  "
        + "\n  ".join(unexpected)
        + "\nEither answer the domain in the platform's responsibility template, "
        "or add the check to UNSCANNABLE with the reason."
    )


def test_the_allowlist_has_no_stale_entries() -> None:
    """An entry that starts scanning must be removed, or the list stops meaning
    anything. This is the half of an allowlist guard that usually rots."""
    registered = {
        check.key: (connector_key, check)  # type: ignore[attr-defined]
        for connector_key, check in _all_checks()
    }
    stale: list[str] = []
    for key in UNSCANNABLE:
        if key not in registered:
            stale.append(f"{key} is no longer a registered check")
            continue
        connector_key, check = registered[key]
        if _applicability(connector_key, check)[0] == "scan":
            stale.append(f"{key} now scans and should be removed from UNSCANNABLE")
    assert stale == [], "\n".join(stale)


def test_every_allowlist_entry_gives_a_real_reason() -> None:
    """A reason of "TODO" teaches the next reader nothing."""
    for key, reason in UNSCANNABLE.items():
        assert len(reason.split()) >= 5, f"{key}: reason too thin to act on: {reason!r}"
        assert "template" in reason, (
            f"{key}: the reason must name what is missing, not just that something is"
        )


def test_msgraph_is_not_on_the_list() -> None:
    """The regression this guard was written for."""
    msgraph_keys = {check.key for check in checks_for("msgraph")}
    assert msgraph_keys, "msgraph must register checks"
    assert msgraph_keys & set(UNSCANNABLE) == set()


@pytest.mark.parametrize("connector_key", ["msgraph", "azure_arm", "gcp"])
def test_fully_scannable_providers_stay_that_way(connector_key: str) -> None:
    """Named individually so a regression says which provider went dark."""
    blocked = [
        check.key
        for check in checks_for(connector_key)
        if _applicability(connector_key, check)[0] != "scan"
    ]
    assert blocked == [], f"{connector_key} checks no longer in scan scope: {blocked}"


def test_the_gap_is_measured_not_just_guarded() -> None:
    """State the size of the hole, so it cannot shrink out of anyone's attention.

    A count is what makes "some checks do not run" actionable; the runbook's
    coverage table counts checks that *exist*, which is a different number.
    """
    total = len(_all_checks())
    blocked = sum(
        1 for ck, check in _all_checks() if _applicability(ck, check)[0] != "scan"
    )
    assert blocked == len(UNSCANNABLE)
    assert (total, blocked) == (32, 6), (
        f"{blocked} of {total} registered checks cannot be scanned; update this "
        "assertion deliberately, and the runbook's section 7 with it"
    )
