"""A registered check that can never be scanned must be named, not silent.

The M365 defect (see `test_m365_responsibility_is_answered.py`) was invisible
for as long as it existed because nothing anywhere asserted that a check Concord
ships can actually run. A check resolving to `manual_scope_review` looks
identical, in every aggregate the product reports, to a check that simply has
nothing to say yet -- and the gap only surfaced because a scheduler cycle
happened to print `checks_expected=164, checks_run=0` where a human could read
it.

Writing this guard found the same defect on two more providers: `aws_govcloud`
could not scan 4 of its 8 checks (root MFA, password policy, access key
rotation, S3 public access block) and `puppetdb` could not scan either of its
two. Both are fixed -- see `test_scan_scope_is_not_responsibility.py` -- so
`UNSCANNABLE` is empty, which is the state this file exists to keep.

It is kept rather than deleted because an empty allowlist is a claim that has to
go on failing: a check added for a control whose domain no template answers must
land here, in a review, rather than in a manual-review count nobody reads.
"""

from __future__ import annotations

import pytest

from ccf.connectors import connector_keys
from ccf.connectors.readiness import _CONNECTOR_PLATFORM
from ccf.posture.checks import checks_for
from ccf.ssp.responsibility import control_domain, scan_scope_for

#: Checks that cannot currently be scanned, each with the reason and what would
#: change it. **Currently empty, and that is the point.**
#:
#: Adding an entry is a deliberate act: it says a check ships that produces no
#: evidence for anybody, which is the failure mode this whole file exists to
#: make loud. Prefer answering the domain -- in the platform's responsibility
#: template if the question is who owns the control, or in
#: `SCAN_SCOPE_OVERRIDES` if the control is plainly customer-configured and only
#: the ownership attribution is unsettled.
UNSCANNABLE: dict[str, str] = {}


def _applicability(connector_key: str, check: object) -> tuple[str, str | None]:
    platform = _CONNECTOR_PLATFORM.get(connector_key, connector_key)
    control_ids = getattr(check, "control_ids", ())
    domain = control_domain(control_ids[0] if control_ids else None)
    return scan_scope_for(platform, domain), domain


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
        + "\nAnswer the domain in the platform's responsibility template, or add "
        "the pair to SCAN_SCOPE_OVERRIDES, or -- last resort -- add the check to "
        "UNSCANNABLE with the reason."
    )


def test_the_allowlist_is_empty() -> None:
    """Every registered check is scannable today. Keep it that way.

    This is deliberately a separate assertion from the one above: that one
    permits an allowlisted check, this one says nothing is allowlisted. A change
    that needs an entry fails here and gets read by someone.
    """
    assert UNSCANNABLE == {}, (
        f"{len(UNSCANNABLE)} check(s) ship without being scannable: "
        f"{sorted(UNSCANNABLE)}"
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


@pytest.mark.parametrize(
    "connector_key", ["msgraph", "aws_govcloud", "azure_arm", "gcp", "puppetdb"]
)
def test_every_provider_is_fully_scannable(connector_key: str) -> None:
    """Named individually so a regression says which provider went dark."""
    checks = checks_for(connector_key)
    assert checks, f"{connector_key} must register checks"
    blocked = [
        check.key
        for check in checks
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
    assert (total, blocked) == (42, 0), (
        f"{blocked} of {total} registered checks cannot be scanned; update this "
        "assertion deliberately, and the runbook's section 7 with it"
    )
