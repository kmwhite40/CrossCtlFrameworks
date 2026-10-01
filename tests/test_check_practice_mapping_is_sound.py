"""The check-to-practice mapping is compliance content, so it is guarded like it.

Each entry in `ccf.posture.practices.CHECK_PRACTICES` asserts that an automated
check is evidence for a named CMMC practice. That claim reaches an authorization
package: a wrong entry files a finding against a requirement the organization
was never failing, or credits one it was. These guards cover the failure modes
that a reader skimming the table would not catch.

They do not, and cannot, check that a mapping is *correct* -- that is a judgment
recorded in the quoted requirement text beside each entry. What they check is
that every id is real, every check is accounted for either way, the two
vocabularies stay separate, and the pass/fail asymmetry holds identically in
both.
"""

from __future__ import annotations

import pytest

from ccf.connectors import connector_keys
from ccf.posture.checks import checks_for
from ccf.posture.evidence import (
    non_passing_practice_attribution,
    pass_practice_attribution,
)
from ccf.posture.practices import CHECK_PRACTICES, UNMAPPED, practices_for_check
from ccf.scoring.parser import load_seed


def _registered_check_keys() -> set[str]:
    return {c.key for k in connector_keys() for c in checks_for(k)}


def _real_practice_ids() -> set[str]:
    return {r["control_id"] for r in load_seed() if r.get("control_id")}


def test_every_mapped_practice_is_a_real_practice() -> None:
    """A typo here becomes a finding filed against nothing.

    Checked against the committed scoring placemat, which is what
    `seed_project_entries` builds a CMMC project's entries from -- so this is
    the same id space the SSP will look the finding up in.
    """
    real = _real_practice_ids()
    assert real, "the placemat must be readable for this guard to mean anything"
    unknown = {
        (check_key, practice)
        for check_key, practices in CHECK_PRACTICES.items()
        for practice in practices
        if practice not in real
    }
    assert unknown == set(), f"practices that do not exist in the placemat: {sorted(unknown)}"


def test_every_mapped_check_is_a_registered_check() -> None:
    """The other half: a mapping for a check nobody ships is dead content."""
    registered = _registered_check_keys()
    orphans = set(CHECK_PRACTICES) - registered
    assert orphans == set(), f"mapped but not registered: {sorted(orphans)}"
    orphan_exclusions = set(UNMAPPED) - registered
    assert orphan_exclusions == set(), (
        f"listed as unmapped but not registered: {sorted(orphan_exclusions)}"
    )


def test_every_registered_check_is_decided_either_way() -> None:
    """No check may be silently absent from both tables.

    This is the guard that keeps the gap a decision. A new check that maps to
    nothing has to be written down as unmapped, with the argument, rather than
    quietly producing verdicts no CMMC document can place.
    """
    registered = _registered_check_keys()
    decided = set(CHECK_PRACTICES) | set(UNMAPPED)
    undecided = registered - decided
    assert undecided == set(), (
        f"these checks are in neither CHECK_PRACTICES nor UNMAPPED: "
        f"{sorted(undecided)}. Map them, or record why they cannot be."
    )


def test_a_check_is_not_both_mapped_and_excluded() -> None:
    both = set(CHECK_PRACTICES) & set(UNMAPPED)
    assert both == set(), f"listed in both tables: {sorted(both)}"


def test_every_exclusion_states_an_argument() -> None:
    """"Unmapped" without a reason is indistinguishable from forgotten."""
    for key, reason in UNMAPPED.items():
        assert len(reason.split()) >= 15, (
            f"{key}: the reason must say what would have to be true, not just "
            f"that it is not mapped: {reason!r}"
        )
        # Naming a candidate practice is what lets the next reader disagree.
        assert any(token in reason for token in ("3.", "800-171")), (
            f"{key}: name the practice(s) considered, so the call can be reviewed"
        )


def test_practices_and_control_ids_stay_in_separate_vocabularies() -> None:
    """A CMMC practice must never appear where an 800-53 id belongs.

    The two id spaces are what the whole defect was about. If a check's
    `control_ids` ever grew a practice id, the rollups keyed on 800-53 would
    start counting it as a control and the coverage numbers would drift.
    """
    for key in connector_keys():
        for check in checks_for(key):
            for cid in check.control_ids:
                assert ".L2-" not in cid, (
                    f"{check.key} declares {cid!r} as an 800-53 control id"
                )
    for practices in CHECK_PRACTICES.values():
        for practice in practices:
            assert ".L2-" in practice, f"{practice!r} is not a CMMC practice id"


def test_no_practice_is_listed_twice_for_one_check() -> None:
    """A duplicate would double-count the same finding on one control."""
    for check_key, practices in CHECK_PRACTICES.items():
        assert len(practices) == len(set(practices)), f"{check_key} repeats a practice"
        assert practices, f"{check_key} maps to an empty tuple; use UNMAPPED instead"


@pytest.mark.parametrize(
    ("check_key", "expected"),
    [
        # The four that were failing on the live tenant, which is why they are
        # spelled out rather than derived: a mapping generated from the table
        # cannot disagree with the table.
        ("m365.identity.mfa_registered", "IA.L2-3.5.3"),
        ("m365.identity.stale_accounts", "IA.L2-3.5.6"),
        ("m365.policy.guest_invites_restricted", "AC.L2-3.1.1"),
        ("m365.policy.default_user_permissions_restricted", "AC.L2-3.1.5"),
        # And the one whose requirement text is the most exact match of all.
        ("m365.device.session_lock_enforced", "AC.L2-3.1.10"),
    ],
)
def test_the_mappings_that_matter_are_pinned(check_key: str, expected: str) -> None:
    assert practices_for_check(check_key)[0] == expected


def test_the_pass_fail_asymmetry_holds_for_practices_too() -> None:
    """A pass credits the primary practice; a non-pass reaches all of them.

    The same rule `ccf.posture.evidence` applies to 800-53 ids. If these
    diverged, a single narrow check could mark several CMMC practices satisfied
    -- a value that validates and is wrong, in a document a regulator acts on.
    """
    multi = "m365.identity.phishing_resistant_mfa"
    assert len(practices_for_check(multi)) > 1, "this test needs a multi-practice check"

    assert pass_practice_attribution(multi) == ["IA.L2-3.5.4"]
    assert non_passing_practice_attribution(multi) == ["IA.L2-3.5.4", "IA.L2-3.5.3"]
    assert len(non_passing_practice_attribution(multi)) > len(
        pass_practice_attribution(multi)
    ), "a failure must reach more practices than a pass credits"


def test_attribution_is_empty_for_an_unmapped_or_unknown_check() -> None:
    """No key, no guess -- in both directions."""
    for key in ("aws.iam.access_key_rotation", "not.a.check", "", None):
        assert pass_practice_attribution(key) == []
        assert non_passing_practice_attribution(key) == []


def test_the_mapped_share_is_stated_not_implied() -> None:
    """Say how much of the suite reaches a CMMC document.

    A count is the difference between "the mapping exists" and knowing what it
    covers. Update it deliberately, along with the runbook.
    """
    registered = _registered_check_keys()
    assert (len(registered), len(CHECK_PRACTICES), len(UNMAPPED)) == (38, 34, 4)
