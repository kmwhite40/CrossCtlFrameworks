"""Session lock, storage encryption and reauthentication, against real Graph shapes.

Three checks chosen because they are the ones this provider can actually
evidence that were still missing: they close AC-11, AC-11(1), AC-12, AC-19(5),
SC-28 and SC-28(1) in the Moderate baseline, and 800-171 requirements 3.1.10,
3.1.11, 3.1.19 and 3.13.16 -- four more than any scan could reach before.

All three are asked of the **tenant**, not of each policy. A device compliance
policy that governs only OS versions does not configure a screen lock, and
reading its silence as a refusal would manufacture findings against
correctly-scoped policies. That is the same misattribution
``DEVICE_UNEVALUATED_STATES`` exists to prevent on the sibling per-device check.
"""

from __future__ import annotations

import pytest

from ccf.posture.parameters import ParameterError, parameterize, validate_parameters
from ccf.posture.providers import m365

TENANT = "d0529da6-0000-0000-0000-000000000000"


def _policy(**kw: object) -> dict[str, object]:
    """An Intune compliance policy with only the keys a caller sets.

    Deliberately sparse: a real policy carries only the properties its
    platform-specific type declares, so an evaluator must never assume a key
    is present.
    """
    base: dict[str, object] = {"id": "pol-1", "displayName": "Baseline"}
    base.update(kw)
    return base


# --- AC-11 / AC-11(1) inactivity lock ----------------------------------------


def test_a_policy_that_locks_within_the_expected_period_passes() -> None:
    rows = [
        _policy(**{"passwordRequired": True, "passwordMinutesOfInactivityBeforeLock": 15})
    ]
    f = m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT)
    assert [x.verdict for x in f] == ["pass"]
    assert f[0].resource_type == "m365_tenant"
    assert "15 minute(s)" in f[0].observed


def test_the_boundary_is_inclusive() -> None:
    """`SESSION_LOCK_MAX_MINUTES` is a maximum, so exactly that value passes."""
    at = [
        _policy(
            **{
                "passwordRequired": True,
                "passwordMinutesOfInactivityBeforeLock": m365.SESSION_LOCK_MAX_MINUTES,
            }
        )
    ]
    over = [
        _policy(
            **{
                "passwordRequired": True,
                "passwordMinutesOfInactivityBeforeLock": m365.SESSION_LOCK_MAX_MINUTES + 1,
            }
        )
    ]
    assert m365.evaluate_session_lock_enforced(at, tenant_id=TENANT)[0].verdict == "pass"
    assert m365.evaluate_session_lock_enforced(over, tenant_id=TENANT)[0].verdict == "fail"


def test_a_lock_that_is_too_late_says_how_late() -> None:
    """"No policy" and "a policy that locks too late" need different remedies."""
    rows = [_policy(**{"passwordRequired": True, "passwordMinutesOfInactivityBeforeLock": 60})]
    f = m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"
    assert "soonest at 60 minute(s)" in f[0].observed
    assert f[0].detail["policies_with_a_lock"] == 1


def test_a_lock_period_without_a_required_password_does_not_pass() -> None:
    """A timeout on a device with no password locks nothing anybody has to unlock."""
    rows = [_policy(**{"passwordRequired": False, "passwordMinutesOfInactivityBeforeLock": 5})]
    f = m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"
    assert "do not require a password" in f[0].observed


@pytest.mark.parametrize("value", [0, None, "15", True, -5])
def test_a_lock_value_that_is_not_a_positive_integer_counts_as_unset(value) -> None:
    """Intune reports 0 as "not configured" on some platform types.

    Reading 0 as "locks immediately" would turn an unconfigured policy into the
    strongest possible pass. `True` is excluded on purpose: in Python it is an
    `int`, and `passwordMinutesOfInactivityBeforeLock: true` is not 1 minute.
    """
    rows = [_policy(**{"passwordRequired": True, "passwordMinutesOfInactivityBeforeLock": value})]
    f = m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"
    assert f[0].detail["policies_with_a_lock"] == 0


def test_one_qualifying_policy_among_many_is_enough() -> None:
    """The question is whether the tenant requires it, not whether all policies do.

    A policy scoped to encryption alone carries no lock setting; failing the
    tenant for that would invent a finding against a correctly-narrow policy.
    """
    rows = [
        _policy(id="enc", **{"storageRequireEncryption": True}),
        _policy(id="osver", **{"osMinimumVersion": "10.0"}),
        _policy(
            id="lock",
            **{"passwordRequired": True, "passwordMinutesOfInactivityBeforeLock": 10},
        ),
    ]
    f = m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT)
    assert f[0].verdict == "pass"
    assert f[0].detail["policy_id"] == "lock"
    assert f[0].detail["policies_examined"] == 3


def test_no_compliance_policy_at_all_is_reported_as_such() -> None:
    f = m365.evaluate_session_lock_enforced([], tenant_id=TENANT)
    assert f[0].verdict == "fail"
    assert f[0].observed == "no device compliance policy exists"


# --- SC-28 / SC-28(1) / AC-19(5) storage encryption --------------------------


def test_a_policy_requiring_storage_encryption_passes() -> None:
    rows = [_policy(displayName="Encrypt", **{"storageRequireEncryption": True})]
    f = m365.evaluate_storage_encryption_required(rows, tenant_id=TENANT)
    assert [x.verdict for x in f] == ["pass"]
    assert "requires storage encryption" in f[0].observed


@pytest.mark.parametrize("value", [False, None, "true", 1])
def test_anything_other_than_a_true_boolean_is_not_a_requirement(value) -> None:
    """A string "true" from a mis-serialized policy is not a configured control."""
    rows = [_policy(**{"storageRequireEncryption": value})]
    f = m365.evaluate_storage_encryption_required(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"


def test_policies_that_do_not_mention_encryption_fail_the_tenant_not_themselves() -> None:
    rows = [_policy(id="a", **{"passwordRequired": True}), _policy(id="b")]
    f = m365.evaluate_storage_encryption_required(rows, tenant_id=TENANT)
    assert len(f) == 1, "one finding per tenant, not one per policy"
    assert f[0].verdict == "fail"
    assert "none of 2 device compliance policy" in f[0].observed


# --- AC-12 session reauthentication ------------------------------------------


def _ca(state: str = "enabled", frequency: object | None = None) -> dict[str, object]:
    policy: dict[str, object] = {"id": "ca-1", "displayName": "Bound sessions", "state": state}
    if frequency is not None:
        policy["sessionControls"] = {"signInFrequency": frequency}
    return policy


def test_an_enabled_policy_with_a_sign_in_frequency_passes() -> None:
    rows = [_ca(frequency={"isEnabled": True, "value": 4, "type": "hours"})]
    f = m365.evaluate_session_reauthentication_required(rows, tenant_id=TENANT)
    assert [x.verdict for x in f] == ["pass"]
    assert "4 hours" in f[0].observed


def test_every_time_reauthentication_is_recognised() -> None:
    """Graph expresses this as `frequencyInterval`, with no value or type."""
    rows = [_ca(frequency={"isEnabled": True, "frequencyInterval": "everyTime"})]
    f = m365.evaluate_session_reauthentication_required(rows, tenant_id=TENANT)
    assert f[0].verdict == "pass"
    assert "every use" in f[0].observed


@pytest.mark.parametrize("state", ["disabled", "enabledForReportingButNotEnforced"])
def test_a_policy_not_in_force_reauthenticates_nobody(state) -> None:
    """Report-only is the trap: the policy exists and enforces nothing.

    Counting it would report AC-12 as operating on the strength of a policy
    somebody deliberately left out of force.
    """
    rows = [_ca(state=state, frequency={"isEnabled": True, "value": 1, "type": "hours"})]
    f = m365.evaluate_session_reauthentication_required(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"


def test_a_sign_in_frequency_switched_off_does_not_count() -> None:
    rows = [_ca(frequency={"isEnabled": False, "value": 4, "type": "hours"})]
    f = m365.evaluate_session_reauthentication_required(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"


def test_a_policy_with_no_session_controls_is_handled() -> None:
    """Most CA policies carry `sessionControls: null`, which must not raise."""
    rows = [_ca(), {"id": "x", "state": "enabled", "sessionControls": None}]
    f = m365.evaluate_session_reauthentication_required(rows, tenant_id=TENANT)
    assert f[0].verdict == "fail"
    assert f[0].detail["policies_examined"] == 2


def test_the_first_qualifying_policy_among_many_is_the_evidence() -> None:
    rows = [
        _ca(state="disabled", frequency={"isEnabled": True, "value": 1, "type": "hours"}),
        {"id": "good", "displayName": "Real", "state": "enabled",
         "sessionControls": {"signInFrequency": {"isEnabled": True, "value": 8, "type": "hours"}}},
    ]
    f = m365.evaluate_session_reauthentication_required(rows, tenant_id=TENANT)
    assert f[0].verdict == "pass"
    assert f[0].detail["policy_id"] == "good"


# --- the registry stays consistent -------------------------------------------


def test_each_new_check_is_wired_end_to_end() -> None:
    """A check with no endpoint or no evaluator is a check that never runs.

    The scan dispatches by key through both dicts, so a definition added to
    CHECKS alone would be advertised and never executed -- the
    advertised-versus-emitted defect this codebase has already had once.
    """
    for check in (
        m365.SESSION_LOCK_ENFORCED,
        m365.STORAGE_ENCRYPTION_REQUIRED,
        m365.SESSION_REAUTHENTICATION_REQUIRED,
    ):
        assert check in m365.CHECKS, check.key
        assert check.key in m365.ENDPOINTS, check.key
        assert check.key in m365.EVALUATORS, check.key
        assert check.control_ids, check.key
        assert check.required_permissions, (
            f"{check.key} names no permission, so a 403 cannot be explained"
        )


# --- the lock period is organization-defined ---------------------------------


def test_a_pack_can_set_its_own_lock_period_and_the_prose_follows() -> None:
    """A parameter is worthless if the statement lies about it.

    FedRAMP and CMMC both leave the inactivity period organization-defined, so
    the check takes one -- and `SESSION_LOCK_EXPECTED` is re-rendered with it,
    because a check enforcing 30 minutes while its `expected` text claims 15
    would put a false sentence into an authorization package.
    """
    relaxed = parameterize(m365.SESSION_LOCK_ENFORCED, {"max_minutes": 30})
    assert "30 minutes" in relaxed.expected
    assert "15" not in relaxed.expected, "the prose still quotes the platform default"

    rows = [
        _policy(**{"passwordRequired": True, "passwordMinutesOfInactivityBeforeLock": 30})
    ]
    assert (
        m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT)[0].verdict == "fail"
    ), "30 minutes passes against the platform's own 15-minute expectation"
    assert (
        m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT, max_minutes=30)[0].verdict
        == "pass"
    )


def test_the_failure_message_quotes_the_period_in_force_not_the_default() -> None:
    rows = [_policy(**{"passwordRequired": True, "passwordMinutesOfInactivityBeforeLock": 45})]
    f = m365.evaluate_session_lock_enforced(rows, tenant_id=TENANT, max_minutes=30)
    assert f[0].verdict == "fail"
    assert "longer than the 30 expected" in f[0].observed
    assert f[0].detail["expected_max_minutes"] == 30


@pytest.mark.parametrize("bad", [0, -1, "30", True, 1.5, None])
def test_an_invalid_lock_period_is_refused_at_install(bad) -> None:
    """Validation runs when a pack is installed, not mid-scan."""
    assert validate_parameters(m365.SESSION_LOCK_ENFORCED.key, {"max_minutes": bad})
    with pytest.raises(ParameterError):
        parameterize(m365.SESSION_LOCK_ENFORCED, {"max_minutes": bad})


def test_the_checks_that_take_no_parameter_reject_one() -> None:
    """An accepted-parameter list is also a refusal list."""
    for check in (m365.STORAGE_ENCRYPTION_REQUIRED, m365.SESSION_REAUTHENTICATION_REQUIRED):
        errors = validate_parameters(check.key, {"max_minutes": 30})
        assert errors, f"{check.key} silently accepted a parameter it does not use"
