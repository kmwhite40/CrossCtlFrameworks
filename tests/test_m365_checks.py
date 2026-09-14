"""The three M365 checks, evaluated against recorded Graph shapes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccf.posture.checks import CheckOutcome, checks_for
from ccf.posture.providers.m365 import (
    LEGACY_AUTH_BLOCKED,
    MFA_REGISTERED,
    STALE_ACCOUNT_DAYS,
    STALE_ACCOUNTS,
    evaluate_legacy_auth_blocked,
    evaluate_mfa_registered,
    evaluate_stale_accounts,
)

NOW = datetime(2026, 9, 14, tzinfo=UTC)


def _iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


# ── MFA registration: a per-user fleet ───────────────────────────────────────


def test_mfa_mixed_fleet_names_the_failures() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "a@x.gov", "isMfaRegistered": True,
         "userType": "member", "isAdmin": False},
        {"id": "u2", "userPrincipalName": "b@x.gov", "isMfaRegistered": False,
         "userType": "member", "isAdmin": False},
        {"id": "u3", "userPrincipalName": "c@x.gov", "isMfaRegistered": True,
         "userType": "guest", "isAdmin": False},
    ]
    findings = evaluate_mfa_registered(rows)
    assert len(findings) == 3
    failing = [f for f in findings if f.verdict == "fail"]
    assert [f.resource_id for f in failing] == ["b@x.gov"]
    assert CheckOutcome.from_findings(MFA_REGISTERED, tuple(findings)).verdict == "fail"


def test_mfa_all_registered_passes() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "a@x.gov", "isMfaRegistered": True},
        {"id": "u2", "userPrincipalName": "b@x.gov", "isMfaRegistered": True},
    ]
    findings = evaluate_mfa_registered(rows)
    assert CheckOutcome.from_findings(MFA_REGISTERED, tuple(findings)).verdict == "pass"


def test_mfa_empty_fleet_is_not_applicable() -> None:
    assert evaluate_mfa_registered([]) == []
    assert CheckOutcome.from_findings(MFA_REGISTERED, ()).verdict == "not_applicable"


def test_mfa_records_what_was_counted() -> None:
    """userRegistrationDetails has no accountEnabled, so detail must show the
    user type that was included."""
    rows = [
        {"id": "u1", "userPrincipalName": "g@x.gov", "isMfaRegistered": False,
         "userType": "guest", "isAdmin": True}
    ]
    (f,) = evaluate_mfa_registered(rows)
    assert f.detail["userType"] == "guest"
    assert f.detail["isAdmin"] is True


def test_mfa_falls_back_to_id_when_upn_missing() -> None:
    (f,) = evaluate_mfa_registered([{"id": "u9", "isMfaRegistered": False}])
    assert f.resource_id == "u9"


# ── Legacy auth: a tenant singleton ──────────────────────────────────────────


def _blocking_policy(state: str = "enabled") -> dict:
    return {
        "id": "p1",
        "displayName": "Block legacy auth",
        "state": state,
        "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
        "grantControls": {"builtInControls": ["block"]},
    }


def test_legacy_auth_enabled_blocking_policy_passes() -> None:
    (f,) = evaluate_legacy_auth_blocked([_blocking_policy()], tenant_id="t-1")
    assert f.verdict == "pass"
    assert f.resource_id == "t-1"
    assert f.resource_type == "m365_tenant"


def test_legacy_auth_disabled_policy_does_not_pass() -> None:
    (f,) = evaluate_legacy_auth_blocked([_blocking_policy("disabled")], tenant_id="t-1")
    assert f.verdict == "fail"


def test_legacy_auth_report_only_policy_does_not_pass() -> None:
    """Report-only enforces nothing."""
    (f,) = evaluate_legacy_auth_blocked(
        [_blocking_policy("enabledForReportingButNotEnforced")], tenant_id="t-1"
    )
    assert f.verdict == "fail"


def test_legacy_auth_policy_without_block_does_not_pass() -> None:
    pol = _blocking_policy()
    pol["grantControls"] = {"builtInControls": ["mfa"]}
    (f,) = evaluate_legacy_auth_blocked([pol], tenant_id="t-1")
    assert f.verdict == "fail"


def test_legacy_auth_policy_not_targeting_legacy_clients_does_not_pass() -> None:
    pol = _blocking_policy()
    pol["conditions"] = {"clientAppTypes": ["browser"]}
    (f,) = evaluate_legacy_auth_blocked([pol], tenant_id="t-1")
    assert f.verdict == "fail"


def test_legacy_auth_no_policies_fails_with_one_finding() -> None:
    findings = evaluate_legacy_auth_blocked([], tenant_id="t-1")
    assert len(findings) == 1  # the tenant is always the resource
    assert findings[0].verdict == "fail"
    assert CheckOutcome.from_findings(LEGACY_AUTH_BLOCKED, tuple(findings)).verdict == "fail"


# ── Stale accounts: per-user with exclusions ─────────────────────────────────


def test_stale_account_fails_past_the_threshold() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "old@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": _iso(STALE_ACCOUNT_DAYS + 10)}}
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "fail"


def test_recent_account_passes() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "new@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": _iso(3)}}
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "pass"


def test_disabled_account_is_not_applicable() -> None:
    """A disabled account is not a stale-access risk."""
    rows = [
        {"id": "u1", "userPrincipalName": "off@x.gov", "accountEnabled": False,
         "signInActivity": {"lastSignInDateTime": _iso(400)}}
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "not_applicable"


def test_missing_sign_in_activity_is_not_applicable() -> None:
    """Graph omits signInActivity without the right licence; absence is not
    evidence of staleness."""
    rows = [{"id": "u1", "userPrincipalName": "x@x.gov", "accountEnabled": True}]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "not_applicable"


def test_uses_interactive_sign_in_not_the_background_one() -> None:
    """lastNonInteractiveSignInDateTime moves on token refresh, so an
    abandoned account would look active under it."""
    rows = [
        {"id": "u1", "userPrincipalName": "abandoned@x.gov", "accountEnabled": True,
         "signInActivity": {
             "lastSignInDateTime": _iso(400),
             "lastNonInteractiveSignInDateTime": _iso(1),
         }}
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "fail"


def test_disabled_accounts_are_excluded_from_the_verdict() -> None:
    """End-to-end proof of P2a's exclusion rule: one disabled account among
    two passing ones must leave the check passing, while still being counted
    as examined."""
    rows = [
        {"id": "a", "userPrincipalName": "a@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": _iso(1)}},
        {"id": "b", "userPrincipalName": "b@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": _iso(2)}},
        {"id": "c", "userPrincipalName": "c@x.gov", "accountEnabled": False,
         "signInActivity": {"lastSignInDateTime": _iso(999)}},
    ]
    findings = evaluate_stale_accounts(rows, now=NOW)
    outcome = CheckOutcome.from_findings(STALE_ACCOUNTS, tuple(findings))
    assert outcome.verdict == "pass"
    assert outcome.evaluated == 3  # counted as examined
    assert outcome.failing == 0


def test_malformed_timestamp_is_not_applicable_not_a_crash() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "bad@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": "not-a-date"}}
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "not_applicable"


# ── Registration ─────────────────────────────────────────────────────────────


def test_all_three_checks_are_registered_under_msgraph() -> None:
    keys = {c.key for c in checks_for("msgraph")}
    assert keys == {
        "m365.identity.mfa_registered",
        "m365.policy.legacy_auth_blocked",
        "m365.identity.stale_accounts",
    }


def test_every_check_declares_controls_and_permissions() -> None:
    for c in checks_for("msgraph"):
        assert c.control_ids, c.key
        assert c.required_permissions, c.key
        assert c.provider == "msgraph"


def test_control_ids_are_canonical_not_zero_padded() -> None:
    for c in checks_for("msgraph"):
        for cid in c.control_ids:
            assert "-0" not in cid, f"{c.key} uses a zero-padded id: {cid}"
