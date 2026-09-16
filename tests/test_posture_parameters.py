"""Form A: a pack parameterizes a platform evaluator instead of replacing it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ccf.posture.parameters import (
    PARAMETERIZABLE,
    ParameterError,
    parameterize,
    validate_parameters,
)
from ccf.posture.providers import m365

NOW = datetime(2026, 9, 14, tzinfo=UTC)


def _user(days_idle: int, *, upn: str = "u@x.gov") -> dict:
    last = (NOW - timedelta(days=days_idle)).isoformat().replace("+00:00", "Z")
    return {
        "userPrincipalName": upn,
        "accountEnabled": True,
        "signInActivity": {"lastSignInDateTime": last},
    }


# ── the threshold actually changes the verdict ───────────────────────────────


def test_the_default_threshold_is_unchanged() -> None:
    """Every existing caller must behave exactly as before."""
    findings = m365.evaluate_stale_accounts([_user(75)], now=NOW)
    assert [f.verdict for f in findings] == ["pass"]


def test_a_tighter_threshold_fails_what_the_default_passes() -> None:
    findings = m365.evaluate_stale_accounts([_user(75)], now=NOW, threshold_days=60)
    assert [f.verdict for f in findings] == ["fail"]


def test_a_looser_threshold_passes_what_the_default_fails() -> None:
    findings = m365.evaluate_stale_accounts([_user(120)], now=NOW, threshold_days=180)
    assert [f.verdict for f in findings] == ["pass"]


def test_the_boundary_is_exclusive_at_every_threshold() -> None:
    """Exactly at the threshold is not yet stale -- as the default always was."""
    at = m365.evaluate_stale_accounts([_user(60)], now=NOW, threshold_days=60)
    past = m365.evaluate_stale_accounts([_user(61)], now=NOW, threshold_days=60)
    assert at[0].verdict == "pass"
    assert past[0].verdict == "fail"


def test_parameterizing_does_not_disturb_the_not_applicable_cases() -> None:
    """A disabled account and a licence-less account stay not_applicable."""
    rows = [
        {"userPrincipalName": "disabled@x.gov", "accountEnabled": False},
        {"userPrincipalName": "nolicence@x.gov", "accountEnabled": True},
    ]
    findings = m365.evaluate_stale_accounts(rows, now=NOW, threshold_days=1)
    assert [f.verdict for f in findings] == ["not_applicable", "not_applicable"]


# ── the expected text must follow the threshold ──────────────────────────────


def test_the_expected_text_reports_the_threshold_in_force() -> None:
    """Prose claiming 90 days while enforcing 60 is a false statement in an SSP."""
    check = parameterize(m365.STALE_ACCOUNTS, {"threshold_days": 60})
    assert "60 days" in check.expected
    assert "90" not in check.expected


def test_parameterizing_preserves_everything_else() -> None:
    check = parameterize(m365.STALE_ACCOUNTS, {"threshold_days": 60})
    assert check.key == m365.STALE_ACCOUNTS.key
    assert check.control_ids == m365.STALE_ACCOUNTS.control_ids
    assert check.required_permissions == m365.STALE_ACCOUNTS.required_permissions
    assert check.resource_type == m365.STALE_ACCOUNTS.resource_type


def test_no_parameters_returns_the_check_unchanged() -> None:
    assert parameterize(m365.STALE_ACCOUNTS, {}) == m365.STALE_ACCOUNTS
    assert parameterize(m365.MFA_REGISTERED, {}) == m365.MFA_REGISTERED


# ── validation is fail-closed, at install time ───────────────────────────────


def test_an_unknown_parameter_is_rejected() -> None:
    errors = validate_parameters(m365.STALE_ACCOUNTS.key, {"threshhold_days": 60})
    assert errors and "threshhold_days" in errors[0]


def test_a_parameter_on_a_non_parameterizable_check_is_rejected() -> None:
    errors = validate_parameters(m365.MFA_REGISTERED.key, {"threshold_days": 60})
    assert errors


def test_an_unknown_evaluator_is_rejected() -> None:
    errors = validate_parameters("m365.identity.nonexistent", {})
    assert errors and "nonexistent" in errors[0]


@pytest.mark.parametrize("bad", ["60", 0, -1, 1.5, True, None])
def test_a_threshold_that_is_not_a_positive_integer_is_rejected(bad: object) -> None:
    """A string would TypeError at scan; zero or negative is meaningless. Note
    bool is rejected explicitly -- True is an int in Python, and a threshold of
    one day from ``true`` is the sort of thing that reaches production."""
    assert validate_parameters(m365.STALE_ACCOUNTS.key, {"threshold_days": bad})


def test_a_valid_threshold_passes_validation() -> None:
    assert validate_parameters(m365.STALE_ACCOUNTS.key, {"threshold_days": 60}) == []


def test_parameterize_refuses_what_validation_refuses() -> None:
    """The two must not disagree: anything that fails validation must not be
    silently applied if it reaches parameterize anyway."""
    with pytest.raises(ParameterError):
        parameterize(m365.STALE_ACCOUNTS, {"threshold_days": "60"})
    with pytest.raises(ParameterError):
        parameterize(m365.MFA_REGISTERED, {"threshold_days": 60})


# ── the registry is the single vocabulary ────────────────────────────────────


def test_every_platform_check_appears_in_the_registry() -> None:
    """A check absent from PARAMETERIZABLE cannot be named by a pack at all,
    so omitting one silently removes it from Form A."""
    for check in m365.CHECKS:
        assert check.key in PARAMETERIZABLE
