"""Unit tests for the fail-closed secure-config guard (IA-01/IA-11) — no DB."""

from __future__ import annotations

import pytest

from ccf.config import Settings, enforce_secure_config, is_dev_env


def _settings(**over) -> Settings:
    base = dict(
        env="production",
        auth_enabled=True,
        auth_session_secret="a-real-secret",
        api_cors_origins=["https://app.example.gov"],
    )
    base.update(over)
    return Settings(**base)


def test_dev_env_is_noop_even_when_insecure() -> None:
    s = _settings(env="dev", auth_enabled=False, auth_session_secret="dev-insecure-change-me")
    assert enforce_secure_config(s) == []


def test_prod_auth_off_refuses_start() -> None:
    with pytest.raises(RuntimeError, match="auth is disabled"):
        enforce_secure_config(_settings(auth_enabled=False))


def test_prod_default_secret_refuses_start() -> None:
    with pytest.raises(RuntimeError, match="session secret"):
        enforce_secure_config(_settings(auth_session_secret="dev-insecure-change-me"))


def test_prod_secure_returns_no_problems() -> None:
    """A secure config does not refuse to start.

    Asserted as "does not raise" rather than "returns []": the return value is
    the *warning* list, and a production deployment with no credential master
    key now legitimately warns while remaining safe to start. Conflating the
    two would make any future warning look like a regression.
    """
    assert enforce_secure_config(_settings()) is not None  # did not raise


def test_a_fully_configured_production_deployment_warns_about_nothing() -> None:
    """The other half: with everything set, the warning list is empty."""
    assert (
        enforce_secure_config(
            _settings(
                ai_credential_master_key="k" * 32,
                ai_credential_key_provider="aws_kms",
            )
        )
        == []
    )


def test_prod_wildcard_cors_refuses_start() -> None:
    with pytest.raises(RuntimeError, match="CORS"):
        enforce_secure_config(_settings(api_cors_origins=["*"]))


def test_is_dev_env_true_for_dev_local_test() -> None:
    for env in ("dev", "local", "test"):
        assert is_dev_env(_settings(env=env)) is True


def test_is_dev_env_false_for_production_and_empty() -> None:
    assert is_dev_env(_settings(env="production")) is False
    assert is_dev_env(_settings(env="")) is False


def test_env_test_insecure_is_noop() -> None:
    s = _settings(
        env="test",
        auth_enabled=False,
        auth_session_secret="dev-insecure-change-me",
        api_cors_origins=["*"],
    )
    assert enforce_secure_config(s) == []


def test_a_missing_credential_master_key_is_warned_about_not_refused() -> None:
    """Credential storage fails closed without it, and said so nowhere.

    An operator met this as "the connector page will not accept my key": the
    cipher refused, correctly, and nothing at startup mentioned that the
    feature was unavailable. Not a refusal to start -- a reader-only
    deployment legitimately stores no credentials, and nothing here lets a
    request act as someone it is not, which is the bar for refusing.
    """
    warnings = enforce_secure_config(_settings(ai_credential_master_key=None))
    assert any("CCF_AI_CREDENTIAL_MASTER_KEY is unset" in w for w in warnings)
    assert any("fails closed" in w for w in warnings)


def test_the_local_key_provider_is_warned_about_in_production() -> None:
    """`local` keeps key material in the process environment."""
    warnings = enforce_secure_config(_settings(ai_credential_master_key="k" * 32))
    assert any("'local'" in w and "environment" in w for w in warnings)


def test_a_managed_provider_with_a_key_warns_about_neither() -> None:
    """Both directions, so a guard that warned unconditionally would fail."""
    warnings = enforce_secure_config(
        _settings(
            ai_credential_master_key="k" * 32,
            ai_credential_key_provider="aws_kms",
        )
    )
    assert not [w for w in warnings if "CREDENTIAL" in w]


def test_neither_warning_fires_in_a_development_environment() -> None:
    """`enforce_secure_config` is a no-op in dev, and must stay one."""
    assert enforce_secure_config(_settings(env="dev", ai_credential_master_key=None)) == []
