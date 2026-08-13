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
    assert enforce_secure_config(_settings()) == []


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
