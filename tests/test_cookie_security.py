"""Regression tests: session cookies must carry Secure outside dev (SC-8, ASVS 3.4.1).

Three cookie-setting sites previously gated the ``Secure`` attribute on
``settings.env == "prod"``. The configured/documented production value is
``"production"`` (the ``Settings.env`` default), so that comparison was False in
a real production deployment and the session cookie was emitted without
``Secure`` — allowing it to travel over plaintext HTTP.

The single source of truth is ``config.is_dev_env`` (dev/local/test), which is
what the API login route already used.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ccf.config import Settings, is_dev_env


def _s(env: str) -> Settings:
    return Settings(
        env=env,
        auth_enabled=True,
        auth_session_secret="a-real-secret",
        api_cors_origins=["https://app.example.gov"],
    )


@pytest.mark.parametrize("env", ["production", "prod", "staging", "gov-prod"])
def test_secure_flag_set_for_non_dev_envs(env: str) -> None:
    """Every non-dev env must yield Secure=True."""
    assert not is_dev_env(_s(env)), f"{env} must not be treated as a dev env"


@pytest.mark.parametrize("env", ["dev", "local", "test"])
def test_secure_flag_relaxed_only_for_dev_envs(env: str) -> None:
    assert is_dev_env(_s(env))


def test_env_default_is_not_the_literal_prod() -> None:
    """Guards the exact defect: ``env == "prod"`` is False for the default env.

    If this ever passes, the old comparison would have been correct and this
    regression test would be silently vacuous.
    """
    # Read the declared field default, not Settings().env — the ambient CCF_ENV
    # of the test runner would otherwise mask the real production default.
    default_env = Settings.model_fields["env"].default
    assert default_env == "production"
    assert default_env != "prod"


def test_no_cookie_site_compares_env_to_prod_literal() -> None:
    """No cookie-setting site may re-introduce the ``env == "prod"`` comparison."""
    src = Path(__file__).resolve().parents[1] / "src" / "ccf"
    offenders = [
        p.relative_to(src).as_posix()
        for p in src.rglob("*.py")
        if 'env == "prod"' in p.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"env == 'prod' comparison reintroduced in: {offenders}"
