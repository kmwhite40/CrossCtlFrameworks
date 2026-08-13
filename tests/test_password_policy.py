"""Unit + CLI tests for the password minimum-length policy (IA-5)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from ccf.auth import validate_password_policy
from ccf.cli import app
from ccf.config import get_settings

runner = CliRunner()


def test_short_password_raises() -> None:
    with pytest.raises(ValueError, match="at least 12 characters"):
        validate_password_policy("short", min_length=12)


def test_min_length_password_is_accepted() -> None:
    validate_password_policy("twelve-chars-ok", min_length=12)  # no raise


def test_default_min_length_is_twelve() -> None:
    assert get_settings().auth_password_min_length == 12


def test_user_create_cli_rejects_short_password() -> None:
    result = runner.invoke(
        app,
        ["user-create", "policy-test@example.com", "--password", "short"],
    )
    assert result.exit_code != 0
    assert "at least 12 characters" in result.stdout
