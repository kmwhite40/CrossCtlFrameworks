"""The revision CLI surfaces listing, diff, impact, import, and adopt."""

from __future__ import annotations

from typer.testing import CliRunner

from ccf.cli import app

runner = CliRunner()


def test_revisions_command_is_registered() -> None:
    result = runner.invoke(app, ["catalog", "revisions", "--help"])
    assert result.exit_code == 0


def test_adopt_command_exposes_the_acknowledge_flag() -> None:
    result = runner.invoke(app, ["catalog", "adopt", "--help"])
    assert result.exit_code == 0
    assert "acknowledge" in result.stdout


def test_import_command_is_registered() -> None:
    assert runner.invoke(app, ["catalog", "import-revision", "--help"]).exit_code == 0


def test_diff_and_impact_commands_are_registered() -> None:
    assert runner.invoke(app, ["catalog", "diff", "--help"]).exit_code == 0
    assert runner.invoke(app, ["catalog", "impact", "--help"]).exit_code == 0


def test_existing_catalog_commands_still_registered() -> None:
    """The new commands must not displace the ones that were already there."""
    assert runner.invoke(app, ["catalog", "reconcile", "--help"]).exit_code == 0
    assert runner.invoke(app, ["catalog", "show", "--help"]).exit_code == 0
