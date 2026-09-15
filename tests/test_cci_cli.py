"""The CLI surface. Assertions avoid rendered help text, which is
terminal-width dependent and has broken CI here before."""
from typer.testing import CliRunner

from ccf.cli import app

runner = CliRunner()


def test_cci_group_is_registered() -> None:
    result = runner.invoke(app, ["cci", "--help"])
    assert result.exit_code == 0
    assert "load" in result.stdout
    assert "reconcile" in result.stdout


def test_source_is_registered_disabled_with_a_reason() -> None:
    from ccf.etl.sources import DEFAULT_SOURCES  # noqa: PLC0415

    spec = next(s for s in DEFAULT_SOURCES if s["key"] == "disa_cci_list")
    assert spec["authority"] == "DISA"
    assert spec["kind"] == "generic"
    # cyber.mil refuses non-browser fetches; an always-erroring source would
    # put a permanent red line in the alert digest that means nothing.
    assert spec["enabled"] is False
