"""No test module may reset the schema while the session is running.

``conftest.clean_migrated_db`` downgrades to ``base`` and upgrades to ``head``
**once, before any module runs**, and its docstring is explicit about why the
timing matters: "a mid-session downgrade wipes data other modules depend on".

Two modules did it anyway, from autouse fixtures — one session-scoped. The
consequences were real and cost hours to diagnose:

* every module that had already run lost its data, so tests failed depending on
  where they landed in the ordering;
* two modules both downgrading raced into a ``pg_type`` collision recreating
  ``ccf.ingestion_runs``, producing thirteen errors in one run and none in the
  next.

Both now truncate the four catalog tables they actually count, which gives the
same determinism with a blast radius of four tables instead of the database.

This guard keeps the pattern from coming back. A module that genuinely needs to
exercise a migration round trip is not forbidden — it is asked to say so, by
naming itself here, so the next person sees the hazard rather than rediscovering
it. The allowed modules are the ones whose *subject* is a migration.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

#: Modules whose subject is a migration round trip, so a downgrade is the thing
#: under test rather than a way of getting a clean slate. Each one must restore
#: ``head`` before it finishes.
_MIGRATION_ROUND_TRIP_MODULES = frozenset(
    {
        "conftest.py",
        "test_3pao_engagements.py",
        "test_migration_0080_backfill.py",
        # Found by this guard on its first run, not by reading: a fourth module
        # was doing it and nobody had noticed.
        "test_migration_0081_document_key.py",
        "test_conftest_cr26_document_key_cleanup.py",
    }
)


def _modules_calling_downgrade() -> dict[str, list[int]]:
    """``{module: [line numbers]}`` for every ``command.downgrade(...)`` call."""
    found: dict[str, list[int]] = {}
    for path in [*sorted(TESTS.glob("test_*.py")), TESTS / "conftest.py"]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken test file fails elsewhere
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "downgrade"
            ):
                found.setdefault(path.name, []).append(node.lineno)
    return found


def test_only_migration_round_trip_modules_downgrade() -> None:
    offenders = {
        name: lines
        for name, lines in _modules_calling_downgrade().items()
        if name not in _MIGRATION_ROUND_TRIP_MODULES
    }
    assert not offenders, (
        "these modules downgrade the shared schema mid-session, which wipes data "
        f"every earlier module depends on: {offenders}. Truncate the tables the "
        "module actually needs empty, or — if a migration round trip really is the "
        "subject — add the module to _MIGRATION_ROUND_TRIP_MODULES here."
    )


def test_the_allowlist_has_no_stale_entries() -> None:
    """An allowlist that outlives its entries stops describing the codebase.

    Same discipline as the coverage table in the production runbook: a list
    nothing keeps true is worse than no list, because it reads as checked.
    """
    calling = set(_modules_calling_downgrade())
    stale = {
        name
        for name in _MIGRATION_ROUND_TRIP_MODULES
        if name not in calling and (TESTS / name).exists()
    }
    assert not stale, (
        f"these modules no longer downgrade and can leave the allowlist: {sorted(stale)}"
    )


@pytest.mark.parametrize("module", sorted(_MIGRATION_ROUND_TRIP_MODULES))
def test_every_allowed_module_returns_to_head(module: str) -> None:
    """A round trip that does not come back leaves the next module broken."""
    path = TESTS / module
    if not path.exists():  # pragma: no cover - covered by the staleness test
        pytest.skip(f"{module} does not exist")
    src = path.read_text(encoding="utf-8")
    assert "upgrade" in src, (
        f"{module} downgrades the schema without any upgrade back to head"
    )
