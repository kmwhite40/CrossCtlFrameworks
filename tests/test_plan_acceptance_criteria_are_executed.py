"""The live-audit plan claims each acceptance criterion is executed. Verify it.

``docs/superpowers/plans/2026-09-26-live-audit-compliance-plan.md`` marks every
acceptance criterion **Executed** and names the test that executes it. That is a
claim in a document, and a claim in a document is the thing this codebase keeps
getting wrong: the runbook's coverage table, the SPRS derivation note, the
provenance markers carried in prose. Each was true when written and quietly
false later.

The specific way this one rots is cheap and certain: somebody renames a test
file, or deletes the one test whose name the plan cites, and the plan goes on
saying the criterion is executed. Nothing fails, because nothing was watching
the sentence.

So: every ``tests/...`` path the criteria section names must exist, every
``::test_name`` it names must be a real test in that file, and no criterion may
be marked Executed without naming one. This guard cannot tell whether a test is
any *good* -- mutation testing is what establishes that, and the plan says so
where it says each criterion was checked by breaking its guard. What this stops
is the plan citing something that is not there.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

PLAN = (
    pathlib.Path(__file__).resolve().parents[1]
    / "docs"
    / "superpowers"
    / "plans"
    / "2026-09-26-live-audit-compliance-plan.md"
)
REPO = pathlib.Path(__file__).resolve().parents[1]

#: `tests/foo.py` or `tests/foo.py::test_bar`, tolerating the line wrap the plan
#: uses inside a `::` reference (`...py::\n  test_name`).
_REFERENCE = re.compile(r"(tests/[A-Za-z0-9_./]+\.py)(?:::\s*([A-Za-z0-9_]+))?")


def _criteria_section() -> str:
    text = PLAN.read_text()
    start = text.index("## Acceptance Criteria")
    return text[start:]


def _flattened() -> str:
    """The criteria section with its line wrapping removed.

    A criterion's wording is a sentence, not a set of lines: "did not run and
    why" is split across two lines in the source and must still be findable.
    Searching the raw markdown made this file fail on its own first run, which
    is the right way round but not a property worth keeping.
    """
    return re.sub(r"\s+", " ", _criteria_section())


def test_the_plan_still_has_an_acceptance_criteria_section() -> None:
    """Guards every other test here: a renamed heading would silence them all."""
    assert PLAN.exists(), f"the plan is gone: {PLAN}"
    section = _criteria_section()
    assert "Executed" in section, "no criterion is marked Executed -- has the plan changed shape?"


def test_every_test_the_criteria_name_exists() -> None:
    refs = _REFERENCE.findall(_criteria_section())
    assert refs, "the criteria section names no tests at all, so it proves nothing"

    missing_files = sorted({path for path, _ in refs if not (REPO / path).exists()})
    assert not missing_files, (
        f"the plan says these execute its acceptance criteria, but they do not "
        f"exist: {missing_files}"
    )


def test_every_named_test_function_exists_in_the_file_named() -> None:
    """A path that exists is not enough -- the plan cites specific tests."""
    named = [(p, n) for p, n in _REFERENCE.findall(_criteria_section()) if n]
    assert named, "no criterion cites a specific test function"

    missing: list[str] = []
    for path, func in named:
        tree = ast.parse((REPO / path).read_text())
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        if func not in defined:
            missing.append(f"{path}::{func}")
    assert not missing, f"the plan cites tests that are not defined: {missing}"


def test_no_criterion_claims_execution_without_naming_a_test() -> None:
    """"Executed" with nothing to point at is the claim this file exists to stop."""
    section = _criteria_section()
    # Each criterion is a top-level bullet; a criterion's text runs until the
    # next one. Split on the bullet marker at the start of a line.
    bullets = [b for b in re.split(r"\n- \*\*", section) if b.strip()]
    offenders: list[str] = []
    for bullet in bullets:
        if not bullet.startswith("Executed"):
            continue
        if not _REFERENCE.search(bullet):
            offenders.append(bullet.strip().splitlines()[0][:90])
    assert not offenders, (
        f"these criteria claim execution and name no test: {offenders}"
    )


@pytest.mark.parametrize(
    "criterion",
    [
        "known misconfigurations",
        "did not run and why",
        "POA&M with actionable guidance",
        "documented-only controls",
    ],
)
def test_all_four_original_criteria_are_still_present(criterion: str) -> None:
    """Marking a criterion Executed by deleting it would also pass the tests above.

    The four phrases are from the plan as originally written. Reworded criteria
    are fine; a criterion that quietly disappeared is not.
    """
    assert criterion in _flattened(), (
        f"the criterion mentioning {criterion!r} is no longer in the plan"
    )


def test_the_uncovered_work_is_still_named() -> None:
    """The criteria are not a completion certificate, and the plan must say so.

    Four green criteria next to no statement of what they leave out reads as
    "done". eMASS is unverified against a live instance and the workers ship
    disabled; a reader deciding whether to authorize on this needs both facts on
    the same page as the green ticks.
    """
    section = _flattened()
    assert "Not covered by these criteria" in section
    for unfinished in ("eMASS", "CCF_SCHEDULER_ENABLED"):
        assert unfinished in section, f"{unfinished} is no longer disclosed as uncovered"
