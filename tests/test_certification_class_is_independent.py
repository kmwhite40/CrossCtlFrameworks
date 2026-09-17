"""Nothing may derive a Certification Class from a baseline, or a baseline from
a Class.

FedRAMP: "Agencies should not treat Certification Classes as one-for-one
replacements for Low, Moderate, or High impact levels." The adequacy ranges
overlap -- a Class B offering may serve a High system, and a High system may be
served by B, C or D -- so a derivation is wrong in BOTH directions.

A source-shaped guard is the right instrument. A derivation added in a private
helper would not be caught by exercising any route, and the whole point is that
the mapping is tempting and wrong.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"
_BASELINE = ("baseline", "fedramp_baseline")
_CERT = {"certification_class", "certification_path"}


def _derivations(tree: ast.AST, label: str) -> list[str]:
    """Assignments whose target names one vocabulary and whose value mentions
    the other."""
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if node.value is None:
            continue
        names = {
            t.attr if isinstance(t, ast.Attribute) else getattr(t, "id", "")
            for t in targets
        }
        value = ast.dump(node.value)
        if names & _CERT and any(b in value for b in _BASELINE):
            hits.append(f"{label}:{node.lineno} derives a Class from a baseline")
        if names & set(_BASELINE) and any(c in value for c in _CERT):
            hits.append(f"{label}:{node.lineno} derives a baseline from a Class")
    return hits


def test_no_code_derives_a_class_from_a_baseline_or_the_reverse() -> None:
    hits: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits += _derivations(tree, str(path.relative_to(_SRC)))
    assert not hits, (
        "FedRAMP states Certification Classes are NOT one-for-one replacements "
        f"for impact levels, and the adequacy ranges overlap. Found: {hits}"
    )


def test_the_guard_detects_the_shape_it_forbids() -> None:
    """Prove the walker fires, without committing the violation it looks for."""
    forward = ast.parse("system.certification_class = _CLASS_FOR[system.baseline]")
    reverse = ast.parse("system.baseline = _BASELINE_FOR[system.certification_class]")
    assert _derivations(forward, "fake.py") == [
        "fake.py:1 derives a Class from a baseline"
    ]
    assert _derivations(reverse, "fake.py") == [
        "fake.py:1 derives a baseline from a Class"
    ]


def test_the_guard_actually_reads_the_source_tree() -> None:
    """A walker pointed at an empty directory passes vacuously forever."""
    assert len(list(_SRC.rglob("*.py"))) > 50
