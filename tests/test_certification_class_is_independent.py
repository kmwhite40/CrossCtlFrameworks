"""Nothing may derive a Certification Class from a baseline, or a baseline from
a Class.

FedRAMP: "Agencies should not treat Certification Classes as one-for-one
replacements for Low, Moderate, or High impact levels." The adequacy ranges
overlap -- a Class B offering may serve a High system, and a High system may be
served by B, C or D -- so a derivation is wrong in BOTH directions.

A source-shaped guard is the right instrument. A derivation added in a private
helper would not be caught by exercising any route, and the whole point is that
the mapping is tempting and wrong.

The guard checks three shapes a target can take: a plain attribute/name
assignment (``system.certification_class = ...``), a tuple/list-unpacking or
augmented assignment, and -- the shape this codebase actually uses to build a
``System`` row (see ``api/routes/ui.py``'s ``System(organization_id=...,
baseline=...)``) -- a constructor call's own keyword argument. A keyword is
checked against only its own value, never merely for co-occurring with the
other vocabulary's keyword on the same call: ``System(certification_class=x,
baseline=y)`` from two unrelated sources must not fire.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"
_BASELINE = ("baseline", "fedramp_baseline")
_CERT = {"certification_class", "certification_path"}


def _target_names(target: ast.expr) -> set[str]:
    """Flatten one assignment target down to the plain or attribute names it
    binds, recursing into tuple/list-unpacking targets so
    ``self.certification_class, x = y, z`` is not invisible to the walker."""
    if isinstance(target, ast.Attribute):
        return {target.attr}
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for elt in target.elts:
            names |= _target_names(elt)
        return names
    return set()


def _keyword_hits(call: ast.Call, label: str) -> list[str]:
    """A constructor call's keyword arguments are targets in their own
    right. Each keyword is judged against only its own value -- the finding
    is ``certification_class=`` deriving from something naming a baseline,
    not the mere presence of a ``baseline=`` keyword on the same call."""
    hits: list[str] = []
    for kw in call.keywords:
        if kw.arg is None:  # a ``**mapping`` unpack -- no name to judge
            continue
        value = ast.dump(kw.value)
        if kw.arg in _CERT and any(b in value for b in _BASELINE):
            hits.append(f"{label}:{call.lineno} derives a Class from a baseline")
        if kw.arg in _BASELINE and any(c in value for c in _CERT):
            hits.append(f"{label}:{call.lineno} derives a baseline from a Class")
    return hits


def _derivations(tree: ast.AST, label: str) -> list[str]:
    """Assignments (attribute/name, tuple/list-unpacking, or augmented) whose
    target names one vocabulary and whose value mentions the other, plus any
    constructor call whose keyword argument names one vocabulary and whose
    own value mentions the other."""
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            hits += _keyword_hits(node, label)
            continue
        if isinstance(node, ast.Assign):
            names: set[str] = set()
            for t in node.targets:
                names |= _target_names(t)
            value_node = node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            names = _target_names(node.target)
            value_node = node.value
        else:
            continue
        if value_node is None:
            continue
        value = ast.dump(value_node)
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


def test_the_guard_catches_the_constructor_keyword_shape() -> None:
    """The idiomatic way this codebase actually builds a ``System`` row --
    e.g. ``api/routes/ui.py``: ``System(organization_id=org.id,
    name=sys_name, baseline=...)`` -- is a keyword argument, not an
    attribute assignment. A guard blind to this shape would miss a future
    edit that innocently adds ``certification_class=CLASS_FOR[baseline]`` to
    a call like that one."""
    forward = ast.parse(
        "sysm = System(certification_class=CLASS_FOR[system.baseline], "
        "baseline=None)"
    )
    reverse = ast.parse(
        "sysm = System(baseline=BASELINE_FOR[system.certification_class], "
        "certification_class=None)"
    )
    assert _derivations(forward, "fake.py") == [
        "fake.py:1 derives a Class from a baseline"
    ]
    assert _derivations(reverse, "fake.py") == [
        "fake.py:1 derives a baseline from a Class"
    ]


def test_the_guard_does_not_fire_on_independent_constructor_keywords() -> None:
    """Two keywords merely co-existing on the same call, each from its own
    unrelated source, is a legitimate constructor and must not be flagged --
    a guard that fires on this would be worse than one that under-reaches."""
    tree = ast.parse(
        "sysm = System(certification_class=existing_class, "
        "baseline=existing_baseline)"
    )
    assert _derivations(tree, "fake.py") == []


def test_the_guard_catches_a_tuple_unpacking_target() -> None:
    """A tuple/list assignment target must not be invisible to the name
    extraction that a plain ``Name``/``Attribute`` target uses."""
    tree = ast.parse("self.certification_class, other = system.baseline, 5")
    assert _derivations(tree, "fake.py") == [
        "fake.py:1 derives a Class from a baseline"
    ]


def test_the_guard_catches_augmented_assignment() -> None:
    tree = ast.parse("self.certification_class += system.baseline")
    assert _derivations(tree, "fake.py") == [
        "fake.py:1 derives a Class from a baseline"
    ]


def test_the_guard_actually_reads_the_source_tree() -> None:
    """A walker pointed at an empty directory passes vacuously forever."""
    assert len(list(_SRC.rglob("*.py"))) > 50
