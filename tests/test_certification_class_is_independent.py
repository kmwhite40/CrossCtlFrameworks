"""Nothing may derive a Certification Class from a baseline, or a baseline from
a Class -- nor a pipeline stage from either, or either from a stage.

FedRAMP: "Agencies should not treat Certification Classes as one-for-one
replacements for Low, Moderate, or High impact levels." The adequacy ranges
overlap -- a Class B offering may serve a High system, and a High system may be
served by B, C or D -- so a derivation is wrong in BOTH directions.

``systems.pipeline_stage`` joined this guard for a related but distinct reason
(``docs/superpowers/specs/2026-09-21-pipeline-stage-design.md`` §3.1). It is
Concord's own note about where a system has got to, and **no platform signal
establishes it**: it is authored or it is NULL. A baseline, a Class or a Path
therefore cannot imply it, and it cannot imply them -- a system may sit in
remediation at any Class and hold any Class at any stage. Derived rather than
authored, it would stop being an operator's statement and become the platform's
inference, presented in the operator's voice.

The three vocabularies are held apart by one pair-driven walker rather than
three walkers: the forbidden SHAPE is identical in each case, and a second
copy of this file would be a second thing to keep current.

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

It walks ``migrations/versions/`` as well as ``src/ccf``. A backfill is the most
realistic way this derivation would actually arrive -- nobody writes
``CLASS_FOR[baseline]`` in a route by accident, but "populate the new column
from the impact level we already have" reads like housekeeping. A **known blind
spot** survives that widening and cannot be closed by an AST walk: the same
backfill written as raw SQL inside ``op.execute("UPDATE ccf.systems SET
certification_class = CASE baseline ...")`` is a string literal to this walker.
It is disclosed in ``docs/architecture/forge-capability-inventory.md`` §6.2k
alongside the intermediate-variable, function-return and ``setattr`` gaps rather
than papered over with a substring scan that would fire on prose.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src" / "ccf"
_MIGRATIONS = _ROOT / "migrations" / "versions"
_BASELINE = frozenset({"baseline", "fedramp_baseline"})
_CERT = frozenset({"certification_class", "certification_path"})
#: Concord's own pipeline stage -- see ``ccf.constants.PIPELINE_STAGES``. Added
#: here rather than in a guard of its own: the shape to forbid is identical and
#: a second walker would be a second thing to keep current.
_STAGE = frozenset({"pipeline_stage"})

#: Every forbidden pairing, with what a hit each way is called. A stage is
#: independent of a baseline for the reason above, and independent of a Class
#: or a Path for a different one: a Class describes the assurance a provider
#: commits to supplying, while a stage is Concord's note about where a system
#: has GOT to. A system may sit in remediation at any Class, and hold any Class
#: at any stage -- so "Class D, therefore continuously monitored" is wrong in
#: both directions too, and ``pipeline_stage`` is the one of the three that no
#: platform signal can establish at all: it is authored or it is NULL.
_FORBIDDEN_PAIRS: tuple[tuple[frozenset[str], frozenset[str], str, str], ...] = (
    (_CERT, _BASELINE, "derives a Class from a baseline", "derives a baseline from a Class"),
    (_STAGE, _BASELINE, "derives a stage from a baseline", "derives a baseline from a stage"),
    (_STAGE, _CERT, "derives a stage from a Class", "derives a Class from a stage"),
)


def _pair_hits(names: set[str], value: str, label: str, lineno: int) -> list[str]:
    """Judge one target-name set against one dumped value, over every pair.

    ``names`` are the names an assignment (or keyword argument) binds; ``value``
    is ``ast.dump`` of what it binds them to. A pairing fires in whichever
    direction matches, and each direction is judged only against its own
    counterpart vocabulary -- never against "some other vocabulary is mentioned
    nearby".
    """
    hits: list[str] = []
    for left, right, forward, reverse in _FORBIDDEN_PAIRS:
        if names & left and any(r in value for r in right):
            hits.append(f"{label}:{lineno} {forward}")
        if names & right and any(left_name in value for left_name in left):
            hits.append(f"{label}:{lineno} {reverse}")
    return hits


def _guarded_files() -> list[tuple[Path, str]]:
    """Every Python file the guard walks, with the label a hit is reported under.

    Application code *and* migrations: a data migration is source too, and it is
    the likelier home for a Class-from-baseline backfill than any route.
    """
    files = [(p, str(p.relative_to(_SRC))) for p in sorted(_SRC.rglob("*.py"))]
    files += [
        (p, f"migrations/versions/{p.name}") for p in sorted(_MIGRATIONS.glob("*.py"))
    ]
    return files


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
        hits += _pair_hits({kw.arg}, ast.dump(kw.value), label, call.lineno)
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
        hits += _pair_hits(names, ast.dump(value_node), label, node.lineno)
    return hits


def test_no_code_derives_a_class_from_a_baseline_or_the_reverse() -> None:
    """The walk itself, over every pairing in :data:`_FORBIDDEN_PAIRS`."""
    hits: list[str] = []
    for path, label in _guarded_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits += _derivations(tree, label)
    assert not hits, (
        "FedRAMP states Certification Classes are NOT one-for-one replacements "
        "for impact levels, and the adequacy ranges overlap; a pipeline stage "
        "is authored or NULL and no platform signal establishes it. "
        f"Found: {hits}"
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


def test_the_guard_catches_a_stage_derived_from_a_baseline_or_the_reverse() -> None:
    """The stage pairing fires in both directions, on the same shapes.

    "A High system must be continuously monitored" is the tempting sentence,
    and it is an inference about the world rather than a fact about this
    system: a High system in preparation has not started monitoring anything.
    """
    forward = ast.parse("system.pipeline_stage = _STAGE_FOR[system.baseline]")
    reverse = ast.parse("system.baseline = _BASELINE_FOR[system.pipeline_stage]")
    assert _derivations(forward, "fake.py") == [
        "fake.py:1 derives a stage from a baseline"
    ]
    assert _derivations(reverse, "fake.py") == [
        "fake.py:1 derives a baseline from a stage"
    ]


def test_the_guard_catches_a_stage_derived_from_a_class_or_a_path() -> None:
    """A Class or a Path is the likelier source of an invented stage than a
    baseline is -- "it has a Path, so it must be in process" reads like
    housekeeping -- so both directions of that pairing are pinned too."""
    from_class = ast.parse("system.pipeline_stage = _STAGE_FOR[system.certification_class]")
    from_path = ast.parse("system.pipeline_stage = _STAGE_FOR[system.certification_path]")
    reverse = ast.parse("system.certification_path = _PATH_FOR[system.pipeline_stage]")
    assert _derivations(from_class, "fake.py") == ["fake.py:1 derives a stage from a Class"]
    assert _derivations(from_path, "fake.py") == ["fake.py:1 derives a stage from a Class"]
    assert _derivations(reverse, "fake.py") == ["fake.py:1 derives a Class from a stage"]


def test_the_guard_catches_the_stage_constructor_keyword_shape() -> None:
    """The shape this codebase actually uses to build a ``System`` row."""
    tree = ast.parse(
        "sysm = System(pipeline_stage=STAGE_FOR[system.baseline], baseline=None)"
    )
    assert _derivations(tree, "fake.py") == [
        "fake.py:1 derives a stage from a baseline"
    ]


def test_the_guard_does_not_fire_on_independent_stage_keywords() -> None:
    """The legitimate constructor: a stage an operator authored, beside a
    baseline and a Class from their own unrelated sources. A guard that fired
    on this would forbid storing the field at all."""
    tree = ast.parse(
        "sysm = System(pipeline_stage=authored_stage, baseline=existing_baseline, "
        "certification_class=existing_class)"
    )
    assert _derivations(tree, "fake.py") == []


def test_the_real_model_declares_the_stage_this_guard_names() -> None:
    """A guard naming a column that does not exist protects nothing.

    ``_STAGE`` is a bare string to the AST walker, so a rename of the column
    -- or a guard written against a column never added -- would leave every
    assertion above passing against nothing at all.
    """
    from ccf.models import System  # noqa: PLC0415 - kept out of the walker's own imports

    columns = set(System.__table__.c.keys())
    assert columns >= _STAGE
    assert columns >= _CERT
    assert "baseline" in System.__table__.c


def test_the_guard_actually_reads_the_source_tree() -> None:
    """A walker pointed at an empty directory passes vacuously forever.

    A floor on each root separately, not on the total: a combined count would
    stay comfortably above any threshold if the migrations glob silently
    resolved to nothing, which is exactly the regression this exists to catch.
    """
    walked = _guarded_files()
    assert len([p for p, _ in walked if _SRC in p.parents]) > 50
    assert len([p for p, _ in walked if p.parent == _MIGRATIONS]) > 50
    assert any(label.startswith("migrations/") for _, label in walked)
