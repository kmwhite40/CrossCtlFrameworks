"""Declarative posture predicates -- desired state expressed as data.

A tenant declares an expectation in a pack manifest and this module evaluates
it against the rows a provider collection returned, producing the same
:class:`ResourceFinding` objects a hand-written evaluator produces. That is
what gives ``PackRule`` its first reader (see the spec for why it had none).

Pure by construction: no database, no network, no clock. Where a check needs a
clock or real logic it stays a platform evaluator and a pack parameterizes it
instead (Form A) -- this module is Form B, for the shapes that are genuinely
declarative.

**The rule that shapes every decision here: a predicate that cannot be
answered never reports ``pass``.** A missing path, a list operator against a
scalar, or a collection that returned nothing all yield
``manual_review_required`` naming the reason. The alternative -- treating
absence as satisfaction -- puts an unobserved claim into an authorization
package, which is the one failure mode that cannot be walked back. So
:func:`evaluate_predicate` is three-valued: ``True``, ``False``, or ``None``
for "this row cannot answer".

The vocabulary is closed and small. Every op omitted (arithmetic, dates,
regex) is omitted deliberately: each one is a form whose edge cases the
evaluator must get right, and the two platform checks that motivated a
declarative form need none of them. An unknown op raises
:class:`PredicateError` rather than returning a verdict, because
``packs.catalog`` rejects unknown vocabulary at install time -- reaching this
module with one means validation was bypassed, and guessing would be worse
than failing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .types import ResourceFinding

#: Closed predicate vocabulary. ``packs.catalog`` validates against this set,
#: so the validator and the evaluator can never drift apart.
OPS: frozenset[str] = frozenset(
    {"truthy", "falsy", "equals", "not_equals", "contains", "intersects", "all_of", "any_of"}
)

#: How findings are shaped: one per row, or one for the whole collection.
MODES: frozenset[str] = frozenset({"per_resource", "any_row"})

_COMPOSITE = ("all_of", "any_of")
_MEMBERSHIP = ("contains", "intersects")

#: Cap on ``all_of``/``any_of`` nesting. Both the recursive validator and the
#: recursive evaluator need it: a manifest nested deeper than this would
#: otherwise raise ``RecursionError`` out of ``validate_manifest`` (whose
#: docstring promises it never raises -- so this would be a 500 on
#: ``/api/packs/validate``) or, for a row that predates validation, out of
#: ``evaluate_predicate`` during a scan. Eight is far past any predicate a
#: human would hand-author (the two platform checks that motivated Form B
#: need zero nesting) and comfortably bounds the recursion either way.
_MAX_PREDICATE_DEPTH = 8


class PredicateError(ValueError):
    """A predicate or spec that cannot be evaluated as written."""


@dataclass(frozen=True)
class DeclaredSpec:
    """A declared check's evaluation half: how to judge rows, and what to say.

    The :class:`PostureCheck` metadata (control ids, provider, permissions)
    lives beside this in a resolved check; this is only what evaluation needs,
    so it stays testable without a database.
    """

    mode: str
    resource_type: str
    predicate: dict[str, Any]
    expected: str
    resource_id_field: str | None = None
    pass_observed: str | None = None
    fail_observed: str | None = None


def resolve_path(row: Any, path: str) -> Any:
    """Walk a dotted path, returning ``None`` where the row cannot answer.

    A missing key, an explicit null, and a scalar where a mapping was expected
    are all ``None``: Graph omits fields it has no licence to report, so the
    three are indistinguishable from the outside and collapsing them is
    correct. What must not happen is raising mid-scan, which would discard the
    checks that did run.
    """
    current = row
    for segment in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def _require(predicate: dict[str, Any], key: str) -> Any:
    if key not in predicate:
        raise PredicateError(f"predicate {predicate.get('op')!r} requires {key!r}")
    return predicate[key]


def _evaluate_composite(
    op: str, predicate: dict[str, Any], row: dict[str, Any], depth: int
) -> bool | None:
    """``all_of`` / ``any_of`` over child predicates."""
    children = predicate.get("predicates")
    if not isinstance(children, list) or not children:
        # An empty all_of is vacuously true, which would pass every resource;
        # an empty any_of is vacuously false. Neither is ever what an author
        # meant, so both are errors rather than verdicts.
        raise PredicateError(f"{op!r} requires a non-empty 'predicates' list")
    results = [evaluate_predicate(child, row, _depth=depth + 1) for child in children]
    if op == "all_of":
        # A definite failure outranks an undeterminable sibling: the row is
        # non-compliant whatever the missing field would have said.
        if any(r is False for r in results):
            return False
        return None if any(r is None for r in results) else True
    if any(r is True for r in results):
        return True
    return None if any(r is None for r in results) else False


def _evaluate_membership(op: str, predicate: dict[str, Any], observed: Any) -> bool | None:
    """``contains`` / ``intersects`` -- list operators, deliberately list-only.

    A string "contains" a substring, and letting that satisfy list membership
    is how a check silently passes, so a scalar is undeterminable rather than
    coerced.
    """
    if op == "contains":
        if not isinstance(observed, list):
            return None
        return _require(predicate, "value") in observed
    values = _require(predicate, "values")
    if not isinstance(values, list):
        raise PredicateError("'intersects' requires 'values' to be a list")
    if not isinstance(observed, list):
        return None
    return bool(set(observed) & set(values))


def _evaluate_value(op: str, predicate: dict[str, Any], observed: Any) -> bool | None:
    """``truthy`` / ``falsy`` / ``equals`` / ``not_equals`` against one value.

    Absence is undeterminable for all four -- including ``falsy``, which is the
    dangerous direction: a missing field must not satisfy a "must be off"
    check.
    """
    if observed is None:
        return None
    if op == "truthy":
        return bool(observed)
    if op == "falsy":
        return not bool(observed)
    equal = observed == _require(predicate, "value")
    return equal if op == "equals" else not equal


def evaluate_predicate(predicate: Any, row: dict[str, Any], *, _depth: int = 0) -> bool | None:
    """Three-valued evaluation: satisfied, violated, or undeterminable.

    ``None`` means *this row cannot answer the question* -- never "no".

    ``_depth`` is internal (recursive composite calls only): it caps
    ``all_of``/``any_of`` nesting at :data:`_MAX_PREDICATE_DEPTH` so a
    pathologically nested spec that predates install-time validation cannot
    blow the stack mid-scan -- it fails closed as an unrunnable check instead
    (the same path a mistyped op already takes).
    """
    if _depth > _MAX_PREDICATE_DEPTH:
        raise PredicateError(f"predicate nesting exceeds max depth of {_MAX_PREDICATE_DEPTH}")
    if not isinstance(predicate, dict):
        raise PredicateError(f"predicate must be an object, got {type(predicate).__name__}")
    op = predicate.get("op")
    if not isinstance(op, str) or op not in OPS:
        raise PredicateError(f"unknown predicate op: {op!r}")
    if op in _COMPOSITE:
        return _evaluate_composite(op, predicate, row, _depth)
    observed = resolve_path(row, str(_require(predicate, "path")))
    if op in _MEMBERSHIP:
        return _evaluate_membership(op, predicate, observed)
    return _evaluate_value(op, predicate, observed)


def _row_id(spec: DeclaredSpec, row: dict[str, Any]) -> str:
    """Never empty, and never dropped.

    An unidentified failing resource is still a failing resource, so a row
    without the declared identifier falls back to ``id`` and then to
    ``"unknown"`` rather than being skipped.
    """
    if spec.resource_id_field:
        value = resolve_path(row, spec.resource_id_field)
        if isinstance(value, str) and value:
            return value
    return str(row.get("id") or "unknown")


def _undeterminable_observed(predicate: dict[str, Any]) -> str:
    """Name what could not be read, so an operator is not left guessing."""
    paths = _paths(predicate)
    if paths:
        return "could not evaluate: no value at " + ", ".join(sorted(paths))
    return "could not evaluate: the collection reported nothing usable"


def _paths(predicate: Any) -> set[str]:
    if not isinstance(predicate, dict):
        return set()
    if predicate.get("op") in _COMPOSITE:
        out: set[str] = set()
        for child in predicate.get("predicates") or []:
            out |= _paths(child)
        return out
    path = predicate.get("path")
    return {str(path)} if isinstance(path, str) else set()


def evaluate_declared(
    spec: DeclaredSpec, rows: list[dict[str, Any]], *, resource_id: str | None = None
) -> list[ResourceFinding]:
    """Findings for one declared check over one collection.

    ``resource_id`` names the subject in ``any_row`` mode, where the resource
    is the tenant rather than a row.
    """
    if spec.mode not in MODES:
        raise PredicateError(f"unknown mode: {spec.mode!r}")

    if spec.mode == "per_resource":
        findings: list[ResourceFinding] = []
        for row in rows:
            result = evaluate_predicate(spec.predicate, row)
            findings.append(
                ResourceFinding(
                    resource_id=_row_id(spec, row),
                    resource_type=spec.resource_type,
                    verdict=(
                        "manual_review_required"
                        if result is None
                        else ("pass" if result else "fail")
                    ),
                    observed=_observed(spec, result),
                )
            )
        return findings

    # any_row: one finding for the collection. Nothing determinable -- including
    # no rows at all -- is manual_review_required, not fail: "no policy exists"
    # must not be asserted from "nothing was returned", the same distinction
    # msgraph._unrunnable draws between a 403 and an empty fleet.
    subject = resource_id or "unknown"
    results = [evaluate_predicate(spec.predicate, row) for row in rows]
    if any(r is True for r in results):
        verdict, result = "pass", True
    elif results and all(r is False for r in results):
        verdict, result = "fail", False
    else:
        verdict, result = "manual_review_required", None
    return [
        ResourceFinding(
            resource_id=subject,
            resource_type=spec.resource_type,
            verdict=verdict,
            observed=_observed(spec, result, examined=len(rows)),
        )
    ]


def _observed(
    spec: DeclaredSpec, result: bool | None, *, examined: int | None = None
) -> str:
    """Observed text, preferring the author's wording over a generic sentence.

    Authored text is what makes a declared check's output read like the
    platform's, which the golden equivalence test in
    ``tests/test_posture_declared.py`` depends on.
    """
    if result is None:
        base = _undeterminable_observed(spec.predicate)
        if examined == 0:
            return "could not evaluate: the collection returned no rows"
        return base
    if result:
        return spec.pass_observed or f"satisfied: {spec.expected}"
    if spec.fail_observed:
        return spec.fail_observed
    if examined is not None:
        return f"not satisfied: {spec.expected} (examined {examined})"
    return f"not satisfied: {spec.expected}"


def validate_predicate(
    predicate: Any, *, where: str = "predicate", _depth: int = 0
) -> list[str]:
    """Errors in a predicate as written; empty means it can be evaluated.

    The mirror of :func:`evaluate_predicate`, and deliberately in the same
    module: a validator that lives elsewhere drifts from the evaluator, and the
    drift shows up as a pack that installs and then cannot be scanned.

    Returns errors rather than raising, because ``packs.catalog.validate_manifest``
    reports every problem in a manifest at once.

    ``_depth`` is internal (recursive composite calls only): see
    :data:`_MAX_PREDICATE_DEPTH`. Without it, a deeply nested ``all_of``/
    ``any_of`` manifest raises ``RecursionError`` out of this function --
    and out of ``validate_manifest``, whose docstring says it never raises.
    """
    if _depth > _MAX_PREDICATE_DEPTH:
        return [f"{where} exceeds max nesting depth of {_MAX_PREDICATE_DEPTH}"]
    if not isinstance(predicate, dict):
        return [f"{where} must be an object"]
    op = predicate.get("op")
    if not isinstance(op, str) or op not in OPS:
        return [f"{where} has unknown op {op!r} (allowed: {', '.join(sorted(OPS))})"]

    if op in _COMPOSITE:
        children = predicate.get("predicates")
        if not isinstance(children, list) or not children:
            return [f"{where} {op!r} requires a non-empty 'predicates' list"]
        errors: list[str] = []
        for i, child in enumerate(children):
            errors.extend(
                validate_predicate(
                    child, where=f"{where}.predicates[{i}]", _depth=_depth + 1
                )
            )
        return errors

    errors = []
    if not isinstance(predicate.get("path"), str) or not predicate["path"]:
        errors.append(f"{where} {op!r} requires a non-empty 'path'")
    if op in ("equals", "not_equals", "contains") and "value" not in predicate:
        errors.append(f"{where} {op!r} requires 'value'")
    if op == "intersects" and not isinstance(predicate.get("values"), list):
        errors.append(f"{where} 'intersects' requires 'values' to be a list")
    return errors
