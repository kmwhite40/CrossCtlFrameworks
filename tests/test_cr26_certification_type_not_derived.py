"""Nothing may derive the CPO's certificationType from a Certification Class.

certificationType enumerates 20x and Rev5 -- which deliverable profile a
package is filed under. It is tempting to infer it from whether a system has a
certification_class, and that inference must not be made: through 2026-27 an
offering may hold a Rev5 ATO and pursue a CR26 Certification at once, so the
presence of a Class says nothing definitive about the profile. It is the same
class of mistake as deriving Class from baseline, which
tests/test_certification_class_is_independent.py exists to prevent.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"
_TYPE = "certificationType"
_CLASS_SOURCES = ("certification_class", "certification_path", "baseline")


def _value_exprs(node: ast.AST) -> list[ast.expr]:
    """The expressions that could *supply* certificationType's value in ``node``.

    Only value positions, never the whole node: a docstring or a comment-like
    string that merely names both certificationType and certification_class --
    as ``ccf.cr26.cpo``'s own docstring does, saying not to do this -- must not
    register as a derivation.
    """
    if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Return)):
        return [node.value] if node.value is not None else []
    if isinstance(node, ast.Call):
        # Covers ident.setdefault("certificationType", X), d.update({...}) and
        # a certificationType=X keyword argument alike.
        return [*node.args, *(kw.value for kw in node.keywords)]
    if isinstance(node, ast.Dict):
        return list(node.values)
    return []


def _derivations(tree: ast.AST, label: str) -> list[str]:
    """Any value-carrying node that mentions certificationType and reads a Class.

    Deliberately blunt about *how* the field is written: it may be assigned,
    set via setdefault or update, returned inside a dict literal, or passed as
    a keyword argument. What is forbidden is only that the value it receives is
    computed from certification_class, certification_path or baseline. So the
    test is "this node mentions the field AND one of its value expressions
    mentions a Class source", which catches the subscript, attribute,
    dict-literal, setdefault, update, return-dict and keyword forms without
    enumerating them at the statement level. Reported once per line, since one
    statement can match as several nested nodes.
    """
    hits: dict[int, str] = {}
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Return, ast.Call, ast.Dict)
        ):
            continue
        values = _value_exprs(node)
        if not values or _TYPE not in ast.dump(node):
            continue
        if any(src in ast.dump(value) for value in values for src in _CLASS_SOURCES):
            hits[node.lineno] = f"{label}:{node.lineno} derives {_TYPE} from a Class or baseline"
    return [hits[line] for line in sorted(hits)]


#: Every way this codebase could plausibly write the field. `setdefault` is not
#: hypothetical -- it is the exact idiom ``ccf.cr26.cpo.seed_cpo`` uses to
#: populate serviceIdentification, so it is the single most likely shape a
#: derivation would arrive in, and an earlier version of this guard (walking
#: only ast.Assign/ast.AnnAssign) could not see it.
_FORBIDDEN_SHAPES = (
    'ident["certificationType"] = "20x" if system.certification_class else "Rev5"',
    'ident["certificationType"]: str = system.certification_class',
    'ident.setdefault("certificationType", "20x" if system.certification_class else "Rev5")',
    'ident.update({"certificationType": profile(system.certification_path)})',
    'build_cpo(certificationType="20x" if system.certification_class else "Rev5")',
    'def f(system):\n    return {"certificationType": "20x" if system.baseline else "Rev5"}',
)

#: Shapes that must NOT register -- the guard has to stay narrow enough to be
#: usable. The last is the reason _value_exprs looks at value positions only.
_ALLOWED_SHAPES = (
    'ident["certificationType"] = document["serviceIdentification"]["certificationType"]',
    'ident.setdefault("certificationType", authored_type)',
    '"""certificationType must never be inferred from certification_class."""',
    'system.certification_class = "20x"',
)


def test_no_code_derives_certification_type_from_a_class_or_baseline() -> None:
    hits: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits += _derivations(tree, str(path.relative_to(_SRC)))
    assert not hits, hits


def test_the_guard_detects_every_shape_it_forbids() -> None:
    for source in _FORBIDDEN_SHAPES:
        hits = _derivations(ast.parse(source), "fake.py")
        assert len(hits) == 1, (source, hits)
        assert hits[0].endswith(f"derives {_TYPE} from a Class or baseline"), (source, hits)


def test_the_guard_does_not_fire_on_shapes_that_are_fine() -> None:
    for source in _ALLOWED_SHAPES:
        assert _derivations(ast.parse(source), "fake.py") == [], source


def test_the_guard_reads_the_real_source_tree() -> None:
    assert len(list(_SRC.rglob("*.py"))) > 50
