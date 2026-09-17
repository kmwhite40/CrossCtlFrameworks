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


def _derivations(tree: ast.AST, label: str) -> list[str]:
    """Any assignment that both mentions certificationType and reads a Class.

    Deliberately blunt: certificationType may be assigned a literal, or a
    variable, or set inside a dict -- what is forbidden is only that its value
    is computed from certification_class, certification_path or baseline. So
    the test is "this statement mentions the field AND its value mentions a
    Class source", which catches the subscript, attribute and dict-literal
    forms without enumerating them.
    """
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        value = ast.dump(node.value)
        if _TYPE in ast.dump(node) and any(src in value for src in _CLASS_SOURCES):
            hits.append(f"{label}:{node.lineno} derives {_TYPE} from a Class or baseline")
    return hits


def test_no_code_derives_certification_type_from_a_class_or_baseline() -> None:
    hits: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits += _derivations(tree, str(path.relative_to(_SRC)))
    assert not hits, hits


def test_the_guard_detects_the_shape_it_forbids() -> None:
    tree = ast.parse(
        'ident["certificationType"] = "20x" if system.certification_class else "Rev5"'
    )
    assert _derivations(tree, "fake.py") == [
        "fake.py:1 derives certificationType from a Class or baseline"
    ]


def test_the_guard_reads_the_real_source_tree() -> None:
    assert len(list(_SRC.rglob("*.py"))) > 50
