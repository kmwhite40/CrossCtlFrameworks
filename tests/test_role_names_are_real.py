"""Every role named in a ``require_role(...)`` must exist in the ``user_role`` enum.

This bug reached FIVE files before anyone noticed: ``waivers.py``,
``enforcement.py``, ``patching.py``, ``fedramp20x.py`` and ``reliability.py``
each named ``issm``, ``isso`` or ``platform_admin`` -- none of which the enum
can hold. ``require_role`` matches on string equality, so such a name matches
nobody and the gate silently narrows to whatever real roles remain beside it.

It fails closed, so it is not a hole. It is worse in a quieter way: the route
reads as broader than it is, a 403 names a role the user could never hold, and
in ``patching.py`` it locked ``control_owner`` -- the operator who actually
runs a patch wave -- out of the endpoint built for them.

A grep is the right shape of test here: the names are string literals at
import time, so no amount of route exercising would catch a dead one.

The first version of this guard only read string literals passed *directly*
to ``require_role(...)``, which left a hole shaped exactly like the bug: a
module-level ``ROLES = ("admin", "issm", "isso")`` splatted in as
``require_role(*ROLES)`` walked straight past it, and ``packs.py`` had carried
two dead names that whole time. The resolver below therefore follows a
splatted module-level tuple/list/set of literals to its members, and -- the
part that keeps this test able to fail -- refuses any argument it *cannot*
resolve rather than skipping it. A guard that silently ignores what it does
not understand is indistinguishable from one that passes.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ccf.models import User

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"


def _enum_members() -> set[str]:
    """The roles the database can actually store, read from the column itself."""
    return set(User.__table__.c.role.type.enums)


def _string_literals(node: ast.AST) -> list[str] | None:
    """The members of a tuple/list/set of string literals, else ``None``."""
    if not isinstance(node, ast.Tuple | ast.List | ast.Set):
        return None
    out: list[str] = []
    for el in node.elts:
        if not (isinstance(el, ast.Constant) and isinstance(el.value, str)):
            return None
        out.append(el.value)
    return out


def _module_role_constants(tree: ast.Module) -> dict[str, list[str]]:
    """Module-level ``NAME = ("a", "b")`` bindings, so ``*NAME`` can be resolved.

    Only top-level assignments: a name rebound inside a function is not what a
    module-scope ``require_role(*NAME)`` default argument evaluates.
    """
    consts: dict[str, list[str]] = {}
    for stmt in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets, value = list(stmt.targets), stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        if value is None:
            continue
        members = _string_literals(value)
        if members is None:
            continue
        for t in targets:
            if isinstance(t, ast.Name):
                consts[t.id] = members
    return consts


def _resolve_arg(arg: ast.expr, consts: dict[str, list[str]]) -> list[str] | None:
    """The role names one ``require_role`` argument contributes, or ``None``.

    ``None`` means "this test cannot tell what roles this names" -- which is
    reported as an offense, not skipped.
    """
    if isinstance(arg, ast.Constant):
        return [arg.value] if isinstance(arg.value, str) else None
    if isinstance(arg, ast.Starred):
        inner = arg.value
        literal = _string_literals(inner)
        if literal is not None:
            return literal
        if isinstance(inner, ast.Name):
            return consts.get(inner.id)
        return None
    return None


def _scan() -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    """``({file: role names}, {file: unresolvable arg sources})``.

    Resolves string literals *and* splatted module-level tuple/list/set
    constants -- ``require_role(*ADOPTER_ROLES)`` counts exactly as much as
    ``require_role("admin", "issm")``, which is how the ``packs.py`` pair of
    dead names survived the literals-only version of this guard.
    """
    found: dict[str, set[str]] = {}
    unresolved: dict[str, list[str]] = {}
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        consts = _module_role_constants(tree)
        where = str(path.relative_to(_SRC))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name != "require_role":
                continue
            for arg in node.args:
                names = _resolve_arg(arg, consts)
                if names is None:
                    unresolved.setdefault(where, []).append(ast.unparse(arg))
                else:
                    found.setdefault(where, set()).update(names)
            if node.keywords:
                unresolved.setdefault(where, []).append(
                    f"keyword arguments to require_role at line {node.lineno}"
                )
    return found, unresolved


def _required_role_names() -> dict[str, set[str]]:
    """Every role name a ``require_role(...)`` call gates on, by file."""
    return _scan()[0]


def test_every_require_role_name_exists_in_the_user_role_enum() -> None:
    valid = _enum_members()
    assert valid, "could not read the user_role enum members"
    offenders = {
        where: sorted(names - valid)
        for where, names in _required_role_names().items()
        if names - valid
    }
    assert not offenders, (
        "require_role names a role the user_role enum cannot hold, so it matches "
        f"nobody and the gate silently narrows: {offenders}. Valid roles: {sorted(valid)}"
    )


def test_the_check_would_catch_a_dead_name() -> None:
    """The guard above is a grep; prove it can fail rather than trusting it."""
    valid = _enum_members()
    assert "platform_admin" not in valid, (
        "platform_admin is not a user_role -- if this ever becomes one, the "
        "guard above stops protecting against it and this test should be revisited"
    )
    assert {"admin", "issm"} - valid == {"issm"}


def test_every_require_role_argument_is_resolvable() -> None:
    """The guard must not quietly skip what it cannot read.

    ``require_role(*ADOPTER_ROLES)`` used to contribute nothing at all to the
    check above -- no names, no complaint -- which is precisely how two roles
    the enum cannot hold sat in ``packs.py`` unnoticed. If a new call site
    names its roles in a way this resolver does not understand, that is a
    failure here, not a silent pass there.
    """
    unresolved = _scan()[1]
    assert not unresolved, (
        "require_role is called with an argument this guard cannot resolve to "
        f"role names, so those names go unchecked: {unresolved}. Either pass "
        "string literals / a module-level tuple of them, or teach _resolve_arg."
    )


def test_the_check_reaches_through_a_splatted_constant() -> None:
    """Prove the widening, the same way ``test_the_check_would_catch_a_dead_name``
    proves the literal path: a synthetic module with a dead name behind a splat
    must be seen, and one behind an unreadable expression must be refused."""
    caught = ast.parse(
        'ROLES = ("admin", "issm")\n'
        "def f(p = Depends(require_role(*ROLES))): ...\n"
    )
    consts = _module_role_constants(caught)
    assert consts == {"ROLES": ["admin", "issm"]}
    call = next(
        n
        for n in ast.walk(caught)
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "require_role"
    )
    assert _resolve_arg(call.args[0], consts) == ["admin", "issm"]

    opaque = ast.parse("def f(p = Depends(require_role(*roles_for(x)))): ...")
    call2 = next(
        n
        for n in ast.walk(opaque)
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "require_role"
    )
    assert _resolve_arg(call2.args[0], {}) is None
