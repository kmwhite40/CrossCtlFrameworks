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
"""

from __future__ import annotations

import ast
from pathlib import Path

from ccf.models import User

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"


def _enum_members() -> set[str]:
    """The roles the database can actually store, read from the column itself."""
    return set(User.__table__.c.role.type.enums)


def _required_role_names() -> dict[str, set[str]]:
    """Every string literal passed to a ``require_role(...)`` call, by file."""
    found: dict[str, set[str]] = {}
    for path in _SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name != "require_role":
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.setdefault(str(path.relative_to(_SRC)), set()).add(arg.value)
    return found


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
