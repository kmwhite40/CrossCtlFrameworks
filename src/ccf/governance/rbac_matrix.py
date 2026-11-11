"""The permission matrix, read out of the running application's routes.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, section F.

Every row is computed from a route's own dependency tree -- the
``require_role(...)`` / ``require_platform_admin()`` closures FastAPI will
actually call -- plus the two gates that sit in front of every route: the
public-path list and the viewer write refusal in
``ccf.api.auth_deps.auth_gate_middleware``. Nothing here is a hand-written
table, so a route whose gate changes changes its row, and a new route appears
the moment it is registered.

What it cannot see, and says so: a role check written inside a handler body
(``if principal.role != ...``) is not a dependency, so a route that does that
is reported as "any signed-in user". The page states this limit next to the
matrix rather than letting the table imply completeness it does not have.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute

from ..api.auth_deps import is_public_path, viewer_may_write
from ..identity.provisioning import VALID_ROLES

#: Tenant roles in the order the page shows them, most privileged first.
#: Derived from ``VALID_ROLES`` so a fifth role cannot be silently dropped:
#: anything not in the preferred order is appended.
_PREFERRED = ("admin", "control_owner", "assessor", "viewer")
ROLES: tuple[str, ...] = tuple(r for r in _PREFERRED if r in VALID_ROLES) + tuple(
    sorted(VALID_ROLES - set(_PREFERRED))
)

GATE_ROLE = "role"
GATE_PLATFORM = "platform"
GATE_SIGNED_IN = "signed_in"
GATE_PUBLIC = "public"
GATES = (GATE_ROLE, GATE_PLATFORM, GATE_SIGNED_IN, GATE_PUBLIC)
GATE_LABELS = {
    GATE_ROLE: "require_role",
    GATE_PLATFORM: "require_platform_admin",
    GATE_SIGNED_IN: "any signed-in user",
    GATE_PUBLIC: "public (no sign-in)",
}

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_PARAM = re.compile(r"\{[^}]+\}")


@dataclass(frozen=True)
class RouteGate:
    """One (path, method) and who the running app admits to it."""

    path: str
    method: str
    gate: str
    #: The roles ``require_role`` names (empty for every other gate).
    roles: tuple[str, ...]
    #: Per tenant role: admitted or not, after the viewer write refusal.
    admits: dict[str, bool]
    #: A viewer would pass the route's own gate but the middleware refuses it.
    viewer_refused_by_middleware: bool
    endpoint: str

    @property
    def gate_label(self) -> str:
        if self.gate == GATE_ROLE:
            return "require_role(" + ", ".join(self.roles) + ")"
        return GATE_LABELS[self.gate]


def _dependency_calls(dependant: Any) -> list[Callable[..., Any]]:
    """Every callable in a route's dependency tree, depth first."""
    out: list[Callable[..., Any]] = []
    stack = list(getattr(dependant, "dependencies", None) or [])
    while stack:
        dep = stack.pop(0)
        call = getattr(dep, "call", None)
        if call is not None:
            out.append(call)
        stack[0:0] = list(getattr(dep, "dependencies", None) or [])
    return out


def _qualname(call: Callable[..., Any]) -> str:
    return getattr(call, "__qualname__", "") or ""


def _closure_roles(call: Callable[..., Any]) -> tuple[str, ...] | None:
    """The ``roles`` a ``require_role(...)`` closure was built with, else ``None``.

    Read from the closure cell -- the same value the dependency compares the
    principal's role against -- not from the source text.
    """
    if not _qualname(call).startswith("require_role.<locals>."):
        return None
    roles = inspect.getclosurevars(call).nonlocals.get("roles")
    if not isinstance(roles, tuple):
        return None
    return tuple(str(r) for r in roles)


def _is_platform_gate(call: Callable[..., Any]) -> bool:
    return _qualname(call).startswith("require_platform_admin.<locals>.")


def classify(path: str, method: str, dependant: Any, endpoint: str = "") -> RouteGate:
    """Who the app admits to ``method path`` given the route's ``dependant``."""
    calls = _dependency_calls(dependant)
    role_sets = [r for r in (_closure_roles(c) for c in calls) if r is not None]
    platform = any(_is_platform_gate(c) for c in calls)

    roles: tuple[str, ...] = ()
    if platform:
        gate = GATE_PLATFORM
        admitted = dict.fromkeys(ROLES, False)
    elif role_sets:
        gate = GATE_ROLE
        # Several require_role dependencies on one route must ALL pass.
        allowed = set(role_sets[0]).intersection(*role_sets[1:])
        roles = tuple(r for r in role_sets[0] if r in allowed)
        admitted = {r: r in allowed for r in ROLES}
    elif is_public_path(path):
        gate = GATE_PUBLIC
        admitted = dict.fromkeys(ROLES, True)
    else:
        gate = GATE_SIGNED_IN
        admitted = dict.fromkeys(ROLES, True)

    # The auth gate refuses a viewer's mutating request off the allowlist on
    # every non-public path, whatever the route's own dependency says.
    refused = False
    if (
        gate != GATE_PUBLIC
        and method in _MUTATING
        and admitted.get("viewer")
        and not viewer_may_write(_PARAM.sub("1", path), method)
    ):
        admitted["viewer"] = False
        refused = True
    return RouteGate(
        path=path,
        method=method,
        gate=gate,
        roles=roles,
        admits=admitted,
        viewer_refused_by_middleware=refused,
        endpoint=endpoint,
    )


def _walk(routes: Iterable[Any]) -> Iterable[Any]:
    """Every API route the app serves, with prefixes and include-level
    dependencies applied (FastAPI wraps included routers lazily)."""
    included = getattr(fastapi_routing, "_IncludedRouter", None)
    effective = getattr(fastapi_routing, "_EffectiveRouteContext", None)
    for route in routes:
        if included is not None and isinstance(route, included):
            yield from _walk(route.effective_candidates())
            continue
        if isinstance(route, APIRoute) or (effective is not None and isinstance(route, effective)):
            yield route
            continue
        sub = getattr(route, "routes", None)
        if sub is not None and not getattr(route, "methods", None):
            yield from _walk(sub)


def route_matrix(app: Any) -> list[RouteGate]:
    """The permission matrix of ``app``, one row per (path, method)."""
    rows: dict[tuple[str, str], RouteGate] = {}
    for route in _walk(app.routes):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        endpoint = getattr(route, "endpoint", None)
        ep = f"{getattr(endpoint, '__module__', '')}.{getattr(endpoint, '__name__', '')}"
        for method in sorted(getattr(route, "methods", None) or ()):
            if method == "HEAD":
                continue
            key = (route.path, method)
            # First registration wins, as it does when Starlette matches.
            rows.setdefault(key, classify(route.path, method, dependant, ep))
    return sorted(rows.values(), key=lambda g: (g.path, g.method))


def summarize(rows: list[RouteGate]) -> dict[str, int]:
    """Routes per gate. The four gates partition the rows: they sum to the total."""
    out = dict.fromkeys(GATES, 0)
    for g in rows:
        out[g.gate] += 1
    out["total"] = len(rows)
    return out
