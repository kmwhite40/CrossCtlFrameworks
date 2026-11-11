"""Every route under ``/admin`` or ``/api/admin`` admits administrators only.

The server-rendered pages kept shipping without the gate their JSON twins
had: ``/api/admin/reliability`` required admin while ``/admin/reliability``
(the same checks, plus the outbox's dead letters) opened for any signed-in
user, and ``/admin/portal`` showed an organization's auditor grants to its
viewers. ``/admin/self-assurance`` was the same defect, found earlier. A
reviewer reading one route at a time misses the page beside it, so this test
reads every route the app serves.

The gate must be **declared** -- a ``require_role("admin")`` or
``require_platform_admin()`` dependency -- not just checked inside the
handler, because the declared gate is what ``/admin/rbac`` shows an auditor
and what :func:`ccf.api.navigation.visible_to` mirrors.
"""

from __future__ import annotations

import pytest

from ccf.api.main import create_app
from ccf.governance import rbac_matrix

#: Tenant roles below admin. None may reach an admin route.
NON_ADMIN_ROLES = ("control_owner", "assessor", "viewer")

#: (method, path) under an admin prefix that every role may reach, each with
#: its reason. Adding one is a review decision.
OPEN_ON_PURPOSE: dict[tuple[str, str], str] = {
    # Data-completeness counts for the caller's own organization: the same
    # figures the executive report (/api/reports/executive) gives every role.
    # Only the path says "admin".
    ("GET", "/api/admin/data-quality"): "org-scoped completeness, also in the executive report",
}


def _admin_routes() -> list[rbac_matrix.RouteGate]:
    return [
        r
        for r in rbac_matrix.route_matrix(create_app())
        if r.path.startswith(("/admin/", "/api/admin/")) or r.path in ("/admin", "/api/admin")
    ]


def test_no_admin_route_admits_a_non_admin_role() -> None:
    open_routes = sorted(
        f"{r.method} {r.path} ({r.gate_label}) admits "
        + ", ".join(k for k in NON_ADMIN_ROLES if r.admits.get(k))
        for r in _admin_routes()
        if (r.method, r.path) not in OPEN_ON_PURPOSE
        and any(r.admits.get(k) for k in NON_ADMIN_ROLES)
    )
    assert not open_routes, (
        "admin route(s) without a declared admin gate -- add "
        "Depends(require_role('admin')) or require_platform_admin(), and give "
        "the rail item audience={'admin'}:\n" + "\n".join(open_routes)
    )


def test_every_open_on_purpose_exemption_still_names_an_open_route() -> None:
    by_key = {(r.method, r.path): r for r in _admin_routes()}
    stale = sorted(
        f"{m} {p}"
        for (m, p) in OPEN_ON_PURPOSE
        if (m, p) not in by_key or not any(by_key[(m, p)].admits.get(k) for k in NON_ADMIN_ROLES)
    )
    assert not stale, f"OPEN_ON_PURPOSE names route(s) that are gone or now gated: {stale}"


def test_the_survey_sees_the_admin_routes_at_all() -> None:
    """Positive control: a prefix typo or a matrix change that returned
    nothing would pass the first test vacuously."""
    paths = {r.path for r in _admin_routes()}
    for expected in ("/admin/reliability", "/admin/portal", "/api/admin/reliability"):
        assert expected in paths, f"{expected} missing from the route survey"


@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
def test_the_matrix_refuses_a_declared_admin_gate(role: str) -> None:
    """Second positive control: the matrix's ``admits`` actually reports a
    refusal for a route known to declare require_role('admin')."""
    row = next(
        r for r in _admin_routes() if r.path == "/api/admin/reliability" and r.method == "GET"
    )
    assert row.admits.get(role) is False
