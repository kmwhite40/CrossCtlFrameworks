"""A deleted system stops appearing in the lists, not only behind its own id.

``tests/test_deleted_systems_are_not_readable.py`` closed the routes that take a
``{system_id}``: ask for a soft-deleted system by id and you get a 404. It sweeps
by path parameter, so it cannot see this defect at all -- these are **list** pages
with no id in the path, which enumerate an organization's systems and hand the
rows to a template.

Four of them did not filter ``deleted_at``:

* ``/assurance`` (``ui_grc.py``) -- the page the user reported
* ``/scans`` (``ui_grc.py``)
* ``/reports`` (``ui.py``)
* and the connector-detail picker in ``ui_grc.py``

Each had hand-written ``select(System).order_by(System.name)`` where the eleven
pages that get it right write
``select(System).where(System.deleted_at.is_(None))``. One rule, many copies,
some of them wrong -- the same shape the readable-routes fix found, in the
surface that sweep does not reach.

It matters for a plain reason: a customer who deleted a system was told it is
gone, and then sees it in a dropdown and picks it. DATA-04 says a deleted
system's id can no longer be used to scope new scans, evidence or POA&Ms -- and
offering it in a picker is an invitation to try.

**This guard is behavioural and swept, not a list of four fixes.** It renders every
GET page the app serves and asserts the deleted system's name is absent from the
HTML, so a page added next month is covered without anybody remembering to add it
here.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import Organization, System

_SEQ = itertools.count()

#: A name no template could render for any other reason, so finding it in the
#: HTML is unambiguous. Distinctive rather than realistic on purpose: a name like
#: "Test System" could appear in boilerplate and make the guard pass or fail for
#: the wrong reason.
DELETED_NAME = "Zzyzx-Deleted-System-Marker"
LIVE_NAME = "Zzyzx-Live-System-Marker"


def _html_get_paths() -> list[str]:
    """Every GET route with no path parameter that serves a page.

    No path parameter, because those are what the readable-routes sweep already
    covers; this is specifically the list surface. ``/api`` is excluded -- the JSON
    routes have their own guard -- and so are the handful of paths that exist to
    end a session or stream a file.
    """
    app = create_app()
    skip = {"/logout", "/login", "/healthz", "/readyz", "/metrics", "/docs", "/redoc"}

    def flatten(obj: object, depth: int = 0):
        """UI routes are not flat on ``app.routes``.

        The first version of this walked ``app.routes`` directly and enumerated
        **zero** pages -- every parametrized test was then skipped with "got empty
        parameter set" and the file passed by doing nothing. The same descent the
        writable-routes sweep uses, for the same reason.
        """
        if depth > 6:
            return
        for attr in (
            "routes",
            "original_router",
            "effective_candidates",
            "effective_low_priority_routes",
        ):
            val = getattr(obj, attr, None)
            if val is None:
                continue
            items = val if isinstance(val, (list, tuple)) else getattr(val, "routes", None)
            if not items:
                continue
            for it in items:
                if isinstance(it, APIRoute):
                    yield it
                else:
                    yield from flatten(it, depth + 1)

    out: set[str] = set()
    for r in app.routes:
        for route in [r, *flatten(r)]:
            if not isinstance(route, APIRoute):
                continue
            if "GET" not in route.methods:
                continue
            path = route.path
            if "{" in path or path.startswith("/api") or path in skip:
                continue
            out.add(path)
    return sorted(out)


PAGES = _html_get_paths()


async def _org_with_a_deleted_system() -> int:
    n = next(_SEQ)
    async with session_scope() as session:
        org = Organization(name=f"DeletedListOrg{n}")
        session.add(org)
        await session.flush()
        session.add(System(organization_id=org.id, name=LIVE_NAME, baseline="moderate"))
        session.add(
            System(
                organization_id=org.id,
                name=DELETED_NAME,
                baseline="moderate",
                deleted_at=datetime.now(UTC),
            )
        )
        await session.flush()
        return org.id


def _client(org_id: int) -> AsyncClient:
    app = create_app()

    def _principal() -> Principal:
        return Principal(user_id=1, email="owner@customer.gov", org_id=org_id, role="admin")

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_principal_optional] = _principal
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def test_the_sweep_found_pages_to_check() -> None:
    """A guard that enumerates nothing passes forever.

    This is the assertion that makes the rest of the file mean something: if
    ``_html_get_paths`` stops matching routes -- a refactor, a router rename -- every
    test below would pass over an empty list.
    """
    assert len(PAGES) >= 20, f"only {len(PAGES)} pages enumerated: {PAGES}"
    for expected in ("/assurance", "/scans", "/reports", "/dashboard", "/workspace"):
        assert expected in PAGES, f"{expected} is not in the swept set"


@pytest.mark.parametrize("path", PAGES)
async def test_no_page_lists_a_deleted_system(path: str) -> None:
    """Named per path, so a regression says which page started showing it."""
    org_id = await _org_with_a_deleted_system()
    async with _client(org_id) as c:
        r = await c.get(path)

    # A page that errors or redirects is not this test's subject -- other tests
    # cover rendering -- but it must not leak the name on the way out either.
    assert DELETED_NAME not in r.text, (
        f"{path} ({r.status_code}) lists a soft-deleted system. A customer who "
        "deleted it was told it is gone, and DATA-04 says its id can no longer "
        "scope new scans, evidence or POA&Ms -- so offering it in a list is an "
        "invitation to pick it."
    )


async def test_the_live_system_is_still_listed_somewhere() -> None:
    """The other direction, and the reason the fixture seeds two systems.

    A filter applied too broadly -- or a page that renders no systems at all --
    would satisfy every assertion above while making the product useless. At
    least one page must show the live system, or this guard is passing because
    nothing works.
    """
    org_id = await _org_with_a_deleted_system()
    showed_live: list[str] = []
    async with _client(org_id) as c:
        for path in PAGES:
            r = await c.get(path)
            if LIVE_NAME in r.text:
                showed_live.append(path)

    assert showed_live, (
        "no page listed the live system, so the deleted-system assertions above "
        "are passing because no system is rendered anywhere"
    )
