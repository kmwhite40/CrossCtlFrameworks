"""A deleted system's data stops being served, through every route that takes its id.

Found by asking the running app for a soft-deleted system by id. Eleven of the
thirty-three endpoints that take a ``system_id`` answered 200 with substantive
content for a system whose ``deleted_at`` was set -- including its **FedRAMP
authorization package** (39.9 KB), its **OSCAL POA&M**, its **OSCAL package
zip**, its full assurance graph (65 KB), its KSI validation results (65 KB), and
an SPRS score of ``-203``.

``org_systems_subq`` already excludes soft-deleted systems, and says why: DATA-04,
so a deleted system's id "can no longer be used to scope in new
risks/scans/evidence/POA&Ms". The nineteen endpoints that route through it
correctly answer 404. The eleven that do not each hand-wrote the same
precondition --

    select(System).where(System.id == system_id)

-- in ``scoring.py``, ``fedramp20x.py``, ``oscal.py``, ``scans.py`` and ``ui.py``,
and every copy omitted the filter. One rule, six implementations, one of them
right.

Two reasons this matters beyond tidiness. A customer who deletes a system has
been told it is gone, while its authorization package and POA&M remain
retrievable by id. And the SPRS score of a deleted system is a number reported
in a DoD context; the analytics rollups were already fixed to exclude these
systems, which is exactly how the per-system reads came to be the only place
still serving them.

Each case asserts **both** directions. A 404 on the deleted system proves nothing
on its own -- the endpoint might 404 for any reason, such as the fixture having
no package to export -- so every case first requires the *live* system to answer
without a 404. That is what makes the deletion the cause.
"""

from __future__ import annotations

import itertools
import re
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Assessment, Organization, System, SystemProfile

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

#: Every endpoint that answered 200 for a soft-deleted system, as a path template
#: taking one ``{sid}``. Kept as data so a new system-scoped read is one line to
#: cover, and so the list reads as the inventory it is.
SYSTEM_READS = [
    # The eleven that served a deleted system when this was found.
    "/api/assurance/graph/systems/{sid}",
    "/api/fedramp/20x/systems/{sid}/authorization-delta",
    "/api/fedramp/20x/systems/{sid}/dependencies",
    "/api/fedramp/20x/systems/{sid}/package",
    "/api/fedramp/20x/systems/{sid}/readiness",
    "/api/fedramp/20x/systems/{sid}/validations",
    "/api/oscal/component-definition/{sid}",
    "/api/oscal/package/{sid}",
    "/api/oscal/poam/{sid}",
    "/api/scoring/systems/{sid}/matrix",
    "/api/scoring/systems/{sid}/score",
    # The twenty that already refused one. Listed so they are *verified* rather
    # than assumed, and so a regression in any of them fails here.
    "/api/fedramp/20x/systems/{sid}/exceptions",
    "/api/fedramp/20x/systems/{sid}/profile",
    "/api/oscal/sar/system/{sid}",
    "/api/systems/{sid}/audit-plan",
    "/api/systems/{sid}/authorization-package",
    "/api/systems/{sid}/baseline-delta",
    "/api/systems/{sid}/boundary/components",
    "/api/systems/{sid}/boundary/information-types",
    "/api/systems/{sid}/boundary/interconnections",
    "/api/systems/{sid}/boundary/inventory",
    "/api/systems/{sid}/control-evaluations",
    "/api/systems/{sid}/coverage",
    "/api/systems/{sid}/cr26-documents",
    "/api/systems/{sid}/evidence-requirements",
    "/api/systems/{sid}/flaw-remediation",
    "/api/systems/{sid}/framework-posture",
    "/api/systems/{sid}/impact",
    "/api/systems/{sid}/live-audit-workflow",
    "/api/systems/{sid}/poams",
    "/api/systems/{sid}/summary",
]


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


class _Caller:
    def __init__(self, *, org_id: int | None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal
        self.app.dependency_overrides[get_principal_optional] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email="owner@customer.gov", org_id=self.org_id, role=self.role)

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


@pytest.fixture
async def one_live_and_one_deleted() -> tuple[int, int, int]:
    """(org_id, live_system_id, deleted_system_id) in the same organization."""
    tag = next(_SEQ)
    async with session_scope() as session:
        org = Organization(name=f"Deletion Scope Org {tag}")
        session.add(org)
        await session.flush()
        live = System(organization_id=org.id, name=f"live-{tag}", baseline="moderate")
        gone = System(organization_id=org.id, name=f"gone-{tag}", baseline="moderate")
        session.add_all([live, gone])
        await session.flush()
        gone.deleted_at = datetime.now(UTC)
        # Both systems get a profile. `coverage` and `evidence-requirements`
        # answer 404 without one ("system has no profile"), which would make the
        # live-side precondition unmeetable and the case prove nothing.
        for system in (live, gone):
            # The OSCAL SAR answers 404 with no assessment to report on, for the
            # same reason: without one the live side cannot answer and the case
            # would prove nothing.
            session.add(
                Assessment(system_id=system.id, name=f"baseline-{tag}", kind="self")
            )
            session.add(
                SystemProfile(
                    system_id=system.id,
                    answers={},
                    environment_type="cloud",
                    cloud_platform="m365_gcc_high",
                    frameworks=["NIST_800_171"],
                    derivation={},
                )
            )
        await session.flush()
        return int(org.id), int(live.id), int(gone.id)


#: Reads that need a query parameter before they will answer at all. Without it
#: they 422, which is neither a refusal nor an answer, and the case proves
#: nothing in either direction.
REQUIRED_QUERY = {
    "/api/systems/{sid}/baseline-delta": "?target=high",
}


@pytest.mark.parametrize("template", SYSTEM_READS)
@pytest.mark.asyncio
async def test_a_deleted_system_is_not_readable(
    template: str, one_live_and_one_deleted: tuple[int, int, int]
) -> None:
    """404 for the deleted system, and not-404 for its live sibling."""
    org_id, live_id, gone_id = one_live_and_one_deleted
    query = REQUIRED_QUERY.get(template, "")
    async with _Caller(org_id=org_id).client() as c:
        live = await c.get(template.format(sid=live_id) + query)
        gone = await c.get(template.format(sid=gone_id) + query)

    assert live.status_code != 404, (
        f"{template} does not serve a LIVE system either ({live.status_code}), so a "
        "404 on the deleted one would prove nothing. Fix the fixture, not the assertion."
    )
    assert gone.status_code == 404, (
        f"{template} served a soft-deleted system: {gone.status_code}, "
        f"{len(gone.content)} bytes"
    )


@pytest.mark.asyncio
async def test_a_deleted_system_is_not_readable_by_a_global_principal(
    one_live_and_one_deleted: tuple[int, int, int],
) -> None:
    """Deleted is deleted, not merely out of the caller's tenant.

    A global principal skips the organization comparison entirely, so without
    this the fix could be implemented as a scope check and still serve deleted
    systems to the one caller that bypasses scope.
    """
    _org_id, live_id, gone_id = one_live_and_one_deleted
    async with _Caller(org_id=None).client() as c:
        live = await c.get(f"/api/scoring/systems/{live_id}/score")
        gone = await c.get(f"/api/scoring/systems/{gone_id}/score")
    assert live.status_code != 404, live.status_code
    assert gone.status_code == 404, (
        f"a global principal still reads a deleted system: {gone.status_code}"
    )


@pytest.mark.asyncio
async def test_the_inventory_covers_every_system_scoped_read() -> None:
    """`SYSTEM_READS` must not quietly fall behind the routes it stands for.

    A new endpoint taking a `system_id` that nobody adds here would reintroduce
    the defect one route at a time, which is how it arrived: six hand-written
    copies of one precondition.
    """
    app = create_app()

    def flatten(obj, depth: int = 0):
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

    found: set[str] = set()
    for r in app.routes:
        for route in [r, *flatten(r)]:
            if not isinstance(route, APIRoute) or "GET" not in route.methods:
                continue
            if (
                "{system_id}" in route.path
                and route.path.startswith("/api")
                and not re.search(r"\{(?!system_id)[^}]+\}", route.path)
            ):
                found.add(route.path.replace("{system_id}", "{sid}"))

    covered = set(SYSTEM_READS)
    assert found - covered == set(), (
        "these system-scoped GETs are not in SYSTEM_READS, so nothing checks "
        f"whether they serve deleted systems: {sorted(found - covered)}"
    )
    assert covered - found == set(), (
        "SYSTEM_READS names routes that no longer exist, which makes their cases "
        f"pass without testing anything: {sorted(covered - found)}"
    )
