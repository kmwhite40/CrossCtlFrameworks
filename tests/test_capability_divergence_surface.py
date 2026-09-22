"""The capability ontology's derived status, where someone can actually see it.

``capability/derive.py`` has always written ``ControlImplementation.derived_status``,
``derived_at`` and ``derived_from``. Nothing read them: ``grep -rn derived_status
src/ccf`` returned the column definition and the writer, and
``tests/test_capability_derive.py`` asserted ``# divergence visible`` about a
value visible only in the database. This file pins the two surfaces that make
it visible to a human -- the ``data_quality`` finding on ``/executive`` and the
control detail page -- and, more importantly, pins the distinction that is easy
to lose on the way out: ``roll_up`` returns ``None`` for "no capability says
anything about this control", which is **not** "your capabilities say it is not
implemented".

Rendering assertions run under real auth, because ``_principal_org`` reads the
request principal: with auth disabled every request is ``SYSTEM_PRINCIPAL``
(``org_id=None``, unscoped), so a page test written the usual way would render
every tenant's rows and prove nothing about scoping.

``controls.identifier`` is globally UNIQUE and shared across the whole test
database, so this file uses the private ``ZV-`` namespace (``canonicalize``
maps ``ZV-01`` -> ``ZV-1`` like any other family) and deletes what it seeds.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.capability.derive import derive_for_system
from ccf.capability.divergence import (
    NO_COVERAGE,
    derivations_for_control,
    divergence_count,
)
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import insights
from ccf.models import (
    Control,
    ControlImplementation,
    Organization,
    System,
    SystemComponent,
    User,
)
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count(1)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Seeded:
    tag: int
    org_id: int
    system_id: int
    control_id: int
    identifier: str
    capability_id: int
    cap_key: str
    cap_title: str
    token: str


async def _seed(
    *,
    authored: str,
    cap_status: str | None,
    cap_title: str = "Conditional Access MFA",
    cap_key: str | None = None,
) -> Seeded:
    """One org + system + component + control + implementation.

    ``cap_status=None`` seeds no capability at all, which is the plainest form
    of "nothing derives this control".
    """
    tag = next(_SEQ)
    identifier = f"ZV-{tag:02d}"
    canonical = f"ZV-{tag}"
    async with session_scope() as s:
        org = Organization(name=f"DivOrg-{tag}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"DivSys-{tag}", baseline="moderate")
        s.add(sys_)
        ctl = Control(identifier=identifier)
        s.add(ctl)
        await s.flush()
        comp = SystemComponent(
            organization_id=org.id, system_id=sys_.id, type="service", title=f"Entra-{tag}"
        )
        s.add(comp)
        s.add(ControlImplementation(system_id=sys_.id, control_id=ctl.id, status=authored))
        cap_id = 0
        cap_key = cap_key or f"cap-div-{tag}"
        if cap_status is not None:
            await s.flush()
            cap = Capability(
                organization_id=org.id, key=cap_key, title=cap_title, status=cap_status
            )
            s.add(cap)
            await s.flush()
            s.add(
                CapabilityComponent(
                    organization_id=org.id, capability_id=cap.id, component_id=comp.id
                )
            )
            s.add(
                CapabilityControl(
                    organization_id=org.id, capability_id=cap.id, control_id=canonical
                )
            )
            cap_id = cap.id
        user = User(
            email=f"admin-div-{tag}@divergence.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return Seeded(
            tag=tag,
            org_id=org.id,
            system_id=sys_.id,
            control_id=ctl.id,
            identifier=identifier,
            capability_id=cap_id,
            cap_key=cap_key,
            cap_title=cap_title,
            token=user.api_token,
        )


async def _derive(system_id: int) -> int:
    async with session_scope() as s:
        return await derive_for_system(s, system_id=system_id)


async def _cleanup(*seeded: Seeded) -> None:
    """Implementations first (``control_id`` is ``ON DELETE RESTRICT``), then the
    organizations (which cascade to systems, components and capabilities), then
    the globally-unique control rows."""
    async with session_scope() as s:
        await s.execute(
            delete(ControlImplementation).where(
                ControlImplementation.control_id.in_([x.control_id for x in seeded])
            )
        )
        await s.execute(
            delete(Organization).where(Organization.id.in_([x.org_id for x in seeded]))
        )
        await s.execute(delete(Control).where(Control.id.in_([x.control_id for x in seeded])))


async def _dq_finding(org_id: int, check: str) -> dict:
    async with session_scope() as s:
        dq = await insights.data_quality(s, org_id=org_id)
    return next(f for f in dq["checks"] if f["check"] == check)


# --- 1. agreement is not a divergence ---------------------------------------


@pytest.mark.asyncio
async def test_authored_status_matching_derived_shows_no_divergence() -> None:
    seeded = await _seed(authored="implemented", cap_status="implemented")
    try:
        assert await _derive(seeded.system_id) == 1  # it really did derive
        async with session_scope() as s:
            rows = await derivations_for_control(
                s, control_id=seeded.control_id, org_id=seeded.org_id
            )
        assert [r.state for r in rows] == ["agrees"]
        assert rows[0].derived_status == "implemented"
        assert not rows[0].divergent

        assert (await _dq_finding(seeded.org_id, "capability_derived_divergence"))["count"] == 0

        async with _client() as c:
            page = await c.get(f"/controls/{seeded.identifier}", headers=_auth(seeded.token))
        assert page.status_code == 200, page.text
        assert "No divergence" in page.text
        assert "diverge</span>" not in page.text
    finally:
        await _cleanup(seeded)


# --- 2. divergence is shown, attributed, and counted ------------------------


@pytest.mark.asyncio
async def test_divergence_is_rendered_named_and_counted() -> None:
    """The authored SSP says planned; the capabilities say implemented."""
    seeded = await _seed(authored="planned", cap_status="implemented")
    try:
        await _derive(seeded.system_id)
        async with session_scope() as s:
            rows = await derivations_for_control(
                s, control_id=seeded.control_id, org_id=seeded.org_id
            )
        assert len(rows) == 1
        row = rows[0]
        assert row.divergent
        assert (row.authored_status, row.derived_status) == ("planned", "implemented")
        # Named, not just counted: derived_from carries capability *keys*, and
        # capabilities have no UI, so the key and the live title are the whole
        # attribution an operator gets.
        assert [c.key for c in row.contributors] == [seeded.cap_key]
        assert [c.status for c in row.contributors] == ["implemented"]
        assert [c.label for c in row.contributors] == [seeded.cap_title]

        assert (await _dq_finding(seeded.org_id, "capability_derived_divergence"))["count"] == 1

        async with _client() as c:
            page = await c.get(f"/controls/{seeded.identifier}", headers=_auth(seeded.token))
        assert page.status_code == 200, page.text
        assert "Capability-derived status" in page.text
        assert "1 of 1 diverge" in page.text
        assert seeded.cap_title in page.text  # the source is named
        assert seeded.cap_key in page.text    # and addressable
    finally:
        await _cleanup(seeded)


@pytest.mark.asyncio
async def test_the_authored_status_is_never_overwritten_by_the_surface() -> None:
    """Reading the divergence must not resolve it."""
    seeded = await _seed(authored="planned", cap_status="implemented")
    try:
        await _derive(seeded.system_id)
        async with session_scope() as s:
            await derivations_for_control(
                s, control_id=seeded.control_id, org_id=seeded.org_id
            )
            await divergence_count(s, org_id=seeded.org_id)
        async with _client() as c:
            await c.get(f"/controls/{seeded.identifier}", headers=_auth(seeded.token))
        async with session_scope() as s:
            impl = (
                await s.execute(
                    select(ControlImplementation).where(
                        ControlImplementation.control_id == seeded.control_id
                    )
                )
            ).scalar_one()
            assert impl.status == "planned"  # the authored claim, untouched
            assert impl.derived_status == "implemented"
    finally:
        await _cleanup(seeded)


# --- 3. None is not not_implemented -----------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cap_status", "why"),
    [
        (None, "no capability is bound to this control at all"),
        ("not_applicable", "the only contributor is excluded from the rollup"),
    ],
)
async def test_no_contributors_is_neither_a_divergence_nor_not_implemented(
    cap_status: str | None, why: str
) -> None:
    """``roll_up`` returns None rather than ``not_implemented`` on purpose, and
    that distinction has to survive to the surface: a control nobody's
    capabilities speak to must not be rendered as one their capabilities
    declare unimplemented."""
    seeded = await _seed(authored="planned", cap_status=cap_status)
    try:
        await _derive(seeded.system_id)
        async with session_scope() as s:
            rows = await derivations_for_control(
                s, control_id=seeded.control_id, org_id=seeded.org_id
            )
        assert len(rows) == 1, why
        row = rows[0]
        assert row.derived_status is None
        assert not row.covered
        assert not row.divergent          # silence contradicts nothing
        assert row.state == NO_COVERAGE   # a state, not a status
        assert NO_COVERAGE not in {"not_implemented", "planned", "partial", "implemented"}

        assert (await _dq_finding(seeded.org_id, "capability_derived_divergence"))["count"] == 0

        async with _client() as c:
            page = await c.get(f"/controls/{seeded.identifier}", headers=_auth(seeded.token))
        assert page.status_code == 200, page.text
        assert "No capability covers this control" in page.text
        # The page must not invent a status for it, in either spelling.
        assert "not_implemented" not in page.text
        assert "not implemented" not in page.text
    finally:
        await _cleanup(seeded)


@pytest.mark.asyncio
async def test_capabilities_saying_not_implemented_render_differently_from_silence() -> None:
    """The other half of the same distinction, asserted side by side.

    Both rows below have authored status ``implemented``. One has capabilities
    that actively say ``not_implemented`` -- a real, dangerous divergence, an
    over-claim in the SSP. The other has nothing saying anything. If these ever
    render the same, the ontology's most important signal has been flattened.
    """
    speaks = await _seed(authored="implemented", cap_status="not_implemented")
    silent = await _seed(authored="implemented", cap_status=None)
    try:
        await _derive(speaks.system_id)
        await _derive(silent.system_id)
        async with session_scope() as s:
            spoke = (
                await derivations_for_control(
                    s, control_id=speaks.control_id, org_id=speaks.org_id
                )
            )[0]
            quiet = (
                await derivations_for_control(
                    s, control_id=silent.control_id, org_id=silent.org_id
                )
            )[0]
        assert spoke.derived_status == "not_implemented"
        assert spoke.divergent and spoke.state == "diverges"
        assert quiet.derived_status is None
        assert not quiet.divergent and quiet.state == NO_COVERAGE

        assert (await _dq_finding(speaks.org_id, "capability_derived_divergence"))["count"] == 1
        assert (await _dq_finding(silent.org_id, "capability_derived_divergence"))["count"] == 0

        async with _client() as c:
            loud_page = await c.get(f"/controls/{speaks.identifier}", headers=_auth(speaks.token))
            quiet_page = await c.get(
                f"/controls/{silent.identifier}", headers=_auth(silent.token)
            )
        assert "not implemented" in loud_page.text      # asserted by the capabilities
        assert "not implemented" not in quiet_page.text  # asserted by nobody
        assert "No capability covers this control" in quiet_page.text
        assert "No capability covers this control" not in loud_page.text
    finally:
        await _cleanup(speaks, silent)


@pytest.mark.asyncio
async def test_the_named_source_is_this_tenants_capability_not_another_tenants() -> None:
    """``Capability.key`` is unique only *within* an organization
    (``uq_capability_org_key``), and ``derived_from`` stores the bare key. An
    unscoped title lookup would therefore print another tenant's capability
    title beside this tenant's key -- a wrong answer that still validates.
    """
    shared_key = f"cap-shared-{next(_SEQ)}"
    mine = await _seed(
        authored="planned",
        cap_status="implemented",
        cap_key=shared_key,
        cap_title="Ours: Conditional Access MFA",
    )
    theirs = await _seed(
        authored="planned",
        cap_status="implemented",
        cap_key=shared_key,
        cap_title="Theirs: Duo push MFA",
    )
    try:
        assert mine.cap_key == theirs.cap_key  # the collision really exists
        await _derive(mine.system_id)
        async with session_scope() as s:  # unscoped: nothing else is filtering
            row = (
                await derivations_for_control(
                    s, control_id=mine.control_id, org_id=mine.org_id
                )
            )[0]
        assert [c.label for c in row.contributors] == ["Ours: Conditional Access MFA"]

        async with _client() as c:
            page = await c.get(f"/controls/{mine.identifier}", headers=_auth(mine.token))
        assert "Ours: Conditional Access MFA" in page.text
        assert "Theirs: Duo push MFA" not in page.text
    finally:
        await _cleanup(mine, theirs)


# --- 4. a cleared derivation stops being reported ---------------------------


@pytest.mark.asyncio
async def test_a_stale_derivation_cleared_by_derive_stops_being_reported() -> None:
    """``derive_for_system`` nulls a derived row whose capability coverage is
    gone. The surface must follow it down, not keep reporting a divergence
    against a capability that no longer backs the control."""
    seeded = await _seed(authored="planned", cap_status="implemented")
    try:
        await _derive(seeded.system_id)
        assert (await _dq_finding(seeded.org_id, "capability_derived_divergence"))["count"] == 1

        async with session_scope() as s:  # the capability stops claiming the control
            await s.execute(
                delete(CapabilityControl).where(
                    CapabilityControl.capability_id == seeded.capability_id
                )
            )
        assert await _derive(seeded.system_id) == 1  # the clearing pass ran

        async with session_scope() as s:
            rows = await derivations_for_control(
                s, control_id=seeded.control_id, org_id=seeded.org_id
            )
        assert rows[0].derived_status is None
        assert rows[0].state == NO_COVERAGE
        assert (await _dq_finding(seeded.org_id, "capability_derived_divergence"))["count"] == 0

        async with _client() as c:
            page = await c.get(f"/controls/{seeded.identifier}", headers=_auth(seeded.token))
        assert "1 of 1 diverge" not in page.text
        assert "No capability covers this control" in page.text
    finally:
        await _cleanup(seeded)


# --- 5. the finding follows the existing shape ------------------------------


@pytest.mark.asyncio
async def test_the_finding_follows_the_shape_of_its_siblings() -> None:
    """Asserted against a sibling finding's keys, not a literal written here:
    a literal would still pass if every other finding grew a field."""
    seeded = await _seed(authored="planned", cap_status="implemented")
    try:
        await _derive(seeded.system_id)
        async with session_scope() as s:
            dq = await insights.data_quality(s, org_id=seeded.org_id)
        by_check = {f["check"]: f for f in dq["checks"]}
        mine = by_check["capability_derived_divergence"]
        sibling = by_check["implemented_without_evidence"]
        assert set(mine) == set(sibling)
        assert type(mine["count"]) is type(sibling["count"])
        assert mine["severity"] in {f["severity"] for f in dq["checks"]}
        # And it participates in the rollup the page actually prints, rather
        # than sitting in `checks` where nothing sums it.
        assert "capability_derived_divergence" in dq["failing_checks"]
        assert dq["total_issues"] >= mine["count"]
        assert not dq["clean"]
    finally:
        await _cleanup(seeded)


# --- 6. tenant isolation ----------------------------------------------------


@pytest.mark.asyncio
async def test_another_organizations_divergence_is_not_counted() -> None:
    """Pinned where the explicit predicate bears weight.

    Over HTTP ``api/deps.get_session`` already binds the RLS tenant, so
    deleting the org predicate fails no request-level test -- it is a
    surviving mutation by construction. The unscoped ``session_scope()`` the
    CLI and scheduler use bypasses RLS by design, so the row below *is*
    visible without the predicate, which is asserted first: otherwise this
    test would only prove that RLS works.
    """
    mine = await _seed(authored="planned", cap_status="implemented")
    theirs = await _seed(authored="planned", cap_status="implemented")
    try:
        await _derive(mine.system_id)
        await _derive(theirs.system_id)
        async with session_scope() as s:  # unscoped: RLS is not filtering here
            visible = (
                await s.execute(
                    select(ControlImplementation.id).where(
                        ControlImplementation.system_id == theirs.system_id,
                        ControlImplementation.derived_status.is_not(None),
                    )
                )
            ).scalars().all()
            assert len(visible) == 1  # the other tenant's row IS reachable

            assert await divergence_count(s, org_id=mine.org_id) == 1
            assert await divergence_count(s, org_id=theirs.org_id) == 1
            assert await divergence_count(s) >= 2  # unscoped sees both

            # And the per-control read is scoped the same way.
            assert (
                await derivations_for_control(
                    s, control_id=theirs.control_id, org_id=mine.org_id
                )
                == []
            )

        assert (await _dq_finding(mine.org_id, "capability_derived_divergence"))["count"] == 1

        async with _client() as c:  # and the page does not render it either
            page = await c.get(f"/controls/{theirs.identifier}", headers=_auth(mine.token))
        assert page.status_code == 200, page.text
        assert "Capability-derived status" not in page.text
    finally:
        await _cleanup(mine, theirs)
