"""Which waivers apply to one control test."""

from __future__ import annotations

import itertools

from ccf.db import session_scope
from ccf.governance.waivers import waivers_for_test
from ccf.models import Organization, System
from ccf.models_grc import ControlTest
from ccf.models_waivers import Waiver

_SEQ = itertools.count()


async def _test_on_system(session, *, check_key: str | None = "m365.identity.mfa_registered"):
    org = Organization(name=f"ResolveWaiverOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"Sys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="IA-2",
        name="MFA registered",
        method="connector",
        check_key=check_key,
    )
    session.add(test)
    await session.flush()
    return org, sys_, test


async def _waiver(session, *, org_id, system_id, **kw) -> Waiver:
    base = dict(
        organization_id=org_id,
        system_id=system_id,
        check_key="m365.identity.mfa_registered",
        rationale="accepted",
        status="approved",
    )
    base.update(kw)
    w = Waiver(**base)
    session.add(w)
    await session.flush()
    return w


async def test_a_waiver_matching_the_check_key_applies() -> None:
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session)
        w = await _waiver(session, org_id=org.id, system_id=sys_.id)
        assert [x.id for x in await waivers_for_test(session, test)] == [w.id]


async def test_a_waiver_matching_the_control_id_applies() -> None:
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session)
        w = await _waiver(
            session, org_id=org.id, system_id=sys_.id, check_key=None, control_id="IA-2"
        )
        assert [x.id for x in await waivers_for_test(session, test)] == [w.id]


async def test_a_waiver_for_a_different_check_does_not_apply() -> None:
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session)
        await _waiver(session, org_id=org.id, system_id=sys_.id, check_key="some.other.check")
        assert await waivers_for_test(session, test) == []


async def test_a_waiver_for_a_different_control_does_not_apply() -> None:
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session)
        await _waiver(
            session, org_id=org.id, system_id=sys_.id, check_key=None, control_id="AC-7"
        )
        assert await waivers_for_test(session, test) == []


async def test_a_waiver_on_another_system_does_not_apply() -> None:
    async with session_scope() as session:
        org, _sys, test = await _test_on_system(session)
        other = System(organization_id=org.id, name=f"Other-{next(_SEQ)}")
        session.add(other)
        await session.flush()
        await _waiver(session, org_id=org.id, system_id=other.id)
        assert await waivers_for_test(session, test) == []


async def test_another_organizations_waiver_does_not_apply() -> None:
    """The leak test. A waiver is an authorization decision; it must not cross
    a tenant boundary even when the check key is identical."""
    async with session_scope() as session:
        _org, sys_, test = await _test_on_system(session)
        other_org = Organization(name=f"OtherOrg-{next(_SEQ)}")
        session.add(other_org)
        await session.flush()
        await _waiver(session, org_id=other_org.id, system_id=sys_.id)
        assert await waivers_for_test(session, test) == []


async def test_a_test_without_a_check_key_matches_only_by_control() -> None:
    """A manual test has no check_key; a NULL check_key must not match a
    waiver whose check_key is also NULL -- that waiver targets a control."""
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session, check_key=None)
        by_control = await _waiver(
            session, org_id=org.id, system_id=sys_.id, check_key=None, control_id="IA-2"
        )
        await _waiver(session, org_id=org.id, system_id=sys_.id, check_key="anything")
        assert [x.id for x in await waivers_for_test(session, test)] == [by_control.id]


async def test_requested_and_revoked_waivers_are_still_returned() -> None:
    """Activity is decided in the pure layer, so there is one definition of it.

    The resolver returns candidates; cover() decides. Filtering status here too
    would create a second, silently divergent definition of "active".
    """
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session)
        await _waiver(session, org_id=org.id, system_id=sys_.id, status="requested")
        await _waiver(session, org_id=org.id, system_id=sys_.id, status="revoked")
        assert len(await waivers_for_test(session, test)) == 2


async def test_a_test_with_no_system_resolves_nothing() -> None:
    """ControlTest.system_id is nullable; an org-wide test has no system to
    scope a waiver to, and matching every system's waivers would be wrong."""
    async with session_scope() as session:
        org, _sys, _t = await _test_on_system(session)
        orgwide = ControlTest(
            organization_id=org.id,
            system_id=None,
            control_id="IA-2",
            name="Org-wide",
            method="manual",
        )
        session.add(orgwide)
        await session.flush()
        assert await waivers_for_test(session, orgwide) == []


async def test_resolution_is_deterministically_ordered() -> None:
    async with session_scope() as session:
        org, sys_, test = await _test_on_system(session)
        a = await _waiver(session, org_id=org.id, system_id=sys_.id, resource_id="zzz")
        b = await _waiver(session, org_id=org.id, system_id=sys_.id, resource_id="aaa")
        ids = [x.id for x in await waivers_for_test(session, test)]
        assert ids == sorted([a.id, b.id])
