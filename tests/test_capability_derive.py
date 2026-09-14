"""Derivation annotates control status without ever claiming it."""

from __future__ import annotations

import itertools

from sqlalchemy import func, select

from ccf.capability.derive import derive_for_system
from ccf.db import session_scope
from ccf.models import (
    Control,
    ControlImplementation,
    Organization,
    System,
    SystemComponent,
)
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

_SEQ = itertools.count()


async def _fixture(session, *, cap_status: str, control_identifier: str, canonical: str):
    """One org + system + component + capability mapped to one control."""
    org = Organization(name=f"DerOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"Sys-{next(_SEQ)}", baseline="moderate")
    session.add(sys_)
    await session.flush()
    comp = SystemComponent(
        organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
    )
    session.add(comp)
    ctl = Control(identifier=control_identifier)
    session.add(ctl)
    await session.flush()
    cap = Capability(
        organization_id=org.id, key=f"cap-{next(_SEQ)}", title="MFA", status=cap_status
    )
    session.add(cap)
    await session.flush()
    session.add(
        CapabilityComponent(organization_id=org.id, capability_id=cap.id, component_id=comp.id)
    )
    session.add(
        CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id=canonical)
    )
    await session.flush()
    return org, sys_, ctl, cap


async def test_annotates_existing_implementation_row() -> None:
    async with session_scope() as session:
        _, sys_, ctl, cap = await _fixture(
            session, cap_status="implemented", control_identifier="ZA-02", canonical="ZA-2"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()

        touched = await derive_for_system(session, system_id=sys_.id)
        assert touched == 1
        await session.refresh(impl)
        assert impl.derived_status == "implemented"
        assert impl.derived_at is not None
        assert cap.key in str(impl.derived_from)


async def test_never_mutates_authored_status() -> None:
    """Divergence must be preserved, not silently resolved."""
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="ZB-02", canonical="ZB-2"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()

        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.status == "planned"              # authored value untouched
        assert impl.derived_status == "implemented"  # divergence visible


async def test_never_creates_an_implementation_row() -> None:
    """status is NOT NULL DEFAULT 'not_implemented'; a created row would assert
    something about a control nobody claimed, and could shift coverage math."""
    async with session_scope() as session:
        _, sys_, _, _ = await _fixture(
            session, cap_status="implemented", control_identifier="ZC-02", canonical="ZC-2"
        )
        before = (
            await session.execute(select(func.count()).select_from(ControlImplementation))
        ).scalar_one()
        touched = await derive_for_system(session, system_id=sys_.id)
        after = (
            await session.execute(select(func.count()).select_from(ControlImplementation))
        ).scalar_one()
        assert after == before
        assert touched == 0


async def test_matches_zero_padded_control_identifier() -> None:
    """Capability stores ZD-2; controls.identifier is ZD-02. Must still join."""
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="ZD-02", canonical="ZD-2"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()
        assert ctl.identifier == "ZD-02"  # the padded form really is stored

        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status == "implemented"


async def test_is_idempotent() -> None:
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="ZE-02", canonical="ZE-2"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()
        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        first = impl.derived_at
        touched = await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status == "implemented"
        assert touched == 0            # unchanged -> nothing rewritten
        assert impl.derived_at == first


async def test_not_applicable_capability_writes_nothing() -> None:
    async with session_scope() as session:
        _, sys_, ctl, _ = await _fixture(
            session, cap_status="not_applicable", control_identifier="ZF-02", canonical="ZF-2"
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="planned")
        session.add(impl)
        await session.flush()
        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status is None


async def test_mixed_statuses_derive_partial() -> None:
    """Two capabilities on one control, one lagging -> conservative partial."""
    async with session_scope() as session:
        org, sys_, ctl, _ = await _fixture(
            session, cap_status="implemented", control_identifier="ZG-02", canonical="ZG-2"
        )
        comp = (
            await session.execute(
                select(SystemComponent).where(SystemComponent.system_id == sys_.id)
            )
        ).scalars().first()
        assert comp is not None
        lagging = Capability(
            organization_id=org.id, key=f"lag-{next(_SEQ)}", title="Lagging", status="planned"
        )
        session.add(lagging)
        await session.flush()
        session.add(
            CapabilityComponent(
                organization_id=org.id, capability_id=lagging.id, component_id=comp.id
            )
        )
        session.add(
            CapabilityControl(
                organization_id=org.id, capability_id=lagging.id, control_id="ZG-2"
            )
        )
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="implemented")
        session.add(impl)
        await session.flush()

        await derive_for_system(session, system_id=sys_.id)
        await session.refresh(impl)
        assert impl.derived_status == "partial"
        assert len(impl.derived_from["capabilities"]) == 2


async def test_system_with_no_capabilities_is_a_noop() -> None:
    async with session_scope() as session:
        org = Organization(name=f"EmptyOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Empty-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        assert await derive_for_system(session, system_id=sys_.id) == 0
