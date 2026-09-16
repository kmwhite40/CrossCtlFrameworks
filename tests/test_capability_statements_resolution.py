"""Capability statements, keyed by canonical control id, scoped to one system."""

from __future__ import annotations

import itertools

from ccf.capability.service import capability_statements_by_control
from ccf.db import session_scope
from ccf.models import Organization, System, SystemComponent
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

_SEQ = itertools.count()


async def _bind(
    session,
    *,
    control_id: str,
    statement: str | None,
    status: str = "implemented",
):
    """One org + system + component + capability mapped to one control."""
    org = Organization(name=f"NarrOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"NarrSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    comp = SystemComponent(
        organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
    )
    session.add(comp)
    cap = Capability(
        organization_id=org.id,
        key=f"cap-{next(_SEQ)}",
        title="MFA",
        statement=statement,
        status=status,
    )
    session.add(cap)
    await session.flush()
    session.add(
        CapabilityComponent(
            organization_id=org.id, capability_id=cap.id, component_id=comp.id
        )
    )
    session.add(
        CapabilityControl(
            organization_id=org.id, capability_id=cap.id, control_id=control_id
        )
    )
    await session.flush()
    return org, sys_, cap


async def test_returns_statements_keyed_by_canonical_control_id() -> None:
    async with session_scope() as session:
        _, sys_, cap = await _bind(
            session, control_id="IA-2", statement="Conditional Access enforces MFA"
        )
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {
            "IA-2": [(cap.key, "Conditional Access enforces MFA", "implemented")]
        }


async def test_key_is_canonicalised_from_a_padded_edge() -> None:
    """An edge stored as IA-02 must still be found under IA-2."""
    async with session_scope() as session:
        _, sys_, cap = await _bind(session, control_id="IA-02", statement="padded edge")
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {"IA-2": [(cap.key, "padded edge", "implemented")]}


async def test_empty_statement_is_excluded() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(session, control_id="IA-2", statement="")
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_null_statement_is_excluded() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(session, control_id="IA-2", statement=None)
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_another_systems_capability_does_not_leak() -> None:
    async with session_scope() as session:
        _, sys_a, cap_a = await _bind(session, control_id="IA-2", statement="system A")
        _, sys_b, cap_b = await _bind(session, control_id="IA-2", statement="system B")
        out_a = await capability_statements_by_control(session, system_id=sys_a.id)
        assert out_a == {"IA-2": [(cap_a.key, "system A", "implemented")]}
        out_b = await capability_statements_by_control(session, system_id=sys_b.id)
        assert out_b == {"IA-2": [(cap_b.key, "system B", "implemented")]}


async def test_system_with_no_capabilities_is_empty() -> None:
    async with session_scope() as session:
        org = Organization(name=f"NarrOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Bare-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_two_capabilities_on_one_control_are_both_returned() -> None:
    async with session_scope() as session:
        org, sys_, cap_first = await _bind(session, control_id="IA-2", statement="first")
        comp = SystemComponent(
            organization_id=org.id, system_id=sys_.id, type="process", title="Runbook"
        )
        session.add(comp)
        second = Capability(
            organization_id=org.id,
            key=f"cap-{next(_SEQ)}",
            title="Second",
            statement="second",
            status="implemented",
        )
        session.add(second)
        await session.flush()
        session.add(
            CapabilityComponent(
                organization_id=org.id, capability_id=second.id, component_id=comp.id
            )
        )
        session.add(
            CapabilityControl(
                organization_id=org.id, capability_id=second.id, control_id="IA-2"
            )
        )
        await session.flush()

        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert sorted(out["IA-2"]) == sorted(
            [
                (cap_first.key, "first", "implemented"),
                (second.key, "second", "implemented"),
            ]
        )


async def test_one_capability_on_two_components_is_not_duplicated() -> None:
    """A capability bound through two components covers the control once."""
    async with session_scope() as session:
        org, sys_, cap = await _bind(session, control_id="IA-2", statement="once")
        extra = SystemComponent(
            organization_id=org.id, system_id=sys_.id, type="process", title="Runbook"
        )
        session.add(extra)
        await session.flush()
        session.add(
            CapabilityComponent(
                organization_id=org.id, capability_id=cap.id, component_id=extra.id
            )
        )
        await session.flush()
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {"IA-2": [(cap.key, "once", "implemented")]}


async def test_an_unparseable_edge_is_skipped_not_crashed() -> None:
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session, control_id="not a control id", statement="orphan"
        )
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


# ── Every status in the enum, per CRITICAL 1 ─────────────────────────────────
#
# Capability.status has six values (models_capability.py:44-54) and defaults
# to "not_implemented" (models_capability.py:81) -- the state of every
# capability an author has created but not yet acted on. Rendering that
# default's statement into an SSP would assert, in the present tense, that a
# mechanism is deployed when it is not. Each status below is exercised so a
# future change to the allow-list is caught here, not in a submitted package.


async def test_not_implemented_capability_is_excluded() -> None:
    """The column default. A capability an author has created but not yet
    implemented must not have its statement rendered as a present-tense
    implementation claim -- see CRITICAL 1."""
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session,
            control_id="IA-2",
            statement="FIDO2 security keys are required for all privileged roles",
            status="not_implemented",
        )
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_planned_capability_is_excluded() -> None:
    """Planned, not yet actioned -- describes future work, not this system's
    current implementation."""
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session,
            control_id="IA-2",
            statement="should not appear",
            status="planned",
        )
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}


async def test_partial_capability_is_included() -> None:
    """Partial implementations are real and belong in the narrative -- the
    caller (ssp/statements.py) is responsible for rendering them under a
    distinct 'Partial implementation:' lead so the SSP does not overstate
    them as complete; this layer's job is only to not exclude them."""
    async with session_scope() as session:
        _, sys_, cap = await _bind(
            session,
            control_id="IA-2",
            statement="half of privileged roles are enrolled",
            status="partial",
        )
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {
            "IA-2": [(cap.key, "half of privileged roles are enrolled", "partial")]
        }


async def test_implemented_capability_is_included() -> None:
    async with session_scope() as session:
        _, sys_, cap = await _bind(
            session, control_id="IA-2", statement="fully rolled out", status="implemented"
        )
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {"IA-2": [(cap.key, "fully rolled out", "implemented")]}


async def test_inherited_capability_is_included() -> None:
    async with session_scope() as session:
        _, sys_, cap = await _bind(
            session,
            control_id="IA-2",
            statement="covered by the provider's authorized baseline",
            status="inherited",
        )
        out = await capability_statements_by_control(session, system_id=sys_.id)
        assert out == {
            "IA-2": [(cap.key, "covered by the provider's authorized baseline", "inherited")]
        }


async def test_not_applicable_capability_is_excluded() -> None:
    """It does not describe this system's implementation, so it must not claim to."""
    async with session_scope() as session:
        _, sys_, _ = await _bind(
            session,
            control_id="IA-2",
            statement="should not appear",
            status="not_applicable",
        )
        assert await capability_statements_by_control(session, system_id=sys_.id) == {}
