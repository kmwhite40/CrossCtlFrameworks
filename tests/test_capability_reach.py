"""One capability, many frameworks -- through the existing crosswalk."""

from __future__ import annotations

import itertools

from sqlalchemy import select

from ccf.capability.service import capabilities_for_control, framework_reach
from ccf.db import session_scope
from ccf.models import Control, Framework, FrameworkMapping, Organization
from ccf.models_capability import Capability, CapabilityControl

_SEQ = itertools.count()


async def _framework(session, code: str) -> Framework:
    fw = (
        await session.execute(select(Framework).where(Framework.code == code))
    ).scalars().first()
    if fw is None:
        fw = Framework(code=code, name=code)
        session.add(fw)
        await session.flush()
    return fw


async def _org_cap(session, key_prefix: str, status: str = "implemented"):
    org = Organization(name=f"ReachOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    cap = Capability(
        organization_id=org.id, key=f"{key_prefix}-{next(_SEQ)}", title="MFA", status=status
    )
    session.add(cap)
    await session.flush()
    return org, cap


async def test_reaches_other_frameworks_via_the_crosswalk() -> None:
    async with session_scope() as session:
        org, cap = await _org_cap(session, "reach")
        # A control this deployment knows, in the zero-padded form.
        ctl = Control(identifier="YA-02")
        session.add(ctl)
        cmmc = await _framework(session, "CMMC")
        await session.flush()
        session.add(
            FrameworkMapping(
                control_id=ctl.id,
                framework_id=cmmc.id,
                column_key="CMMC",
                value="IA.L2-3.5.3",
            )
        )
        # The capability maps to the CANONICAL id, not the padded one.
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="YA-2")
        )
        await session.flush()

        reach = await framework_reach(session, capability_id=cap.id)
        assert "IA.L2-3.5.3" in reach.get("CMMC", [])


async def test_one_capability_reaches_several_frameworks() -> None:
    """The whole point: declare once, satisfy many."""
    async with session_scope() as session:
        org, cap = await _org_cap(session, "multi")
        ctl = Control(identifier="YB-02")
        session.add(ctl)
        await session.flush()
        for code, value in (("CMMC", "AC.L2-3.1.2"), ("FEDRAMP", "AC-2"), ("ISO_27001", "A.5.16")):
            fw = await _framework(session, code)
            session.add(
                FrameworkMapping(
                    control_id=ctl.id, framework_id=fw.id, column_key=code, value=value
                )
            )
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="YB-2")
        )
        await session.flush()

        reach = await framework_reach(session, capability_id=cap.id)
        assert reach["CMMC"] == ["AC.L2-3.1.2"]
        assert reach["FEDRAMP"] == ["AC-2"]
        assert reach["ISO_27001"] == ["A.5.16"]


async def test_capability_with_no_edges_reaches_nothing() -> None:
    async with session_scope() as session:
        _, cap = await _org_cap(session, "bare", status="planned")
        assert await framework_reach(session, capability_id=cap.id) == {}


async def test_control_absent_from_this_deployment_returns_empty() -> None:
    """A capability may legitimately target a catalog control the workbook lacks."""
    async with session_scope() as session:
        org, cap = await _org_cap(session, "ghost")
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="ZZ-99")
        )
        await session.flush()
        assert await framework_reach(session, capability_id=cap.id) == {}


async def test_capabilities_for_control_is_spelling_insensitive() -> None:
    async with session_scope() as session:
        org, cap = await _org_cap(session, "lookup")
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="YC-2")
        )
        await session.flush()

        for spelling in ("YC-2", "YC-02"):
            found = await capabilities_for_control(session, control_id=spelling)
            assert cap.id in [c.id for c in found], spelling


async def test_capabilities_for_control_rejects_nonsense() -> None:
    async with session_scope() as session:
        assert await capabilities_for_control(session, control_id="not a control") == []
        assert await capabilities_for_control(session, control_id="") == []
