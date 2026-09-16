"""End to end: edit one capability, and every control it maps to re-renders."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import ai as ai_module
from ccf.governance.automation import generate_statements
from ccf.models import (
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
    SystemComponent,
    SystemProfile,
)
from ccf.models_capability import Capability, CapabilityComponent, CapabilityControl

_SEQ = itertools.count()
CAP_TEXT = "Entra ID Conditional Access enforces MFA on all interactive sign-ins"


async def _project_with_capability(
    session, *, control_ids: list[str], status: str = "implemented", statement: str = CAP_TEXT
):
    """A project whose system has one capability covering several controls."""
    org = Organization(name=f"E2EOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"E2ESys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    comp = SystemComponent(
        organization_id=org.id, system_id=sys_.id, type="service", title="Entra ID"
    )
    session.add(comp)
    profile = SystemProfile(system_id=sys_.id, cloud_platform="m365_gcc_high")
    session.add(profile)
    project = SSPProject(
        organization_id=org.id, system_id=sys_.id, customer_name="E2E", platform="m365"
    )
    session.add(project)
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
    for cid in control_ids:
        session.add(
            CapabilityControl(
                organization_id=org.id, capability_id=cap.id, control_id=cid
            )
        )
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id=cid,
                nist_id=cid,
                requirement="uniquely identify and authenticate users",
            )
        )
    await session.flush()
    return project, profile, cap


async def _narratives(session, project_id: int) -> dict[str, str]:
    rows = (
        (
            await session.execute(
                select(SSPControlEntry).where(SSPControlEntry.project_id == project_id)
            )
        )
        .scalars()
        .all()
    )
    return {
        r.control_id: " ".join(p.get("text", "") for p in (r.part_narratives or []))
        for r in rows
    }


async def test_capability_text_reaches_every_mapped_control() -> None:
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session, control_ids=["IA-2", "AC-7"]
        )
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert CAP_TEXT in narratives["IA-2"]
        assert CAP_TEXT in narratives["AC-7"]


async def test_editing_the_capability_rerenders_both_controls() -> None:
    """The point of the whole sub-project."""
    async with session_scope() as session:
        project, profile, cap = await _project_with_capability(
            session, control_ids=["IA-2", "AC-7"]
        )
        await generate_statements(session, project=project, profile=profile)

        cap.statement = "FIDO2 security keys are required for all privileged roles"
        await session.flush()
        await generate_statements(session, project=project, profile=profile)

        narratives = await _narratives(session, project.id)
        for cid in ("IA-2", "AC-7"):
            assert "FIDO2 security keys" in narratives[cid], cid
            assert CAP_TEXT not in narratives[cid], cid


async def test_a_control_with_no_capability_gets_the_generic_mechanism() -> None:
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session, control_ids=["IA-2"]
        )
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="AU-2",
                nist_id="AU-2",
                requirement="record auditable events",
            )
        )
        await session.flush()
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert CAP_TEXT in narratives["IA-2"]
        assert CAP_TEXT not in narratives["AU-2"]
        assert narratives["AU-2"], "the control still gets a composed statement"


async def test_a_cmmc_entry_matches_through_nist_id() -> None:
    """``control_id`` may be a CMMC practice that does not canonicalize;
    ``nist_id`` carries the 800-53 form and must still find the capability."""
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session, control_ids=["IA-2"]
        )
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="IA.L2-3.5.3",
                nist_id="IA-2",
                requirement="use multifactor authentication",
            )
        )
        await session.flush()
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert CAP_TEXT in narratives["IA.L2-3.5.3"]


async def test_a_project_with_no_system_still_generates() -> None:
    """``SSPProject.system_id`` is nullable; an unbound project composes as before."""
    async with session_scope() as session:
        org = Organization(name=f"E2EOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"E2ESys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        profile = SystemProfile(system_id=sys_.id, cloud_platform="m365_gcc_high")
        session.add(profile)
        project = SSPProject(
            organization_id=org.id, system_id=None, customer_name="Unbound"
        )
        session.add(project)
        await session.flush()
        session.add(
            SSPControlEntry(
                project_id=project.id,
                control_id="IA-2",
                nist_id="IA-2",
                requirement="authenticate users",
            )
        )
        await session.flush()
        out = await generate_statements(session, project=project, profile=profile)
        assert out is not None
        narratives = await _narratives(session, project.id)
        assert narratives["IA-2"], "composed without capability narrative"


# --- CRITICAL 1: not_implemented/planned must never reach the SSP -----------


async def test_not_implemented_capability_never_reaches_the_narrative() -> None:
    """The status every newly-authored capability starts in (the column
    default) must not render a present-tense implementation claim."""
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session,
            control_ids=["IA-2"],
            status="not_implemented",
            statement="FIDO2 security keys are required for all privileged roles",
        )
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert "FIDO2 security keys" not in narratives["IA-2"]


# --- IMPORTANT 1 / CRITICAL 1: partial renders, but distinctly ---------------


async def test_partial_capability_reaches_the_narrative_under_its_own_lead() -> None:
    async with session_scope() as session:
        project, profile, _ = await _project_with_capability(
            session,
            control_ids=["IA-2"],
            status="partial",
            statement="MFA enrollment covers half of privileged roles",
        )
        await generate_statements(session, project=project, profile=profile)
        narratives = await _narratives(session, project.id)
        assert "Partial implementation: MFA enrollment covers half" in narratives["IA-2"]


# --- IMPORTANT 2: the AI path must not discard the capability clause --------


async def test_ai_path_still_appends_the_capability_clause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before the fix, ``automation.py``'s ai_ready branch replaced the whole
    composed statement (capability clause included) with ``DRAFT_PREFIX +
    ai_text``, so a project with AI drafting enabled silently stopped
    re-rendering capability narrative even though the deterministic path
    still did -- the PR's headline promise ("edit one capability, re-render
    every control it maps to") did not hold for AI-enabled projects. The
    capability clause must now be appended to the AI-drafted text."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", "sk-ant-fake-key-for-test")
    get_settings.cache_clear()

    ai_text = "AI-DRAFTED-NARRATIVE-CAP-CLAUSE-TEST"

    class _FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"content": [{"type": "text", "text": ai_text}]}

    class _FakeAsyncClient:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *_a: object) -> bool:
            return False

        async def post(self, *_a: object, **_k: object) -> _FakeResponse:
            return _FakeResponse()

    monkeypatch.setattr(ai_module.httpx, "AsyncClient", _FakeAsyncClient)

    try:
        async with session_scope() as session:
            project, profile, _ = await _project_with_capability(
                session, control_ids=["IA-2"]
            )
            out = await generate_statements(
                session, project=project, profile=profile, use_ai=True
            )
            assert out["ai_used"] >= 1
            narratives = await _narratives(session, project.id)
            assert ai_text in narratives["IA-2"]
            assert CAP_TEXT in narratives["IA-2"], (
                "capability clause was discarded by the AI path"
            )
    finally:
        get_settings.cache_clear()
