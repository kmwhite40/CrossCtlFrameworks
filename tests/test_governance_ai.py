"""Coverage for ``ccf.governance.ai`` — previously zero test coverage despite its
output (``draft_narrative``) being spliced directly into an SSP implementation
statement (``ccf.governance.automation.generate_statements``), which becomes
narrative in a FedRAMP authorization package.

These tests drive the real production splice point — ``generate_statements``
against a real database, with the network boundary (``httpx`` for the legacy
global-key path, ``ccf.ai.gateway.generate_text`` for the org-scoped path)
faked — rather than mocking ``ai.draft_narrative`` itself, so ``ai.py``'s own
``generate``/``draft_narrative``/``is_configured`` code actually executes.
"""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select

from ccf.ai import gateway
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import ai
from ccf.governance.automation import derive_system, generate_ssp, generate_statements
from ccf.models import (
    Organization,
    ScoringControl,
    SSPControlEntry,
    SSPProject,
    System,
    SystemProfile,
)
from ccf.ssp.constants import DRAFT_PREFIX

pytestmark = pytest.mark.usefixtures("fresh_engine")

# A connector-backed platform (see ssp/platforms.py CONNECTOR_PLATFORMS) with an
# AC-domain control lands as responsibility "unknown" (aws_govcloud's per-domain
# table has no AC entry — see ssp/constants.py PLATFORM_DOMAIN_RESPONSIBILITY),
# which is one of the three responsibilities generate_statements will attempt an
# AI draft for. Being connector-backed also means the "no capture connector"
# branch (automation.py ~577-586) never fires here, which would otherwise force
# its own DRAFT_PREFIX/MANUAL_EVIDENCE_NOTE and confound the assertions below.
_PLATFORM = "aws_govcloud"

_FAKE_AI_TEXT = "AI-DRAFTED-NARRATIVE-TOKEN-7f3c"
_LEGACY_KEY = "sk-ant-legacy-poison-marker"


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self._text = text

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return {"content": [{"type": "text", "text": self._text}]}


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient that never touches the network."""

    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *_a: object) -> bool:
        return False

    async def post(self, *_a: object, **_k: object) -> _FakeResponse:
        return _FakeResponse(_FAKE_AI_TEXT)


class _RaisingAsyncClient:
    """Stand-in that fails as if the network call itself blew up."""

    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    async def __aenter__(self) -> _RaisingAsyncClient:
        return self

    async def __aexit__(self, *_a: object) -> bool:
        return False

    async def post(self, *_a: object, **_k: object) -> _FakeResponse:
        raise RuntimeError("simulated provider outage")


async def _make_system(session, name: str) -> System:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sys = System(organization_id=org.id, name=f"{name} system")
    session.add(sys)
    await session.flush()
    return sys


async def _seed_control(session, control_id: str, prefix: str) -> None:
    session.add(
        ScoringControl(
            control_id=control_id,
            nist_id=f"AC-{prefix}-1",
            domain="AC",
            title="Access Control",
            point_value="5",
            requirement="limit system access to authorized users",
            sort_order=1,
        )
    )
    await session.flush()


async def _seeded(name: str, prefix: str) -> tuple[str, int, int, int]:
    """Seed one AC-domain control on aws_govcloud, derive + generate the SSP
    once (use_ai=False), and return (control_id, project_id, system_id, org_id)
    so each test can re-derive statements with its own AI configuration."""
    control_id = f"AC.{prefix}-3.1.1"
    async with session_scope() as session:
        sys = await _make_system(session, name)
        await _seed_control(session, control_id, prefix)
        profile = SystemProfile(
            system_id=sys.id, environment_type="cloud", cloud_platform=_PLATFORM
        )
        session.add(profile)
        await session.flush()
        await derive_system(
            session,
            system_id=sys.id,
            org_id=sys.organization_id,
            profile=profile,
            create_poams=False,
        )
        proj_id = await generate_ssp(session, system=sys, profile=profile)
        return control_id, proj_id, sys.id, sys.organization_id


async def _cleanup_control(control_id: str) -> None:
    async with session_scope() as session:
        await session.execute(delete(ScoringControl).where(ScoringControl.control_id == control_id))


async def _regenerate_and_get_text(
    proj_id: int, sys_id: int, control_id: str, *, use_ai: bool, mark_draft: bool
) -> tuple[str, dict]:
    """Re-run generate_statements with the given AI flags against the already-
    seeded project/profile, and return (statement_text, result_dict).

    seed_project_entries seeds one SSPControlEntry per row of the GLOBAL
    ScoringControl catalog (the full ~110-practice CMMC catalog persists across
    the whole test session once any other test has seeded it — see
    test_cloud_environment_fidelity.py's note on the same behaviour), so the
    project generally has far more than one entry; pick out ours by control_id.
    """
    async with session_scope() as session:
        proj = await session.get(SSPProject, proj_id)
        assert proj is not None
        profile = (
            await session.execute(select(SystemProfile).where(SystemProfile.system_id == sys_id))
        ).scalar_one()
        out = await generate_statements(
            session, project=proj, profile=profile, use_ai=use_ai, mark_draft=mark_draft
        )
        entry = (
            await session.execute(
                select(SSPControlEntry).where(
                    SSPControlEntry.project_id == proj.id,
                    SSPControlEntry.control_id == control_id,
                )
            )
        ).scalar_one()
        parts = entry.part_narratives or []
        assert len(parts) == 1
        text = parts[0].get("text") or ""
        return text, out


# --- Property 1: the draft marker is actually applied, and the AI text survives


async def test_ai_used_marks_draft_prefix_and_preserves_ai_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _FakeAsyncClient)

    control_id, proj_id, sys_id, _org_id = await _seeded("Ai Marker Org", "AIMARK")
    try:
        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=True, mark_draft=True
        )
        # >=1 rather than ==1: generate_statements runs over every entry seeded
        # from the global ScoringControl catalog (not just this test's one
        # control — see _regenerate_and_get_text's docstring), so other
        # catalog entries eligible for an AI draft (responsibility in
        # customer/shared/unknown) may also count toward ai_used.
        assert out["ai_used"] >= 1
        assert text.startswith(DRAFT_PREFIX), f"missing DRAFT_PREFIX: {text!r}"
        # A test asserting only the prefix would pass even if the AI content
        # itself were dropped after it — assert the content survives too.
        assert _FAKE_AI_TEXT in text
        assert text[len(DRAFT_PREFIX) :].startswith(_FAKE_AI_TEXT)
    finally:
        await _cleanup_control(control_id)


# --- Property 2: mark_draft=False, stated as the code actually behaves --------


async def test_mark_draft_false_lets_unmarked_ai_text_reach_the_statement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Documents the code AS WRITTEN: with mark_draft=False, generate_statements
    splices raw AI text into the statement with NO [DRAFT] marker at all — the
    resulting narrative is indistinguishable from human-authored prose. This is
    not asserting a desired behaviour; it is pinning down what actually happens
    so a future change to it is a deliberate, visible decision, not a silent
    regression. See the report for why this is worth a second look."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _FakeAsyncClient)

    control_id, proj_id, sys_id, _org_id = await _seeded("Ai Unmarked Org", "AIUNMK")
    try:
        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=True, mark_draft=False
        )
        assert out["ai_used"] >= 1  # see marker test's note on >=1 vs ==1
        assert _FAKE_AI_TEXT in text
        assert not text.startswith(DRAFT_PREFIX)
        assert DRAFT_PREFIX not in text
    finally:
        await _cleanup_control(control_id)


# --- Property 3: the no-AI fallback is real deterministic content -------------


async def test_no_provider_configured_falls_back_to_deterministic_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CCF_ANTHROPIC_API_KEY", raising=False)
    get_settings.cache_clear()
    assert ai.is_configured() is False

    control_id, proj_id, sys_id, _org_id = await _seeded("Ai Fallback Org", "AIFALL")
    try:
        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=True, mark_draft=True
        )
        assert out["ai_used"] == 0
        assert text
        assert text != DRAFT_PREFIX
        assert len(text) > len(DRAFT_PREFIX) + 20  # real content, not a bare marker
        assert _FAKE_AI_TEXT not in text
    finally:
        await _cleanup_control(control_id)


# --- Property 4: provider failure is isolated, not propagated -----------------


async def test_provider_failure_does_not_propagate_and_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _RaisingAsyncClient)

    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(ai.log, "warning", lambda event, **kw: warnings.append((event, kw)))

    control_id, proj_id, sys_id, _org_id = await _seeded("Ai Failure Org", "AIFAIL")
    try:
        # Must not raise — a propagated provider exception would abort the
        # whole SSP generation for every other control too.
        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=True, mark_draft=True
        )
        assert out["ai_used"] == 0
        # Not just "didn't crash" — the fallback content must be the real
        # deterministic statement, and the failure must have been observable
        # (logged), not silently swallowed with no trace at all.
        assert text
        assert _FAKE_AI_TEXT not in text
        assert len(text) > len(DRAFT_PREFIX) + 20
        assert any(event == "ai.generate_failed" for event, _ in warnings)
    finally:
        await _cleanup_control(control_id)


# --- Property 5: org-scoped gateway is preferred over the legacy global key ---


async def test_org_scoped_gateway_preferred_over_legacy_global_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ai.py's own docstring: prefers the org-scoped gateway when a session and
    org id are supplied, falling back to CCF_ANTHROPIC_API_KEY only otherwise.
    Asymmetric fixture: the org-scoped stub and the legacy path return/behave
    differently, so a silent fallback to the legacy key would be caught by
    either the wrong text coming back or the poisoned legacy client firing."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()

    async def _fake_generate_text(session, org_id, **_kw) -> str:
        return "ORG-SCOPED-TEXT-9d21"

    monkeypatch.setattr(gateway, "generate_text", _fake_generate_text)
    monkeypatch.setattr(ai.httpx, "AsyncClient", _RaisingAsyncClient)

    async with session_scope() as session:
        org = Organization(name="Org Pref Org")
        session.add(org)
        await session.flush()
        text = await ai.generate(
            "draft AC-2", session=session, organization_id=org.id, purpose="ssp_narrative"
        )
    assert text == "ORG-SCOPED-TEXT-9d21"
