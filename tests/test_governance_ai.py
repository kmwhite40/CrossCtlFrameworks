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

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.ai import gateway
from ccf.ai.providers.base import GenerateTextResponse
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
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
    User,
)
from ccf.ssp.constants import DRAFT_PREFIX
from ccf.ssp.statements import is_draft_narrative

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _credential_master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Required for ``gateway.set_credential`` to envelope-encrypt the org's
    provider key in the call-site tests below (real gateway config resolution,
    not mocked away)."""
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()

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


async def _seeded(
    name: str, prefix: str, *, platform: str = _PLATFORM
) -> tuple[str, int, int, int]:
    """Seed one AC-domain control on ``platform`` (default aws_govcloud), derive
    + generate the SSP once (use_ai=False), and return (control_id, project_id,
    system_id, org_id) so each test can re-derive statements with its own AI
    configuration."""
    control_id = f"AC.{prefix}-3.1.1"
    async with session_scope() as session:
        sys = await _make_system(session, name)
        await _seed_control(session, control_id, prefix)
        profile = SystemProfile(
            system_id=sys.id, environment_type="cloud", cloud_platform=platform
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


# --- Property 2: mark_draft=False no longer suppresses the AI draft marker ----


async def test_mark_draft_false_still_marks_ai_text_as_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Was: "documents the code AS WRITTEN: with mark_draft=False, ... NO
    [DRAFT] marker at all". That behaviour was a bug, not a decision: CISO-02
    (is_draft_narrative's docstring) requires AI-drafted content to stay
    visibly distinguishable until a human clears it, and DRAFT_PREFIX in the
    stored text is the *only* durable record of that once persisted --
    compose()'s needs_review flag is never saved. automation.py:580 now
    applies DRAFT_PREFIX to AI-sourced text unconditionally; mark_draft
    still legitimately gates the review marker on *deterministic* text (see
    test_mark_draft_false_still_suppresses_deterministic_review_marker below
    for proof that knob wasn't turned into a no-op).

    This also ties the fix to the requirement the report/UI actually consume:
    is_draft_narrative(...) must be True for such an entry, since that's the
    signal reports.py and ui.py key off to flag AI-sourced content -- not
    merely the presence of the prefix string as an implementation detail."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _FakeAsyncClient)

    control_id, proj_id, sys_id, _org_id = await _seeded("Ai Unmarked Org", "AIUNMK")
    try:
        async with session_scope() as session:
            proj = await session.get(SSPProject, proj_id)
            assert proj is not None
            profile = (
                await session.execute(
                    select(SystemProfile).where(SystemProfile.system_id == sys_id)
                )
            ).scalar_one()
            out = await generate_statements(
                session, project=proj, profile=profile, use_ai=True, mark_draft=False
            )
            await session.flush()
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

            assert out["ai_used"] >= 1  # see marker test's note on >=1 vs ==1
            # A test asserting only the prefix would still pass against code
            # that dropped the AI content after prepending it -- assert both.
            assert text.startswith(DRAFT_PREFIX), f"missing DRAFT_PREFIX: {text!r}"
            assert _FAKE_AI_TEXT in text
            assert text[len(DRAFT_PREFIX) :].startswith(_FAKE_AI_TEXT)
            # The signal reports.py/ui.py actually consume, not just the raw
            # string -- ties the fix to the requirement, not an implementation
            # detail of where the prefix happens to sit.
            assert is_draft_narrative(parts) is True
    finally:
        await _cleanup_control(control_id)


async def test_mark_draft_false_still_suppresses_deterministic_review_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves the fix was surgical: mark_draft=False with NO AI text involved
    (use_ai=False) must behave exactly as before.

    Uses intake code "azure_gov" (-> ssp platform "azure" via PLATFORM_TO_SSP)
    rather than the module's usual aws_govcloud fixture platform specifically
    because "azure" carries no capture connector (see ssp/platforms.py
    CONNECTOR_PLATFORMS) -- this exercises the automation.py:588
    ``if mark_draft and not text.startswith(DRAFT_PREFIX)`` branch directly
    (the "no capture connector, force review" path), which is the second,
    untouched call site for the ``mark_draft`` knob besides statements.py:174.
    If either deterministic-path gate regressed into an unconditional prefix,
    mark_draft would have become a no-op outside the AI path too -- which is
    not the change that was made."""
    monkeypatch.delenv("CCF_ANTHROPIC_API_KEY", raising=False)
    get_settings.cache_clear()

    control_id, proj_id, sys_id, _org_id = await _seeded(
        "Ai Deterministic Org", "AIDETM", platform="azure_gov"
    )
    try:
        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=False, mark_draft=False
        )
        assert out["ai_used"] == 0
        assert out["manual_evidence_required"] >= 1  # confirms the :588 branch ran
        assert _FAKE_AI_TEXT not in text
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


# --- Property 6/7/8/9: the CALL SITES actually pass session/organization_id ---
#
# Properties 1-5 above cover ai.py's own generate/draft_narrative logic and
# already passed while both real callers (automation.py's generate_statements
# and the /api/ai/narrative route) silently dropped session/organization_id,
# which is exactly the defect: those callers never reached this file's tests.
# These four go through the real gateway DB resolution (AiProviderConfig via
# gateway.set_credential, real gateway.resolve) with only the provider adapter
# boundary (gateway.build_provider) stubbed -- so a mix-up between two orgs'
# configs would be caught by a real (mis-scoped) SQL WHERE, not a mock keyed by
# the right answer already baked in.


def _model_echoing_provider(provider: str, _key: str) -> object:
    """Stand-in adapter that echoes the resolved model into the generated text,
    so the caller's returned text proves *which* org's config was resolved."""

    class _StubProvider:
        name = provider

        async def generate_text(self, request: object) -> GenerateTextResponse:
            model = request.model  # type: ignore[attr-defined]
            return GenerateTextResponse(
                text=f"ORG-TEXT::{model}", model=model, input_tokens=1, output_tokens=1
            )

    return _StubProvider()


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
    async with session_scope() as session:
        org = Organization(name=org_name)
        session.add(org)
        await session.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role="viewer",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        session.add(user)
        await session.flush()
        return user.api_token, org.id


async def test_generate_statements_reaches_org_scoped_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Call site 1 (automation.py generate_statements -> ai.draft_narrative):
    with the org configured, the org-scoped gateway must be used -- not the
    legacy global key. The legacy client is poisoned to raise so a silent
    fallback to it (e.g. from dropped kwargs) surfaces as no AI text at all."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _RaisingAsyncClient)

    control_id, proj_id, sys_id, org_id = await _seeded("Ai Gateway Site1 Org", "AIGATE1")
    try:
        async with session_scope() as session:
            await gateway.set_credential(
                session,
                org_id,
                "anthropic",
                api_key="sk-ant-site1-org-key",
                enabled=True,
                default_model="site1-org-model-marker",
            )
        monkeypatch.setattr(gateway, "build_provider", _model_echoing_provider)

        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=True, mark_draft=True
        )
        assert out["ai_used"] >= 1
        assert "ORG-TEXT::site1-org-model-marker" in text, (
            f"expected the org-scoped gateway's marker in the statement, got: {text!r}"
        )
    finally:
        await _cleanup_control(control_id)


async def test_route_ai_narrative_reaches_org_scoped_gateway_from_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Call site 2 (api/routes/automation.py's /api/ai/narrative): organization
    context must come from the authenticated principal (real bearer-token auth
    below), never a request-body field -- ``NarrativeIn`` carries no org id at
    all, so this also pins that it can't be reintroduced there."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    monkeypatch.setattr(ai.httpx, "AsyncClient", _RaisingAsyncClient)
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        token, org_id = await _mk_user("route-org-scoped@ai-callsite.test", "Route Org Scoped Org")
        async with session_scope() as session:
            await gateway.set_credential(
                session,
                org_id,
                "anthropic",
                api_key="sk-ant-route-org-key",
                enabled=True,
                default_model="route-org-model-marker",
            )
        monkeypatch.setattr(gateway, "build_provider", _model_echoing_provider)

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await client.post(
                "/api/ai/narrative",
                json={"control_id": "AC-2", "requirement": "limit system access"},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["configured"] is True
        assert body["text"] == "ORG-TEXT::route-org-model-marker", (
            f"expected the principal's org-scoped gateway marker, got: {body!r}"
        )
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()


async def test_tenant_isolation_org_a_statement_never_uses_org_bs_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant isolation, asserted as an attack: org A and org B get genuinely
    different configured models, both stored as real AiProviderConfig rows and
    resolved through the real gateway.resolve() DB query. Org A's generated
    statement must carry org A's marker and never org B's -- an identical-config
    fixture would pass even against code that mixed the two orgs up."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _RaisingAsyncClient)

    control_a, proj_a, sys_a, org_a = await _seeded("Ai Isolation Org A", "AISOA")
    control_b, _proj_b, _sys_b, org_b = await _seeded("Ai Isolation Org B", "AISOB")
    try:
        async with session_scope() as session:
            await gateway.set_credential(
                session,
                org_a,
                "anthropic",
                api_key="sk-ant-tenant-a-key",
                enabled=True,
                default_model="tenant-a-model-marker",
            )
            await gateway.set_credential(
                session,
                org_b,
                "anthropic",
                api_key="sk-ant-tenant-b-key",
                enabled=True,
                default_model="tenant-b-model-marker",
            )
        monkeypatch.setattr(gateway, "build_provider", _model_echoing_provider)

        text, out = await _regenerate_and_get_text(
            proj_a, sys_a, control_a, use_ai=True, mark_draft=True
        )
        assert out["ai_used"] >= 1
        assert "ORG-TEXT::tenant-a-model-marker" in text
        assert "tenant-b-model-marker" not in text, (
            "org A's statement leaked org B's provider config"
        )
    finally:
        await _cleanup_control(control_a)
        await _cleanup_control(control_b)


async def test_generate_statements_falls_back_to_legacy_when_org_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirms the existing fallback still works post-fix: with session and
    organization_id now passed for real, but no AiProviderConfig row for this
    org, gateway.resolve() genuinely raises (no mock of the gateway itself) and
    ai.generate falls back to the legacy global key, which still drafts text."""
    monkeypatch.setenv("CCF_ANTHROPIC_API_KEY", _LEGACY_KEY)
    get_settings.cache_clear()
    monkeypatch.setattr(ai.httpx, "AsyncClient", _FakeAsyncClient)
    # Deliberately no gateway.set_credential call -- this org has no configured
    # provider, so the real gateway.resolve() must fail and fall back.

    control_id, proj_id, sys_id, _org_id = await _seeded("Ai Legacy Fallback Org", "AILEGF")
    try:
        text, out = await _regenerate_and_get_text(
            proj_id, sys_id, control_id, use_ai=True, mark_draft=True
        )
        assert out["ai_used"] >= 1
        assert _FAKE_AI_TEXT in text
    finally:
        await _cleanup_control(control_id)
