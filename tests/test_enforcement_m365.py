"""The one provider that writes: exactly one field, and reversibly."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ccf.enforcement.providers.m365 import M365AccountProvider
from ccf.enforcement.types import RemediationStep, provider_for
from ccf.posture.providers import m365 as m365_checks
from ccf.posture.types import ResourceFinding

WRITE_CRED = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}


def _step(resource_id: str = "stale@acme.gov", *, enabled: bool = True) -> RemediationStep:
    return RemediationStep(
        resource_id=resource_id,
        resource_type="entra_user",
        action="disable_account",
        description=f"disable {resource_id}",
        current_state={"accountEnabled": enabled},
        target_state={"accountEnabled": False},
    )


class _Recorder:
    """Captures the exact request the provider makes."""

    def __init__(self, *, status: int = 204, get_body: dict[str, Any] | None = None) -> None:
        self.status = status
        self.get_body = get_body if get_body is not None else {"accountEnabled": True}
        self.patches: list[tuple[str, dict[str, Any]]] = []

    async def __aenter__(self) -> _Recorder:
        return self

    async def __aexit__(self, *a: object) -> None:
        return None

    async def post(self, url: str, data: dict[str, Any]) -> httpx.Response:
        return httpx.Response(
            200, json={"access_token": "tok"}, request=httpx.Request("POST", url)
        )

    async def get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(
            200, json=self.get_body, request=httpx.Request("GET", url)
        )

    async def patch(
        self, url: str, headers: dict[str, str], json: dict[str, Any]
    ) -> httpx.Response:
        self.patches.append((url, json))
        return httpx.Response(self.status, request=httpx.Request("PATCH", url))


def _patch_client(monkeypatch: pytest.MonkeyPatch, recorder: _Recorder) -> None:
    import ccf.enforcement.providers.m365 as mod

    monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **k: recorder)


# ── the credential separation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_credential_is_not_write_configured() -> None:
    assert await M365AccountProvider().is_write_configured() is False


@pytest.mark.asyncio
async def test_a_partial_credential_is_not_write_configured() -> None:
    provider = M365AccountProvider(credential={"tenant_id": "t-1"})
    assert await provider.is_write_configured() is False


@pytest.mark.asyncio
async def test_a_complete_write_credential_is_write_configured() -> None:
    assert await M365AccountProvider(credential=WRITE_CRED).is_write_configured() is True


def test_the_write_credential_is_a_different_type_from_the_read_connector() -> None:
    """The whole safety property: a read-only deployment has no such credential."""
    from ccf.connectors.msgraph import MsGraphConnector

    assert M365AccountProvider.write_credential_type == "msgraph_write"
    assert M365AccountProvider.write_credential_type != MsGraphConnector.key


def test_it_requires_a_write_scope_the_read_checks_do_not() -> None:
    assert M365AccountProvider.required_permissions == ("User.ReadWrite.All",)
    for check in m365_checks.CHECKS:
        assert "User.ReadWrite.All" not in check.required_permissions


# ── the registry ─────────────────────────────────────────────────────────────


def test_it_is_registered_for_the_stale_account_check_only() -> None:
    assert provider_for(m365_checks.STALE_ACCOUNTS.key) is M365AccountProvider
    assert provider_for(m365_checks.MFA_REGISTERED.key) is None
    assert provider_for(m365_checks.LEGACY_AUTH_BLOCKED.key) is None


def test_conditional_access_has_no_provider() -> None:
    """Deliberately: a policy change can lock every administrator out of a
    tenant, and a provider that can cause a lockout is not the one to learn
    on."""
    assert provider_for(m365_checks.LEGACY_AUTH_BLOCKED.key) is None


# ── planning reads the current state ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_plan_captures_the_current_state_from_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder(get_body={"accountEnabled": True})
    _patch_client(monkeypatch, recorder)
    provider = M365AccountProvider(credential=WRITE_CRED)
    steps = await provider.plan(
        [ResourceFinding("stale@acme.gov", "entra_user", "fail", "idle 200 days")]
    )
    assert len(steps) == 1
    assert steps[0].current_state == {"accountEnabled": True}
    assert steps[0].target_state == {"accountEnabled": False}
    assert "idle 200 days" in steps[0].description


@pytest.mark.asyncio
async def test_plan_skips_an_account_whose_state_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No reversal data means no step -- build_steps then refuses the plan."""
    recorder = _Recorder(get_body={"id": "x"})  # no accountEnabled field
    _patch_client(monkeypatch, recorder)
    provider = M365AccountProvider(credential=WRITE_CRED)
    steps = await provider.plan(
        [ResourceFinding("opaque@acme.gov", "entra_user", "fail", "idle")]
    )
    assert steps == []


@pytest.mark.asyncio
async def test_plan_writes_nothing() -> None:
    recorder = _Recorder()
    provider = M365AccountProvider(credential=WRITE_CRED)
    import ccf.enforcement.providers.m365 as mod

    original = mod.httpx.AsyncClient
    mod.httpx.AsyncClient = lambda **k: recorder  # type: ignore[assignment]
    try:
        await provider.plan([ResourceFinding("a@acme.gov", "entra_user", "fail", "idle")])
    finally:
        mod.httpx.AsyncClient = original  # type: ignore[assignment]
    assert recorder.patches == [], "planning must never PATCH"


@pytest.mark.asyncio
async def test_plan_without_a_write_credential_produces_nothing() -> None:
    provider = M365AccountProvider()
    assert await provider.plan(
        [ResourceFinding("a@acme.gov", "entra_user", "fail", "idle")]
    ) == []


# ── the bodies ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_patches_exactly_one_field(monkeypatch: pytest.MonkeyPatch) -> None:
    """The body is the blast radius of a single step. Anything else in it is a
    change nobody approved."""
    recorder = _Recorder()
    _patch_client(monkeypatch, recorder)
    provider = M365AccountProvider(credential=WRITE_CRED)
    outcome = await provider.apply(_step())
    assert outcome.status == "applied"
    assert len(recorder.patches) == 1
    url, body = recorder.patches[0]
    assert body == {"accountEnabled": False}
    assert url.endswith("/v1.0/users/stale@acme.gov")


@pytest.mark.asyncio
async def test_reverse_restores_the_captured_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder()
    _patch_client(monkeypatch, recorder)
    provider = M365AccountProvider(credential=WRITE_CRED)
    outcome = await provider.reverse(_step(enabled=True))
    assert outcome.status == "applied"
    assert recorder.patches[0][1] == {"accountEnabled": True}


@pytest.mark.asyncio
async def test_reverse_of_an_account_that_was_already_disabled_restores_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It restores the captured state, not an assumption that it was enabled."""
    recorder = _Recorder()
    _patch_client(monkeypatch, recorder)
    provider = M365AccountProvider(credential=WRITE_CRED)
    await provider.reverse(_step(enabled=False))
    assert recorder.patches[0][1] == {"accountEnabled": False}


# ── failures are outcomes ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_403_is_a_failed_outcome_naming_the_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder(status=403)
    _patch_client(monkeypatch, recorder)
    provider = M365AccountProvider(credential=WRITE_CRED)
    outcome = await provider.apply(_step())
    assert outcome.status == "failed"
    assert "403" in outcome.detail
    assert "User.ReadWrite.All" in outcome.detail


@pytest.mark.asyncio
async def test_apply_without_a_write_credential_is_skipped_not_attempted() -> None:
    outcome = await M365AccountProvider().apply(_step())
    assert outcome.status == "skipped"
    assert "write credential" in outcome.detail
