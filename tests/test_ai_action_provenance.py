"""An AI action records the provider that ACTUALLY produced its output.

``ai_action_runs.provider`` was set from ``settings.ai_provider`` before the
call, while ``ai_actions/provider.generate`` ignored its argument and always
returned the deterministic stub. So on any deployment with
``CCF_AI_ENABLED=true``, every run recorded a vendor no model had answered --
a false attribution in the one audit trail whose job is to say what was
machine-generated and by what.

The fix is structural rather than a rule: ``generate`` returns the provider and
model that produced the output, and ``run_action`` records what it is handed.
"""

from __future__ import annotations

import itertools
from typing import Any, ClassVar

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.ai_actions import provider as action_provider
from ccf.ai_actions import service
from ccf.ai_actions.registry import get_action
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, System
from ccf.models_ai_actions import AiActionRun

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _ai_on(monkeypatch: pytest.MonkeyPatch):
    """The condition the defect needed: AI enabled, a vendor configured."""
    monkeypatch.setenv("CCF_AI_ENABLED", "true")
    monkeypatch.setenv("CCF_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("CCF_AI_REQUIRE_APPROVAL", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _poam() -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"AIProv {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"sys {next(_SEQ)}")
        s.add(sysrow)
        await s.flush()
        poam = POAM(
            system_id=sysrow.id,
            title="Audit log gaps",
            weakness="Audit events are not fully enumerated.",
            severity="moderate",
            status="open",
        )
        s.add(poam)
        await s.flush()
        return org.id, poam.id


async def _run(org_id: int, poam_id: int) -> AiActionRun:
    async with session_scope() as s:
        run = await service.run_action(
            s,
            action_key="draft_poam_remediation",
            entity_type="poam",
            entity_id=str(poam_id),
            org_id=org_id,
            actor="tester",
        )
        await s.flush()
        return run


# ── the defect ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_stub_run_is_never_recorded_as_a_vendor() -> None:
    """With AI enabled and no organization credential, nothing real can answer.

    The run must say ``stub``. It used to say ``anthropic``, because the value
    came from settings before the call rather than from the call.
    """
    org_id, poam_id = await _poam()
    assert get_settings().ai_enabled is True
    assert get_settings().ai_provider == "anthropic"

    run = await _run(org_id, poam_id)
    assert run.provider == "stub", (
        f"a run produced by the stub recorded provider={run.provider!r}"
    )
    assert run.model is None

    async with session_scope() as s:
        stored = (
            await s.execute(select(AiActionRun).where(AiActionRun.id == run.id))
        ).scalar_one()
        assert stored.provider == "stub"
        assert stored.model is None


@pytest.mark.asyncio
async def test_a_real_provider_is_recorded_with_its_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction: when a model does answer, the row says which one.

    Without this the fix could be "always write stub", which would be honest
    and useless.
    """
    org_id, poam_id = await _poam()

    class _Result:
        data: ClassVar[dict[str, Any]] = {
            "content": "Remediate by enabling audit forwarding.",
            "citations": [],
        }
        provider: str = "anthropic"
        model: str | None = "claude-test-1"

    async def _fake(*_a: Any, **_kw: Any) -> Any:
        return _Result()

    monkeypatch.setattr(
        action_provider.gateway, "generate_structured_resolved", _fake
    )

    run = await _run(org_id, poam_id)
    assert run.provider == "anthropic"
    assert run.model == "claude-test-1"


@pytest.mark.asyncio
async def test_a_provider_failure_falls_back_and_says_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run that failed over to the stub and still named a vendor would be
    exactly the false attribution this file exists for."""
    org_id, poam_id = await _poam()

    async def _boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(
        action_provider.gateway, "generate_structured_resolved", _boom
    )

    run = await _run(org_id, poam_id)
    assert run.provider == "stub"
    assert run.model is None
    assert run.output_hash, "the action still produced usable output"


@pytest.mark.asyncio
async def test_an_empty_answer_falls_back_rather_than_recording_a_vendor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty answer is not an answer."""
    org_id, poam_id = await _poam()

    class _Empty:
        data: ClassVar[dict[str, Any]] = {"content": "   ", "citations": []}
        provider: str = "anthropic"
        model: str | None = "claude-test-1"

    async def _fake(*_a: Any, **_kw: Any) -> Any:
        return _Empty()

    monkeypatch.setattr(action_provider.gateway, "generate_structured_resolved", _fake)
    run = await _run(org_id, poam_id)
    assert run.provider == "stub"


# ── citations a model cannot fabricate ──────────────────────────────────────


def _ctx(n: int) -> dict[str, Any]:
    return {
        "label": "POA&M 1",
        "target_type": "poam",
        "target_id": "1",
        "facts": {"severity": "moderate"},
        "sources": [
            {"source_type": "poam", "source_id": str(i), "label": f"src {i}"}
            for i in range(n)
        ],
    }


@pytest.mark.asyncio
async def test_a_citation_index_outside_the_supplied_sources_is_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Citations are indices into what the caller supplied, so a model cannot
    reference a document it was never given -- there is no way to express one.
    An index that does not resolve is a model error, and a plausible-looking
    reference to nothing is the worst thing this path can put in front of a
    reviewer.
    """
    class _Result:
        data: ClassVar[dict[str, Any]] = {"content": "text", "citations": [0, 99, -1, 2, "two", 0]}
        provider: str = "anthropic"
        model: str | None = "m"

    async def _fake(*_a: Any, **_kw: Any) -> Any:
        return _Result()

    monkeypatch.setattr(action_provider.gateway, "generate_structured_resolved", _fake)

    async with session_scope() as s:
        out = await action_provider.generate(
            get_action("draft_poam_remediation"), _ctx(3), session=s, org_id=1
        )
    # 0 and 2 resolve; 99 is out of range, -1 is invalid, "two" is not an int,
    # and the repeated 0 is not duplicated.
    assert [c["source_id"] for c in out["citations"]] == ["0", "2"]


@pytest.mark.asyncio
async def test_the_prompt_numbers_the_sources_it_expects_to_be_cited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserted on the prompt actually sent: citing by index only works if the
    indices were shown."""
    seen: dict[str, Any] = {}

    class _Result:
        data: ClassVar[dict[str, Any]] = {"content": "text", "citations": [1]}
        provider: str = "anthropic"
        model: str | None = "m"

    async def _fake(*_a: Any, **kw: Any) -> Any:
        seen.update(kw)
        return _Result()

    monkeypatch.setattr(action_provider.gateway, "generate_structured_resolved", _fake)

    async with session_scope() as s:
        await action_provider.generate(
            get_action("draft_poam_remediation"), _ctx(2), session=s, org_id=1
        )

    assert "[0]" in seen["prompt"] and "[1]" in seen["prompt"]
    assert "severity: moderate" in seen["prompt"]
    assert seen["schema"]["properties"]["citations"]["items"]["type"] == "integer"
    assert "omit the statement" in seen["system"]


@pytest.mark.asyncio
async def test_without_a_session_the_stub_answers_and_says_so() -> None:
    """The path every test and local run takes."""
    out = await action_provider.generate(get_action("draft_poam_remediation"), _ctx(1))
    assert out["provider"] == "stub"
    assert out["model"] is None
    assert out["content"]
    assert len(out["citations"]) == 1
