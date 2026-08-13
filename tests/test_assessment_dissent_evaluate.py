"""The challenger call: satisfied-only policy, disagreement routing to
insufficient_evidence, and failure isolation.

CCF_ASSESSMENT_DISSENT_ENABLED is off by default -- these tests enable it
explicitly via monkeypatch.setenv + get_settings.cache_clear(), mirroring
test_calibration_snapshot.py's pattern for the same reason: Settings is
process-wide and lru_cache'd (ccf.config.get_settings), so a stale cached
instance from an earlier test would silently ignore the env var.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from ccf.ai import gateway
from ccf.assessment.engine import evaluate as evaluate_module
from ccf.assessment.engine.evaluate import (
    DISSENT_CHALLENGE_ACTION_KEY,
    DISSENT_CHALLENGE_PURPOSE,
    PURPOSE,
    evaluate_objective,
)
from ccf.assessment.engine.objectives import Objective, objective_sha256
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_ai_actions import AiActionRun
from ccf.prep import retriever
from ccf.prep.retriever import RetrievedUnit

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _objective(text: str = "multifactor authentication is implemented;") -> Objective:
    return Objective(label="IA-2a", text=text, text_sha256=objective_sha256(text), sort_order=0)


def _unit(unit_id: int, content: str) -> RetrievedUnit:
    return RetrievedUnit(
        unit_id=unit_id, content=content, score=0.5, page_numbers=[3],
        section_path="Access Control", table_coordinates=None,
        source_kind="evidence_version", control_identifiers=["IA-2"],
        evidence_strength="strong", lexical_rank=1, vector_rank=1,
    )


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


def _resolved(
    data: dict[str, Any], model: str = "fake-model", provider: str = "fake"
) -> gateway.StructuredResult:
    return gateway.StructuredResult(data=data, model=model, provider=provider)


def _enable_dissent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_ASSESSMENT_DISSENT_ENABLED", "true")
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Any:
    yield
    get_settings.cache_clear()


def _dispatching_structured(
    primary: dict[str, Any], challenge: dict[str, Any] | Exception | None
) -> tuple[Any, list[str]]:
    """A fake generate_structured_resolved that answers differently for the
    primary call (purpose=PURPOSE) and the challenge call
    (purpose=DISSENT_CHALLENGE_PURPOSE) -- dispatch on purpose, not call
    order, so "no second call was made" is unambiguous. Returns (fake_fn,
    calls), where calls records every purpose seen, in order, so a test can
    assert the exact call count -- not just the resulting columns, since the
    satisfied-only policy is specifically about not making a call at all.
    """
    calls: list[str] = []

    async def _fake(session: Any, org_id: Any, *, purpose: str, **kwargs: Any) -> Any:
        calls.append(purpose)
        if purpose == PURPOSE:
            return _resolved(primary)
        assert purpose == DISSENT_CHALLENGE_PURPOSE
        if challenge is None:
            raise AssertionError("no challenge call was expected")
        if isinstance(challenge, Exception):
            raise challenge
        return _resolved(challenge, model="challenger-model", provider="fake")

    return _fake, calls


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    org_id: int,
    primary: dict[str, Any],
    challenge: dict[str, Any] | Exception | None,
) -> tuple[Any, list[str]]:
    fake, calls = _dispatching_structured(primary, challenge)

    async def _fake_retrieve(*args: Any, **kwargs: Any) -> list[RetrievedUnit]:
        return [_unit(7, "Admins use MFA.")]

    monkeypatch.setattr(retriever, "retrieve", _fake_retrieve)
    monkeypatch.setattr(gateway, "generate_structured_resolved", fake)
    async with session_scope() as s:
        result = await evaluate_objective(
            s, org_id=org_id, control_identifier="IA-2", objective=_objective(), system_id=None,
        )
    return result, calls


_SATISFIED = {
    "verdict": "satisfied", "cited_unit_ids": [7], "gaps": [], "contradictions": [],
    "rationale": "The primary reviewer's own rationale.", "confidence": 0.95,
}
_NOT_SATISFIED = {
    "verdict": "not_satisfied", "cited_unit_ids": [], "gaps": ["nothing addresses key rotation"],
    "contradictions": [], "rationale": "The primary reviewer's own rationale.", "confidence": 0.9,
}
_INSUFFICIENT = {
    "verdict": "insufficient_evidence", "cited_unit_ids": [], "gaps": ["ambiguous"],
    "contradictions": [], "rationale": "The primary reviewer's own rationale.", "confidence": 0.4,
}


# --- Disabled by default / satisfied-only ------------------------------------


async def test_disabled_by_default_makes_no_challenger_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, calls = await _run(monkeypatch, await _org("dissent-disabled"), _SATISFIED, None)
    assert calls == [PURPOSE]
    assert result.verdict == "satisfied"
    assert result.challenger_verdict is None


async def test_a_not_satisfied_primary_verdict_is_never_challenged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dissent(monkeypatch)
    result, calls = await _run(monkeypatch, await _org("dissent-skip-ns"), _NOT_SATISFIED, None)
    assert calls == [PURPOSE], "a not_satisfied verdict must not trigger a second model call"
    assert result.verdict == "not_satisfied"
    assert result.challenger_verdict is None


async def test_an_insufficient_evidence_primary_verdict_is_never_challenged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dissent(monkeypatch)
    result, calls = await _run(monkeypatch, await _org("dissent-skip-ie"), _INSUFFICIENT, None)
    assert calls == [PURPOSE], "insufficient_evidence must not trigger a second model call"
    assert result.verdict == "insufficient_evidence"
    assert result.challenger_verdict is None


# --- Agreement vs disagreement ------------------------------------------------


async def test_agreement_is_recorded_without_escalating(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_dissent(monkeypatch)
    challenge_agrees = {
        "verdict": "satisfied", "cited_unit_ids": [7],
        "rationale": "The challenger's own, distinct argument -- also satisfied.",
    }
    result, calls = await _run(
        monkeypatch, await _org("dissent-agree"), _SATISFIED, challenge_agrees
    )
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "satisfied", "agreement must not change the objective's verdict"
    assert result.challenger_verdict == "satisfied"
    assert (
        result.challenger_rationale
        == "The challenger's own, distinct argument -- also satisfied."
    )
    assert result.challenger_ai_action_run_id is not None


async def test_disagreement_flips_the_verdict_and_retains_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asymmetric fixture: primary and challenger carry different confidence,
    different rationale text, and different verdicts, so a swap bug (primary
    and challenger rationale/verdict transposed) would be caught, and a
    confidence-weighted "average" implementation would visibly disagree with
    the asserted outcome.
    """
    _enable_dissent(monkeypatch)
    challenge_disagrees = {
        "verdict": "not_satisfied", "cited_unit_ids": [7],
        "rationale": "The challenger's own argument: passage 7 does not actually cover rotation.",
    }
    result, calls = await _run(
        monkeypatch, await _org("dissent-disagree"), _SATISFIED, challenge_disagrees
    )
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "insufficient_evidence", (
        "a credible disagreement routes to insufficient_evidence -- never satisfied "
        "(the primary) and never not_satisfied (the challenger): the two are never "
        "tie-broken toward either side"
    )
    assert result.rationale == "The primary reviewer's own rationale.", (
        "the primary's own rationale must survive unchanged"
    )
    assert result.challenger_verdict == "not_satisfied"
    assert (
        result.challenger_rationale
        == "The challenger's own argument: passage 7 does not actually cover rotation."
    )
    assert result.challenger_ai_action_run_id is not None


async def test_an_uncited_disagreement_does_not_escalate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bar is a differing verdict WITH at least one citation -- an
    uncited disagreement is still recorded (challenger_verdict populated) but
    must not flip the objective. Confirms escalation is never gated on the
    challenger's own confidence either, since this fixture supplies none.
    """
    _enable_dissent(monkeypatch)
    challenge_uncited = {
        "verdict": "not_satisfied", "cited_unit_ids": [],
        "rationale": "The challenger's argument, but grounded in nothing offered.",
    }
    result, _ = await _run(
        monkeypatch, await _org("dissent-uncited"), _SATISFIED, challenge_uncited
    )
    assert result.verdict == "satisfied"
    assert result.challenger_verdict == "not_satisfied"


# --- Failure isolation --------------------------------------------------------


async def test_a_raising_challenger_call_leaves_the_primary_verdict_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_dissent(monkeypatch)
    warn = MagicMock()
    monkeypatch.setattr(evaluate_module.log, "warning", warn)
    result, calls = await _run(
        monkeypatch,
        await _org("dissent-raise"),
        _SATISFIED,
        RuntimeError("simulated provider timeout"),
    )
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "satisfied"
    assert result.challenger_verdict is None
    assert result.challenger_rationale is None
    assert result.challenger_ai_action_run_id is None
    warn.assert_called_once()
    assert warn.call_args.args[0] == "assessment.challenger_failed"


async def test_a_challenger_call_that_never_ran_logs_no_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The subtler trap: a best-effort except handler makes "skipped
    correctly" and "raised and was swallowed" indistinguishable to a test
    that only asserts the absence of the challenger columns. Assert the
    warning log's absence too, on the disabled-by-default path where no
    challenge is even attempted.
    """
    warn = MagicMock()
    monkeypatch.setattr(evaluate_module.log, "warning", warn)
    await _run(monkeypatch, await _org("dissent-no-warn"), _SATISFIED, None)
    warn.assert_not_called()


async def test_a_malformed_challenger_response_rolls_back_its_own_partial_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """record_ai_run for the challenge call succeeds and writes a real
    AiActionRun row *before* this function parses c_data["verdict"] -- a
    challenge response missing "verdict" raises there, after that write. With
    the challenger call wrapped in its own begin_nested(), that partial write
    is rolled back cleanly; without it, the row would survive as an orphan
    even though the challenge is reported as failed. This is what actually
    discriminates begin_nested()'s presence: record_ai_run's own internal
    savepoint means it never raises on its own, so a plain monkeypatched
    RuntimeError (as in the test above) cannot distinguish "wrapped in its
    own savepoint" from "just a bare try/except" -- this test can.
    """
    _enable_dissent(monkeypatch)
    org_id = await _org("dissent-orphan-rollback")
    malformed_challenge = {"cited_unit_ids": [7], "rationale": "missing the verdict key"}
    result, calls = await _run(monkeypatch, org_id, _SATISFIED, malformed_challenge)
    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE]
    assert result.verdict == "satisfied"
    assert result.challenger_verdict is None

    async with session_scope() as s:
        orphans = (
            await s.execute(
                select(AiActionRun).where(
                    AiActionRun.action_key == DISSENT_CHALLENGE_ACTION_KEY,
                    AiActionRun.organization_id == org_id,
                )
            )
        ).scalars().all()
    assert orphans == [], (
        "a failed challenge must leave no orphan AiActionRun row behind for this "
        "organization -- this is what begin_nested() actually protects"
    )


async def test_the_primary_verdict_is_recorded_not_inferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """primary_verdict must be stored on both outcomes of a challenge.

    Under today's satisfied-only policy a challenged objective's primary
    verdict was "satisfied" by construction, so it looks inferable. The spec
    expects that policy to broaden, and on the day it does every previously
    contested row becomes unreadable. So it is recorded, not derived.

    Both branches are asserted, and the contested one asymmetrically:
    primary_verdict must differ from verdict, which a test asserting only
    `primary_verdict == "satisfied"` would still pass if the field were wired
    to `verdict` *before* the flip by coincidence rather than by intent.
    """
    _enable_dissent(monkeypatch)
    agrees = {
        "verdict": "satisfied", "cited_unit_ids": [7],
        "rationale": "The challenger could not make the opposite case.",
    }
    agreed, _ = await _run(monkeypatch, await _org("dissent-pv-agree"), _SATISFIED, agrees)
    assert agreed.verdict == "satisfied"
    assert agreed.primary_verdict == "satisfied", "recorded even when the challenge agreed"

    disagrees = {
        "verdict": "not_satisfied", "cited_unit_ids": [7],
        "rationale": "The challenger's own argument.",
    }
    contested, _ = await _run(
        monkeypatch, await _org("dissent-pv-contest"), _SATISFIED, disagrees
    )
    assert contested.verdict == "insufficient_evidence"
    assert contested.primary_verdict == "satisfied", "must survive the flip"
    assert contested.primary_verdict != contested.verdict


async def test_a_disagreement_citing_a_passage_never_offered_does_not_escalate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The challenger may cite only from the passages it was shown.

    Only unit 7 is retrieved, so a citation of 99 is a passage the challenger
    was never offered -- it either hallucinated the id or reached outside its
    evidence. Either way that is not a credible disagreement, and the escalation
    bar requires a real citation.

    This guard had no test at all: the final review deleted the `in offered`
    check and all eighteen dissent tests stayed green. The cited id is
    deliberately one that does not exist, so a missing guard admits something
    unresolvable rather than silently substituting a real passage.
    """
    _enable_dissent(monkeypatch)
    out_of_scope = {
        "verdict": "not_satisfied", "cited_unit_ids": [99],
        "rationale": "The challenger cites a passage it was never shown.",
    }
    result, calls = await _run(
        monkeypatch, await _org("dissent-oob-cite"), _SATISFIED, out_of_scope
    )

    assert calls == [PURPOSE, DISSENT_CHALLENGE_PURPOSE], "the challenge still ran"
    assert result.verdict == "satisfied", "an out-of-scope citation is not a credible disagreement"
    assert result.challenger_verdict == "not_satisfied", "but the dissent is still recorded"
