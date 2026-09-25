"""KSI rules can see what Concord actually tested, not only what was claimed.

`SystemContext` carried an implementation *record* and a capture, but no
control-test outcome -- so a system whose scans proved a control satisfied
against the live tenant still reported the KSI as failing, because no
implementation row claimed it. 39 of 51 KSIs failed that way on a tenant with
real machine evidence.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from ccf.db import session_scope
from ccf.fedramp20x.validation import SystemContext, build_context, evaluate_rule
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult

pytestmark = pytest.mark.usefixtures("fresh_engine")

_KSI = {"identifier": "KSI-IAM-01", "category": "Identity and Access Management"}


def _rule(*controls: str) -> dict:
    return {"kind": "control_state", "controls": list(controls)}


# --- the rule ----------------------------------------------------------------


def test_a_passing_automated_test_satisfies_a_control() -> None:
    ctx = SystemContext(control_tests={"AC-17": "pass"})
    verdict = evaluate_rule(_rule("AC-17"), ctx, ksi=_KSI)
    assert verdict.status == "pass"


def test_the_evidence_reference_says_it_was_a_test() -> None:
    """An unlabelled automated claim inside a readiness number is the defect
    this closes, not one to introduce."""
    ctx = SystemContext(control_tests={"AC-17": "pass"})
    verdict = evaluate_rule(_rule("AC-17"), ctx, ksi=_KSI)
    assert "AC-17:test:pass" in verdict.evidence_refs


def test_a_failing_test_satisfies_nothing() -> None:
    ctx = SystemContext(control_tests={"AC-17": "fail"})
    assert evaluate_rule(_rule("AC-17"), ctx, ksi=_KSI).status == "fail"


def test_a_failing_test_never_overrides_a_claimed_implementation() -> None:
    """Whether a failing test invalidates an implementation is the assessor's
    call, not a rule's -- the rule only ever adds satisfaction."""
    ctx = SystemContext(
        impl_status={"AC-17": "implemented"}, control_tests={"AC-17": "fail"}
    )
    assert evaluate_rule(_rule("AC-17"), ctx, ksi=_KSI).status == "pass"


def test_a_control_with_neither_is_still_a_failure() -> None:
    """Both directions, so a rule that passed everything would fail here."""
    assert evaluate_rule(_rule("AC-17"), SystemContext(), ksi=_KSI).status == "fail"


def test_a_partially_tested_rule_reports_what_is_missing() -> None:
    ctx = SystemContext(control_tests={"AC-17": "pass"})
    verdict = evaluate_rule(_rule("AC-17", "AC-2"), ctx, ksi=_KSI)
    assert verdict.status == "warn"
    assert "AC-2" in (verdict.failure_reason or "")


# --- building the context ----------------------------------------------------


async def _system_with_tests(*tests: tuple[str, str]) -> int:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"KSI Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Sys {tag}")
        s.add(system)
        await s.flush()
        for control_id, status in tests:
            test = ControlTest(
                organization_id=org.id, system_id=system.id, control_id=control_id,
                name=f"{control_id} check", method="automated", last_status=status,
            )
            s.add(test)
            await s.flush()
            s.add(
                ControlTestResult(
                    control_test_id=test.id, status=status,
                    run_at=datetime.now(UTC), evaluated=1,
                    failing=0 if status == "pass" else 1,
                )
            )
        await s.flush()
        return system.id


@pytest.mark.asyncio
async def test_a_control_whose_tests_all_pass_is_credited() -> None:
    system_id = await _system_with_tests(("AC-17", "pass"), ("AC-17(2)", "pass"))
    async with session_scope() as s:
        ctx = await build_context(s, system_id)
    assert ctx.control_tests.get("AC-17") == "pass"


@pytest.mark.asyncio
async def test_one_failing_enhancement_withholds_the_whole_control() -> None:
    """`normalize_control` folds enhancements together: IA-2, IA-2(1) and
    IA-2(11) are all `IA-2`.

    A tenant with FIDO2 enabled (IA-2(11) passing) and six users without MFA
    (IA-2 failing) has not satisfied IA-2. Crediting it because one
    enhancement passed would put a claim in a readiness number that the
    evidence contradicts -- which is the live state of the tenant this was
    built against.
    """
    system_id = await _system_with_tests(
        ("IA-2", "fail"), ("IA-2(1)", "pass"), ("IA-2(11)", "pass")
    )
    async with session_scope() as s:
        ctx = await build_context(s, system_id)
    assert "IA-2" not in ctx.control_tests


@pytest.mark.asyncio
async def test_the_result_does_not_depend_on_which_check_ran_last() -> None:
    """All-pass rather than last-write-wins.

    Taking the newest result per key made the answer depend on the order the
    checks happened to run, so the same evidence could credit a control or not
    from one scan to the next.
    """
    fail_last = await _system_with_tests(("IA-2(11)", "pass"), ("IA-2", "fail"))
    pass_last = await _system_with_tests(("IA-2", "fail"), ("IA-2(11)", "pass"))
    async with session_scope() as s:
        a = await build_context(s, fail_last)
        b = await build_context(s, pass_last)
    assert a.control_tests == b.control_tests == {}


@pytest.mark.asyncio
async def test_another_systems_tests_do_not_leak_in() -> None:
    mine = await _system_with_tests(("AC-17", "pass"))
    theirs = await _system_with_tests(("AC-2", "pass"))
    async with session_scope() as s:
        ctx = await build_context(s, mine)
    assert ctx.control_tests == {"AC-17": "pass"}, "another system's tests were counted"
    assert theirs != mine
