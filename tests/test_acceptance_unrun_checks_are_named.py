"""Acceptance: a scan response names every applicable check that did not run.

The second acceptance criterion of
``docs/superpowers/plans/2026-09-26-live-audit-compliance-plan.md``:

    A scan response names every applicable check that did not run and why.

``tests/test_posture_scan.py`` already covers this per-path: the arithmetic
adds up, an inactive test is named, an unconfigured connector is named, and an
outcome for an unknown check is reported separately instead of being mixed in.
What none of those establishes is the criterion as stated, which is a claim
about *every* path at once -- including the ones nobody wrote a test for yet.

A per-path test answers "does this reason appear". The criterion asks "is there
any way for a check to go missing quietly". Those are different questions, and
only the second one is worth calling an acceptance criterion: the failure mode
is a new code path that drops a check without a sentence, which by construction
has no test of its own on the day it is written.

So this file asserts the property, over the paths that exist, and a structural
guard that a new ``skipped_checks`` entry anywhere in the scan module carries a
reason.

The distinction that makes the number honest is also covered: an *unexpected*
outcome (a connector answering for a check this build does not define) is not a
skipped check. It goes in its own bucket, because counting it as skipped would
break the arithmetic while looking like extra diligence.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest
from ccf.posture import scan as scan_mod
from ccf.posture.checks import CheckOutcome, PostureCheck, ResourceFinding
from ccf.posture.scan import scan_for_system

_SEQ = itertools.count()

RAN = PostureCheck(
    key="demo.bucket.public",
    title="Buckets block public access",
    provider="demo_provider",
    resource_type="bucket",
    expected="public access blocked",
    control_ids=("AC-3",),
)
SILENT = PostureCheck(
    key="demo.bucket.encrypted",
    title="Buckets are encrypted",
    provider="demo_provider",
    resource_type="bucket",
    expected="server-side encryption enabled",
    control_ids=("SC-28",),
)


def _outcome(check: PostureCheck, *verdicts: str) -> CheckOutcome:
    findings = tuple(
        ResourceFinding(f"res-{i}", "bucket", v, "observed") for i, v in enumerate(verdicts)
    )
    return CheckOutcome.from_findings(check, findings)


class _FakeConnector:
    key = "demo_provider"

    def __init__(self, outcomes: list[CheckOutcome]) -> None:
        self._outcomes = outcomes

    def is_configured(self) -> bool:
        return True

    async def scan(self, checks: object = None) -> list[CheckOutcome]:
        return self._outcomes


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    checks: tuple[PostureCheck, ...],
    outcomes: list[CheckOutcome],
    connector: object | None = ...,  # type: ignore[assignment]
) -> None:
    async def _fake_connector(*_a: object, **_k: object) -> object:
        return _FakeConnector(outcomes) if connector is ... else connector

    async def _fake_resolve(*_a: object, **_k: object) -> tuple[object, ...]:
        return tuple(
            SimpleNamespace(check=c, endpoint=f"/{c.key}", source="platform") for c in checks
        )

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


async def _system() -> int:
    async with session_scope() as session:
        org = Organization(name=f"UnrunOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"UnrunSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        return sys_.id


async def _scan(system_id: int) -> dict[str, Any]:
    async with session_scope() as session:
        return await scan_for_system(
            session, system_id=system_id, connector_key="demo_provider"
        )


def _assert_report_is_answerable(out: dict[str, Any]) -> None:
    """The criterion, as one function, applied to every scan this file runs.

    Three things together make a report answerable, and any one of them alone
    is not enough:

    * the arithmetic closes, so no check fell out of the loop unnoticed;
    * every skipped entry names *which* check, so an operator can look it up;
    * every skipped entry carries a non-blank reason, so "1 of 2 checks ran"
      never leaves somebody to work out the missing one by subtraction.
    """
    assert out["checks_expected"] == out["checks_run"] + len(out["skipped_checks"]), (
        f"{out['checks_expected']} expected != {out['checks_run']} run + "
        f"{len(out['skipped_checks'])} skipped -- a check went missing quietly"
    )
    for entry in out["skipped_checks"]:
        assert entry.get("check_key"), f"a skipped check is unnamed: {entry}"
        reason = str(entry.get("reason") or "").strip()
        assert reason, f"{entry['check_key']} was skipped with no reason given"
        # A reason that is only a status word ("skipped", "error", "n/a") is
        # the same dead end as no reason at all -- it restates that the check
        # did not run without saying what to do about it.
        assert len(reason.split()) >= 3, (
            f"{entry['check_key']}: {reason!r} restates the skip instead of explaining it"
        )


# ---------------------------------------------------------------------------
# Every path that can leave a check unrun
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_check_the_connector_answered_nothing_for_is_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The silent case: two checks expected, the connector returns one outcome."""
    _patch(monkeypatch, checks=(RAN, SILENT), outcomes=[_outcome(RAN, "pass")])
    out = await _scan(await _system())

    _assert_report_is_answerable(out)
    assert out["checks_run"] == 1
    assert [s["check_key"] for s in out["skipped_checks"]] == [SILENT.key]


@pytest.mark.asyncio
async def test_an_unconfigured_connector_names_every_expected_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing ran, so *both* checks must be named -- not one, and not zero."""
    _patch(monkeypatch, checks=(RAN, SILENT), outcomes=[], connector=None)
    out = await _scan(await _system())

    _assert_report_is_answerable(out)
    assert out["checks_run"] == 0
    assert {s["check_key"] for s in out["skipped_checks"]} == {RAN.key, SILENT.key}


@pytest.mark.asyncio
async def test_a_deactivated_test_is_named_rather_than_silently_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A human turned the generated test off. That is a third reason, not a gap."""
    system_id = await _system()
    _patch(monkeypatch, checks=(RAN,), outcomes=[_outcome(RAN, "fail")])
    await _scan(system_id)

    async with session_scope() as session:
        test = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == system_id)
            )
        ).scalars().one()
        test.active = False
        await session.flush()

    out = await _scan(system_id)
    _assert_report_is_answerable(out)
    assert out["checks_run"] == 0
    assert [s["check_key"] for s in out["skipped_checks"]] == [RAN.key]


@pytest.mark.asyncio
async def test_the_reasons_are_distinct_so_the_remedy_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three causes, three sentences.

    One shared reason across every path would satisfy "names why" to the letter
    and tell an operator nothing: a missing credential, a connector that went
    quiet, and a test somebody deactivated need three different actions.
    """
    reasons: set[str] = set()

    _patch(monkeypatch, checks=(RAN, SILENT), outcomes=[_outcome(RAN, "pass")])
    reasons.add(str((await _scan(await _system()))["skipped_checks"][0]["reason"]))

    _patch(monkeypatch, checks=(RAN,), outcomes=[], connector=None)
    reasons.add(str((await _scan(await _system()))["skipped_checks"][0]["reason"]))

    system_id = await _system()
    _patch(monkeypatch, checks=(RAN,), outcomes=[_outcome(RAN, "fail")])
    await _scan(system_id)
    async with session_scope() as session:
        test = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == system_id)
            )
        ).scalars().one()
        test.active = False
        await session.flush()
    reasons.add(str((await _scan(system_id))["skipped_checks"][0]["reason"]))

    assert len(reasons) == 3, f"the paths share a reason: {sorted(reasons)}"


# ---------------------------------------------------------------------------
# What must NOT be counted as a skipped check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_outcome_for_an_undefined_check_does_not_inflate_the_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It is still reported -- in its own bucket, with its own reason.

    Folding it into ``skipped_checks`` would break the arithmetic above while
    looking like extra diligence, which is the worst of both: a number that no
    longer adds up and a reader with no reason to doubt it.
    """
    stranger = PostureCheck(
        key="demo.unknown.thing",
        title="Something this build does not define",
        provider="demo_provider",
        resource_type="bucket",
        expected="?",
        control_ids=("XX-1",),
    )
    _patch(
        monkeypatch,
        checks=(RAN,),
        outcomes=[
            _outcome(RAN, "pass"),
            CheckOutcome.from_findings(
                stranger, (ResourceFinding("res-0", "bucket", "fail", "observed"),)
            ),
        ],
    )
    out = await _scan(await _system())

    _assert_report_is_answerable(out)
    assert [u["check_key"] for u in out["unexpected_outcomes"]] == [stranger.key]
    assert str(out["unexpected_outcomes"][0]["reason"]).strip()
    assert all(s["check_key"] != stranger.key for s in out["skipped_checks"])


@pytest.mark.asyncio
async def test_the_response_shape_does_not_depend_on_what_happened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A consumer must not have to guess which branch produced the answer.

    A response that grows and shrinks its own keys makes every reader write a
    `.get` dance, and the key most likely to be missing on the unhappy path is
    the one that explains the unhappy path.
    """
    required = {
        "checks_expected",
        "checks_run",
        "results",
        "skipped_checks",
        "unexpected_outcomes",
        "reason",
    }

    _patch(monkeypatch, checks=(RAN,), outcomes=[_outcome(RAN, "pass")])
    happy = await _scan(await _system())

    _patch(monkeypatch, checks=(RAN,), outcomes=[], connector=None)
    unhappy = await _scan(await _system())

    for label, out in (("configured", happy), ("unconfigured", unhappy)):
        assert required <= set(out), f"{label} response is missing {required - set(out)}"


# ---------------------------------------------------------------------------
# The guard for the path nobody has written yet
# ---------------------------------------------------------------------------


def test_every_skipped_check_the_module_builds_carries_a_reason() -> None:
    """Parsed from the source: each ``skipped_checks`` entry sets ``reason``.

    The tests above cover the three paths that exist today. The criterion is
    about the fourth one -- a new branch that appends a check key and forgets
    the sentence, written on a day when no test exists to catch it.

    This reads the dict literals the scan module appends to a skipped list and
    requires ``check_key`` and ``reason`` on each. It is a structural guard and
    is stated as one: it cannot tell whether a reason is *true*, only that the
    author was made to write one. The behavioural half is above.
    """
    import ast  # noqa: PLC0415
    import pathlib  # noqa: PLC0415

    source = pathlib.Path(scan_mod.__file__).read_text()
    tree = ast.parse(source)

    def entries_under(node: ast.AST) -> list[ast.Dict]:
        return [n for n in ast.walk(node) if isinstance(n, ast.Dict)]

    candidates: list[ast.Dict] = []
    for node in ast.walk(tree):
        # `skipped.append({...})`
        if isinstance(node, ast.Call):
            func = node.func
            target = ""
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                target = func.value.id
            if "skip" in target.lower():
                for arg in node.args:
                    candidates.extend(entries_under(arg))
        # `skipped = [...]`
        if isinstance(node, ast.Assign):
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if any("skip" in n.lower() for n in names):
                candidates.extend(entries_under(node.value))
        # `return {..., "skipped_checks": [ {...} for ... ], ...}` -- the shape
        # the first version of this guard missed entirely, because the entries
        # there are built with `{**check, "reason": ...}` and name no literal
        # `check_key`. A mutation removing that reason passed the guard while
        # failing two behavioural tests, which is the wrong way round.
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and key.value == "skipped_checks":
                    candidates.extend(entries_under(value))

    offenders = sorted(
        {
            d.lineno
            for d in candidates
            if "reason"
            not in {k.value for k in d.keys if isinstance(k, ast.Constant)}
        }
    )

    assert candidates, (
        "the guard found no skipped-check entries to inspect at all -- it is "
        "passing vacuously and proves nothing"
    )
    assert not offenders, (
        "posture/scan.py builds a skipped-check entry with no `reason` at "
        f"line(s) {offenders}: an operator reading the report would have to "
        "work out the missing check by subtraction"
    )
