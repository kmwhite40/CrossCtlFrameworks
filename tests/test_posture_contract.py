"""The scan() contract, and that adding it left capture() alone."""

from __future__ import annotations

import pytest

from ccf.connectors import connector_keys, get_connector, list_connectors
from ccf.connectors.base import ConfigConnector
from ccf.posture.checks import (
    CHECK_REGISTRY,
    CheckOutcome,
    PostureCheck,
    ResourceFinding,
    checks_for,
)


def _check() -> PostureCheck:
    return PostureCheck(
        key="test.demo.check",
        title="Demo",
        provider="demo",
        resource_type="bucket",
        expected="public access blocked",
        control_ids=("AC-3",),
    )


def test_outcome_counts_from_findings() -> None:
    findings = (
        ResourceFinding("a", "bucket", "pass", "blocked"),
        ResourceFinding("b", "bucket", "fail", "open"),
        ResourceFinding("c", "bucket", "not_applicable", "n/a"),
    )
    out = CheckOutcome.from_findings(_check(), findings)
    assert out.check_key == "test.demo.check"
    assert out.evaluated == 3
    assert out.failing == 1
    assert out.verdict == "fail"  # one failure fails the check
    assert out.expected == "public access blocked"


def test_outcome_with_no_findings_is_not_applicable() -> None:
    out = CheckOutcome.from_findings(_check(), ())
    assert out.verdict == "not_applicable"
    assert out.evaluated == 0
    assert out.failing == 0


def test_outcome_rejects_an_unknown_verdict() -> None:
    with pytest.raises(ValueError, match="unknown verdict"):
        CheckOutcome.from_findings(
            _check(), (ResourceFinding("a", "bucket", "nonsense", "x"),)
        )


async def test_base_scan_returns_empty() -> None:
    """Adding scan() must not disturb connectors that do not implement it."""

    class Bare(ConfigConnector):
        key = "bare"
        label = "Bare"

        def is_configured(self) -> bool:
            return False

        async def capture(self) -> list:
            return []

    assert await Bare().scan() == []


async def test_existing_connectors_still_scan_empty() -> None:
    for conn in list_connectors():
        assert await conn.scan() == [], conn.key


async def test_existing_connectors_still_capture_nothing_unconfigured() -> None:
    """capture() behaviour is unchanged."""
    for key in ("msgraph", "aws_govcloud"):
        conn = get_connector(key)
        assert conn is not None
        assert conn.is_configured() is False
        assert await conn.capture() == []


def _validate_registry(registry: dict[str, tuple[PostureCheck, ...]]) -> None:
    """The invariant CHECK_REGISTRY must hold: every check is filed under its
    own provider, no check key repeats, and every check evidences at least
    one control."""
    seen: set[str] = set()
    for provider, checks in registry.items():
        for c in checks:
            assert c.provider == provider, f"{c.key} filed under {provider}"
            assert c.key not in seen, f"duplicate check key {c.key}"
            seen.add(c.key)
            assert c.control_ids, f"{c.key} evidences no control"


def _demo_check(key: str, provider: str, control_ids: tuple[str, ...] = ("AC-3",)) -> PostureCheck:
    return PostureCheck(
        key=key,
        title=key,
        provider=provider,
        resource_type="bucket",
        expected="x",
        control_ids=control_ids,
    )


def test_registry_is_keyed_by_provider_and_unique() -> None:
    """CHECK_REGISTRY ships empty until P3 adds real checks (see checks.py's
    docstring), so a loop over it -- as this test originally was -- never
    executes its body: every assertion inside is unreachable, and the test
    passes no matter what the invariant-checking code says. Exercised here
    against synthetic data shaped like a populated registry instead, so the
    invariant itself is actually tested; each individual assertion is proven
    capable of failing, not merely of holding by default.
    """
    _validate_registry(CHECK_REGISTRY)  # holds trivially today: nothing to iterate.

    good = {
        "demo_a": (
            _demo_check("demo.a.one", "demo_a"),
            _demo_check("demo.a.two", "demo_a", ("AC-4",)),
        ),
        "demo_b": (_demo_check("demo.b.one", "demo_b", ("AC-5",)),),
    }
    _validate_registry(good)  # the loop body actually runs this time.

    mismatched_provider = {"demo_a": (_demo_check("demo.a.one", "demo_b"),)}
    with pytest.raises(AssertionError, match="filed under"):
        _validate_registry(mismatched_provider)

    duplicate_key = {
        "demo_a": (
            _demo_check("demo.a.one", "demo_a"),
            _demo_check("demo.a.one", "demo_a", ("AC-4",)),
        )
    }
    with pytest.raises(AssertionError, match="duplicate check key"):
        _validate_registry(duplicate_key)

    no_controls = {"demo_a": (_demo_check("demo.a.one", "demo_a", ()),)}
    with pytest.raises(AssertionError, match="evidences no control"):
        _validate_registry(no_controls)


def test_checks_for_unknown_provider_is_empty() -> None:
    assert checks_for("no-such-provider") == ()


def test_registry_providers_are_real_connector_keys() -> None:
    """A check filed under a provider no connector serves would never run."""
    assert set(CHECK_REGISTRY) <= set(connector_keys())
