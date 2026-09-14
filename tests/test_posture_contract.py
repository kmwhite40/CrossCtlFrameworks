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


def test_registry_is_keyed_by_provider_and_unique() -> None:
    seen: set[str] = set()
    for provider, checks in CHECK_REGISTRY.items():
        for c in checks:
            assert c.provider == provider, f"{c.key} filed under {provider}"
            assert c.key not in seen, f"duplicate check key {c.key}"
            seen.add(c.key)
            assert c.control_ids, f"{c.key} evidences no control"


def test_checks_for_unknown_provider_is_empty() -> None:
    assert checks_for("no-such-provider") == ()


def test_registry_providers_are_real_connector_keys() -> None:
    """A check filed under a provider no connector serves would never run."""
    assert set(CHECK_REGISTRY) <= set(connector_keys())
