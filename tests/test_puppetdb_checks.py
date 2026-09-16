"""PuppetDB posture checks: is the fleet managed, and is state being enforced?"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccf.posture.checks import checks_for, endpoint_for, platform_check_keys
from ccf.posture.providers import puppetdb
from ccf.posture.rollup import roll_up_findings

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)


def _node(certname: str, *, hours_ago: float | None = 1.0, status: str = "unchanged",
          timestamp: str | None = "sentinel") -> dict:
    node: dict = {"certname": certname, "latest_report_status": status}
    if timestamp == "sentinel":
        node["report_timestamp"] = (
            None
            if hours_ago is None
            else (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")
        )
    else:
        node["report_timestamp"] = timestamp
    return node


def _verdicts(findings) -> dict[str, str]:
    return {f.resource_id: f.verdict for f in findings}


# ── reporting freshness ──────────────────────────────────────────────────────


def test_a_node_reporting_recently_passes() -> None:
    findings = puppetdb.evaluate_node_reporting([_node("web01")], now=NOW)
    assert _verdicts(findings) == {"web01": "pass"}


def test_a_node_past_the_threshold_fails() -> None:
    """Silence is not compliance: an unmanaged node is a finding whatever its
    last known state said."""
    findings = puppetdb.evaluate_node_reporting(
        [_node("stale01", hours_ago=100)], now=NOW
    )
    assert _verdicts(findings) == {"stale01": "fail"}


def test_exactly_at_the_threshold_still_passes() -> None:
    findings = puppetdb.evaluate_node_reporting(
        [_node("edge01", hours_ago=puppetdb.STALE_AFTER_HOURS)], now=NOW
    )
    assert _verdicts(findings) == {"edge01": "pass"}


def test_a_node_that_never_reported_is_manual_review_not_pass() -> None:
    """Never having reported is not evidence of health."""
    findings = puppetdb.evaluate_node_reporting([_node("new01", hours_ago=None)], now=NOW)
    assert _verdicts(findings) == {"new01": "manual_review_required"}
    assert "never reported" in findings[0].observed


def test_an_unparseable_timestamp_is_manual_review_not_pass() -> None:
    findings = puppetdb.evaluate_node_reporting(
        [_node("odd01", timestamp="last tuesday")], now=NOW
    )
    assert _verdicts(findings) == {"odd01": "manual_review_required"}


def test_an_offset_less_timestamp_is_manual_review_not_a_crash() -> None:
    """IMPORTANT 4: `datetime.fromisoformat` accepts an offset-less string and
    returns a naive datetime rather than raising. Subtracting that from the
    timezone-aware `now` below used to raise TypeError and take down the
    whole fleet's verdict for this one node -- confirmed by evaluating a
    mixed batch: a good node's finding must still come back."""
    findings = puppetdb.evaluate_node_reporting(
        [_node("naive01", timestamp="2026-09-15T11:30:00"), _node("web01")], now=NOW
    )
    assert _verdicts(findings) == {"naive01": "manual_review_required", "web01": "pass"}


def test_a_custom_threshold_is_honoured() -> None:
    findings = puppetdb.evaluate_node_reporting(
        [_node("web01", hours_ago=5)], now=NOW, threshold_hours=2
    )
    assert _verdicts(findings) == {"web01": "fail"}


# ── is desired state actually being enforced ─────────────────────────────────


def test_a_failed_run_fails_the_check() -> None:
    """The finding worth having: a node whose last Puppet run failed is one
    where declared configuration is NOT being applied."""
    findings = puppetdb.evaluate_last_run_ok([_node("broken01", status="failed")])
    assert _verdicts(findings) == {"broken01": "fail"}
    assert "failed" in findings[0].observed


def test_an_unchanged_run_passes() -> None:
    findings = puppetdb.evaluate_last_run_ok([_node("web01", status="unchanged")])
    assert _verdicts(findings) == {"web01": "pass"}


def test_a_changed_run_passes() -> None:
    """Puppet converging a drifted node is Puppet working, not a finding."""
    findings = puppetdb.evaluate_last_run_ok([_node("web02", status="changed")])
    assert _verdicts(findings) == {"web02": "pass"}


def test_an_unknown_run_status_is_manual_review() -> None:
    findings = puppetdb.evaluate_last_run_ok([_node("web03", status="perplexed")])
    assert _verdicts(findings) == {"web03": "manual_review_required"}


def test_a_missing_run_status_is_manual_review_not_pass() -> None:
    findings = puppetdb.evaluate_last_run_ok([{"certname": "quiet01"}])
    assert _verdicts(findings) == {"quiet01": "manual_review_required"}


# ── shape ────────────────────────────────────────────────────────────────────


def test_no_nodes_yields_no_findings() -> None:
    """roll_up_findings maps zero findings to not_applicable, which is right:
    an empty PuppetDB is not a healthy fleet."""
    assert puppetdb.evaluate_node_reporting([], now=NOW) == []
    assert puppetdb.evaluate_last_run_ok([]) == []
    assert roll_up_findings([]) == "not_applicable"


def test_a_node_with_no_certname_is_still_reported() -> None:
    """Never silently drop a node -- an unidentified one is still unmanaged."""
    findings = puppetdb.evaluate_node_reporting([{"report_timestamp": None}], now=NOW)
    assert len(findings) == 1
    assert findings[0].resource_id == "unknown"


def test_both_checks_carry_the_controls_they_evidence() -> None:
    for check in puppetdb.CHECKS:
        assert check.control_ids, check.key
        assert check.provider == "puppetdb"
        assert check.required_permissions


def test_the_provider_is_registered_with_endpoints() -> None:
    keys = {c.key for c in checks_for("puppetdb")}
    assert keys == {c.key for c in puppetdb.CHECKS}
    for check in puppetdb.CHECKS:
        assert endpoint_for("puppetdb", check.key), check.key
        assert check.key in platform_check_keys()
