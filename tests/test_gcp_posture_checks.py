"""Google Cloud posture checks, against the payload shapes the connector parses.

Like `azure_arm` before it, the GCP connector read three real collections,
mapped each to an 800-53 control, and registered no checks: a system whose only
connector was Google Cloud resolved nothing and reported `checks_expected: 0`,
which reads as clean rather than unassessed.

Worth being honest about the size of this: only `SC-12` is a control no other
provider already reaches, so headline coverage moves by one. The gain is that a
GCP-only tenant goes from nothing scanned to three checks with verdicts — a
distinction a coverage count hides, which is why it is asserted below.
"""

from __future__ import annotations

import pytest

from ccf.connectors import connector_keys
from ccf.posture.checks import checks_for, endpoint_for
from ccf.posture.providers import gcp

PROJECT = "concord-demo-1234"


# --- SC-28 / SC-12 customer-managed keys --------------------------------------


def test_a_bucket_with_a_customer_managed_key_passes() -> None:
    rows = [{"name": "cui-bucket", "encryption": {"defaultKmsKeyName": "projects/p/k/ring/key1"}}]
    f = gcp.evaluate_bucket_customer_managed_keys(rows)
    assert [x.verdict for x in f] == ["pass"]
    assert "key1" in f[0].observed


def test_google_managed_keys_fail_rather_than_pass_as_encrypted() -> None:
    """Google encrypts every bucket unconditionally.

    A check answering "is it encrypted" would pass every project on earth and
    tell an assessor nothing. The question is whose key — the connector's own
    distinction, applied to the verdict.
    """
    for row in ({"name": "b"}, {"name": "b", "encryption": {}},
                {"name": "b", "encryption": {"defaultKmsKeyName": ""}},
                {"name": "b", "encryption": None}):
        f = gcp.evaluate_bucket_customer_managed_keys([row])
        assert f[0].verdict == "fail", row
        assert "Google-managed" in f[0].observed


def test_one_finding_per_bucket() -> None:
    rows = [
        {"name": "good", "encryption": {"defaultKmsKeyName": "projects/p/k/r/key"}},
        {"name": "bad"},
    ]
    f = gcp.evaluate_bucket_customer_managed_keys(rows)
    assert {x.resource_id: x.verdict for x in f} == {"good": "pass", "bad": "fail"}


# --- AU-11 retention ----------------------------------------------------------


def test_a_bucket_retaining_long_enough_passes() -> None:
    f = gcp.evaluate_log_retention([{"name": "projects/p/buckets/_Default", "retentionDays": 400}])
    assert f[0].verdict == "pass"
    assert f[0].resource_id == "_Default", "the fully-qualified name is not reduced"


def test_a_short_retention_fails_and_names_both_numbers() -> None:
    f = gcp.evaluate_log_retention([{"name": "b", "retentionDays": 30}])
    assert f[0].verdict == "fail"
    assert f[0].detail["expected_min_days"] == gcp.LOG_RETENTION_MIN_DAYS


def test_the_boundary_is_inclusive() -> None:
    at = gcp.evaluate_log_retention([{"name": "b", "retentionDays": gcp.LOG_RETENTION_MIN_DAYS}])
    under = gcp.evaluate_log_retention(
        [{"name": "b", "retentionDays": gcp.LOG_RETENTION_MIN_DAYS - 1}]
    )
    assert at[0].verdict == "pass"
    assert under[0].verdict == "fail"


@pytest.mark.parametrize("value", [None, 0, -1, "400", True])
def test_an_absent_retention_is_not_a_failure(value) -> None:
    """Absence is not evidence of a short retention.

    `True` is excluded on purpose: it is an `int` in Python, and
    `retentionDays: true` is not one day.
    """
    f = gcp.evaluate_log_retention([{"name": "b", "retentionDays": value}])
    assert f[0].verdict == "manual_review_required"


def test_a_float_retention_is_read_rather_than_refused() -> None:
    """The connector accepts `int | float` here; the check must agree."""
    f = gcp.evaluate_log_retention([{"name": "b", "retentionDays": 365.0}])
    assert f[0].verdict == "pass"
    assert f[0].detail["retention_days"] == 365


def test_a_pack_can_set_its_own_retention_floor() -> None:
    rows = [{"name": "b", "retentionDays": 100}]
    assert gcp.evaluate_log_retention(rows)[0].verdict == "pass"
    assert gcp.evaluate_log_retention(rows, min_days=365)[0].verdict == "fail"


# --- CM-2 organization policy -------------------------------------------------


def test_a_constraint_in_effect_passes_and_is_named() -> None:
    f = gcp.evaluate_org_policy_enforced(
        [{"name": "projects/p/policies/compute.requireOsLogin"}], project_id=PROJECT
    )
    assert f[0].verdict == "pass"
    assert f[0].resource_id == PROJECT
    assert "compute.requireOsLogin" in f[0].observed


def test_no_constraint_at_all_fails() -> None:
    f = gcp.evaluate_org_policy_enforced([], project_id=PROJECT)
    assert f[0].verdict == "fail"
    assert "no Organization Policy constraint" in f[0].observed


def test_one_finding_for_the_project_not_one_per_constraint() -> None:
    rows = [{"name": f"projects/p/policies/c{i}"} for i in range(5)]
    f = gcp.evaluate_org_policy_enforced(rows, project_id=PROJECT)
    assert len(f) == 1
    assert f[0].detail["total"] == 5


# --- the registry -------------------------------------------------------------


def test_the_provider_is_registered_with_every_check_wired() -> None:
    """`gcp` shipped as a registered connector with zero checks.

    A scan against it reported `checks_expected: 0`, which reads as a clean
    result rather than an unassessed one.
    """
    registered = checks_for("gcp")
    assert len(registered) == len(gcp.CHECKS) == 3
    for check in registered:
        assert endpoint_for("gcp", check.key), check.key
        assert check.key in gcp.EVALUATORS, check.key
        assert check.control_ids, check.key
        assert check.required_permissions, (
            f"{check.key} names no permission, so a 403 cannot be explained"
        )


def test_every_endpoint_carries_a_url_and_an_envelope_key() -> None:
    """Google's three APIs return three differently-named arrays.

    The envelope travels with the URL so it cannot drift from a second table.
    """
    for key, endpoint in gcp.ENDPOINTS.items():
        url, sep, envelope = endpoint.partition("#")
        assert sep and url and envelope, f"{key} carries no envelope key: {endpoint!r}"
        assert url.startswith("https://"), f"{key} is not an https URL: {url!r}"


def test_no_registered_connector_is_left_without_checks() -> None:
    """The gap this closes, asserted as a rule rather than a one-off.

    A connector an operator can bind a credential to, that then scans nothing,
    reports `checks_expected: 0` — indistinguishable on the page from a clean
    result.
    """
    without = [k for k in connector_keys() if not checks_for(k)]
    assert not without, (
        f"these connectors register no posture checks, so a system whose only "
        f"connector is one of them scans nothing: {without}"
    )
