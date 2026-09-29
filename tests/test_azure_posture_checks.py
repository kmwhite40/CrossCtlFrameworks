"""Azure ARM posture checks, against the payload shapes the connector parses.

`azure_arm` reached five real ARM collections and mapped each to an 800-53
control, but registered no posture checks and had no `scan`. So a system whose
only connector was Azure resolved zero checks and reported
`checks_expected: 0` — which reads as clean far more readily than "nothing was
assessed". These turn captures that already existed into verdicts.

Field names here are taken from the connector's own `_map_*` mappers, not from
the ARM documentation, so the capture half and the check half cannot disagree
about what a payload looks like.
"""

from __future__ import annotations

import pytest

from ccf.posture.checks import checks_for, endpoint_for
from ccf.posture.providers import azure

SUB = "00000000-1111-2222-3333-444444444444"


def _storage(name: str, **props: object) -> dict[str, object]:
    return {"name": name, "properties": props}


def _encrypted(blob: bool = True, file: bool = True) -> dict[str, object]:
    return {"services": {"blob": {"enabled": blob}, "file": {"enabled": file}}}


# --- SC-28 encryption at rest -------------------------------------------------


def test_an_account_encrypting_blob_and_file_passes() -> None:
    rows = [_storage("acct1", encryption=_encrypted())]
    f = azure.evaluate_storage_encryption_at_rest(rows)
    assert [x.verdict for x in f] == ["pass"]
    assert f[0].resource_id == "acct1"


@pytest.mark.parametrize(
    ("blob", "file", "named"),
    [(True, False, "file"), (False, True, "blob"), (False, False, "blob and file")],
)
def test_encrypting_only_one_service_is_a_failure(blob, file, named) -> None:
    """The connector's own rule: blob *and* file, never either.

    An account that encrypts blobs and not files does not protect CUI at rest,
    and passing it would overstate the fleet.
    """
    f = azure.evaluate_storage_encryption_at_rest(
        [_storage("acct1", encryption=_encrypted(blob=blob, file=file))]
    )
    assert f[0].verdict == "fail"
    assert named in f[0].observed


def test_an_account_with_no_encryption_block_fails_rather_than_raising() -> None:
    """ARM omits properties on malformed or partially-projected rows."""
    for row in ({"name": "a"}, {"name": "b", "properties": {}},
                {"name": "c", "properties": {"encryption": None}}):
        f = azure.evaluate_storage_encryption_at_rest([row])
        assert f[0].verdict == "fail", row


def test_one_finding_per_account() -> None:
    rows = [
        _storage("good", encryption=_encrypted()),
        _storage("bad", encryption=_encrypted(file=False)),
    ]
    f = azure.evaluate_storage_encryption_at_rest(rows)
    assert {x.resource_id: x.verdict for x in f} == {"good": "pass", "bad": "fail"}


# --- SC-8 transmission --------------------------------------------------------


def test_https_only_at_a_current_tls_passes() -> None:
    f = azure.evaluate_storage_https_only(
        [_storage("a", supportsHttpsTrafficOnly=True, minimumTlsVersion="TLS1_2")]
    )
    assert f[0].verdict == "pass"


@pytest.mark.parametrize("tls", ["TLS1_0", "TLS1_1", None, "", "tls1_2", "nonsense"])
def test_a_tls_floor_below_the_minimum_or_unrecognised_fails(tls) -> None:
    """An unrecognised spelling is not assumed to be newer.

    Compared by rank rather than lexically: `"TLS1_10"` sorts below `"TLS1_2"`
    as a string, which would silently pass a version this cannot interpret.
    """
    f = azure.evaluate_storage_https_only(
        [_storage("a", supportsHttpsTrafficOnly=True, minimumTlsVersion=tls)]
    )
    assert f[0].verdict == "fail"


def test_tls_1_3_is_above_the_floor_not_below_it() -> None:
    f = azure.evaluate_storage_https_only(
        [_storage("a", supportsHttpsTrafficOnly=True, minimumTlsVersion="TLS1_3")]
    )
    assert f[0].verdict == "pass"


def test_permitting_http_fails_even_at_a_good_tls_floor() -> None:
    f = azure.evaluate_storage_https_only(
        [_storage("a", supportsHttpsTrafficOnly=False, minimumTlsVersion="TLS1_2")]
    )
    assert f[0].verdict == "fail"
    assert "HTTP traffic permitted" in f[0].observed


def test_both_problems_are_reported_not_just_the_first() -> None:
    f = azure.evaluate_storage_https_only(
        [_storage("a", supportsHttpsTrafficOnly=False, minimumTlsVersion="TLS1_0")]
    )
    assert "HTTP traffic permitted" in f[0].observed
    assert "below" in f[0].observed


# --- AU-11 log retention ------------------------------------------------------


def test_a_workspace_retaining_long_enough_passes() -> None:
    f = azure.evaluate_log_retention([_storage("ws", retentionInDays=365)])
    assert f[0].verdict == "pass"
    assert "365 day(s)" in f[0].observed


def test_a_short_retention_fails_and_names_both_numbers() -> None:
    f = azure.evaluate_log_retention([_storage("ws", retentionInDays=30)])
    assert f[0].verdict == "fail"
    assert f[0].detail["expected_min_days"] == azure.LOG_RETENTION_MIN_DAYS


def test_the_boundary_is_inclusive() -> None:
    at = azure.evaluate_log_retention(
        [_storage("ws", retentionInDays=azure.LOG_RETENTION_MIN_DAYS)]
    )
    under = azure.evaluate_log_retention(
        [_storage("ws", retentionInDays=azure.LOG_RETENTION_MIN_DAYS - 1)]
    )
    assert at[0].verdict == "pass"
    assert under[0].verdict == "fail"


@pytest.mark.parametrize("value", [None, 0, -30, "365", True])
def test_an_absent_retention_is_not_a_failure(value) -> None:
    """ARM omits the field on some workspace SKUs.

    Absence is not evidence of a short retention, so it is
    `manual_review_required` — a failure here would manufacture a finding out of
    a gap in what ARM reports. `True` is excluded on purpose: it is an `int` in
    Python, and `retentionInDays: true` is not one day.
    """
    f = azure.evaluate_log_retention([_storage("ws", retentionInDays=value)])
    assert f[0].verdict == "manual_review_required"


def test_a_pack_can_set_its_own_retention_floor() -> None:
    rows = [_storage("ws", retentionInDays=100)]
    assert azure.evaluate_log_retention(rows)[0].verdict == "pass"
    assert azure.evaluate_log_retention(rows, min_days=365)[0].verdict == "fail"


# --- CM-2 policy baseline -----------------------------------------------------


def test_an_enforcing_assignment_passes_and_is_named() -> None:
    f = azure.evaluate_policy_baseline_enforced(
        [{"name": "p1", "properties": {"displayName": "FedRAMP Moderate"}}],
        subscription_id=SUB,
    )
    assert f[0].verdict == "pass"
    assert f[0].resource_id == SUB
    assert "FedRAMP Moderate" in f[0].observed


def test_audit_only_assignments_do_not_count_as_a_baseline() -> None:
    """`DoNotEnforce` observes drift; it does not maintain a baseline.

    The connector's own reasoning, applied to the verdict rather than the
    capture — counting it would overstate CM-2.
    """
    f = azure.evaluate_policy_baseline_enforced(
        [{"name": "p1", "properties": {"enforcementMode": "DoNotEnforce"}}],
        subscription_id=SUB,
    )
    assert f[0].verdict == "fail"
    assert "audit-only" in f[0].observed
    assert f[0].detail["audit_only"] == 1


def test_no_assignment_at_all_reads_differently_from_audit_only() -> None:
    f = azure.evaluate_policy_baseline_enforced([], subscription_id=SUB)
    assert f[0].verdict == "fail"
    assert "no Azure Policy assignment" in f[0].observed


def test_one_finding_for_the_subscription_not_one_per_policy() -> None:
    rows = [{"name": f"p{i}"} for i in range(4)]
    f = azure.evaluate_policy_baseline_enforced(rows, subscription_id=SUB)
    assert len(f) == 1
    assert f[0].detail["enforcing"] == 4


# --- SI-3 Defender ------------------------------------------------------------


def test_a_standard_plan_passes() -> None:
    f = azure.evaluate_defender_workload_protection(
        [{"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}],
        subscription_id=SUB,
    )
    assert f[0].verdict == "pass"
    assert "VirtualMachines" in f[0].observed


def test_only_free_plans_fails_and_says_how_many_were_examined() -> None:
    """`Free` is the tier that runs no workload protection."""
    rows = [{"name": n, "properties": {"pricingTier": "Free"}} for n in ("VMs", "SQL")]
    f = azure.evaluate_defender_workload_protection(rows, subscription_id=SUB)
    assert f[0].verdict == "fail"
    assert "2 plan(s) examined" in f[0].observed


# --- the registry -------------------------------------------------------------


def test_the_provider_is_registered_with_every_check_wired() -> None:
    """A check with no endpoint cannot be scanned; one with no evaluator raises.

    `azure_arm` shipped as a registered connector with zero checks, so a scan
    against it reported `checks_expected: 0` and looked like a clean result.
    """
    registered = checks_for("azure_arm")
    assert len(registered) == len(azure.CHECKS) == 5
    for check in registered:
        assert endpoint_for("azure_arm", check.key), check.key
        assert check.key in azure.EVALUATORS, check.key
        assert check.control_ids, check.key
        assert check.required_permissions, (
            f"{check.key} names no permission, so a 403 cannot be explained"
        )


def test_every_endpoint_pins_an_api_version() -> None:
    """An unpinned ARM call is a 400, and a floating one is a silent shape change."""
    for key, endpoint in azure.ENDPOINTS.items():
        path, sep, version = endpoint.partition("@")
        assert sep and path and version, f"{key} does not pin an api-version: {endpoint!r}"
        assert version[:4].isdigit(), f"{key} api-version looks wrong: {version!r}"
