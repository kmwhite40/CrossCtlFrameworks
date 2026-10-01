"""Three M365 checks against Graph endpoints the connector was not reading.

The msgraph connector read nine Graph endpoints for fourteen checks. These three
use fields confirmed present on the live tenant before any of this was written --
the shapes below are observed, not assumed:

    /beta/settings  "Password Rule Settings"  LockoutThreshold = 3
    /v1.0/security/alerts_v2                  status = "resolved", severity
    /v1.0/deviceManagement/deviceConfigurations
        windows10GeneralConfiguration.storageBlockRemovableStorage = False

Each closes a practice nothing else reached:

* ``AC.L2-3.1.8``   "Limit unsuccessful logon attempts."
* ``SI.L2-3.14.3``  "Monitor system security alerts and advisories and take
                     action in response."
* ``MP.L2-3.8.7``   "Control the use of removable media on system components."

The removable-storage one already fails on the live tenant, which is the point of
building it.

**Alerts are judged differently from configuration, deliberately.** An empty
configuration response means the call did not answer, so those checks report
``manual_review_required``. An empty *alert* list is a real state -- nothing has
fired -- so it passes. Treating event data like configuration would manufacture a
manual-review finding out of a quiet tenant.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ccf.posture.providers import m365

_TENANT = "contoso.onmicrosoft.us"


def _settings(values: dict[str, str], *, name: str = "Password Rule Settings") -> dict[str, Any]:
    return {
        "displayName": name,
        "values": [{"name": k, "value": v} for k, v in values.items()],
    }


# ── AC.L2-3.1.8 — lockout threshold ──────────────────────────────────────────


def test_a_threshold_within_the_limit_passes() -> None:
    findings = m365.evaluate_lockout_threshold(
        [_settings({"LockoutThreshold": "3", "LockoutDurationInSeconds": "900"})],
        tenant_id=_TENANT,
        max_attempts=10,
    )
    assert [f.verdict for f in findings] == ["pass"]
    assert "3" in findings[0].observed


def test_a_threshold_above_the_limit_fails() -> None:
    findings = m365.evaluate_lockout_threshold(
        [_settings({"LockoutThreshold": "50"})], tenant_id=_TENANT, max_attempts=10
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "50" in findings[0].observed


def test_a_threshold_of_zero_is_lockout_disabled_and_fails() -> None:
    """Zero means never lock out, which is the opposite of the requirement.

    Reading it as "0 <= 10, therefore compliant" is the arithmetic trap here.
    """
    findings = m365.evaluate_lockout_threshold(
        [_settings({"LockoutThreshold": "0"})], tenant_id=_TENANT, max_attempts=10
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "disabled" in findings[0].observed.lower()


def test_a_missing_password_settings_object_is_unassessable() -> None:
    """A tenant with no password-rule settings has not been shown compliant.

    Entra applies a default threshold, so the honest answer is that this build
    could not read the tenant's own value -- not that the default is acceptable.
    """
    findings = m365.evaluate_lockout_threshold(
        [_settings({"EnableAdminConsentRequests": "true"}, name="Consent Policy Settings")],
        tenant_id=_TENANT,
        max_attempts=10,
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]


def test_a_non_numeric_threshold_is_unassessable_not_a_failure() -> None:
    """Graph returns these as strings; a malformed one is unknown, not wrong."""
    findings = m365.evaluate_lockout_threshold(
        [_settings({"LockoutThreshold": ""})], tenant_id=_TENANT, max_attempts=10
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]


def test_the_limit_is_parameterised() -> None:
    """3.1.8 is organization-defined, so the bound is a parameter, not a constant."""
    rows = [_settings({"LockoutThreshold": "5"})]
    assert m365.evaluate_lockout_threshold(rows, tenant_id=_TENANT, max_attempts=10)[
        0
    ].verdict == "pass"
    assert m365.evaluate_lockout_threshold(rows, tenant_id=_TENANT, max_attempts=3)[
        0
    ].verdict == "fail"


# ── SI.L2-3.14.3 — security alerts acted on ──────────────────────────────────


def _alert(
    alert_id: str, *, status: str, severity: str = "high", age_days: int = 1
) -> dict[str, Any]:
    return {
        "id": alert_id,
        "status": status,
        "severity": severity,
        "title": f"alert {alert_id}",
        "createdDateTime": (datetime.now(UTC) - timedelta(days=age_days)).isoformat(),
    }


def test_a_resolved_alert_is_not_a_finding() -> None:
    findings = m365.evaluate_security_alerts_triaged(
        [_alert("a1", status="resolved", age_days=90)],
        tenant_id=_TENANT,
        threshold_days=30,
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_an_old_unresolved_high_alert_fails() -> None:
    findings = m365.evaluate_security_alerts_triaged(
        [_alert("a2", status="new", severity="high", age_days=60)],
        tenant_id=_TENANT,
        threshold_days=30,
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert findings[0].resource_id == "a2"


def test_a_recent_unresolved_alert_is_not_yet_a_finding() -> None:
    """The requirement is to act, and acting takes time.

    Failing an alert raised this morning would make the check unusable: every
    tenant would fail permanently, which is indistinguishable from no check.
    """
    findings = m365.evaluate_security_alerts_triaged(
        [_alert("a3", status="new", severity="high", age_days=2)],
        tenant_id=_TENANT,
        threshold_days=30,
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_a_low_severity_alert_left_open_is_not_a_finding() -> None:
    """Informational noise left open is not a control failure."""
    findings = m365.evaluate_security_alerts_triaged(
        [_alert("a4", status="new", severity="informational", age_days=200)],
        tenant_id=_TENANT,
        threshold_days=30,
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_each_stale_alert_is_its_own_finding() -> None:
    findings = m365.evaluate_security_alerts_triaged(
        [
            _alert("old1", status="new", severity="high", age_days=90),
            _alert("old2", status="inProgress", severity="critical", age_days=45),
            _alert("fresh", status="new", severity="high", age_days=1),
            _alert("done", status="resolved", severity="high", age_days=90),
        ],
        tenant_id=_TENANT,
        threshold_days=30,
    )
    failed = {f.resource_id for f in findings if f.verdict == "fail"}
    assert failed == {"old1", "old2"}


def test_no_alerts_at_all_passes() -> None:
    """Event data, not configuration: an empty list is a real, clean state."""
    findings = m365.evaluate_security_alerts_triaged(
        [], tenant_id=_TENANT, threshold_days=30
    )
    assert [f.verdict for f in findings] == ["pass"]
    assert findings[0].resource_id == _TENANT


# ── MP.L2-3.8.7 — removable storage ──────────────────────────────────────────


def _general(name: str, *, blocked: bool | None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": name,
        "displayName": name,
        "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
    }
    if blocked is not None:
        row["storageBlockRemovableStorage"] = blocked
    return row


def test_a_policy_blocking_removable_storage_passes() -> None:
    findings = m365.evaluate_removable_storage_blocked(
        [_general("corp", blocked=True)], tenant_id=_TENANT
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_a_policy_allowing_removable_storage_fails() -> None:
    """The live tenant's state when this was written: False."""
    findings = m365.evaluate_removable_storage_blocked(
        [_general("corp", blocked=False)], tenant_id=_TENANT
    )
    assert [f.verdict for f in findings] == ["fail"]


def test_any_policy_blocking_is_enough() -> None:
    """Asked of the tenant, not of each profile.

    A configuration profile scoped to kiosks does not set this, and failing it for
    that would manufacture findings against correctly-scoped policies -- the same
    reasoning the session-lock check already applies.
    """
    findings = m365.evaluate_removable_storage_blocked(
        [_general("kiosk", blocked=None), _general("corp", blocked=True)],
        tenant_id=_TENANT,
    )
    assert [f.verdict for f in findings] == ["pass"]
    assert "corp" in findings[0].observed


def test_profiles_that_do_not_set_it_at_all_are_unassessable() -> None:
    """None of them expressed an opinion, so the tenant's posture is unknown."""
    findings = m365.evaluate_removable_storage_blocked(
        [_general("a", blocked=None), _general("b", blocked=None)], tenant_id=_TENANT
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]


def test_no_configuration_profiles_is_unassessable() -> None:
    findings = m365.evaluate_removable_storage_blocked([], tenant_id=_TENANT)
    assert [f.verdict for f in findings] == ["manual_review_required"]


# ── registration ─────────────────────────────────────────────────────────────


def test_all_three_are_registered_with_permissions_and_controls() -> None:
    for check in (
        m365.LOCKOUT_THRESHOLD,
        m365.SECURITY_ALERTS_TRIAGED,
        m365.REMOVABLE_STORAGE_BLOCKED,
    ):
        assert check.provider == "msgraph"
        assert check.required_permissions, f"{check.key} names no Graph permission"
        assert check.control_ids, f"{check.key} declares no control"
        assert check.expected
