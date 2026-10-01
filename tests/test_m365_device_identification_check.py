"""IA-3: are devices identified and authenticated before they get access?

``IA-3`` is in a FedRAMP Moderate baseline and no provider reached it. Entra's
mechanism is a Conditional Access policy whose grant controls require a
**compliant** or **hybrid Entra joined** device: access is conditional on the
device being known to the tenant and meeting its policy, which is device
identification and authentication enforced at the point of access.

The subtlety that makes this worth a check rather than a glance is the one the
live tenant happens to demonstrate. It has four policies naming
``compliantDevice`` or ``domainJoinedDevice``, and only two of them do anything:

* one is ``disabled`` — enforces nothing;
* one is ``enabledForReportingButNotEnforced`` — report-only, so it logs what it
  *would* have blocked and blocks nobody;
* two are ``enabled``.

A check that counted policies rather than *enforced* policies would pass on a
tenant whose only device policy is in report-only mode, and would put "devices
are identified before access" into an SSP on the strength of a policy deliberately
not in force. ``_blocks_legacy_auth`` and ``_sets_signin_frequency`` already apply
exactly this rule and say why; this follows them rather than inventing a third
reading of ``state``.
"""

from __future__ import annotations

import pytest

from ccf.posture.checks import checks_for
from ccf.posture.providers import m365

TENANT = "tenant-1"


def _policy(
    *,
    state: str = "enabled",
    controls: list[str] | None = None,
    name: str = "Require compliant device",
    operator: str = "OR",
) -> dict:
    return {
        "id": name.lower().replace(" ", "-"),
        "displayName": name,
        "state": state,
        "conditions": {"clientAppTypes": ["all"]},
        "grantControls": {
            "operator": operator,
            "builtInControls": controls if controls is not None else ["compliantDevice"],
        },
    }


def _verdicts(findings: list) -> list[str]:
    return [f.verdict for f in findings]


def test_an_enabled_compliant_device_policy_passes() -> None:
    findings = m365.evaluate_device_compliance_required([_policy()], tenant_id=TENANT)
    assert _verdicts(findings) == ["pass"]
    assert "Require compliant device" in findings[0].observed


def test_a_hybrid_joined_requirement_also_satisfies_ia_3() -> None:
    """``domainJoinedDevice`` is Entra's name for hybrid-joined.

    A device joined to the directory is identified by that join, which is the
    same assurance by a different route -- so accepting only ``compliantDevice``
    would fail a tenant that is doing the right thing.
    """
    findings = m365.evaluate_device_compliance_required(
        [_policy(controls=["domainJoinedDevice"])], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["pass"]


@pytest.mark.parametrize("state", ["disabled", "enabledForReportingButNotEnforced"])
def test_a_policy_that_is_not_enforced_does_not_satisfy_ia_3(state: str) -> None:
    """The defect this check is shaped around.

    ``disabled`` enforces nothing and report-only blocks nobody. Either one
    satisfying the check would assert that devices are identified before access
    on the strength of a policy deliberately not in force -- in a document an
    assessor reads.
    """
    findings = m365.evaluate_device_compliance_required(
        [_policy(state=state)], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["fail"]
    assert state in findings[0].observed or "not enforced" in findings[0].observed


def test_an_enforced_policy_among_unenforced_ones_passes() -> None:
    """The live tenant's actual shape: four device policies, two enforced."""
    findings = m365.evaluate_device_compliance_required(
        [
            _policy(state="disabled", name="AI platform connections"),
            _policy(state="enabledForReportingButNotEnforced", name="Restrict unmanaged"),
            _policy(state="enabled", name="Require Compliant Device"),
        ],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["pass"]
    assert "Require Compliant Device" in findings[0].observed


def test_a_tenant_with_no_device_policy_at_all_fails() -> None:
    """Policies exist but none requires a device. A real answer, not an
    unreadable one: Graph listed the policies and none grants on device state."""
    findings = m365.evaluate_device_compliance_required(
        [_policy(controls=["mfa"]), _policy(controls=["block"])], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["fail"]
    assert "no enabled" in findings[0].observed.lower()


def test_no_policies_at_all_fails() -> None:
    findings = m365.evaluate_device_compliance_required([], tenant_id=TENANT)
    assert _verdicts(findings) == ["fail"]
    assert "no conditional access" in findings[0].observed.lower()


def test_a_policy_with_no_grant_controls_is_not_a_device_policy() -> None:
    """A session-control-only policy has ``grantControls: null``. Reading that as
    a device requirement would pass on a policy that grants nothing at all."""
    findings = m365.evaluate_device_compliance_required(
        [{"id": "p", "displayName": "Session only", "state": "enabled",
          "grantControls": None, "sessionControls": {"signInFrequency": {"isEnabled": True}}}],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["fail"]


def test_a_malformed_policy_does_not_crash_the_check() -> None:
    """One bad row must not cost the verdict for the whole tenant."""
    findings = m365.evaluate_device_compliance_required(
        ["not a policy", {"state": 7}, None, _policy()],  # type: ignore[list-item]
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["pass"]


def test_the_detail_names_how_many_policies_were_considered() -> None:
    """So a failing tenant can tell "no policy requires a device" from "Concord
    saw no policies", which are different things to go and fix."""
    findings = m365.evaluate_device_compliance_required(
        [_policy(controls=["mfa"])], tenant_id=TENANT
    )
    assert findings[0].detail["policies"] == 1


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_the_check_is_registered_and_wired() -> None:
    key = "m365.policy.device_compliance_required"
    assert key in {c.key for c in checks_for("msgraph")}
    assert m365.ENDPOINTS[key] == "/v1.0/identity/conditionalAccess/policies"
    assert key in m365.EVALUATORS


def test_the_check_declares_ia_3_alone() -> None:
    """IA-3 only, deliberately.

    A compliant-device requirement is tempting to also attribute to ``AC-19``
    (Access Control for Mobile Devices), which is equally uncovered. It is not
    claimed here: this policy applies to every device, not specifically to mobile
    ones, and a non-passing verdict reaches *every* declared control -- so
    listing AC-19 would file a finding against a requirement this check never
    observed.
    """
    by_key = {c.key: c for c in checks_for("msgraph")}
    assert by_key["m365.policy.device_compliance_required"].control_ids == ("IA-3",)


def test_the_check_names_the_permission_it_needs() -> None:
    by_key = {c.key: c for c in checks_for("msgraph")}
    assert by_key["m365.policy.device_compliance_required"].required_permissions


def test_the_policy_count_is_the_whole_list_not_where_the_loop_stopped() -> None:
    """Found on the live tenant: ``policies: 13`` for a tenant with 23.

    The count was incremented inside the loop, so the early return on the first
    enforced policy left it at "how many were examined before a match" rather
    than how many exist. A reader comparing it with the Entra portal sees a number
    that is simply wrong, and its wrongness depends on where the matching policy
    happens to sit in the list.
    """
    rows = [
        _policy(controls=["mfa"], name="one"),
        _policy(controls=["block"], name="two"),
        _policy(name="three enforced"),  # the match, at index 2
        _policy(controls=["mfa"], name="four"),
        _policy(controls=["mfa"], name="five"),
    ]
    findings = m365.evaluate_device_compliance_required(rows, tenant_id=TENANT)
    assert _verdicts(findings) == ["pass"]
    assert findings[0].detail["policies"] == 5, (
        "the count stopped where the loop did instead of describing the tenant"
    )


def test_malformed_rows_are_excluded_from_the_count() -> None:
    """A count of policies must not include things that are not policies."""
    findings = m365.evaluate_device_compliance_required(
        ["nope", None, _policy()],  # type: ignore[list-item]
        tenant_id=TENANT,
    )
    assert findings[0].detail["policies"] == 1
