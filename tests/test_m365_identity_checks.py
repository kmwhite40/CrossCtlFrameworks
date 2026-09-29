"""The four identity/authorization checks, against the shapes Graph returns.

Every fixture here is the real shape, trimmed: `authenticationMethodsPolicy`
and `authorizationPolicy` are singleton resources that Graph returns as the
object itself with no ``value`` envelope, which is why `_get_all` has to
surface them as one row.
"""

from __future__ import annotations

import pytest

from ccf.posture.providers import m365

TENANT = "d0529da6-0000-0000-0000-000000000000"


def _methods_policy(*enabled: str) -> list[dict]:
    """The policy lists every method; `state` is what distinguishes them."""
    known = ("Fido2", "MicrosoftAuthenticator", "Sms", "Voice", "Email", "X509Certificate")
    return [
        {
            "authenticationMethodConfigurations": [
                {"id": name, "state": "enabled" if name in enabled else "disabled"}
                for name in known
            ]
        }
    ]


# --- IA-2(11) phishing-resistant ---------------------------------------------


def test_fido2_alone_satisfies_phishing_resistance() -> None:
    findings = m365.evaluate_phishing_resistant_mfa(
        _methods_policy("Fido2", "MicrosoftAuthenticator"), tenant_id=TENANT
    )
    assert [f.verdict for f in findings] == ["pass"]
    assert "Fido2" in findings[0].observed


def test_a_tenant_with_only_app_based_mfa_fails_phishing_resistance() -> None:
    """MicrosoftAuthenticator push is MFA but is not phishing-resistant."""
    findings = m365.evaluate_phishing_resistant_mfa(
        _methods_policy("MicrosoftAuthenticator"), tenant_id=TENANT
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "no phishing-resistant method" in findings[0].observed


def test_a_method_graph_omits_is_not_treated_as_enabled() -> None:
    """Absence and `disabled` mean the same thing; neither is availability."""
    findings = m365.evaluate_phishing_resistant_mfa(
        [{"authenticationMethodConfigurations": []}], tenant_id=TENANT
    )
    assert [f.verdict for f in findings] == ["fail"]


# --- IA-2(1)/(2) interceptable methods ---------------------------------------


def test_sms_enabled_fails_even_when_fido2_is_also_enabled() -> None:
    """The separate check earns its place here.

    A tenant can offer FIDO2 and still accept SMS, and an attacker only has to
    defeat the weakest method the tenant will accept -- so a single combined
    check would have passed this tenant.
    """
    rows = _methods_policy("Fido2", "Sms")
    assert m365.evaluate_phishing_resistant_mfa(rows, tenant_id=TENANT)[0].verdict == "pass"
    weak = m365.evaluate_phishable_methods_disabled(rows, tenant_id=TENANT)
    assert weak[0].verdict == "fail"
    assert "Sms" in weak[0].observed


def test_no_interceptable_method_enabled_passes() -> None:
    findings = m365.evaluate_phishable_methods_disabled(
        _methods_policy("Fido2", "MicrosoftAuthenticator"), tenant_id=TENANT
    )
    assert [f.verdict for f in findings] == ["pass"]


# --- AC-3/AC-6 guest invitations ---------------------------------------------


@pytest.mark.parametrize("setting", ["everyone", "adminsGuestInvitersAndAllMembers"])
def test_member_level_invitation_settings_fail(setting: str) -> None:
    findings = m365.evaluate_guest_invites_restricted(
        [{"allowInvitesFrom": setting}], tenant_id=TENANT
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert setting in findings[0].observed


def test_admin_only_invitations_pass() -> None:
    findings = m365.evaluate_guest_invites_restricted(
        [{"allowInvitesFrom": "adminsAndGuestInviters"}], tenant_id=TENANT
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_a_tenant_that_reports_no_invitation_setting_is_not_a_failure() -> None:
    """Absent is not the same as permissive; guessing either way is a claim."""
    findings = m365.evaluate_guest_invites_restricted([{}], tenant_id=TENANT)
    assert [f.verdict for f in findings] == ["not_applicable"]


# --- AC-6 default user permissions -------------------------------------------


def test_privileged_default_permissions_are_reported_by_name() -> None:
    findings = m365.evaluate_default_user_permissions(
        [
            {
                "defaultUserRolePermissions": {
                    "allowedToCreateTenants": True,
                    "allowedToCreateApps": True,
                    "allowedToCreateSecurityGroups": False,
                    "allowedToReadOtherUsers": True,
                }
            }
        ],
        tenant_id=TENANT,
    )
    assert [f.verdict for f in findings] == ["fail"]
    assert "allowedToCreateTenants" in findings[0].observed
    assert "allowedToCreateApps" in findings[0].observed
    # Not one of the privileged capabilities checked, and must not be reported.
    assert "allowedToReadOtherUsers" not in findings[0].observed


def test_a_restricted_default_role_passes() -> None:
    findings = m365.evaluate_default_user_permissions(
        [
            {
                "defaultUserRolePermissions": {
                    name: False for name in m365.PRIVILEGED_DEFAULT_PERMISSIONS
                }
            }
        ],
        tenant_id=TENANT,
    )
    assert [f.verdict for f in findings] == ["pass"]


def test_missing_permissions_object_is_not_scored_as_a_pass() -> None:
    """A tenant that reported nothing has not been shown to be restricted."""
    findings = m365.evaluate_default_user_permissions([{}], tenant_id=TENANT)
    assert [f.verdict for f in findings] == ["not_applicable"]


# --- every check is wired ----------------------------------------------------


def test_every_check_has_an_endpoint_and_an_evaluator() -> None:
    """A check missing either cannot be scanned, and resolution refuses one
    without an endpoint -- so the omission is silent."""
    for check in m365.CHECKS:
        assert check.key in m365.ENDPOINTS, f"{check.key} has no endpoint"
        assert check.key in m365.EVALUATORS, f"{check.key} has no evaluator"
    assert len(m365.CHECKS) == len(m365.ENDPOINTS) == len(m365.EVALUATORS)


@pytest.mark.asyncio
async def test_every_evaluator_receives_the_arguments_it_declares() -> None:
    """The wiring defect that shipped four checks as "manual review required".

    ``_evaluate`` used to decide which keyword each evaluator needed with a
    branch per check key. A new tenant-level evaluator that nobody added to
    that branch raised ``TypeError: missing 1 required keyword-only argument:
    'tenant_id'`` at scan time -- which the per-check isolation caught and
    reported as ``manual_review_required``. A wiring omission wearing the
    costume of a finding, and it looked like four controls needing review.

    Driving every registered evaluator through ``_evaluate`` means a new one
    cannot be half-wired: the dispatcher reads the signature, so there is no
    branch left to forget.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415
    from ccf.posture.resolve import ResolvedCheck  # noqa: PLC0415

    connector = MsGraphConnector(
        credential={"tenant_id": TENANT, "client_id": "c", "client_secret": "s"}
    )
    # Rows that every evaluator can read without raising: a singleton policy
    # object, which is also a one-element fleet.
    rows = [
        {
            "authenticationMethodConfigurations": [],
            "allowInvitesFrom": "adminsAndGuestInviters",
            "defaultUserRolePermissions": {},
            "id": "x",
            "userPrincipalName": "x@example.test",
            "accountEnabled": False,
        }
    ]
    for check in m365.CHECKS:
        outcome = connector._evaluate(
            ResolvedCheck(
                check=check,
                endpoint=m365.ENDPOINTS[check.key],
                source="platform",
            ),
            rows,
            tenant_id=TENANT,
            now=datetime.now(UTC),
        )
        assert outcome.check_key == check.key
        # `manual_review_required` is what a raised evaluator produces; no
        # check here should be reporting it from a fixture it can read.
        assert outcome.verdict != "manual_review_required", (
            f"{check.key} did not receive the arguments its evaluator declares"
        )


@pytest.mark.asyncio
async def test_a_singleton_policy_endpoint_yields_one_row() -> None:
    """`_get_all` extracts `payload["value"]`, which these endpoints do not have.

    `policies/authorizationPolicy` and `policies/authenticationMethodsPolicy`
    return the object itself. Without the singleton branch they yielded zero
    rows, and a check reading one would see an empty fleet and report nothing
    to assess rather than assessing the tenant.

    Driven through `_get_all` on purpose: the evaluator tests above pass rows
    in directly, so they pass whether or not the fetch produces any -- the
    mutation that removed this branch left all of them green.
    """
    import httpx  # noqa: PLC0415

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    body = {"allowInvitesFrom": "everyone", "defaultUserRolePermissions": {}}

    async def _serve(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    connector = MsGraphConnector(
        credential={"tenant_id": TENANT, "client_id": "c", "client_secret": "s"}
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(_serve)) as client:
        rows = await connector._get_all(
            client, "/v1.0/policies/authorizationPolicy", {}
        )

    assert rows == [body], "the singleton resource produced no row to assess"
    # And it reaches the evaluator as a real finding rather than an empty fleet.
    findings = m365.evaluate_guest_invites_restricted(rows, tenant_id=TENANT)
    assert [f.verdict for f in findings] == ["fail"]


@pytest.mark.asyncio
async def test_a_collection_that_is_genuinely_empty_stays_empty() -> None:
    """The branch keys on the absence of `value`, not on its truthiness.

    A collection endpoint returning `{"value": []}` means "no resources",
    which must not become one row containing the envelope.
    """
    import httpx  # noqa: PLC0415

    from ccf.connectors.msgraph import MsGraphConnector  # noqa: PLC0415

    async def _serve(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": []})

    connector = MsGraphConnector(
        credential={"tenant_id": TENANT, "client_id": "c", "client_secret": "s"}
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(_serve)) as client:
        rows = await connector._get_all(client, "/v1.0/users", {})
    assert rows == []
