"""A control no provider could evidence, and the Graph read that can.

Concord's fifty-odd checks across five providers reach no control in the **AT**
family at all, and do not reach ``AC-8`` either. Both are in a FedRAMP Moderate
baseline, so both were sitting in "not yet addressed" with nothing able to move
them -- which is a gap in what the product can assess, not a gap in a tenant.

``AC-8`` System Use Notification. Entra's terms-of-use agreements are the
mechanism: an agreement the user must be shown and accept before reaching the
system is exactly what AC-8 describes. ``agreement`` is in the v1.0 model with
``isViewingBeforeAcceptanceRequired``, which is the property that distinguishes a
notification a user actually saw from a document filed somewhere.

An ``AT-2`` check shipped alongside this one, reading
``/v1.0/security/attackSimulation/simulations``, and was removed. Its tests are
gone with it, and the reason is worth keeping:

``$metadata`` said the type existed, and it does -- in the **commercial** model
published at ``graph.microsoft.com``. ``graph.microsoft.us`` answers ``400
BadRequest: Resource not found for the segment 'attackSimulation'`` on both
``/v1.0`` and ``/beta``, while ``/v1.0/security`` itself answers 200. A cloud
capability gap, not a licensing one -- that answers 403. The check would have
reported ``manual_review_required`` on every scan of every GCC High tenant for
ever, and read as a tenant problem rather than a platform one.

So verifying against the model is necessary and not sufficient: the model is
per-cloud, and the only thing that settles whether a check can run is asking the
tenant. The AC-8 endpoint below was asked, and returns agreements carrying
``isViewingBeforeAcceptanceRequired``.
"""

from __future__ import annotations

from ccf.posture.checks import checks_for
from ccf.posture.providers import m365

TENANT = "tenant-1"


def _verdicts(findings: list) -> list[str]:
    return [f.verdict for f in findings]


# --------------------------------------------------------------------------
# AC-8: a system use notification the user is actually shown
# --------------------------------------------------------------------------


def test_an_agreement_shown_before_acceptance_passes() -> None:
    findings = m365.evaluate_system_use_notification(
        [
            {
                "id": "a1",
                "displayName": "Acceptable Use Policy",
                "isViewingBeforeAcceptanceRequired": True,
            }
        ],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["pass"]
    assert "Acceptable Use Policy" in findings[0].observed


def test_an_agreement_nobody_has_to_read_does_not_satisfy_ac_8() -> None:
    """The distinction the control turns on.

    AC-8 requires the notification to be *displayed* before access is granted. An
    agreement a user accepts without being shown it is a record of consent, not a
    system use notification, and crediting it would put a value that validates and
    is wrong into an SSP.
    """
    findings = m365.evaluate_system_use_notification(
        [
            {
                "id": "a1",
                "displayName": "Acceptable Use Policy",
                "isViewingBeforeAcceptanceRequired": False,
            }
        ],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["fail"]
    assert "without being shown" in findings[0].observed


def test_one_qualifying_agreement_among_several_passes() -> None:
    """Tenants accumulate agreements. One that qualifies is enough."""
    findings = m365.evaluate_system_use_notification(
        [
            {"id": "a1", "displayName": "Old notice", "isViewingBeforeAcceptanceRequired": False},
            {"id": "a2", "displayName": "Banner", "isViewingBeforeAcceptanceRequired": True},
        ],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["pass"]
    assert "Banner" in findings[0].observed


def test_no_agreement_at_all_fails_rather_than_going_unassessed() -> None:
    """An empty collection is a real answer here: Graph listed the tenant's
    agreements and there are none, so no notification is configured. That is a
    finding, not something Concord could not read."""
    findings = m365.evaluate_system_use_notification([], tenant_id=TENANT)
    assert _verdicts(findings) == ["fail"]
    assert "no terms-of-use agreement" in findings[0].observed


def test_a_missing_property_is_manual_review_not_a_failure() -> None:
    """The licensing case. Terms of use needs Entra ID P1/P2, and a tenant
    without it can return agreements whose property set differs. Reporting that
    as "configured wrongly" sends an operator to fix something that is not
    broken; `manual_review_required` sends them to look."""
    findings = m365.evaluate_system_use_notification(
        [{"id": "a1", "displayName": "Policy"}], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["manual_review_required"]


# --------------------------------------------------------------------------
# Registration: the check must actually be reachable
# --------------------------------------------------------------------------


def test_the_check_is_registered_for_msgraph() -> None:
    """A check that exists but is not in CHECKS runs for nobody."""
    keys = {c.key for c in checks_for("msgraph")}
    assert "m365.identity.system_use_notification" in keys


def test_the_removed_at2_check_is_gone_from_every_table() -> None:
    """Removal has to be complete, not partial.

    A key left in ENDPOINTS or EVALUATORS with no PostureCheck behind it is dead
    weight the next reader has to reason about; a key left in CHECKS with no
    endpoint raises at scan time, for every tenant. Asserted over all three
    tables rather than trusting that the edit touched them all.
    """
    assert not [c for c in checks_for("msgraph") if "awareness" in c.key]
    assert not [k for k in m365.ENDPOINTS if "awareness" in k]
    assert not [k for k in m365.EVALUATORS if "awareness" in k]
    assert "attackSimulation" not in "".join(m365.ENDPOINTS.values())


def test_the_check_declares_an_endpoint() -> None:
    """A registered check with no endpoint raises UnknownGraphSourceError at scan
    time -- i.e. in production, for every tenant, rather than here."""
    key = "m365.identity.system_use_notification"
    assert key in m365.ENDPOINTS, f"{key} has no endpoint"
    assert m365.ENDPOINTS[key].startswith("/v1.0/")


def test_the_check_declares_the_control_it_evidences() -> None:
    """The point of adding it: a control nothing else reaches."""
    by_key = {c.key: c for c in checks_for("msgraph")}
    assert by_key["m365.identity.system_use_notification"].control_ids == ("AC-8",)


def test_the_check_names_the_permission_it_needs() -> None:
    """So a 403 reports "grant this" rather than leaving an operator to infer it."""
    by_key = {c.key: c for c in checks_for("msgraph")}
    assert by_key["m365.identity.system_use_notification"].required_permissions
