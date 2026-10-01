"""Two controls no provider could evidence, and the two Graph reads that can.

Concord's fifty-odd checks across five providers reach no control in the **AT**
family at all, and do not reach ``AC-8`` either. Both are in a FedRAMP Moderate
baseline, so both were sitting in "not yet addressed" with nothing able to move
them -- which is a gap in what the product can assess, not a gap in a tenant.

``AC-8`` System Use Notification. Entra's terms-of-use agreements are the
mechanism: an agreement the user must be shown and accept before reaching the
system is exactly what AC-8 describes. ``agreement`` is in the v1.0 model with
``isViewingBeforeAcceptanceRequired``, which is the property that distinguishes a
notification a user actually saw from a document filed somewhere.

``AT-2`` Literacy Training and Awareness, and ``AT-2(3)`` Social Engineering and
Mining. Entra's attack-simulation training is the mechanism, and ``simulation`` is
in the v1.0 model with ``status``, ``completionDateTime`` and ``trainingSetting``.

Both endpoints and every property read here were checked against Microsoft's
published Graph metadata (``$metadata``, v1.0) rather than taken from
documentation prose, because inventing a property name produces a check that
reports ``manual_review_required`` forever and looks like a tenant problem.

What these checks must not do is overclaim. A completed phishing simulation is
not proof that every user received annual training, and the ``expected`` text says
precisely what was observed instead of implying the control is met. Concord's
existing asymmetry does the rest: a pass credits only the primary control.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

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
# AT-2 / AT-2(3): awareness training that actually ran
# --------------------------------------------------------------------------


def _sim(
    *,
    status: str = "succeeded",
    days_ago: int = 30,
    training: bool = True,
    name: str = "Q1 phishing",
) -> dict:
    completed = datetime.now(UTC) - timedelta(days=days_ago)
    out: dict = {
        "id": "s1",
        "displayName": name,
        "status": status,
        "completionDateTime": completed.isoformat().replace("+00:00", "Z"),
    }
    if training:
        out["trainingSetting"] = {"settingType": "microsoftCustom"}
    return out


def test_a_completed_simulation_with_training_in_the_window_passes() -> None:
    findings = m365.evaluate_awareness_training_current([_sim()], tenant_id=TENANT)
    assert _verdicts(findings) == ["pass"]
    assert "Q1 phishing" in findings[0].observed


def test_a_simulation_older_than_the_window_fails() -> None:
    """AT-2 is an annual obligation, so recency is the whole question.

    A simulation from three years ago is evidence the tenant once had a
    programme, not that it has one.
    """
    findings = m365.evaluate_awareness_training_current(
        [_sim(days_ago=m365.AWARENESS_TRAINING_DAYS + 30)], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["fail"]
    assert "days ago" in findings[0].observed


def test_the_newest_qualifying_simulation_decides() -> None:
    """An old one must not drag down a tenant that also ran a recent one."""
    findings = m365.evaluate_awareness_training_current(
        [_sim(days_ago=900, name="ancient"), _sim(days_ago=10, name="recent")],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["pass"]
    assert "recent" in findings[0].observed


@pytest.mark.parametrize("status", ["running", "scheduled", "draft", "cancelled", "failed"])
def test_a_simulation_that_did_not_complete_is_not_training_delivered(
    status: str,
) -> None:
    """A scheduled simulation is an intention. AT-2 asks what users received."""
    findings = m365.evaluate_awareness_training_current(
        [_sim(status=status, days_ago=5)], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["fail"]


def test_a_simulation_with_no_training_attached_does_not_evidence_training() -> None:
    """A phishing test with no training is a measurement, not awareness training.

    This is the overclaim the check exists to avoid: AT-2 is about what users were
    taught, and a simulation that taught nobody anything evidences AT-2(3)'s
    exercise at most -- so it does not pass a check whose primary control is AT-2.
    """
    findings = m365.evaluate_awareness_training_current(
        [_sim(training=False)], tenant_id=TENANT
    )
    assert _verdicts(findings) == ["fail"]
    assert "no training" in findings[0].observed


def test_no_simulations_at_all_fails() -> None:
    findings = m365.evaluate_awareness_training_current([], tenant_id=TENANT)
    assert _verdicts(findings) == ["fail"]
    assert "no attack-simulation" in findings[0].observed


def test_an_unparseable_completion_date_is_manual_review() -> None:
    """Not a failure: Concord could not read the date, which is different from the
    simulation being stale. Guessing "stale" from an unreadable timestamp is the
    same overclaim `_tenant_finding(unassessable=...)` exists for."""
    findings = m365.evaluate_awareness_training_current(
        [{"id": "s1", "displayName": "x", "status": "succeeded",
          "completionDateTime": "not-a-date", "trainingSetting": {"settingType": "x"}}],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["manual_review_required"]


def test_a_completed_simulation_with_no_completion_date_is_manual_review() -> None:
    findings = m365.evaluate_awareness_training_current(
        [{"id": "s1", "displayName": "x", "status": "succeeded",
          "trainingSetting": {"settingType": "x"}}],
        tenant_id=TENANT,
    )
    assert _verdicts(findings) == ["manual_review_required"]


# --------------------------------------------------------------------------
# Registration: both checks must actually be reachable
# --------------------------------------------------------------------------


def test_both_checks_are_registered_for_msgraph() -> None:
    """A check that exists but is not in CHECKS runs for nobody.

    `tests/test_connector_advertised_vs_emitted.py` makes the general version of
    this assertion behaviourally; this is the narrow one, named so a regression
    says which check went missing.
    """
    keys = {c.key for c in checks_for("msgraph")}
    assert "m365.identity.system_use_notification" in keys
    assert "m365.awareness.training_current" in keys


def test_both_checks_declare_an_endpoint() -> None:
    """A registered check with no endpoint raises UnknownGraphSourceError at scan
    time -- i.e. in production, for every tenant, rather than here."""
    for key in ("m365.identity.system_use_notification", "m365.awareness.training_current"):
        assert key in m365.ENDPOINTS, f"{key} has no endpoint"
        assert m365.ENDPOINTS[key].startswith("/v1.0/"), (
            f"{key} reads a beta endpoint; both of these are in the v1.0 model, "
            "which was verified against Graph's published $metadata"
        )


def test_the_new_checks_declare_the_controls_they_evidence() -> None:
    """The point of adding them: controls nothing else reaches."""
    by_key = {c.key: c for c in checks_for("msgraph")}
    assert by_key["m365.identity.system_use_notification"].control_ids == ("AC-8",)
    assert by_key["m365.awareness.training_current"].control_ids == ("AT-2", "AT-2(3)")


def test_the_new_checks_name_the_permission_they_need() -> None:
    """So a 403 reports "grant this" rather than leaving an operator to infer it."""
    by_key = {c.key: c for c in checks_for("msgraph")}
    for key in ("m365.identity.system_use_notification", "m365.awareness.training_current"):
        assert by_key[key].required_permissions, f"{key} names no permission"
