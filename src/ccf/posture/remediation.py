"""Deterministic remediation playbooks for posture checks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemediationPlaybook:
    actions: tuple[str, ...]
    evidence: tuple[str, ...]
    milestones: tuple[str, ...] = ()


_PLAYBOOKS: dict[str, RemediationPlaybook] = {
    "m365.identity.mfa_registered": RemediationPlaybook(
        actions=(
            "Identify users without registered MFA methods from the failing-resource list.",
            (
                "Require registration through Conditional Access or authentication-methods "
                "registration campaign."
            ),
            (
                "Confirm break-glass and service accounts have documented compensating "
                "controls or approved exclusions."
            ),
        ),
        evidence=(
            "Graph authentication method registration report or equivalent export.",
            "Conditional Access/authentication methods policy export.",
            "Re-scan result showing all applicable users pass or approved waivers for exclusions.",
        ),
        milestones=(
            "Notify affected account owners and set registration deadline.",
            "Enable or update MFA registration enforcement.",
            "Re-run the automated M365 identity check and attach passing evidence.",
        ),
    ),
    "m365.policy.legacy_auth_blocked": RemediationPlaybook(
        actions=(
            "Review Conditional Access policies for legacy client app coverage.",
            (
                "Create or enable a policy blocking Exchange ActiveSync and other legacy "
                "authentication clients."
            ),
            (
                "Monitor sign-in logs for blocked legacy-auth attempts and legitimate "
                "application impact."
            ),
        ),
        evidence=(
            "Conditional Access policy export showing legacy clients blocked.",
            "Sign-in log sample showing policy enforcement.",
            "Passing re-scan result for the legacy-auth check.",
        ),
    ),
    "aws.iam.root_mfa_enabled": RemediationPlaybook(
        actions=(
            "Sign in with the account root user through the approved emergency process.",
            "Register a hardware or virtual MFA device for the root user.",
            (
                "Store root credentials and MFA recovery material according to "
                "privileged-access procedure."
            ),
        ),
        evidence=(
            "IAM account summary or credential report showing root MFA enabled.",
            "Privileged-access procedure or access vault record.",
            "Passing re-scan result for root MFA.",
        ),
    ),
    "aws.cloudtrail.multi_region_logging": RemediationPlaybook(
        actions=(
            "Create or update an organization/account CloudTrail trail to apply to all regions.",
            "Enable logging and confirm the trail writes to the approved protected destination.",
            "Review CloudTrail status for delivery errors.",
        ),
        evidence=(
            "CloudTrail trail configuration export showing multi-region logging enabled.",
            "Trail status showing IsLogging=true.",
            "Passing re-scan result for CloudTrail multi-region logging.",
        ),
    ),
}


def playbook_for(check_key: str | None) -> RemediationPlaybook | None:
    """Known deterministic playbook for a posture check."""
    if not check_key:
        return None
    return _PLAYBOOKS.get(check_key)
