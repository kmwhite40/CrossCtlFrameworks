"""Microsoft Secure Score, read through a crosswalk Concord authored.

**What this is, stated first because it is the whole point.** Microsoft publishes
no 800-53 mapping for Secure Score. Measured against a live GCC High tenant: 417
control profiles, none with a non-empty ``complianceInformation``, no
certification of any kind (see ``ccf.posture.attested.securescore_mapping`` and
the runbook). Every control attribution below is therefore **Concord's own
claim**, not Microsoft's, and it is labelled as such everywhere it surfaces:

* its own ``check_source`` (:data:`CHECK_SOURCE`), never ``platform`` and never
  the provider-attested one;
* its own trust tier in ``posture.scan.trust_tier``, below a provider's own
  mapping, so any Concord check or AWS attestation on the same control wins;
* its own bucket in framework posture (``crosswalk_only``), so a control credited
  only by this crosswalk is never counted among the ones Concord verified;
* no remediation opened automatically (``open_remediation=False``). A failure is
  recorded and shown; filing it as a POA&M is a human's decision, because the
  attribution that would put it in the package is Concord's, not observed.

**What Microsoft does provide** is the measurement: per profile, a score out of
``maxScore`` for this tenant. Concord reads that and nothing else. Two rules turn
it into a verdict, both conservative:

* **Full points or it is not a pass.** Device-level profiles are fleet ratios --
  ``7.83 / 8`` means some devices are not compliant -- and Concord's rule
  everywhere else is that the worst resource decides (``posture.rollup``). A
  partial score is a ``fail``, with the fraction in the detail.
* **An administrator's assertion is not an observation.** Secure Score lets an
  admin mark a control "resolved through third party", which awards full points
  without Microsoft observing anything, or "ignored" (risk accepted). The live
  tenant has both: Linux real-time antivirus reads ``10 / 10`` and is
  ``ThirdParty``. Either state is ``manual_review_required``, never a pass.

**Membership is explicit.** Profiles are listed by id, grouped into families that
share one rationale and one primary control. No keyword or category rule assigns
a profile to a control: that is how a mapping quietly grows past what anyone
reviewed. Every id here was read from the live tenant's profile list, and every
control is checked against the bundled 800-53 Rev. 5 catalog by the tests.

A profile the tenant does not score (not licensed, not applicable) produces no
row: nothing was measured. A pass credits only the family's primary control; a
failure reaches every control the family declares -- the same asymmetry as
``ccf.posture.evidence``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

#: ``ControlTest.check_source`` for every row this module produces. Distinct from
#: ``platform`` and from ``ccf.posture.attested.CHECK_SOURCE``: trust tiers and
#: posture labels key on it.
CHECK_SOURCE = "crosswalk:securescore"

#: Prefix of each row's ``check_key``. Not a registered platform check key, so a
#: pack cannot borrow this trust by naming a rule like it -- the tier is read from
#: ``check_source``, never from the key's spelling.
CHECK_KEY_PREFIX = "msgraph.securescore."

#: Secure Score ``controlStateUpdates`` states that mean an administrator decided,
#: rather than Microsoft observed. ``Default`` is the only observed state.
_ASSERTED_STATES: dict[str, str] = {
    "thirdparty": (
        "an administrator marked it resolved through a third party; Secure Score "
        "awards the points without observing anything"
    ),
    "ignored": (
        "an administrator marked it ignored (risk accepted) in Secure Score; if "
        "this is an accepted risk, record it as a Concord waiver"
    ),
    "reviewed": "an administrator marked it reviewed in Secure Score",
}


@dataclass(frozen=True)
class Family:
    """Secure Score profiles that share one 800-53 meaning."""

    key: str
    primary: str
    supporting: tuple[str, ...]
    rationale: str
    profiles: tuple[str, ...]

    @property
    def controls(self) -> tuple[str, ...]:
        return (self.primary, *self.supporting)


CROSSWALK: tuple[Family, ...] = (
    # --- Identity -------------------------------------------------------------
    Family(
        key="compromised_passwords",
        primary="IA-5(1)",
        supporting=(),
        rationale=(
            "IA-5(1)(a) requires a list of commonly-used, expected or compromised "
            "passwords that new passwords are checked against; these enable "
            "Entra password protection's banned-password lists."
        ),
        profiles=("aad_custom_banned_passwords", "aad_password_protection"),
    ),
    Family(
        key="privileged_mfa",
        primary="IA-2(1)",
        supporting=(),
        rationale="Multi-factor authentication required for privileged accounts.",
        profiles=("aad_phishing_MFA_strength",),
    ),
    Family(
        key="separate_admin_accounts",
        primary="AC-6(2)",
        supporting=(),
        rationale=(
            "Administrators use separate, non-privileged accounts for "
            "non-security functions."
        ),
        profiles=("aad_admin_accounts_separate_unassigned_cloud_only",),
    ),
    Family(
        key="session_termination",
        primary="AC-12",
        supporting=(),
        rationale="Sign-in frequency ends sessions after a defined condition.",
        profiles=("aad_sign_in_freq_session_timeout",),
    ),
    # --- Audit ------------------------------------------------------------------
    Family(
        key="audit_generation",
        primary="AU-12",
        supporting=("AU-2",),
        rationale="Mailbox and unified audit logging generate the audit records.",
        profiles=("exo_mailboxaudit", "mip_search_auditlog"),
    ),
    # --- Information flow and external systems ---------------------------------
    Family(
        key="information_flow",
        primary="AC-4",
        supporting=("SC-7(10)",),
        rationale=(
            "Data loss prevention and blocked automatic forwarding enforce approved "
            "information flows and restrict exfiltration."
        ),
        profiles=(
            "dlp_datalossprevention",
            "mip_DLP_policies_Teams",
            "mdo_autoforwardingmode",
            "mdo_blockmailforward",
        ),
    ),
    Family(
        key="security_attributes",
        primary="AC-16",
        supporting=(),
        rationale="Sensitivity labels associate security attributes with information.",
        profiles=(
            "mip_autosensitivitylabelspolicies",
            "mip_sensitivitylabelspolicies",
            "mip_purviewlabelconsent",
        ),
    ),
    Family(
        key="external_systems",
        primary="AC-20",
        supporting=(),
        rationale=(
            "Restricts use of external systems: third-party storage from Outlook "
            "on the web, and OneDrive sync to devices the organization does not "
            "manage."
        ),
        profiles=(
            "exo_storageproviderrestricted",
            "spo_block_onedrive_sync_unmanaged_devices",
        ),
    ),
    Family(
        key="user_installed_software",
        primary="CM-11",
        supporting=(),
        rationale="Users may not install Outlook add-ins.",
        profiles=("exo_outlookaddins",),
    ),
    # --- Mail: spam, phishing, malicious content --------------------------------
    Family(
        key="spam_protection",
        primary="SI-8",
        supporting=(),
        rationale=(
            "Anti-spam and anti-phishing policy on the mail system: spam "
            "protection at the entry point for unsolicited messages."
        ),
        profiles=(
            "mdo_allowedsenderscombined",
            "mdo_bulkspamaction",
            "mdo_bulkthreshold",
            "mdo_connectionfilter",
            "mdo_highconfidencespamaction",
            "mdo_spamaction",
            "mdo_zapspam",
            "exo_transportrulesallowlistdomains",
            "mdo_antiphishingpolicies",
            "mdo_enabledomainstoprotect",
            "mdo_enablemailboxintelligence",
            "mdo_highconfidencephishaction",
            "mdo_mailboxintelligenceprotection",
            "mdo_mailboxintelligenceprotectionaction",
            "mdo_phishthresholdlevel",
            "mdo_phisspamacation",
            "mdo_targeteddomainprotectionaction",
            "mdo_targeteduserprotectionaction",
            "mdo_targetedusersprotection",
            "mdo_zapphish",
        ),
    ),
    Family(
        key="malicious_code_mail",
        primary="SI-3",
        supporting=(),
        rationale=(
            "Malicious code protection for mail, files and links: attachment "
            "filtering, Safe Attachments, Safe Documents, Safe Links and "
            "zero-hour purge of malware."
        ),
        profiles=(
            "mdo_commonattachmentsfilter",
            "mdo_safeattachmentpolicy",
            "mdo_safeattachments",
            "mdo_safedocuments",
            "mdo_atpprotection",
            "mdo_zapmalware",
            "mdo_safelinksforemail",
            "mdo_safelinksforOfficeApps",
        ),
    ),
    # --- Monitoring ---------------------------------------------------------------
    Family(
        key="system_monitoring",
        primary="SI-4",
        supporting=(),
        rationale=(
            "Endpoint and cloud-app monitoring: the Defender sensors are onboarded, "
            "reporting and current, and Defender for Cloud Apps is collecting."
        ),
        profiles=(
            "mcas_mda_enabled",
            "McasFirewallLogUpload",
            "scid_2000",
            "scid_20000",
            "scid_2001",
            "scid_2002",
            "scid_2030",
            "scid_5001",
            "scid_5002",
            "scid_6001",
            "scid_6002",
            "scid_6100",
        ),
    ),
    # --- Endpoint -----------------------------------------------------------------
    Family(
        key="malicious_code_endpoint",
        primary="SI-3",
        supporting=(),
        rationale=(
            "Malicious code protection on endpoints: antivirus on and current, "
            "real-time, cloud-delivered and behaviour protection, tamper "
            "protection, SmartScreen, and attack surface reduction rules that "
            "block malicious code behaviours."
        ),
        profiles=(
            "scid_2003",
            "scid_2010",
            "scid_2011",
            "scid_2012",
            "scid_2013",
            "scid_2014",
            "scid_2016",
            "scid_2021",
            "scid_2060",
            "scid_2061",
            "scid_89",
            "scid_90",
            "scid_91",
            "scid_92",
            "scid_96",
            "scid_5090",
            "scid_5091",
            "scid_5092",
            "scid_5094",
            "scid_5095",
            "scid_6090",
            "scid_6091",
            "scid_6094",
            "scid_6095",
            "scid_2500",
            "scid_2501",
            "scid_2502",
            "scid_2503",
            "scid_2504",
            "scid_2505",
            "scid_2506",
            "scid_2507",
            "scid_2508",
            "scid_2509",
            "scid_2510",
            "scid_2511",
            "scid_2512",
            "scid_2513",
            "scid_2514",
            "scid_2515",
            "scid_2517",
            "scid_2518",
        ),
    ),
    Family(
        key="host_firewall",
        primary="SC-7(12)",
        supporting=(),
        rationale="Host-based boundary protection: the host firewall is on and configured.",
        profiles=(
            "scid_2070",
            "scid_2071",
            "scid_2072",
            "scid_2073",
            "scid_50",
            "scid_51",
            "scid_5007",
        ),
    ),
    Family(
        key="encryption_at_rest",
        primary="SC-28",
        supporting=(),
        rationale="Full-disk encryption: BitLocker on Windows, FileVault on macOS.",
        profiles=("scid_2090", "scid_2091", "scid_2093", "scid_5011"),
    ),
    Family(
        key="flaw_remediation",
        primary="SI-2",
        supporting=(),
        rationale="Automatic installation of security updates.",
        profiles=("scid_15",),
    ),
    Family(
        key="password_length",
        primary="IA-5(1)",
        supporting=(),
        rationale="Minimum password length enforced on local accounts.",
        profiles=("scid_32", "scid_5003"),
    ),
    Family(
        key="authenticator_protection",
        primary="IA-5",
        supporting=(),
        rationale=(
            "Protects authenticator content: Credential Guard and LSA protection, "
            "no WDigest plaintext, no LAN Manager hashes, no locally stored "
            "credentials, and unique managed local administrator passwords (LAPS)."
        ),
        profiles=("scid_2080", "scid_102", "scid_57", "scid_65", "scid_93", "scid_113"),
    ),
    Family(
        key="account_lockout",
        primary="AC-7",
        supporting=(),
        rationale="Unsuccessful logon attempts lock the account.",
        profiles=("scid_41", "scid_42", "scid_44", "scid_5006"),
    ),
    Family(
        key="device_lock",
        primary="AC-11",
        supporting=(),
        rationale="Inactivity locks the device.",
        profiles=("scid_28", "scid_5013"),
    ),
    Family(
        key="remote_access_protection",
        primary="AC-17(2)",
        supporting=(),
        rationale=(
            "Remote Desktop sessions are protected with TLS and Network Level "
            "Authentication."
        ),
        profiles=("scid_24", "scid_45"),
    ),
    Family(
        key="least_functionality",
        primary="CM-7",
        supporting=(),
        rationale=(
            "Unnecessary functions and services disabled: SMBv1, Remote Registry, "
            "Remote Assistance, Internet Connection Sharing, network bridging and "
            "AutoRun."
        ),
        profiles=(
            "scid_53",
            "scid_54",
            "scid_108",
            "scid_63",
            "scid_87",
            "scid_60",
            "scid_58",
            "scid_69",
            "scid_70",
        ),
    ),
    Family(
        key="least_privilege",
        primary="AC-6",
        supporting=(),
        rationale=(
            "Built-in Administrator disabled, standard users cannot elevate, and "
            "installers do not run with elevated privileges by default."
        ),
        profiles=("scid_3010", "scid_27", "scid_66"),
    ),
    Family(
        key="unauthenticated_actions",
        primary="AC-14",
        supporting=(),
        rationale=(
            "Actions permitted without identification are restricted: no anonymous "
            "enumeration of accounts or shares, no anonymous access to pipes and "
            "shares, and the Guest account disabled."
        ),
        profiles=("scid_55", "scid_64", "scid_68", "scid_88", "scid_3011"),
    ),
    Family(
        key="transmission_protection",
        primary="SC-8",
        supporting=(),
        rationale=(
            "Confidentiality and integrity of transmitted information: LDAP signing "
            "and encryption, signed and encrypted secure channel, SMB signing, and "
            "no plaintext passwords to third-party SMB servers."
        ),
        profiles=(
            "scid_103",
            "scid_104",
            "scid_37",
            "scid_38",
            "scid_39",
            "scid_95",
            "scid_94",
        ),
    ),
    Family(
        key="software_integrity",
        primary="SI-7",
        supporting=(),
        rationale=(
            "Software, firmware and boot integrity: Secure Boot, memory integrity "
            "(HVCI), macOS System Integrity Protection and Gatekeeper, and no "
            "software with an invalid signature."
        ),
        profiles=("scid_112", "scid_118", "scid_5010", "scid_5009", "scid_79"),
    ),
    Family(
        key="internet_exposure",
        primary="SC-7",
        supporting=(),
        rationale=(
            "Unnecessary inbound internet exposure on internet-facing devices is "
            "removed."
        ),
        profiles=("scid_114",),
    ),
)


def crosswalk_index() -> dict[str, Family]:
    """Profile id -> its family. Raises if a profile is listed twice.

    One profile in two families would credit two primaries from one measurement,
    which is the over-attribution the asymmetric rule exists to prevent.
    """
    index: dict[str, Family] = {}
    for family in CROSSWALK:
        for profile_id in family.profiles:
            if profile_id in index:
                raise ValueError(
                    f"Secure Score profile {profile_id!r} is in both "
                    f"{index[profile_id].key!r} and {family.key!r}"
                )
            index[profile_id] = family
    return index


def check_key_for(profile_id: str) -> str:
    return f"{CHECK_KEY_PREFIX}{profile_id}"


def _state(profile: Mapping[str, Any]) -> str:
    """The latest ``controlStateUpdates`` state, lower-cased; ``default`` when none."""
    updates = profile.get("controlStateUpdates")
    if isinstance(updates, (list, tuple)) and updates:
        last = updates[-1]
        if isinstance(last, Mapping) and last.get("state"):
            return str(last["state"]).strip().lower()
    return "default"


def verdict_for(
    profile: Mapping[str, Any], score: Mapping[str, Any]
) -> tuple[str, str]:
    """``(status, detail)`` for one scored profile. See the module docstring.

    Never a pass by default: a missing or unreadable number is
    ``manual_review_required``, because "could not read the score" and "scored
    full marks" must not look alike.
    """
    state = _state(profile)
    if state in _ASSERTED_STATES:
        return "manual_review_required", f"Not observed: {_ASSERTED_STATES[state]}."
    if state != "default":
        return (
            "manual_review_required",
            f"Secure Score reports an unrecognised control state {state!r}.",
        )
    try:
        achieved = float(score.get("score"))  # type: ignore[arg-type]
        maximum = float(profile.get("maxScore"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "manual_review_required", "Secure Score returned no readable score."
    if maximum <= 0:
        return "manual_review_required", "Secure Score lists no points for this control."
    if achieved >= maximum:
        return "pass", f"Secure Score: {achieved:g} of {maximum:g} points."
    return (
        "fail",
        f"Secure Score: {achieved:g} of {maximum:g} points. Less than full points; "
        "for a device control that means some devices are not compliant.",
    )


@dataclass(frozen=True)
class CrosswalkRow:
    profile_id: str
    title: str
    family: Family
    status: str
    detail: str

    @property
    def check_key(self) -> str:
        return check_key_for(self.profile_id)


def crosswalk_rows(
    profiles: Iterable[Mapping[str, Any]],
    control_scores: Iterable[Mapping[str, Any]],
) -> tuple[list[CrosswalkRow], dict[str, Any]]:
    """Rows for every mapped profile this tenant scores, and what was left out.

    The report names the mapped profiles the tenant does not score and the scored
    profiles the crosswalk does not map, so "how much of Secure Score does this
    reach" is answered by counting, not by assumption.
    """
    index = crosswalk_index()
    by_id = {
        str(p["id"]): p for p in profiles if isinstance(p, Mapping) and p.get("id")
    }
    scores = {
        str(c["controlName"]): c
        for c in control_scores
        if isinstance(c, Mapping) and c.get("controlName")
    }
    rows: list[CrosswalkRow] = []
    for profile_id, family in index.items():
        profile = by_id.get(profile_id)
        score = scores.get(profile_id)
        if profile is None or score is None or profile.get("deprecated") is True:
            continue
        status, detail = verdict_for(profile, score)
        rows.append(
            CrosswalkRow(
                profile_id=profile_id,
                title=str(profile.get("title") or profile_id),
                family=family,
                status=status,
                detail=detail,
            )
        )
    report = {
        "profiles": len(by_id),
        "scored": len(scores),
        "mapped": len(index),
        "rows": len(rows),
        "mapped_but_not_scored": sorted(p for p in index if p not in scores),
        "scored_but_not_mapped": sorted(p for p in scores if p not in index),
    }
    return rows, report


__all__ = [
    "CHECK_KEY_PREFIX",
    "CHECK_SOURCE",
    "CROSSWALK",
    "CrosswalkRow",
    "Family",
    "check_key_for",
    "crosswalk_index",
    "crosswalk_rows",
    "verdict_for",
]
