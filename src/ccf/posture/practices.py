"""Which CMMC / 800-171 practices each posture check evidences.

A posture check declares NIST 800-53 control ids, because that is the
vocabulary its assertion is written in. A CMMC project's SSP entries are
practice ids (``AC.L2-3.1.1``), seeded from ``ccf.scoring_controls``. The two do
not intersect, so before this module every posture verdict -- passes cited as
evidence and failures owed a POA&M alike -- landed on no entry in the document
an assessor actually reads. Measured on a live tenant: 2 of 110 entry ids
matched any control test, and both of those came from hand-authored tests
rather than from any scan.

The catalog crosswalk cannot close it. ``framework_mappings`` stores the
800-171 side as prose that happens to begin with a requirement number, and it
reaches 14 of the 32 registered checks -- **none** of the four that were
failing on the live tenant. So the mapping is stated here instead.

**This is compliance content, not plumbing.** Each entry says an automated
check is evidence for a specific CMMC practice, and that claim ends up in an
authorization package: a wrong entry files a finding against a requirement the
organization was never failing, or credits one it was. So each mapping quotes
the practice's own requirement text, and the rule for inclusion is that the
check's assertion and the requirement say the same thing without an argument in
between. Anything needing an argument is left in :data:`UNMAPPED`, with the
argument written down, and goes on being reported as unattributable rather than
guessed at.

The mapping lives here rather than on ``PostureCheck`` so that it can be
reviewed as one document. A reviewer checking thirty-two compliance assertions
should not have to read five provider modules to find them.
"""

from __future__ import annotations

#: check key -> the CMMC practices it evidences, most specific first.
#:
#: The first entry is the **primary** practice. A passing check credits only
#: that one, while a non-passing check is a finding against every practice
#: listed -- the same asymmetry ``ccf.posture.evidence`` applies to 800-53 ids,
#: and for the same reason: passing one test does not demonstrate a whole
#: requirement, but failing it does contradict every requirement that relies on
#: the thing that failed.
CHECK_PRACTICES: dict[str, tuple[str, ...]] = {
    # ── Identification and authentication ────────────────────────────────────
    # IA.L2-3.5.3  "Use multifactor authentication for local and network access
    #               to privileged accounts and for network access to
    #               non-privileged accounts."
    "aws.iam.root_mfa_enabled": ("IA.L2-3.5.3",),
    "m365.identity.mfa_registered": ("IA.L2-3.5.3",),
    # Legacy authentication protocols cannot present a second factor, so a
    # tenant that still allows them has not met 3.5.3 whatever its MFA policy
    # says. The check is evidence about the same requirement, not a separate one.
    "m365.policy.legacy_auth_blocked": ("IA.L2-3.5.3",),
    # IA.L2-3.5.4  "Employ replay-resistant authentication mechanisms for
    #               network access to privileged and non-privileged accounts."
    # FIDO2 and certificate-based authentication are the replay-resistant
    # mechanisms; enabling one is what 3.5.4 asks for, and it is also a stronger
    # form of the 3.5.3 factor, hence both.
    "m365.identity.phishing_resistant_mfa": ("IA.L2-3.5.4", "IA.L2-3.5.3"),
    # Disabling SMS and voice one-time codes removes the interceptable
    # mechanisms, which is the same requirement approached from the other side.
    "m365.identity.phishable_methods_disabled": ("IA.L2-3.5.4",),
    # IA.L2-3.5.6  "Disable identifiers after a defined period of inactivity."
    "m365.identity.stale_accounts": ("IA.L2-3.5.6",),
    # IA.L2-3.5.7  "Enforce a minimum password complexity and change of
    #               characters when new passwords are created."
    # IA.L2-3.5.8  "Prohibit password reuse for a specified number of
    #               generations."
    # The check asserts both halves -- at least 14 characters, and no reuse of
    # the last 24 -- so it is evidence for both, and a failure could be either.
    "aws.iam.password_policy": ("IA.L2-3.5.7", "IA.L2-3.5.8"),
    # ── Access control ───────────────────────────────────────────────────────
    # AC.L2-3.1.1   "Limit system access to authorized users, processes acting
    #                on behalf of authorized users, and devices."
    # Restricting who may invite guests is a limit on who can become an
    # authorized user of the tenant.
    "m365.policy.guest_invites_restricted": ("AC.L2-3.1.1",),
    # AC.L2-3.1.5   "Employ the principle of least privilege, including for
    #                specific security functions and privileged accounts."
    "m365.policy.default_user_permissions_restricted": ("AC.L2-3.1.5",),
    # AC.L2-3.1.8   "Limit unsuccessful logon attempts."
    # A lockout threshold is the limit, stated as a number. Nothing else in the
    # tenant expresses this requirement.
    "m365.identity.lockout_threshold_enforced": ("AC.L2-3.1.8",),
    # AC.L2-3.1.10  "Use session lock with pattern-hiding displays to prevent
    #                access and viewing of data after a period of inactivity."
    "m365.device.session_lock_enforced": ("AC.L2-3.1.10",),
    # AC.L2-3.1.19  "Encrypt CUI on mobile devices and mobile computing
    #                platforms."
    # SC.L2-3.13.16 "Protect the confidentiality of CUI at rest."
    # The policy governs mobile devices specifically, so 3.1.19 leads.
    "m365.device.storage_encryption_required": ("AC.L2-3.1.19", "SC.L2-3.13.16"),
    # AC.L2-3.1.22  "Control CUI posted or processed on publicly accessible
    #                systems."
    "aws.s3.public_access_blocked": ("AC.L2-3.1.22",),
    # ── Boundary protection ──────────────────────────────────────────────────
    # CM.L2-3.4.7   "Restrict, disable, or prevent the use of nonessential
    #                programs, functions, ports, protocols, and services."
    # SC.L2-3.13.6  "Deny network communications traffic by default and allow
    #                network communications traffic by exception."
    # SSH and RDP reachable from the whole internet is the canonical failure of
    # both: a nonessential port left open, and traffic permitted by default. The
    # check is narrow on purpose (only 22 and 3389, only 0.0.0.0/0 and ::/0), so
    # a load balancer on 443 is not a finding.
    "aws.ec2.security_groups_no_public_admin_ingress": (
        "CM.L2-3.4.7",
        "SC.L2-3.13.6",
    ),
    # SC.L2-3.13.1  "Monitor, control, and protect communications ... at the
    #                external boundaries and key internal boundaries."
    # SI.L2-3.14.6  "Monitor organizational systems, including inbound and
    #                outbound communications traffic, to detect attacks."
    # Flow logs are the record of traffic crossing the VPC boundary. Without one
    # there is nothing to monitor, which is what both requirements ask for; 3.13.1
    # leads because the boundary is what a VPC is.
    "aws.vpc.flow_logs_enabled": ("SC.L2-3.13.1", "SI.L2-3.14.6"),
    # SC.L2-3.13.5  "Implement subnetworks for publicly accessible system
    #                components that are physically or logically separated from
    #                internal networks."
    # A publicly accessible database is the plainest machine-readable violation:
    # an internal component sitting on the public network rather than behind the
    # subnetwork that should separate it.
    "aws.rds.not_publicly_accessible": ("SC.L2-3.13.5",),
    # ── Audit and accountability ─────────────────────────────────────────────
    # AU.L2-3.3.1  "Create and retain system audit logs and records to the
    #               extent needed to enable the monitoring, analysis,
    #               investigation, and reporting of unlawful or unauthorized
    #               system activity."
    "aws.cloudtrail.multi_region_logging": ("AU.L2-3.3.1",),
    # Retention checks evidence the "and retain" half of the same requirement.
    "azure.monitor.log_retention": ("AU.L2-3.3.1",),
    "gcp.logging.retention": ("AU.L2-3.3.1",),
    # AU.L2-3.3.2  "Ensure that the actions of individual system users can be
    #               uniquely traced to those users."
    # Sign-in and directory-change records are per-user by construction, so they
    # evidence traceability as well as the existence of the log.
    "m365.audit.signin_records_current": ("AU.L2-3.3.1", "AU.L2-3.3.2"),
    "m365.audit.directory_changes_recorded": ("AU.L2-3.3.1", "AU.L2-3.3.2"),
    # AU.L2-3.3.8  "Protect audit information and audit logging tools from
    #               unauthorized access, modification, and deletion."
    # Log file validation is the integrity mechanism that detects modification.
    "aws.cloudtrail.log_file_validation": ("AU.L2-3.3.8",),
    # ── Configuration management ─────────────────────────────────────────────
    # CM.L2-3.4.2  "Establish and enforce security configuration settings for
    #               information technology products employed in organizational
    #               systems."
    # The operative word in all four is *enforce*: each check distinguishes an
    # enforcing configuration from an advisory one.
    "azure.policy.baseline_enforced": ("CM.L2-3.4.2",),
    "gcp.orgpolicy.constraints_enforced": ("CM.L2-3.4.2",),
    "m365.device.compliance_enforced": ("CM.L2-3.4.2",),
    "puppetdb.node.last_run_succeeded": ("CM.L2-3.4.2",),
    # CM.L2-3.4.1  "Establish and maintain baseline configurations and
    #               inventories of organizational systems."
    # A node that reports to PuppetDB is a node in the inventory; one that has
    # stopped reporting is missing from it.
    "puppetdb.node.reporting": ("CM.L2-3.4.1",),
    # ── System and communications protection ─────────────────────────────────
    # SC.L2-3.13.16 "Protect the confidentiality of CUI at rest."
    "aws.s3.default_encryption": ("SC.L2-3.13.16",),
    "aws.ec2.ebs_encryption_by_default": ("SC.L2-3.13.16",),
    "azure.storage.encryption_at_rest": ("SC.L2-3.13.16",),
    # SC.L2-3.13.10 "Establish and manage cryptographic keys for cryptography
    #                employed in organizational systems."
    # A customer-managed key is the key-management claim; it also protects data
    # at rest, so 3.13.16 follows it.
    "gcp.storage.customer_managed_keys": ("SC.L2-3.13.10", "SC.L2-3.13.16"),
    # SC.L2-3.13.8  "Implement cryptographic mechanisms to prevent unauthorized
    #                disclosure of CUI during transmission unless otherwise
    #                protected by alternative physical safeguards."
    "azure.storage.https_only": ("SC.L2-3.13.8",),
    # ── Media protection ─────────────────────────────────────────────────────
    # MP.L2-3.8.7   "Control the use of removable media on system components."
    # A device restriction blocking removable storage is that control, expressed
    # on the component. Distinct from 3.8.6, which is about *encrypting* CUI on
    # media -- the device-encryption check carries that one.
    "m365.device.removable_storage_blocked": ("MP.L2-3.8.7",),
    # ── Flaw and threat response ─────────────────────────────────────────────
    # SI.L2-3.14.3  "Monitor system security alerts and advisories and take
    #                action in response."
    # The check observes both halves: alerts are being surfaced, and the
    # high-severity ones are not sitting unactioned. An alert left `new` for
    # months is the absence of the response the requirement asks for.
    "m365.security.alerts_triaged": ("SI.L2-3.14.3",),
}

#: Checks deliberately left unmapped, and the argument that would be needed.
#:
#: Present so the gap is a decision rather than an omission. These keep landing
#: in ``generate_statements``' ``findings_unmatched_controls``, which is the
#: honest outcome: the verdict exists, the document cannot place it, and both
#: facts are visible.
UNMAPPED: dict[str, str] = {
    "aws.iam.access_key_rotation": (
        "800-171 has no authenticator-lifetime requirement. 3.5.5 and 3.5.6 "
        "govern identifiers, not credential age, and reading a 90-day key "
        "rotation as either would file a finding against a requirement that "
        "does not ask for it."
    ),
    "azure.defender.workload_protection": (
        "The check asserts that at least one Defender plan is on the Standard "
        "tier, which does not establish which protection is running. 3.14.2 "
        "(malicious code), 3.14.6 (attack detection) and 3.11.2 (vulnerability "
        "scanning) are each plausible and none is demonstrated."
    ),
    "m365.identity.risky_users_resolved": (
        "Identity Protection risk detections are not a named 800-171 practice. "
        "The nearest candidates -- 3.3.5 (correlate audit review) and 3.14.6 "
        "(monitor to detect attacks) -- both describe a process the check does "
        "not observe."
    ),
    "m365.policy.session_reauthentication_required": (
        "Conditional Access sign-in frequency forces re-authentication; it does "
        "not terminate a session (3.1.11) or a network connection (3.13.9). "
        "Treating it as either is the same substitution that put an eight-hour "
        "'inactivity period' under the session-lock requirement."
    ),
}


def practices_for_check(check_key: str | None) -> tuple[str, ...]:
    """CMMC practices this check evidences, or empty when unmapped."""
    if not check_key:
        return ()
    return CHECK_PRACTICES.get(check_key, ())
