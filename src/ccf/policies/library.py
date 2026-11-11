"""The policy, plan and procedure template catalog.

Provenance
----------
The 23 policies are adapted from the ``POLICY_TEMPLATES`` list in m365-docs-hub's
``src/services/policy-management-service.ts``, and the plans and procedures from
the ``POLICY_STATEMENTS`` table in its ``src/services/supplemental-doc-service.ts``.
Both were written by SBS Federal. Where that source had no text for a plan, the
text here was written for Concord from NIST SP 800-53 Rev. 5 and the relevant
NIST special publication; each template's ``provenance`` says which.

Rewriting rules applied to every template
-----------------------------------------
A. Every value an organization must choose -- a duration, count, threshold,
   frequency, retention period, timeout or deadline -- is a ``{{parameter}}``
   declared in that template's ``parameters``. A parameter's hint may record the
   value the source text used and what NIST or FedRAMP guidance says, but no
   parameter carries a default. The same concept uses the same key in every
   template (``access_review_frequency``, ``remediation_deadline_high`` ...).
B. No named vendor product, service or cloud offering appears in any template.
   Capability language replaces it: "the organization's identity provider",
   "privileged access management", "endpoint management", "the SIEM",
   "conditional access controls", "the authorized cloud environment".
C. A template states requirements the organization adopts ("shall"). It never
   claims that something is already in place, and it carries no status, score,
   count, evidence list or traceability matrix.
D. Scope reads "systems that process, store, or transmit {{organization}}
   information, including Controlled Unclassified Information (CUI) where
   applicable".
E. Citations are limited to publications and clauses that exist under the
   number given.

Every template has the same seven sections in the same order; the fourth is
headed "Policy", "Plan" or "Procedure" according to its kind. ``{{organization}}``
and ``{{policy_owner}}`` are context tokens and are never declared as parameters.
"""

from __future__ import annotations

from ccf.policies.templates import Parameter, Section, Template

_SRC_POLICY = (
    "Adapted from m365-docs-hub policy-management-service.ts (SBS Federal); "
    "product-specific assertions removed and fixed values parameterized."
)

#: One label per parameter key, so a key reused across templates reads the same.
_LABELS: dict[str, str] = {
    "access_review_frequency": "Access review frequency",
    "account_disable_after_separation": "Time to revoke access after separation or role change",
    "account_lockout_duration": "Account lockout duration",
    "account_lockout_threshold": "Consecutive failed logon attempts before lockout",
    "acceptable_use_acknowledgment_frequency": "Acceptable use re-acknowledgment frequency",
    "actively_exploited_remediation_deadline": (
        "Remediation deadline for actively exploited vulnerabilities"
    ),
    "audit_analysis_frequency": "Audit reduction and analysis frequency",
    "audit_log_online_retention": "Audit log online retention period",
    "audit_log_retention": "Audit log total retention period (online and archived)",
    "audit_log_review_frequency": "Audit log review frequency",
    "audit_summary_report_frequency": "Audit summary report frequency",
    "authentication_log_review_frequency": "Authentication log review frequency",
    "awareness_training_frequency": "Security awareness refresher training frequency",
    "backup_integrity_check_frequency": "Backup integrity verification frequency",
    "backup_test_restore_frequency": "Backup test restoration frequency",
    "badge_deactivation_deadline": "Time to deactivate a badge after separation or transfer",
    "baseline_review_frequency": "Baseline configuration review frequency",
    "byod_prohibited_impact_level": (
        "Lowest FIPS 199 impact level at which personally owned devices are prohibited"
    ),
    "communication_template_test_frequency": "Incident communication template test frequency",
    "configuration_scan_frequency": "Configuration compliance scan frequency",
    "conmon_report_frequency": "Continuous monitoring status report frequency",
    "contingency_plan_test_frequency": "Contingency plan test frequency",
    "contingency_scope_impact_level": (
        "Lowest FIPS 199 impact level requiring a contingency plan and automated backup"
    ),
    "contingency_training_frequency": "Contingency role training frequency",
    "critical_alert_triage_deadline": "Triage deadline for critical security alerts",
    "critical_control_monitoring_frequency": "Monitoring frequency for critical controls",
    "critical_incident_update_interval": "Status update interval for Critical incidents",
    "emergency_change_documentation_deadline": "Deadline to document an emergency change",
    "emergency_maintenance_documentation_deadline": "Deadline to document emergency maintenance",
    "emergency_power_duration": "Minimum emergency power duration for critical systems",
    "external_incident_reporting_deadline": "Deadline for external incident reporting",
    "external_vulnerability_scan_frequency": "Scan frequency for internet-facing assets",
    "full_backup_frequency": "Full backup frequency",
    "guest_account_review_frequency": "Guest and external account review frequency",
    "high_control_assessment_frequency": "Assessment frequency for high-priority controls",
    "high_incident_update_interval": "Status update interval for High incidents",
    "inactive_account_threshold": "Inactivity period before an account is flagged and disabled",
    "incident_records_retention": "Incident records retention period",
    "incident_reporting_deadline": "Deadline for personnel to report a suspected incident",
    "incremental_backup_frequency": "Incremental backup frequency",
    "initial_training_deadline": "Deadline for initial security awareness training",
    "ir_plan_test_frequency": "Incident response test frequency",
    "ir_training_frequency": "Incident response training frequency",
    "leadership_conmon_report_frequency": "Continuous monitoring report frequency to leadership",
    "low_control_assessment_frequency": "Assessment frequency for low-criticality controls",
    "low_incident_update_interval": "Status update interval for Low incidents",
    "maintenance_notice_period": "Advance notice for planned maintenance",
    "maintenance_records_retention": "Maintenance records retention period",
    "malware_signature_update_frequency": "Malware signature update frequency",
    "media_inventory_reconciliation_frequency": "CUI media inventory reconciliation frequency",
    "medium_incident_update_interval": "Status update interval for Medium incidents",
    "minimum_tls_version": "Minimum TLS version",
    "moderate_control_assessment_frequency": "Assessment frequency for moderate controls",
    "noncritical_alert_triage_deadline": "Triage deadline for non-critical security alerts",
    "overdue_training_suspension_deadline": "Grace period before overdue training suspends access",
    "password_composition_rules": "Password composition rules",
    "password_history_count": "Password generations that may not be reused",
    "password_min_length": "Minimum password length",
    "penetration_test_frequency": "Penetration test frequency",
    "phishing_remedial_training_deadline": "Remedial training deadline after a failed simulation",
    "phishing_simulation_frequency": "Phishing simulation frequency",
    "physical_access_review_frequency": "Physical access authorization review frequency",
    "plan_review_frequency": "Plan review frequency",
    "policy_review_frequency": "Policy review frequency",
    "post_incident_review_deadline": "Deadline for the post-incident review",
    "privileged_activation_max_duration": "Maximum privileged role activation duration",
    "privileged_password_change_frequency": "Privileged account password change frequency",
    "procedure_review_frequency": "Procedure review frequency",
    "reinvestigation_frequency": "Maximum interval between personnel reinvestigations",
    "remediation_deadline_critical": "Remediation deadline for Critical vulnerabilities",
    "remediation_deadline_high": "Remediation deadline for High vulnerabilities",
    "remediation_deadline_low": "Remediation deadline for Low vulnerabilities",
    "remediation_deadline_medium": "Remediation deadline for Medium vulnerabilities",
    "remote_access_log_review_frequency": "Remote access log review frequency",
    "recovery_procedure_test_frequency": "Recovery procedure test frequency",
    "risk_assessment_frequency": "Risk assessment update frequency",
    "risk_register_review_frequency": "Risk register review frequency",
    "routine_patch_cycle": "Routine patch cycle",
    "sanitization_records_retention": "Sanitization records retention period",
    "scan_results_retention": "Vulnerability scan results retention period",
    "service_account_certificate_rotation": "Service account certificate rotation frequency",
    "service_account_password_rotation": "Service account password rotation frequency",
    "session_inactivity_timeout": "Session inactivity timeout",
    "standard_control_assessment_frequency": "Assessment frequency for standard controls",
    "supply_chain_risk_review_frequency": "Supply chain risk review frequency",
    "telework_agreement_frequency": "Telework agreement renewal frequency",
    "training_completion_report_frequency": "Training completion report frequency",
    "training_content_review_frequency": "Training content review frequency",
    "training_records_retention": "Training records retention period",
    "user_password_change_frequency": "Standard user password change frequency",
    "vendor_incident_notification_deadline": "Supplier incident notification deadline",
    "vendor_reassessment_frequency": "Supplier security reassessment frequency",
    "visitor_log_review_frequency": "Visitor log review frequency",
    "vulnerability_scan_frequency": "Vulnerability scan frequency",
    "wireless_security_protocol": "Required wireless security protocol",
}


def _p(key: str, hint: str) -> Parameter:
    return Parameter(key=key, label=_LABELS[key], hint=hint)


_BODY_HEADING = {"policy": "Policy", "plan": "Plan", "procedure": "Procedure"}
_REVIEW_KEY = {
    "policy": "policy_review_frequency",
    "plan": "plan_review_frequency",
    "procedure": "procedure_review_frequency",
}

# Hints shared by the remediation-deadline keys, which several templates use.
_FEDRAMP_REMEDIATION = (
    "NIST SP 800-53 Rev. 5 RA-5 and SI-2 leave response times organization-defined; "
    "FedRAMP continuous monitoring guidance has used 30 days for high-risk, 90 days "
    "for moderate-risk and 180 days for low-risk findings."
)


def _default_compliance(kind: str) -> str:
    return (
        "The ISSM and ISSO shall monitor compliance with this " + kind + ". Violations "
        "may result in loss of system access and disciplinary action, up to and "
        "including termination, consistent with {{organization}} personnel policies."
    )


def _default_exceptions(kind: str) -> str:
    return (
        "Exceptions to this " + kind + " shall be requested in writing, shall state the "
        "requirement affected, the resulting risk, and any compensating controls, and "
        "shall be approved by the Authorizing Official (AO) before taking effect. "
        "Approved exceptions shall be recorded and re-evaluated at each review of this "
        + kind
        + "."
    )


def _template(
    *,
    key: str,
    title: str,
    kind: str,
    family: str,
    summary: str,
    controls: tuple[str, ...],
    requirements_171: tuple[str, ...],
    parameters: tuple[Parameter, ...],
    purpose: str,
    roles: str,
    body: str,
    compliance: str,
    review_events: str,
    provenance: str,
    tags: tuple[str, ...],
    scope_extra: str = "",
    exceptions: str | None = None,
    review_source: str = "Source text used annually.",
    review_control: str | None = None,
) -> Template:
    """Assemble a template with the seven sections in their fixed order.

    The review section and its frequency parameter are built here so that every
    template declares the review cadence it uses."""
    review_key = _REVIEW_KEY[kind]
    scope = (
        "This " + kind + " applies to all systems that process, store, or transmit "
        "{{organization}} information, including Controlled Unclassified Information "
        "(CUI) where applicable, and to all personnel, contractors, and other users "
        "who access those systems."
    )
    if scope_extra:
        scope = scope + " " + scope_extra
    review_token = "{{" + review_key + "}}"
    review = (
        f"This {kind} shall be reviewed {review_token} and following {review_events}, "
        "and updated as needed. The review, the record of its outcome, and the "
        "communication of changes to the personnel affected are the responsibility "
        "of {{policy_owner}}."
    )
    review_param = _p(
        review_key,
        "How often this "
        + kind
        + " is reviewed and updated. "
        + review_source
        + " NIST SP 800-53 Rev. 5 "
        + (review_control or family + "-1")
        + " leaves the frequency organization-defined.",
    )
    sections = (
        Section("Purpose", purpose),
        Section("Scope", scope),
        Section("Roles and Responsibilities", roles),
        Section(_BODY_HEADING[kind], body),
        Section("Compliance and Enforcement", compliance),
        Section("Exceptions", exceptions or _default_exceptions(kind)),
        Section("Review and Maintenance", review),
    )
    return Template(
        key=key,
        title=title,
        kind=kind,
        family=family,
        summary=summary,
        controls=controls,
        requirements_171=requirements_171,
        parameters=(*parameters, review_param),
        sections=sections,
        review_frequency="annual",
        provenance=provenance,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# Policies (from POLICY_TEMPLATES)
# ---------------------------------------------------------------------------

ACCESS_CONTROL_POLICY = _template(
    key="access_control_policy",
    title="Access Control Policy",
    kind="policy",
    family="AC",
    summary=(
        "Least privilege, separation of duties and need-to-know for all logical access, "
        "with formal provisioning, periodic review and prompt revocation."
    ),
    controls=("AC-1", "AC-2", "AC-3", "AC-5", "AC-6", "AC-7", "AC-11", "AC-17", "AC-20"),
    requirements_171=("3.1.1", "3.1.2", "3.1.3", "3.1.5", "3.1.7", "3.1.12", "3.1.20"),
    parameters=(
        _p(
            "access_review_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 AC-2 leaves the account "
            "review frequency organization-defined.",
        ),
        _p(
            "account_disable_after_separation",
            "Source text used 24 hours. NIST SP 800-53 Rev. 5 PS-4 and AC-2 leave this "
            "time period organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the requirements for managing logical access to "
        "{{organization}} information systems and data. It defines the principles of "
        "least privilege, separation of duties, and need-to-know that govern all access "
        "decisions within the organization."
    ),
    roles=(
        "System Owners shall approve access to their systems and review access rights "
        "{{access_review_frequency}}. The Information System Security Manager (ISSM) shall "
        "approve any shared or generic account together with its documented compensating "
        "controls, and shares responsibility with System Owners for enforcing this policy. "
        "The Information System Security Officer (ISSO) shall monitor account activity for "
        "conformance with this policy. The Authorizing Official (AO) shall approve "
        "exceptions. Personnel shall use only the access they have been authorized to use."
    ),
    body=(
        "All access shall be explicitly authorized, documented, and reviewed on a "
        "recurring basis to ensure continued appropriateness. Access decisions shall "
        "follow the principles of least privilege, separation of duties, and "
        "need-to-know.\n\n"
        "{{organization}} shall employ role-based access control (RBAC) across all "
        "information systems. User accounts shall be provisioned through a formal request "
        "and approval process, with each account tied to a specific individual. Shared or "
        "generic accounts are prohibited except where explicitly approved by the ISSM with "
        "compensating controls documented. Privileged access shall require multi-factor "
        "authentication and shall be granted through privileged access management for the "
        "minimum duration necessary.\n\n"
        "All access rights shall be reviewed {{access_review_frequency}} by System Owners. "
        "Terminated or transferred personnel shall have access revoked within "
        "{{account_disable_after_separation}} of separation or role change. Remote access "
        "is permitted only through organization-approved virtual private network (VPN) "
        "connections or conditional access controls that verify device compliance."
    ),
    compliance=(
        "Enforcement is the responsibility of the ISSM and System Owners. Violations of "
        "this policy may result in immediate access revocation and disciplinary action up "
        "to and including termination."
    ),
    review_events="significant system changes",
    provenance=_SRC_POLICY,
    tags=("access-control", "rbac", "least-privilege", "privileged-access", "mfa"),
)

REMOTE_ACCESS_POLICY = _template(
    key="remote_access_policy",
    title="Remote Access Policy",
    kind="policy",
    family="AC",
    summary=(
        "Remote access only through managed, encrypted, MFA-protected paths from "
        "organization-managed devices, with monitoring and session time-outs."
    ),
    controls=("AC-1", "AC-17", "AC-17(1)", "AC-17(2)", "AC-19", "AC-20"),
    requirements_171=("3.1.12", "3.1.14", "3.1.18", "3.1.19", "3.1.20"),
    parameters=(
        _p(
            "byod_prohibited_impact_level",
            "A FIPS 199 impact level (low, moderate or high). Source text used moderate. "
            "NIST SP 800-53 Rev. 5 AC-20 lets the organization restrict the use of "
            "non-organizationally owned systems.",
        ),
        _p(
            "telework_agreement_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 PS-6 leaves the review "
            "frequency of access agreements organization-defined.",
        ),
        _p(
            "session_inactivity_timeout",
            "Source text used 15 minutes. NIST SP 800-53 Rev. 5 AC-11 and AC-12 leave "
            "inactivity periods organization-defined; FedRAMP baselines commonly specify "
            "15 minutes for AC-11.",
        ),
        _p(
            "remote_access_log_review_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 AU-6 leaves the review "
            "frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy governs all remote access to {{organization}} information systems. "
        "Remote access introduces additional risk vectors and requires enhanced security "
        "controls to protect the confidentiality, integrity, and availability of the "
        "information those systems hold, including government data."
    ),
    scope_extra=(
        "It covers telework, remote administration, and any connection to organizational "
        "systems from outside organization-controlled facilities."
    ),
    roles=(
        "The ISSO shall review remote access logs {{remote_access_log_review_frequency}} "
        "and report anomalies to the ISSM. The ISSM shall oversee enforcement of this "
        "policy. System Owners shall authorize remote access to their systems. Personnel "
        "who telework shall sign a telework agreement and protect organizational "
        "information and devices at their remote work location."
    ),
    body=(
        "All remote access connections shall traverse organization-managed virtual private "
        "network (VPN) tunnels or conditional access controls that enforce device "
        "compliance, multi-factor authentication, and session controls. Split tunneling is "
        "prohibited on any device accessing CUI.\n\n"
        "Remote endpoints shall be organization-managed devices enrolled in endpoint "
        "management with current compliance baselines, including endpoint detection and "
        "response (EDR), disk encryption, and up-to-date security patches.\n\n"
        "Personally owned devices shall not be permitted to access CUI repositories, the "
        "authorized cloud environment, or any system categorized at "
        "{{byod_prohibited_impact_level}} impact or above. Telework agreements shall be "
        "signed {{telework_agreement_frequency}} and shall include acknowledgment of "
        "security responsibilities.\n\n"
        "All remote sessions are subject to monitoring and logging, and shall time out "
        "automatically after {{session_inactivity_timeout}} of inactivity."
    ),
    compliance=(
        "Violations of this policy shall result in immediate session termination and may "
        "lead to revocation of remote access privileges."
    ),
    review_events="changes in the threat landscape or organizational requirements",
    provenance=_SRC_POLICY,
    tags=("remote-access", "vpn", "conditional-access", "telework", "cui"),
)

SECURITY_AWARENESS_TRAINING_POLICY = _template(
    key="security_awareness_training_policy",
    title="Security Awareness and Training Policy",
    kind="policy",
    family="AT",
    summary=(
        "Initial and recurring security awareness training for all personnel, role-based "
        "training for privileged users, phishing exercises and training records."
    ),
    controls=("AT-1", "AT-2", "AT-3", "AT-4"),
    requirements_171=("3.2.1", "3.2.2", "3.2.3"),
    parameters=(
        _p(
            "awareness_training_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 AT-2 leaves the refresher "
            "frequency organization-defined; at least annually is the common value.",
        ),
        _p(
            "initial_training_deadline",
            "Source text used 5 business days. NIST SP 800-53 Rev. 5 AT-2 requires "
            "training as part of initial training for new users; the deadline is "
            "organization-defined.",
        ),
        _p(
            "training_content_review_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 AT-2 leaves the "
            "content update frequency organization-defined.",
        ),
        _p(
            "training_records_retention",
            "Source text used 3 years. NIST SP 800-53 Rev. 5 AT-4 leaves the retention "
            "period organization-defined.",
        ),
        _p(
            "phishing_simulation_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 AT-2(1) calls for practical "
            "exercises such as simulated phishing; the frequency is organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the requirements for security awareness and role-based "
        "training across {{organization}}, so that personnel who use organizational "
        "systems can recognize and report threats and handle information, including CUI, "
        "correctly."
    ),
    roles=(
        "The ISSM is responsible for the training program curriculum, scheduling, and "
        "compliance tracking. Supervisors shall ensure their personnel complete required "
        "training on time. Privileged users, system administrators, and security personnel "
        "shall complete the role-based training assigned to them. All personnel shall "
        "complete required training within the timeframes this policy sets."
    ),
    body=(
        "All personnel who access information systems processing, storing, or transmitting "
        "CUI shall complete security awareness training before being granted access and "
        "{{awareness_training_frequency}} thereafter. New personnel shall complete initial "
        "security awareness training within {{initial_training_deadline}} of onboarding. "
        "Role-based training is required for personnel with significant security "
        "responsibilities.\n\n"
        "The training program shall cover topics including but not limited to: "
        "recognizing and reporting phishing and social engineering attacks, proper "
        "handling and marking of CUI, password hygiene and multi-factor authentication "
        "usage, physical security awareness, insider threat indicators, incident reporting "
        "procedures, and acceptable use of organizational IT resources. Training content "
        "shall be reviewed and updated {{training_content_review_frequency}} to address "
        "current threats and organizational changes.\n\n"
        "Privileged users, system administrators, and security personnel shall receive "
        "additional role-specific training commensurate with their responsibilities, "
        "including secure configuration management, log analysis, incident response "
        "procedures, and vulnerability management.\n\n"
        "Simulated phishing exercises shall be conducted {{phishing_simulation_frequency}} "
        "to assess organizational resilience. Records of all training completions shall be "
        "maintained for a minimum of {{training_records_retention}}."
    ),
    compliance=(
        "Personnel who fail to complete required training within the specified timeframe "
        "shall have system access suspended until training is completed."
    ),
    review_events="significant changes to threats, systems, or organizational requirements",
    review_source="Source text set no review cadence for the policy itself.",
    provenance=_SRC_POLICY,
    tags=("training", "awareness", "phishing", "insider-threat", "cui-handling"),
)

AUDIT_ACCOUNTABILITY_POLICY = _template(
    key="audit_accountability_policy",
    title="Audit and Accountability Policy",
    kind="policy",
    family="AU",
    summary=(
        "Which events are logged, what each record contains, how long logs are kept, how "
        "they are protected and aggregated, and how often they are reviewed."
    ),
    controls=(
        "AU-1",
        "AU-2",
        "AU-3",
        "AU-4",
        "AU-5",
        "AU-6",
        "AU-7",
        "AU-8",
        "AU-9",
        "AU-11",
        "AU-12",
    ),
    requirements_171=("3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3.8", "3.3.9"),
    parameters=(
        _p(
            "audit_log_online_retention",
            "Source text used 1 year online. NIST SP 800-53 Rev. 5 AU-11 leaves retention "
            "organization-defined; OMB M-21-31 sets log retention expectations for federal "
            "agencies, and contracts or records schedules may require more.",
        ),
        _p(
            "audit_log_retention",
            "Source text used 3 years in archived storage. NIST SP 800-53 Rev. 5 AU-11 "
            "leaves retention organization-defined; OMB M-21-31 sets log retention "
            "expectations for federal agencies, and contracts or records schedules may "
            "require more.",
        ),
        _p(
            "audit_log_review_frequency",
            "Source text used weekly. NIST SP 800-53 Rev. 5 AU-6 leaves the review "
            "frequency organization-defined.",
        ),
        _p(
            "audit_analysis_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 AU-6 and AU-7 leave this "
            "organization-defined.",
        ),
        _p(
            "audit_summary_report_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 AU-6 leaves reporting of "
            "findings organization-defined.",
        ),
    ),
    purpose=(
        "This policy defines the requirements for audit logging, monitoring, and "
        "accountability across {{organization}} information systems. Comprehensive audit "
        "trails are essential for detecting unauthorized activity, supporting incident "
        "investigations, and demonstrating compliance with federal security requirements."
    ),
    roles=(
        "The ISSO shall review audit logs {{audit_log_review_frequency}} and conduct audit "
        "reduction and analysis {{audit_analysis_frequency}}. The ISSM shall receive "
        "summary reports of security-relevant events and trends "
        "{{audit_summary_report_frequency}}. System Owners shall ensure their systems "
        "generate, protect, and forward the audit records this policy requires. The "
        "Authorizing Official (AO) shall be informed of any failure to maintain audit "
        "logging on a system processing CUI."
    ),
    body=(
        "All information systems shall generate audit records for the following events: "
        "successful and failed authentication attempts, privilege escalation, access to "
        "CUI, changes to security configurations, creation and deletion of user accounts, "
        "use of privileged functions, and system startup and shutdown. Audit records shall "
        "include timestamps synchronized to an authoritative time source, user identity, "
        "event type, event outcome, and the affected resource.\n\n"
        "Audit logs shall be retained online for a minimum of "
        "{{audit_log_online_retention}} and in total, including archived storage, for a "
        "minimum of {{audit_log_retention}}.\n\n"
        "Audit logs shall be protected against unauthorized modification and deletion, "
        "and log integrity shall be verified using cryptographic hashing. Audit data shall "
        "be forwarded in near-real time to the organization's Security "
        "Information and Event Management (SIEM) system for correlation, alerting, and "
        "analysis. Automated alerts shall be configured for high-risk events, including "
        "multiple failed authentication attempts, privilege escalation, and after-hours "
        "administrative actions."
    ),
    compliance=(
        "Failure to maintain audit logging on any system processing CUI constitutes a "
        "material finding that shall be reported to the Authorizing Official. Personnel "
        "who disable, alter, or delete audit records without authorization may be subject "
        "to disciplinary action."
    ),
    review_events="any security incident",
    provenance=_SRC_POLICY,
    tags=("audit", "logging", "siem", "accountability", "log-retention"),
)

CONFIGURATION_MANAGEMENT_POLICY = _template(
    key="configuration_management_policy",
    title="Configuration Management Policy",
    kind="policy",
    family="CM",
    summary=(
        "Component inventory, documented secure baselines, formal change control, drift "
        "scanning and least functionality for every system."
    ),
    controls=(
        "CM-1",
        "CM-2",
        "CM-3",
        "CM-4",
        "CM-5",
        "CM-6",
        "CM-7",
        "CM-8",
        "CM-9",
        "CM-10",
        "CM-11",
    ),
    requirements_171=(
        "3.4.1",
        "3.4.2",
        "3.4.3",
        "3.4.4",
        "3.4.5",
        "3.4.6",
        "3.4.7",
        "3.4.8",
        "3.4.9",
    ),
    parameters=(
        _p(
            "emergency_change_documentation_deadline",
            "Source text used 48 hours. NIST SP 800-53 Rev. 5 CM-3 leaves this "
            "organization-defined.",
        ),
        _p(
            "configuration_scan_frequency",
            "Source text used monthly (rendered as 'at least monthly'). NIST SP 800-53 "
            "Rev. 5 CM-6 and CA-7 leave monitoring frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the requirements for configuration management of all "
        "{{organization}} information systems. Effective configuration management ensures "
        "that systems are deployed in a known, secure state and that changes are "
        "controlled, documented, and traceable throughout the system lifecycle."
    ),
    roles=(
        "System Owners shall maintain the component inventory and baseline configurations "
        "for their systems. The Change Advisory Board (CAB) shall approve changes before "
        "they are made. The ISSM shall approve documented risk acceptance for any "
        "deviation from an approved baseline. The ISSO shall review configuration scan "
        "results and initiate a security review of any unauthorized change. System "
        "administrators shall make changes only through the change management process."
    ),
    body=(
        "{{organization}} shall maintain an inventory of all hardware and software "
        "components for each information system. Baseline configurations shall be "
        "established, documented, and maintained for all system components, including "
        "operating systems, middleware, applications, network devices, and security tools. "
        "Baselines shall be derived from vendor guidance, DISA STIGs, CIS benchmarks, and "
        "organizational security requirements. Deviations from approved baselines require "
        "documented risk acceptance from the ISSM.\n\n"
        "All changes to information systems shall follow a formal change management "
        "process that includes a change request, impact analysis, testing in a "
        "non-production environment, approval by the CAB, implementation with rollback "
        "procedures, and post-implementation verification. Emergency changes are "
        "permitted only to address active security incidents and shall be documented "
        "retrospectively within {{emergency_change_documentation_deadline}}. Unauthorized "
        "changes detected through continuous monitoring shall trigger an immediate "
        "security review.\n\n"
        "Configuration scanning shall be performed at least "
        "{{configuration_scan_frequency}} using automated tools to detect drift from "
        "approved baselines. {{organization}} shall employ the principle of least "
        "functionality by disabling unnecessary services, ports, protocols, and software. "
        "Software installation shall be restricted through application allowlisting where "
        "technically feasible."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in system architecture or the threat landscape",
    provenance=_SRC_POLICY,
    tags=("configuration", "baselines", "change-management", "stig", "drift-detection"),
)

CONTINGENCY_PLANNING_POLICY = _template(
    key="contingency_planning_policy",
    title="Contingency Planning Policy",
    kind="policy",
    family="CP",
    summary=(
        "Contingency plans with recovery objectives, alternate processing and backup "
        "strategies, tested on a set cadence and maintained by a coordinator."
    ),
    controls=("CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-7", "CP-9", "CP-10"),
    requirements_171=("3.8.9",),
    parameters=(
        _p(
            "contingency_scope_impact_level",
            "A FIPS 199 impact level (low, moderate or high). Source text used moderate.",
        ),
        _p(
            "contingency_plan_test_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 CP-4 leaves the "
            "test frequency organization-defined.",
        ),
        _p(
            "incremental_backup_frequency",
            "Source text used daily. NIST SP 800-53 Rev. 5 CP-9 requires a frequency "
            "consistent with recovery time and recovery point objectives.",
        ),
        _p(
            "full_backup_frequency",
            "Source text used weekly. NIST SP 800-53 Rev. 5 CP-9 requires a frequency "
            "consistent with recovery time and recovery point objectives.",
        ),
        _p(
            "backup_integrity_check_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 CP-9(1) leaves the testing "
            "frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the requirements for contingency planning to ensure the "
        "continued availability and recoverability of {{organization}} information "
        "systems. Contingency planning addresses the full spectrum of disruptions from "
        "minor outages to catastrophic events, with the objective of minimizing impact to "
        "mission-essential operations."
    ),
    scope_extra="It applies to all information systems within the authorization boundary.",
    roles=(
        "The Contingency Planning Coordinator is responsible for maintaining plans, "
        "scheduling tests, and ensuring corrective actions are completed. System Owners "
        "shall ensure a contingency plan exists and is tested for each system in scope. "
        "All personnel with contingency roles shall be trained on their responsibilities "
        "prior to assuming those roles."
    ),
    body=(
        "{{organization}} shall develop, maintain, and test contingency plans for all "
        "information systems categorized at {{contingency_scope_impact_level}} impact or "
        "above. Each contingency plan shall define recovery time objectives (RTO), "
        "recovery point objectives (RPO), roles and responsibilities, escalation "
        "procedures, communication plans, and alternate processing site arrangements. "
        "Plans shall address data backup strategies, including frequency, retention, "
        "encryption, and geographic separation of backup media.\n\n"
        "Contingency plan testing shall be conducted {{contingency_plan_test_frequency}} "
        "using a combination of tabletop exercises, functional tests, and full-scale "
        "recovery exercises. Test results shall be documented, including lessons learned "
        "and corrective actions.\n\n"
        "Information system backups shall be performed {{incremental_backup_frequency}} "
        "for incremental backups and {{full_backup_frequency}} for full backups, with "
        "backup integrity verification performed {{backup_integrity_check_frequency}}. "
        "Backup data shall be encrypted in transit and at rest using FIPS 140-validated "
        "cryptographic modules."
    ),
    compliance=_default_compliance("policy"),
    review_events="any contingency plan activation",
    provenance=_SRC_POLICY,
    tags=("contingency", "disaster-recovery", "backup", "business-continuity", "rto", "rpo"),
)

IDENTIFICATION_AUTHENTICATION_POLICY = _template(
    key="identification_authentication_policy",
    title="Identification and Authentication Policy",
    kind="policy",
    family="IA",
    summary=(
        "Unique identification, mandatory MFA, password and lockout rules, and device "
        "identification before access to any system."
    ),
    controls=(
        "IA-1",
        "IA-2",
        "IA-2(1)",
        "IA-2(2)",
        "IA-3",
        "IA-4",
        "IA-5",
        "IA-5(1)",
        "IA-6",
        "IA-8",
    ),
    requirements_171=(
        "3.5.1",
        "3.5.2",
        "3.5.3",
        "3.5.4",
        "3.5.7",
        "3.5.8",
        "3.5.10",
        "3.5.11",
    ),
    parameters=(
        _p(
            "password_min_length",
            "Include the unit. Source text used 14 characters. NIST SP 800-53 Rev. 5 "
            "IA-5(1) and NIST SP 800-63B govern password length.",
        ),
        _p(
            "password_composition_rules",
            "Source text required uppercase, lowercase, numbers and special characters. "
            "NIST SP 800-53 Rev. 5 IA-5(1) leaves composition rules organization-defined; "
            "NIST SP 800-63B recommends against imposing composition rules.",
        ),
        _p(
            "password_history_count",
            "A number. Source text used 24. NIST SP 800-171 Rev. 2 3.5.8 leaves the number "
            "of generations organization-defined.",
        ),
        _p(
            "account_lockout_threshold",
            "A number. Source text used 5. NIST SP 800-53 Rev. 5 AC-7 leaves the number "
            "of attempts organization-defined.",
        ),
        _p(
            "account_lockout_duration",
            "Source text used 30 minutes. NIST SP 800-53 Rev. 5 AC-7 leaves the lockout "
            "period organization-defined.",
        ),
        _p(
            "privileged_password_change_frequency",
            "Source text used 60 days. NIST SP 800-63B recommends against periodic forced "
            "changes absent evidence of compromise, and NIST SP 800-53 Rev. 5 IA-5(1) "
            "does not require a maximum lifetime.",
        ),
        _p(
            "user_password_change_frequency",
            "Source text used 90 days. NIST SP 800-63B recommends against periodic forced "
            "changes absent evidence of compromise, and NIST SP 800-53 Rev. 5 IA-5(1) "
            "does not require a maximum lifetime.",
        ),
        _p(
            "authentication_log_review_frequency",
            "Source text used weekly. NIST SP 800-53 Rev. 5 AU-6 leaves the review "
            "frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy defines the requirements for identifying and authenticating users, "
        "processes, and devices before granting access to {{organization}} information "
        "systems. Strong identification and authentication mechanisms are the foundation "
        "of access control and are required for all systems processing CUI."
    ),
    roles=(
        "The ISSO shall review authentication logs {{authentication_log_review_frequency}} "
        "for anomalous patterns. The ISSM shall approve the authenticator types permitted "
        "under this policy. System Owners shall ensure their systems authenticate users "
        "through the organization's identity provider. Personnel shall protect their "
        "authenticators and report loss or suspected compromise immediately."
    ),
    body=(
        "All users shall be uniquely identified through organization-issued identifiers "
        "managed in the organization's identity provider. Multi-factor authentication "
        "(MFA) is mandatory for all interactive sessions, including local, remote, and "
        "privileged access. Acceptable MFA methods include FIDO2 security keys, "
        "authenticator application push notifications, and certificate-based "
        "authentication. SMS-based one-time passcodes are not approved for systems "
        "processing CUI. Service accounts and non-person entities shall use "
        "certificate-based or platform-issued workload identity authentication where "
        "technically feasible.\n\n"
        "Passwords shall be a minimum of {{password_min_length}} and shall meet the "
        "following composition rules: {{password_composition_rules}}. Passwords shall not "
        "contain the user's name or common dictionary words. Password reuse shall be "
        "prohibited for {{password_history_count}} generations. Accounts shall lock after "
        "{{account_lockout_threshold}} consecutive failed attempts for "
        "{{account_lockout_duration}}. Passwords for privileged accounts shall be changed "
        "every {{privileged_password_change_frequency}} and standard user passwords every "
        "{{user_password_change_frequency}}, and any password shall be changed upon "
        "suspected compromise.\n\n"
        "Device identification is required for all endpoints connecting to the "
        "organization's network. Devices shall present valid certificates or be "
        "registered in the organization's identity provider with verified compliance "
        "status. Network access control shall deny connections from unrecognized devices."
    ),
    compliance=_default_compliance("policy"),
    review_events="significant advances in authentication technology or changes in threats",
    provenance=_SRC_POLICY,
    tags=("authentication", "mfa", "passwords", "fido2", "identity"),
)

INCIDENT_RESPONSE_POLICY = _template(
    key="incident_response_policy",
    title="Incident Response Policy",
    kind="policy",
    family="IR",
    summary=(
        "An incident response capability with a CSIRT, severity taxonomy, reporting "
        "deadlines, NIST SP 800-61 phases, evidence preservation and lessons learned."
    ),
    controls=("IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8"),
    requirements_171=("3.6.1", "3.6.2", "3.6.3"),
    parameters=(
        _p(
            "incident_reporting_deadline",
            "Source text used 1 hour. NIST SP 800-53 Rev. 5 IR-6 leaves this time period "
            "organization-defined.",
        ),
        _p(
            "external_incident_reporting_deadline",
            "Source text used 72 hours, the DFARS 252.204-7012 reporting window for DoD "
            "contractors. Set no longer than any contractual or regulatory deadline that "
            "applies to the organization.",
        ),
        _p(
            "post_incident_review_deadline",
            "Source text used 5 business days. NIST SP 800-53 Rev. 5 IR-4 leaves this "
            "organization-defined.",
        ),
        _p(
            "ir_plan_test_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 IR-3 leaves the "
            "test frequency organization-defined.",
        ),
        _p(
            "incident_records_retention",
            "Source text used 3 years. Contracts and records schedules may require more.",
        ),
    ),
    purpose=(
        "This policy establishes the {{organization}} incident response capability and "
        "defines the processes for detecting, analyzing, containing, eradicating, and "
        "recovering from security incidents. A well-defined incident response capability "
        "is critical for minimizing damage, reducing recovery time, and meeting federal "
        "reporting requirements for information systems processing CUI."
    ),
    roles=(
        "The Computer Security Incident Response Team (CSIRT) shall handle incidents, with "
        "an Incident Commander who leads the response, a Lead Analyst, a Communications "
        "Coordinator, and a Legal Liaison. The ISSM shall oversee the incident response "
        "capability and ensure required notifications are made. All personnel shall "
        "report suspected security incidents to the CSIRT within "
        "{{incident_reporting_deadline}} of detection."
    ),
    body=(
        "{{organization}} shall establish a CSIRT with defined roles including Incident "
        "Commander, Lead Analyst, Communications Coordinator, and Legal Liaison. The CSIRT "
        "shall maintain an incident classification taxonomy with severity levels "
        "(Critical, High, Medium, Low) that drive response timelines and escalation "
        "procedures. Automated detection mechanisms, including the SIEM and endpoint "
        "detection and response, shall provide continuous monitoring and automated "
        "alerting.\n\n"
        "Incident response shall follow the phases described in NIST SP 800-61: "
        "preparation; detection and analysis; containment (short-term and long-term), "
        "eradication, and recovery; and post-incident activity. For incidents involving "
        "CUI spillage or suspected compromise of federal data, {{organization}} shall "
        "notify the contracting agency, and the Department of Defense through DIBNet "
        "where DFARS 252.204-7012 applies, within "
        "{{external_incident_reporting_deadline}}. Forensic evidence shall be preserved "
        "using chain-of-custody procedures, and affected systems shall be isolated to "
        "prevent lateral movement.\n\n"
        "Post-incident reviews shall be conducted within {{post_incident_review_deadline}} "
        "of incident closure. Lessons learned shall be documented and incorporated into "
        "updated incident response procedures, security controls, and training materials. "
        "The incident response capability shall be tested {{ir_plan_test_frequency}} "
        "through tabletop exercises and simulated incident scenarios. All incident records "
        "shall be retained for a minimum of {{incident_records_retention}}."
    ),
    compliance=_default_compliance("policy"),
    review_events="any significant security incident",
    provenance=(
        _SRC_POLICY + " The source titled this text 'Incident Response Plan'; it is a "
        "policy and is keyed apart from incident_response_plan. The source's 'DIBCIS' "
        "reporting reference was replaced with DIBNet, the DFARS 252.204-7012 channel."
    ),
    tags=("incident-response", "csirt", "dfars", "forensics", "cui-spillage"),
)

INCIDENT_RESPONSE_COMMUNICATIONS_POLICY = _template(
    key="incident_response_communications_policy",
    title="Incident Response Communications Policy",
    kind="policy",
    family="IR",
    summary=(
        "Who speaks for an incident, out-of-band channels, update intervals by severity, "
        "and regulatory, law-enforcement and media notifications."
    ),
    controls=("IR-1", "IR-6", "IR-6(1)", "IR-7", "IR-7(1)"),
    requirements_171=("3.6.2", "3.6.3"),
    parameters=(
        _p("critical_incident_update_interval", "Source text used every 2 hours."),
        _p("high_incident_update_interval", "Source text used every 4 hours."),
        _p("medium_incident_update_interval", "Source text used daily."),
        _p("low_incident_update_interval", "Source text used upon resolution."),
        _p(
            "external_incident_reporting_deadline",
            "Source text used 72 hours, the DFARS 252.204-7012 reporting window for DoD "
            "contractors. Set no longer than any contractual or regulatory deadline that "
            "applies to the organization.",
        ),
        _p("communication_template_test_frequency", "Source text used annually."),
    ),
    purpose=(
        "This policy defines the communication protocols and notification requirements "
        "during security incidents. Effective communication is essential for coordinating "
        "response efforts, meeting regulatory reporting obligations, and maintaining "
        "stakeholder confidence during incident handling."
    ),
    roles=(
        "The Incident Commander is the single point of authority for all incident-related "
        "communications. The Legal Liaison shall coordinate any notification to law "
        "enforcement. The designated Public Affairs Officer shall handle all media "
        "inquiries. No other personnel are authorized to discuss incidents with external "
        "parties."
    ),
    body=(
        "Internal communications shall use pre-established out-of-band channels, such as "
        "encrypted phone bridges or pre-approved messaging platforms, to prevent adversary "
        "awareness of response activities. Status updates shall be provided to "
        "organizational leadership at intervals based on incident severity: Critical "
        "incidents {{critical_incident_update_interval}}, High "
        "{{high_incident_update_interval}}, Medium {{medium_incident_update_interval}}, "
        "and Low {{low_incident_update_interval}}.\n\n"
        "External notifications shall comply with all applicable regulatory requirements. "
        "Incidents involving CUI require notification to the prime contractor or "
        "contracting agency, and to the Department of Defense through DIBNet where DFARS "
        "252.204-7012 applies, within {{external_incident_reporting_deadline}}. If "
        "personally identifiable information (PII) is compromised, {{organization}} shall "
        "comply with applicable breach notification laws. Law enforcement notification is "
        "required for incidents involving suspected criminal activity and shall be "
        "coordinated through the Legal Liaison.\n\n"
        "Communication templates for common incident scenarios shall be maintained and "
        "tested {{communication_template_test_frequency}}. All incident communications "
        "shall be logged and preserved as part of the incident record. Media inquiries "
        "shall be directed exclusively to the designated Public Affairs Officer."
    ),
    compliance=(
        "No personnel are authorized to discuss incidents on social media or with "
        "unauthorized parties. Unauthorized disclosure of incident information may result "
        "in disciplinary action."
    ),
    review_events="any significant incident, and alongside each review of the incident "
    "response plan",
    provenance=(
        _SRC_POLICY + " The source titled this text 'Incident Response Communications "
        "Plan'; its content is policy. The source's 'DIBCIS' reporting reference was "
        "replaced with DIBNet, the DFARS 252.204-7012 channel."
    ),
    tags=("incident-communications", "dfars", "notification", "breach-response"),
)

SYSTEM_MAINTENANCE_POLICY = _template(
    key="system_maintenance_policy",
    title="System Maintenance Policy",
    kind="policy",
    family="MA",
    summary=(
        "Scheduled, approved and documented maintenance, controlled remote maintenance "
        "and maintenance personnel, and severity-based patching."
    ),
    controls=("MA-1", "MA-2", "MA-3", "MA-4", "MA-5", "MA-6"),
    requirements_171=("3.7.1", "3.7.2", "3.7.5", "3.7.6"),
    parameters=(
        _p("maintenance_notice_period", "Source text used 48 hours."),
        _p(
            "emergency_maintenance_documentation_deadline",
            "Source text used 24 hours.",
        ),
        _p(
            "maintenance_records_retention",
            "Source text used 3 years. NIST SP 800-53 Rev. 5 MA-2 leaves record keeping "
            "organization-defined.",
        ),
        _p(
            "remediation_deadline_critical",
            "Source text here used 30 days for Critical and High patches together; other "
            "source policies used 15 days for Critical. " + _FEDRAMP_REMEDIATION,
        ),
        _p(
            "remediation_deadline_high",
            "Source text used 30 days. " + _FEDRAMP_REMEDIATION,
        ),
        _p(
            "routine_patch_cycle",
            "Source text used monthly (rendered as 'the monthly maintenance cycle').",
        ),
    ),
    purpose=(
        "This policy establishes requirements for the maintenance of {{organization}} "
        "information systems. Proper maintenance practices are essential for ensuring "
        "system reliability, security, and compliance with federal standards. Maintenance "
        "activities shall be planned, documented, and executed in a controlled manner that "
        "does not compromise the security posture of the information system."
    ),
    roles=(
        "The ISSM shall approve maintenance activities, including verbal approval of "
        "emergency maintenance. System administrators shall perform and document "
        "maintenance. Authorized personnel shall escort and monitor maintenance personnel "
        "who are not regular system administrators, and shall monitor remote maintenance "
        "sessions in real time."
    ),
    body=(
        "All maintenance activities, whether performed locally or remotely, shall be "
        "scheduled, approved, and documented. Maintenance windows shall be communicated to "
        "affected users at least {{maintenance_notice_period}} in advance for planned "
        "activities. Emergency maintenance to address active security vulnerabilities or "
        "system failures may proceed with verbal ISSM approval, followed by written "
        "documentation within {{emergency_maintenance_documentation_deadline}}. Remote "
        "maintenance sessions shall require multi-factor authentication, encrypted "
        "connections, and real-time monitoring by authorized personnel.\n\n"
        "Maintenance personnel who are not regular system administrators shall be escorted "
        "and their activities monitored and logged. All maintenance tools brought onto the "
        "premises shall be inspected and approved. Diagnostic and test equipment shall be "
        "checked for malicious code and sanitized before use on production systems. "
        "Maintenance records shall include the date, description of work performed, "
        "personnel involved, components affected, and any security-relevant observations, "
        "and shall be retained for {{maintenance_records_retention}}.\n\n"
        "Patch management is a critical maintenance function. Security patches rated "
        "Critical by the vendor shall be applied within {{remediation_deadline_critical}} "
        "and those rated High within {{remediation_deadline_high}} of release, or "
        "compensating controls shall be documented. Routine patches shall be applied "
        "within the {{routine_patch_cycle}} maintenance cycle. All patches shall be tested "
        "in a non-production environment prior to deployment."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in system architecture or maintenance requirements",
    provenance=_SRC_POLICY,
    tags=("maintenance", "patching", "remote-maintenance", "change-windows"),
)

MEDIA_PROTECTION_POLICY = _template(
    key="media_protection_policy",
    title="Media Protection Policy",
    kind="policy",
    family="MP",
    summary=(
        "Encryption, marking, storage, transport, inventory and NIST SP 800-88 "
        "sanitization of media containing CUI."
    ),
    controls=("MP-1", "MP-2", "MP-3", "MP-4", "MP-5", "MP-6", "MP-7"),
    requirements_171=("3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5", "3.8.6", "3.8.7"),
    parameters=(_p("media_inventory_reconciliation_frequency", "Source text used quarterly."),),
    purpose=(
        "This policy establishes the requirements for protecting information system media "
        "containing CUI. Media protection controls ensure that CUI stored on digital and "
        "non-digital media is safeguarded against unauthorized access, disclosure, and "
        "destruction throughout its lifecycle, from creation through disposal."
    ),
    roles=(
        "The ISSM shall approve all media disposal procedures. System Owners shall ensure "
        "media used by their systems is encrypted, inventoried, and sanitized as this "
        "policy requires. Personnel who handle CUI media shall mark, store, transport, and "
        "dispose of it in accordance with this policy."
    ),
    body=(
        "All digital media containing CUI shall be encrypted using FIPS 140-validated "
        "cryptographic modules. This includes hard drives, solid-state drives, USB storage "
        "devices, backup tapes, and optical media. Endpoint disk encryption shall use a "
        "FIPS 140-validated full-disk encryption capability protected by a hardware root "
        "of trust such as a Trusted Platform Module (TPM). Removable media usage shall be "
        "restricted through endpoint management device configuration, and only "
        "organization-approved encrypted devices are permitted. The use of personal "
        "removable media on organizational systems is prohibited.\n\n"
        "Physical media containing CUI shall be marked with appropriate CUI banners and "
        "handling instructions. Storage of CUI media requires controlled areas with access "
        "limited to authorized personnel. Transport of CUI media outside organizational "
        "facilities requires encryption, tamper-evident packaging, and an authorized "
        "courier or tracked shipping service. An inventory of all media containing CUI "
        "shall be maintained and reconciled {{media_inventory_reconciliation_frequency}}."
        "\n\n"
        "Media sanitization prior to disposal or reuse shall follow NIST SP 800-88. Hard "
        "drives shall be purged using approved tools or physically destroyed. Sanitization "
        "actions shall be documented, including the method used, date, responsible "
        "individual, and verification of sanitization."
    ),
    compliance=_default_compliance("policy"),
    review_events="the introduction of new media technologies or changes in threats",
    provenance=_SRC_POLICY,
    tags=("media-protection", "encryption", "sanitization", "cui-marking", "removable-media"),
)

PERSONNEL_SECURITY_POLICY = _template(
    key="personnel_security_policy",
    title="Personnel Security Policy",
    kind="policy",
    family="PS",
    summary=(
        "Screening before access, reinvestigation, prompt revocation on termination or "
        "transfer, access agreements, and third-party personnel requirements."
    ),
    controls=("PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8"),
    requirements_171=("3.9.1", "3.9.2"),
    parameters=(
        _p(
            "reinvestigation_frequency",
            "Source text used 5 years, or the sponsoring agency's interval if sooner. "
            "NIST SP 800-53 Rev. 5 PS-3 leaves the rescreening frequency "
            "organization-defined.",
        ),
        _p(
            "account_disable_after_separation",
            "Source text used 24 hours. NIST SP 800-53 Rev. 5 PS-4 leaves this time "
            "period organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the personnel security requirements for individuals who "
        "access {{organization}} information systems containing CUI. Personnel security "
        "controls ensure that individuals are trustworthy, understand their security "
        "responsibilities, and are appropriately managed throughout their employment "
        "lifecycle."
    ),
    roles=(
        "Human Resources, IT, and Security shall coordinate personnel transfers and "
        "terminations. Supervisors shall initiate access reviews when personnel change "
        "positions. An authorized organizational official shall sponsor each third-party "
        "individual. Personnel shall sign the access agreements this policy requires "
        "before accessing CUI."
    ),
    body=(
        "All personnel requiring access to CUI shall undergo a background investigation "
        "commensurate with the sensitivity of their assigned duties prior to receiving "
        "access. Investigations shall be conducted in accordance with applicable federal "
        "guidance and organizational requirements. Personnel in positions of significant "
        "trust, including system administrators, security administrators, and individuals "
        "with access to cryptographic materials, require enhanced screening. "
        "Reinvestigations shall be conducted at intervals defined by the sponsoring agency "
        "or every {{reinvestigation_frequency}}, whichever is sooner.\n\n"
        "Upon termination, all access shall be revoked within "
        "{{account_disable_after_separation}}, organization-issued equipment and "
        "credentials shall be returned, and an exit briefing shall be conducted covering "
        "the individual's continuing obligations regarding CUI protection. For involuntary "
        "terminations or terminations for cause, access shall be revoked immediately, and "
        "prior to notification where operationally feasible. Transfers between positions "
        "require an access review to ensure privileges match the new role.\n\n"
        "All personnel shall sign acceptable use agreements and non-disclosure agreements "
        "before accessing CUI. Third-party personnel (contractors, vendors, consultants) "
        "shall meet the same screening requirements as {{organization}} personnel in "
        "equivalent positions and shall be sponsored by an authorized organizational "
        "official."
    ),
    compliance=_default_compliance("policy"),
    review_events="any personnel security incident",
    provenance=(
        _SRC_POLICY + " The source mapped this policy to 800-171 3.10.1 and 3.10.2 "
        "(physical protection); corrected to 3.9.1 and 3.9.2."
    ),
    tags=("personnel-security", "background-check", "termination", "nda", "access-agreements"),
)

PHYSICAL_ENVIRONMENTAL_PROTECTION_POLICY = _template(
    key="physical_environmental_protection_policy",
    title="Physical and Environmental Protection Policy",
    kind="policy",
    family="PE",
    summary=(
        "Layered physical access controls, visitor control, environmental protections, "
        "emergency power and periodic access review for facilities housing systems."
    ),
    controls=(
        "PE-1",
        "PE-2",
        "PE-3",
        "PE-4",
        "PE-5",
        "PE-6",
        "PE-8",
        "PE-9",
        "PE-10",
        "PE-11",
        "PE-12",
        "PE-13",
        "PE-14",
        "PE-15",
    ),
    requirements_171=("3.10.1", "3.10.2", "3.10.3", "3.10.4", "3.10.5", "3.10.6"),
    parameters=(
        _p(
            "visitor_log_review_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 PE-8 leaves the review "
            "frequency organization-defined.",
        ),
        _p(
            "emergency_power_duration",
            "Source text used 8 hours. NIST SP 800-53 Rev. 5 PE-11 leaves emergency power "
            "requirements organization-defined.",
        ),
        _p(
            "physical_access_review_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 PE-2 leaves the review "
            "frequency organization-defined.",
        ),
        _p("badge_deactivation_deadline", "Source text used 24 hours."),
    ),
    purpose=(
        "This policy establishes the requirements for physical and environmental "
        "protection of {{organization}} facilities and information systems. Physical "
        "security controls prevent unauthorized physical access, damage, and interference "
        "to organizational information systems and the facilities in which they are "
        "housed."
    ),
    roles=(
        "The ISSM shall oversee physical and environmental protections for facilities "
        "housing in-scope systems and ensure physical access authorizations are reviewed "
        "{{physical_access_review_frequency}}. Authorized personnel shall escort visitors "
        "within restricted areas. Designated security personnel shall receive and respond "
        "to environmental alerts."
    ),
    body=(
        "All facilities housing information systems that process, store, or transmit CUI "
        "shall have layered physical access controls. These controls include perimeter "
        "security (fencing, exterior lighting, security cameras), building access (card "
        "readers, biometric scanners, security guards), and internal zone controls (locked "
        "server rooms, restricted areas). Visitor access requires escort by authorized "
        "personnel at all times within restricted areas. Visitor logs shall be maintained "
        "and reviewed {{visitor_log_review_frequency}}.\n\n"
        "Environmental controls shall include fire detection and suppression systems (wet "
        "pipe or clean agent), temperature and humidity monitoring with automated "
        "alerting, uninterruptible power supplies (UPS) and backup generators for critical "
        "systems, and water damage detection. Environmental monitoring shall provide "
        "continuous alerting to designated security personnel. Emergency power shall "
        "sustain critical operations for a minimum of {{emergency_power_duration}} or "
        "until orderly shutdown can be completed.\n\n"
        "Physical access authorizations shall be reviewed "
        "{{physical_access_review_frequency}}. Access badges for terminated or transferred "
        "personnel shall be deactivated within {{badge_deactivation_deadline}}. Delivery "
        "and loading areas shall be controlled and monitored. Cabling infrastructure shall "
        "be protected from interception and damage. Emergency exits shall comply with "
        "local fire codes while maintaining security monitoring."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in facility configuration or emerging physical threats",
    provenance=_SRC_POLICY,
    tags=("physical-security", "environmental", "facility", "visitor-control", "cctv"),
)

RISK_ASSESSMENT_POLICY = _template(
    key="risk_assessment_policy",
    title="Risk Assessment Policy",
    kind="policy",
    family="RA",
    summary=(
        "RMF-based risk assessments before authorization and on a set cadence, "
        "vulnerability scanning, severity-based remediation, and a living risk register."
    ),
    controls=("RA-1", "RA-2", "RA-3", "RA-5", "RA-7"),
    requirements_171=("3.11.1", "3.11.2", "3.11.3"),
    parameters=(
        _p(
            "risk_assessment_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 RA-3 leaves the "
            "update frequency organization-defined.",
        ),
        _p(
            "vulnerability_scan_frequency",
            "Source text used monthly (rendered as 'at least monthly'). NIST SP 800-53 "
            "Rev. 5 RA-5 leaves the frequency organization-defined; FedRAMP requires "
            "monthly scanning.",
        ),
        _p("external_vulnerability_scan_frequency", "Source text used weekly."),
        _p("remediation_deadline_critical", "Source text used 15 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_high", "Source text used 30 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_medium", "Source text used 90 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_low", "Source text used 180 days. " + _FEDRAMP_REMEDIATION),
    ),
    purpose=(
        "This policy establishes the requirements for conducting risk assessments of "
        "{{organization}} information systems and environments. Risk assessments identify "
        "threats, vulnerabilities, and potential impacts to enable informed risk "
        "management decisions and appropriate resource allocation for security controls."
    ),
    roles=(
        "The Authorizing Official (AO) shall make risk acceptance decisions on the basis "
        "of documented risk assessment results. System Owners shall ensure risk "
        "assessments and vulnerability scans are performed for their systems and that "
        "findings are remediated or tracked. The ISSM shall maintain the risk register. "
        "The ISSO shall review scan results and incorporate threat intelligence into risk "
        "assessment activities."
    ),
    body=(
        "{{organization}} shall conduct comprehensive risk assessments for each "
        "information system prior to authorization and {{risk_assessment_frequency}} "
        "thereafter. Ad hoc risk assessments shall be performed when significant changes "
        "occur to the system, threat landscape, or operating environment. Risk assessments "
        "shall follow the NIST Risk Management Framework (RMF) described in NIST SP 800-37 "
        "and shall identify and evaluate threats, vulnerabilities, likelihood of "
        "exploitation, and potential mission impact.\n\n"
        "Vulnerability scanning shall be conducted at least "
        "{{vulnerability_scan_frequency}} for all network-accessible systems and "
        "{{external_vulnerability_scan_frequency}} for internet-facing assets. Scans shall "
        "include both authenticated and unauthenticated perspectives. Identified "
        "vulnerabilities shall be categorized using the Common Vulnerability Scoring "
        "System (CVSS) and remediated according to severity: Critical within "
        "{{remediation_deadline_critical}}, High within {{remediation_deadline_high}}, "
        "Medium within {{remediation_deadline_medium}}, and Low within "
        "{{remediation_deadline_low}}. Vulnerabilities that cannot be remediated within "
        "these timeframes require a documented risk acceptance or a Plan of Action and "
        "Milestones (POA&M) entry.\n\n"
        "Risk assessment results shall be documented in a formal risk assessment report "
        "and presented to the AO for risk acceptance decisions. The risk register shall be "
        "maintained as a living document, updated with new findings and changes in risk "
        "posture. Threat intelligence from CISA and other authoritative sources shall be "
        "incorporated into risk assessment activities."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in organizational risk tolerance or the threat environment",
    provenance=_SRC_POLICY,
    tags=("risk-assessment", "vulnerability-scanning", "rmf", "cvss", "threat-intelligence"),
)

SYSTEM_COMMUNICATIONS_PROTECTION_POLICY = _template(
    key="system_communications_protection_policy",
    title="System and Communications Protection Policy",
    kind="policy",
    family="SC",
    summary=(
        "FIPS-validated encryption in transit and at rest, prohibited legacy protocols, "
        "defense-in-depth boundaries, segmentation and key management."
    ),
    controls=(
        "SC-1",
        "SC-7",
        "SC-8",
        "SC-12",
        "SC-13",
        "SC-15",
        "SC-20",
        "SC-21",
        "SC-22",
        "SC-28",
    ),
    requirements_171=(
        "3.13.1",
        "3.13.2",
        "3.13.5",
        "3.13.6",
        "3.13.8",
        "3.13.11",
        "3.13.15",
        "3.13.16",
    ),
    parameters=(
        _p(
            "minimum_tls_version",
            "A TLS version number (rendered as 'TLS version X or higher'). Source text used "
            "1.2. NIST SP 800-52 Rev. 2 requires TLS 1.2 at minimum for federal systems "
            "and support for TLS 1.3.",
        ),
    ),
    purpose=(
        "This policy establishes the requirements for protecting the confidentiality and "
        "integrity of information in transit and at rest across {{organization}} systems "
        "and communication channels, defending against interception, unauthorized "
        "modification, and man-in-the-middle attacks."
    ),
    roles=(
        "System Owners shall ensure their systems meet the encryption and boundary "
        "requirements of this policy. Network and system administrators shall configure "
        "boundary protection devices and segmentation as this policy requires. The ISSO "
        "shall monitor internal network traffic for anomalous patterns. The ISSM shall "
        "approve cryptographic key management procedures."
    ),
    body=(
        "All data transmissions containing CUI shall be encrypted using FIPS "
        "140-validated cryptographic modules. Web-based communications shall use TLS "
        "version {{minimum_tls_version}} or higher. Site-to-site connections shall use "
        "IPsec VPN tunnels with FIPS-validated encryption. Email containing CUI shall be "
        "transmitted via encrypted channels, and sensitivity labels that apply encryption "
        "and rights management shall be applied to CUI. Legacy protocols that do not "
        "support modern encryption (SSLv3, TLS 1.0 and 1.1, unencrypted FTP, Telnet) are "
        "prohibited.\n\n"
        "Network architecture shall provide defense-in-depth through boundary protection "
        "devices (firewalls, web application firewalls, intrusion detection and prevention "
        "systems), network segmentation to isolate CUI processing environments, and "
        "demilitarized zones (DMZs) for public-facing services. Internal network traffic "
        "shall be monitored for anomalous patterns. DNS filtering and web content "
        "filtering shall prevent connections to known malicious domains.\n\n"
        "Publicly accessible system components shall be placed in separate subnetworks. "
        "VoIP systems shall be separated from data networks. Collaborative computing "
        "devices (cameras, microphones) shall be disabled or controlled when not in active "
        "use. Cryptographic key management shall follow NIST SP 800-57 with documented "
        "key generation, distribution, storage, rotation, and destruction procedures."
    ),
    compliance=_default_compliance("policy"),
    review_events="advances in cryptographic standards or emerging communication threats",
    provenance=_SRC_POLICY,
    tags=("encryption", "tls", "network-segmentation", "fips", "boundary-protection", "cui"),
)

BOUNDARY_PROTECTION_POLICY = _template(
    key="boundary_protection_policy",
    title="Boundary Protection and Network Segmentation Policy",
    kind="policy",
    family="SC",
    summary=(
        "Managed interfaces at external and key internal boundaries, deny-by-default "
        "traffic policy, segmentation of CUI environments, and interconnection agreements."
    ),
    controls=("SC-1", "SC-7", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(8)", "SC-7(18)"),
    requirements_171=("3.13.1", "3.13.2", "3.13.5", "3.13.6"),
    parameters=(
        _p(
            "wireless_security_protocol",
            "Source text used WPA3-Enterprise. NIST SP 800-53 Rev. 5 AC-18 leaves wireless "
            "authentication and encryption requirements to the organization.",
        ),
    ),
    purpose=(
        "This policy defines the requirements for network boundary protections and "
        "segmentation controls. Effective boundary protection is critical for controlling "
        "information flows between security domains and preventing unauthorized access to "
        "systems processing CUI."
    ),
    roles=(
        "The Authorizing Official (AO) shall approve interconnection security agreements "
        "(ISAs). Network administrators shall configure and maintain boundary devices and "
        "segmentation rules. The ISSO shall analyze network flow logs for policy "
        "violations and anomalous traffic. System Owners shall document the "
        "interconnections of their systems."
    ),
    body=(
        "{{organization}} shall have managed interfaces at all external network "
        "boundaries and at key internal boundaries separating CUI processing environments "
        "from general-purpose networks. External boundary protections shall include "
        "next-generation firewalls with deep packet inspection, intrusion detection and "
        "prevention systems (IDS/IPS), and web application firewalls for public-facing "
        "services. All inbound and outbound traffic shall traverse monitored boundary "
        "devices with deny-all default policies.\n\n"
        "Network segmentation shall isolate CUI processing environments, including the "
        "authorized cloud environment, from commercial workloads and general-purpose "
        "networks. Micro-segmentation shall be used where technically feasible to limit "
        "lateral movement within CUI environments. Cloud network security groups and "
        "cloud firewalls shall enforce segmentation in cloud environments. Network flow "
        "logs shall be captured and analyzed for policy violations and anomalous traffic "
        "patterns.\n\n"
        "Connections to external networks and partner organizations require formal "
        "interconnection security agreements (ISAs) approved by the AO. Each "
        "interconnection shall document the data types exchanged, security controls at "
        "each endpoint, and incident response coordination procedures. Wireless networks "
        "shall be segmented from wired CUI networks and shall require "
        "{{wireless_security_protocol}} authentication."
    ),
    compliance=_default_compliance("policy"),
    review_events="any significant change to network architecture",
    provenance=_SRC_POLICY,
    tags=("boundary-protection", "network-segmentation", "firewall", "ids-ips"),
)

SYSTEM_INFORMATION_INTEGRITY_POLICY = _template(
    key="system_information_integrity_policy",
    title="System and Information Integrity Policy",
    kind="policy",
    family="SI",
    summary=(
        "Flaw remediation on severity-based deadlines, anti-malware on every endpoint, "
        "integrity monitoring, alert triage deadlines and spam filtering."
    ),
    controls=("SI-1", "SI-2", "SI-3", "SI-4", "SI-5", "SI-7", "SI-8", "SI-10"),
    requirements_171=(
        "3.14.1",
        "3.14.2",
        "3.14.3",
        "3.14.4",
        "3.14.5",
        "3.14.6",
        "3.14.7",
    ),
    parameters=(
        _p("remediation_deadline_critical", "Source text used 15 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_high", "Source text used 30 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_medium", "Source text used 90 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_low", "Source text used 180 days. " + _FEDRAMP_REMEDIATION),
        _p(
            "malware_signature_update_frequency",
            "Source text used daily (rendered as 'at least daily'). NIST SP 800-53 Rev. 5 "
            "SI-3 requires updates whenever new releases are available.",
        ),
        _p("critical_alert_triage_deadline", "Source text used 4 hours."),
        _p("noncritical_alert_triage_deadline", "Source text used 24 hours."),
    ),
    purpose=(
        "This policy establishes the requirements for maintaining the integrity of "
        "{{organization}} information systems and the data they process, so that systems "
        "operate as intended, flaws are identified and corrected in a timely manner, and "
        "the organization is protected against malicious code and unauthorized changes."
    ),
    roles=(
        "System Owners shall ensure flaws in their systems are remediated within the "
        "deadlines this policy sets or documented for risk acceptance. The ISSO shall "
        "monitor security advisories and triage security alerts. System administrators "
        "shall deploy patches, endpoint protection, and integrity monitoring. Users shall "
        "not disable or modify endpoint protection."
    ),
    body=(
        "{{organization}} shall maintain a comprehensive flaw remediation program. "
        "Security advisories from vendors, CISA, and DISA shall be monitored continuously. "
        "Software patches and firmware updates shall be evaluated, tested, and deployed "
        "according to severity-based timelines: Critical within "
        "{{remediation_deadline_critical}}, High within {{remediation_deadline_high}}, "
        "Medium within {{remediation_deadline_medium}}, and Low within "
        "{{remediation_deadline_low}}. All production systems shall run supported "
        "software versions; end-of-life software requires documented risk acceptance and "
        "a migration plan.\n\n"
        "Anti-malware protection is mandatory on all endpoints and servers. Endpoint "
        "protection with real-time protection, cloud-delivered protection, and automated "
        "investigation and response shall be deployed organization-wide. Malware signature "
        "updates shall occur at least {{malware_signature_update_frequency}}. Email and "
        "web content shall be scanned for malicious payloads at the network boundary. "
        "Users shall not have the ability to disable or modify endpoint protection "
        "configurations.\n\n"
        "System integrity monitoring shall detect unauthorized changes to critical system "
        "files, configuration parameters, and security-relevant settings. File integrity "
        "monitoring (FIM) shall cover operating system binaries, security configuration "
        "files, and application executables. Security alerts from monitoring tools shall "
        "be triaged within {{critical_alert_triage_deadline}} for critical alerts and "
        "{{noncritical_alert_triage_deadline}} for non-critical alerts. Spam filtering "
        "shall reduce the volume of unsolicited messages."
    ),
    compliance=_default_compliance("policy"),
    review_events="any significant integrity-related incident",
    provenance=_SRC_POLICY,
    tags=("integrity", "patching", "anti-malware", "fim", "flaw-remediation"),
)

ACCEPTABLE_USE_POLICY = _template(
    key="acceptable_use_policy",
    title="Acceptable Use Policy",
    kind="policy",
    family="PL",
    summary=(
        "Rules of behavior for organizational IT resources: permitted use, monitoring "
        "consent, prohibited activities, user responsibilities and acknowledgment."
    ),
    controls=("PL-1", "AC-8", "PL-4", "PS-6", "AT-2"),
    requirements_171=("3.1.9", "3.2.1", "3.2.2"),
    parameters=(
        _p(
            "acceptable_use_acknowledgment_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 PL-4 leaves the "
            "re-acknowledgment frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy defines the acceptable use of {{organization}} information technology "
        "resources, including computers, networks, email, internet access, and cloud "
        "services. Adherence to this policy is essential for protecting organizational "
        "assets, maintaining compliance with federal security requirements, and ensuring "
        "the confidentiality of CUI."
    ),
    roles=(
        "All users shall read and acknowledge this policy and follow it. Supervisors shall "
        "ensure their personnel have acknowledged it. The ISSM shall maintain this policy "
        "and the acknowledgment records."
    ),
    body=(
        "Organizational IT resources are provided for authorized business purposes. "
        "Limited personal use is permitted provided it does not interfere with work "
        "duties, consume excessive resources, or violate any law, regulation, or "
        "organizational policy. Users have no expectation of privacy when using "
        "organizational IT resources. {{organization}} reserves the right to monitor, "
        "intercept, and review all data stored on or transmitted through its systems for "
        "security, compliance, and investigative purposes.\n\n"
        "Prohibited activities include but are not limited to: accessing or distributing "
        "illegal content, unauthorized access to systems or data, circumventing security "
        "controls, installing unauthorized software, using organizational resources for "
        "commercial enterprises, sharing credentials, transmitting CUI through unapproved "
        "channels, connecting unauthorized devices to the network, and engaging in any "
        "activity that could bring discredit to the organization or compromise system "
        "security.\n\n"
        "Users are responsible for safeguarding their authentication credentials, locking "
        "workstations when unattended, reporting suspected security incidents immediately, "
        "and protecting CUI in accordance with organizational marking and handling "
        "procedures. All users shall acknowledge this policy upon initial access and "
        "{{acceptable_use_acknowledgment_frequency}} thereafter."
    ),
    compliance=(
        "Violations of this policy may result in revocation of system access, "
        "disciplinary action, and potential criminal prosecution for violations of "
        "federal law."
    ),
    review_events="significant changes to organizational systems or legal requirements",
    review_source="Source text set no review cadence for the policy itself.",
    provenance=_SRC_POLICY,
    tags=("acceptable-use", "user-responsibility", "monitoring-consent", "cui-handling"),
)

CONTINUOUS_MONITORING_POLICY = _template(
    key="continuous_monitoring_policy",
    title="Continuous Monitoring Policy",
    kind="policy",
    family="CA",
    summary=(
        "The continuous monitoring strategy: activities, monitoring frequency by control "
        "criticality, configuration scanning and status reporting into risk decisions."
    ),
    controls=("CA-1", "CA-7", "RA-3", "RA-5", "SI-4", "PM-14"),
    requirements_171=("3.11.2", "3.11.3", "3.14.3", "3.14.6", "3.14.7", "3.12.3"),
    parameters=(
        _p(
            "critical_control_monitoring_frequency",
            "Source text used continuously (real time). NIST SP 800-53 Rev. 5 CA-7 leaves "
            "monitoring frequencies organization-defined.",
        ),
        _p(
            "high_control_assessment_frequency",
            "Source text used weekly. NIST SP 800-53 Rev. 5 CA-7 leaves monitoring "
            "frequencies organization-defined.",
        ),
        _p(
            "moderate_control_assessment_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 CA-7 leaves monitoring "
            "frequencies organization-defined.",
        ),
        _p(
            "low_control_assessment_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 CA-7 leaves monitoring "
            "frequencies organization-defined.",
        ),
        _p(
            "configuration_scan_frequency",
            "Source text used monthly (rendered as 'at least monthly'). NIST SP 800-53 "
            "Rev. 5 CM-6 and CA-7 leave monitoring frequency organization-defined.",
        ),
        _p(
            "conmon_report_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 CA-7 leaves the reporting "
            "frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the {{organization}} continuous monitoring strategy to "
        "maintain ongoing awareness of information security posture, vulnerabilities, and "
        "threats. Continuous monitoring enables risk-based decision making by providing "
        "near-real-time visibility into the effectiveness of security controls and the "
        "overall security state of the information system."
    ),
    roles=(
        "The ISSM and the Authorizing Official (AO) shall receive security status reports "
        "{{conmon_report_frequency}} and use them in risk acceptance and POA&M "
        "prioritization decisions. The ISSO shall operate the monitoring activities and "
        "investigate deviations. System Owners shall remediate deviations in their "
        "systems."
    ),
    body=(
        "The continuous monitoring program shall encompass automated security control "
        "assessments, vulnerability scanning, configuration compliance monitoring, network "
        "traffic analysis, security event log analysis, and threat intelligence "
        "integration. The SIEM shall serve as the primary platform for log aggregation, "
        "correlation, and alerting in the authorized cloud environment. Dashboards shall "
        "provide visibility into key security metrics such as open vulnerabilities by "
        "severity, configuration compliance, incident volume, and patch status.\n\n"
        "Monitoring frequencies shall be set by control criticality: critical controls "
        "shall be monitored {{critical_control_monitoring_frequency}}, high-criticality "
        "controls assessed {{high_control_assessment_frequency}}, moderate-criticality "
        "controls assessed {{moderate_control_assessment_frequency}}, and low-criticality "
        "controls assessed {{low_control_assessment_frequency}}. Automated compliance "
        "scanning shall run against DISA STIG baselines and CIS benchmarks at least "
        "{{configuration_scan_frequency}}. Deviations detected through continuous "
        "monitoring shall trigger automated alerts and shall be investigated within the "
        "timeframes defined in the incident response plan.\n\n"
        "Continuous monitoring data shall feed into the organization's risk management "
        "process to inform POA&M prioritization, resource allocation, and risk acceptance "
        "decisions. Security status reports shall be generated "
        "{{conmon_report_frequency}} for the ISSM and AO, including trend analysis, risk "
        "posture changes, and recommended actions."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in system architecture, the threat landscape, or compliance "
    "requirements",
    provenance=(
        _SRC_POLICY + " The source titled this text 'Continuous Monitoring Strategy'. "
        "800-171 3.12.3 (monitor security controls on an ongoing basis) was added to the "
        "source's mapping."
    ),
    tags=("continuous-monitoring", "siem", "compliance-scanning", "risk-management"),
)

SUPPLY_CHAIN_RISK_MANAGEMENT_POLICY = _template(
    key="supply_chain_risk_management_policy",
    title="Supply Chain Risk Management Policy",
    kind="policy",
    family="SR",
    summary=(
        "Supply chain risk evaluation for every IT acquisition, prohibited suppliers, "
        "vendor assessments, contract security clauses and SBOMs."
    ),
    controls=("SR-1", "RA-3(1)", "SA-4", "SA-9", "SR-2", "SR-3", "SR-5"),
    requirements_171=("3.11.1", "3.11.2"),
    parameters=(
        _p(
            "vendor_reassessment_frequency",
            "Source text said 'at defined intervals'. NIST SP 800-53 Rev. 5 SR-6 leaves "
            "the supplier review frequency organization-defined.",
        ),
        _p(
            "vendor_incident_notification_deadline",
            "Source text used 72 hours. NIST SP 800-53 Rev. 5 SR-8 leaves notification "
            "agreements organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the requirements for managing supply chain risks "
        "associated with information technology products and services. Supply chain risk "
        "management (SCRM) addresses threats introduced through the acquisition of "
        "hardware, software, and services from external providers, including risks of "
        "tampering, counterfeiting, and insertion of malicious functionality."
    ),
    roles=(
        "The ISSM shall maintain a register of supply chain risks and coordinate with the "
        "contracting office to ensure security requirements are incorporated into all "
        "relevant solicitations and contracts. The contracting office shall include the "
        "contract terms this policy requires. System Owners shall identify the criticality "
        "of products and services their systems depend on."
    ),
    body=(
        "{{organization}} shall evaluate supply chain risks for all IT acquisitions by "
        "assessing the criticality of the product or service, the trustworthiness of the "
        "supplier, the geographic origin of components, and the availability of "
        "alternatives. Acquisitions of IT products for systems processing CUI shall "
        "prioritize vendors with FedRAMP authorized offerings, CMMC certification, or "
        "equivalent security attestations. Products and services prohibited under Section "
        "889 of the John S. McCain National Defense Authorization Act for Fiscal Year 2019, "
        "or on any other prohibited supplier list that applies to {{organization}}, shall "
        "not be acquired.\n\n"
        "Vendor security assessments shall be conducted prior to contract award and "
        "{{vendor_reassessment_frequency}} during the contract period. Assessments shall "
        "evaluate the vendor's security posture, incident response capabilities, data "
        "protection practices, and subcontractor management. Contracts shall include "
        "security requirements, right-to-audit clauses, incident notification obligations "
        "(within {{vendor_incident_notification_deadline}}), and data handling and "
        "destruction provisions. A software bill of materials (SBOM) shall be required for "
        "custom-developed software."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in supply chain threat intelligence, regulatory requirements, or "
    "acquisition strategy",
    provenance=(
        _SRC_POLICY + " The source listed SA-12, which NIST SP 800-53 Rev. 5 withdrew into "
        "the SR family; it was dropped."
    ),
    tags=("supply-chain", "scrm", "vendor-risk", "ndaa", "sbom", "acquisition"),
)

VULNERABILITY_MANAGEMENT_POLICY = _template(
    key="vulnerability_management_policy",
    title="Vulnerability Management Policy",
    kind="policy",
    family="RA",
    summary=(
        "Authenticated scanning on a set cadence, CVSS-based remediation deadlines, POA&M "
        "tracking, emergency handling of exploited flaws, and penetration testing."
    ),
    controls=("RA-1", "RA-5", "RA-5(2)", "RA-5(5)", "SI-2", "SI-5", "CA-8"),
    requirements_171=("3.11.2", "3.11.3", "3.14.1"),
    parameters=(
        _p(
            "vulnerability_scan_frequency",
            "Source text used monthly (rendered as 'at least monthly'). NIST SP 800-53 "
            "Rev. 5 RA-5 leaves the frequency organization-defined; FedRAMP requires "
            "monthly scanning.",
        ),
        _p("external_vulnerability_scan_frequency", "Source text used weekly."),
        _p("scan_results_retention", "Source text used 1 year."),
        _p("remediation_deadline_critical", "Source text used 15 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_high", "Source text used 30 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_medium", "Source text used 90 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_low", "Source text used 180 days. " + _FEDRAMP_REMEDIATION),
        _p(
            "actively_exploited_remediation_deadline",
            "Source text used 48 hours. CISA Binding Operational Directive 22-01 sets due "
            "dates for Known Exploited Vulnerabilities on federal systems.",
        ),
        _p(
            "penetration_test_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 CA-8 leaves the frequency "
            "organization-defined.",
        ),
    ),
    purpose=(
        "This policy establishes the {{organization}} vulnerability management program for "
        "identifying, evaluating, remediating, and tracking vulnerabilities across all "
        "information systems. Effective vulnerability management reduces the attack "
        "surface and mitigates the risk of exploitation by threat actors targeting known "
        "weaknesses."
    ),
    roles=(
        "The ISSM shall receive penetration test results and oversee their tracking "
        "through the POA&M process. The ISSO shall run or oversee vulnerability scanning "
        "and prioritize findings. System Owners shall remediate findings in their systems "
        "within the deadlines this policy sets or document them in a POA&M. Qualified "
        "assessors independent of the personnel who develop and administer the system "
        "shall perform penetration testing."
    ),
    body=(
        "Vulnerability scanning shall be performed using authenticated scanning tools on "
        "all network-accessible systems at least {{vulnerability_scan_frequency}}, and "
        "{{external_vulnerability_scan_frequency}} for internet-facing assets and systems "
        "directly processing CUI. Scans shall include operating systems, applications, "
        "databases, network devices, and container images. Scan results shall be "
        "correlated with threat intelligence and asset criticality to prioritize "
        "remediation, and shall be retained for a minimum of {{scan_results_retention}} "
        "for trend analysis.\n\n"
        "Remediation timelines are governed by CVSS severity: Critical (CVSS 9.0-10.0) "
        "within {{remediation_deadline_critical}}, High (CVSS 7.0-8.9) within "
        "{{remediation_deadline_high}}, Medium (CVSS 4.0-6.9) within "
        "{{remediation_deadline_medium}}, and Low (CVSS 0.1-3.9) within "
        "{{remediation_deadline_low}}. Vulnerabilities that cannot be remediated within "
        "the required timelines shall be documented in a POA&M with compensating controls, "
        "risk justification, and a projected remediation date. Zero-day vulnerabilities "
        "with active exploitation require emergency remediation within "
        "{{actively_exploited_remediation_deadline}}.\n\n"
        "Penetration testing shall be conducted {{penetration_test_frequency}} by "
        "qualified assessors independent of the system's developers and administrators. "
        "Penetration test scope shall include external and internal network testing, web "
        "application testing, and social engineering assessments. Results shall be "
        "reported to the ISSM and tracked through the POA&M process."
    ),
    compliance=_default_compliance("policy"),
    review_events="significant changes in the vulnerability landscape",
    provenance=_SRC_POLICY,
    tags=(
        "vulnerability-management",
        "scanning",
        "penetration-testing",
        "cvss",
        "poam",
        "remediation",
    ),
)

DATA_BACKUP_RECOVERY_POLICY = _template(
    key="data_backup_recovery_policy",
    title="Data Backup and Recovery Policy",
    kind="policy",
    family="CP",
    summary=(
        "RPO-driven backup schedules, encrypted and geographically separated copies, "
        "integrity checks, test restores and tested recovery procedures."
    ),
    controls=("CP-1", "CP-6", "CP-9", "CP-9(1)", "CP-9(3)", "CP-10"),
    requirements_171=("3.8.9",),
    parameters=(
        _p(
            "contingency_scope_impact_level",
            "A FIPS 199 impact level (low, moderate or high). Source text used moderate.",
        ),
        _p(
            "full_backup_frequency",
            "Source text used weekly. NIST SP 800-53 Rev. 5 CP-9 requires a frequency "
            "consistent with recovery time and recovery point objectives.",
        ),
        _p(
            "backup_integrity_check_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 CP-9(1) leaves the testing "
            "frequency organization-defined.",
        ),
        _p(
            "backup_test_restore_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 CP-9(1) leaves the testing "
            "frequency organization-defined.",
        ),
        _p(
            "recovery_procedure_test_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 CP-4 leaves the "
            "test frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy defines the requirements for backing up and recovering "
        "{{organization}} data and information systems. Reliable backup and recovery "
        "capabilities are essential for maintaining business continuity, meeting recovery "
        "objectives, and ensuring the availability of CUI following a disruptive event."
    ),
    roles=(
        "The Contingency Planning Coordinator shall maintain backup schedules and monitor "
        "backup job success with automated alerting for failures. System Owners shall "
        "document recovery procedures and recovery objectives for their systems. Backup "
        "and recovery roles and responsibilities shall be clearly defined for each system."
    ),
    body=(
        "{{organization}} shall perform automated backups for all information systems "
        "categorized at {{contingency_scope_impact_level}} impact or above. Backup "
        "frequency for each system shall be set so that the interval between recoverable "
        "copies does not exceed the system's Recovery Point Objective (RPO); systems whose "
        "RPO is shorter than a backup cycle shall use continuous data protection or "
        "transaction log shipping. Full backups shall be performed "
        "{{full_backup_frequency}} for all systems.\n\n"
        "All backup data shall be encrypted at rest using FIPS 140-validated encryption. "
        "Backup media or cloud storage shall be geographically separated from the primary "
        "site by a distance sufficient that both are not exposed to the same hazards. "
        "Backup copies of CUI shall receive the same protections as the source data. "
        "Backup integrity shall be verified {{backup_integrity_check_frequency}} through "
        "automated checksum validation and {{backup_test_restore_frequency}} through test "
        "restoration of selected datasets.\n\n"
        "Recovery procedures shall be documented for each information system and tested "
        "{{recovery_procedure_test_frequency}}. Test restorations shall validate that data "
        "is complete, current, and usable. Recovery time objectives (RTO) shall be "
        "documented and shown to be achievable by test results."
    ),
    compliance=_default_compliance("policy"),
    review_events="changes in system architecture or data protection requirements",
    provenance=(
        _SRC_POLICY + " The source's RPO-tier backup table (4, 24 and 72 hours) was "
        "replaced by the requirement that backup frequency follow each system's RPO."
    ),
    tags=("backup", "recovery", "disaster-recovery", "rpo", "rto", "encryption"),
)

ACCOUNT_MANAGEMENT_POLICY = _template(
    key="account_management_policy",
    title="Account Management and Privilege Escalation Policy",
    kind="policy",
    family="AC",
    summary=(
        "Account provisioning, separate privileged accounts with time-bound activation, "
        "periodic reviews, inactivity handling, service, emergency and guest accounts."
    ),
    controls=("AC-1", "AC-2", "AC-5", "AC-6", "AC-6(1)", "AC-6(5)", "IA-4", "IA-5"),
    requirements_171=("3.1.1", "3.1.2", "3.1.5", "3.1.7", "3.5.1", "3.5.2", "3.5.3"),
    parameters=(
        _p("privileged_activation_max_duration", "Source text used 6 hours."),
        _p(
            "access_review_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 AC-2 leaves the account "
            "review frequency organization-defined.",
        ),
        _p(
            "inactive_account_threshold",
            "Source text used 35 days. NIST SP 800-53 Rev. 5 AC-2(3) leaves the "
            "inactivity period organization-defined.",
        ),
        _p("service_account_password_rotation", "Source text used every 90 days."),
        _p("service_account_certificate_rotation", "Source text used annually."),
        _p(
            "guest_account_review_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 AC-2 leaves the account "
            "review frequency organization-defined.",
        ),
    ),
    purpose=(
        "This policy defines the requirements for managing user accounts and controlling "
        "privilege escalation across {{organization}} information systems. Proper account "
        "management prevents unauthorized access, reduces the risk of insider threats, and "
        "ensures that access privileges remain aligned with job responsibilities."
    ),
    roles=(
        "Managers shall approve account requests for their personnel. System Owners shall "
        "review accounts {{access_review_frequency}}. Sponsors shall approve guest and "
        "external user accounts. The ISSM shall approve any shared account and shall be "
        "alerted to every use of an emergency account. Service account owners shall "
        "maintain the documentation and credential rotation this policy requires."
    ),
    body=(
        "All user accounts shall be created through a formal provisioning process that "
        "includes identity verification, role assignment, management approval, and "
        "security awareness training completion. Accounts shall be assigned the minimum "
        "privileges necessary to perform authorized functions (least privilege). "
        "Privileged accounts, such as identity, security, and messaging administrator "
        "roles, shall be separate from standard user accounts and used exclusively for "
        "administrative functions. Privileged access shall be activated through privileged "
        "access management for no longer than {{privileged_activation_max_duration}} per "
        "activation, with multi-factor authentication and documented justification.\n\n"
        "Account reviews shall be conducted {{access_review_frequency}} by System Owners "
        "to validate continued need-to-know and appropriate privilege levels. Accounts "
        "that have been inactive for {{inactive_account_threshold}} or more shall be "
        "flagged for review and disabled if no valid justification is provided. Service "
        "accounts shall have documented owners, defined scopes, and scheduled credential "
        "rotation: every {{service_account_password_rotation}} for password-based "
        "credentials and {{service_account_certificate_rotation}} for certificate-based "
        'credentials. Emergency ("break glass") accounts shall be documented and secured '
        "with strong passphrases stored in a physical safe or approved secrets vault, and "
        "their use shall trigger immediate alerting to the ISSM.\n\n"
        "Shared accounts are prohibited except where explicitly approved by the ISSM with "
        "documented compensating controls. Guest and external user accounts require "
        "sponsor approval and shall be reviewed {{guest_account_review_frequency}}. All "
        "account lifecycle events (creation, modification, privilege changes, "
        "disablement, deletion) shall be logged in the audit trail."
    ),
    compliance=_default_compliance("policy"),
    review_events="any account-related security incident",
    provenance=_SRC_POLICY,
    tags=(
        "account-management",
        "privileged-access",
        "least-privilege",
        "service-accounts",
    ),
)

# ---------------------------------------------------------------------------
# Plans and procedures (from POLICY_STATEMENTS, or written for Concord)
# ---------------------------------------------------------------------------

INCIDENT_RESPONSE_PLAN = _template(
    key="incident_response_plan",
    title="Incident Response Plan",
    kind="plan",
    family="IR",
    summary=(
        "How incidents are prepared for, detected, reported, contained, recovered from "
        "and reviewed: team, playbooks, external reporting, testing and records."
    ),
    controls=("IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8"),
    requirements_171=("3.6.1", "3.6.2", "3.6.3"),
    parameters=(
        _p(
            "incident_reporting_deadline",
            "Source policy text used 1 hour. NIST SP 800-53 Rev. 5 IR-6 leaves this time "
            "period organization-defined.",
        ),
        _p(
            "ir_training_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 IR-2 leaves the refresher "
            "frequency organization-defined.",
        ),
        _p(
            "external_incident_reporting_deadline",
            "Source text used 72 hours, the DFARS 252.204-7012 reporting window for DoD "
            "contractors. Set no longer than any contractual or regulatory deadline that "
            "applies to the organization.",
        ),
        _p(
            "post_incident_review_deadline",
            "Source policy text used 5 business days. NIST SP 800-53 Rev. 5 IR-4 leaves "
            "this organization-defined.",
        ),
        _p(
            "ir_plan_test_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 IR-3 leaves the "
            "test frequency organization-defined.",
        ),
        _p(
            "incident_records_retention",
            "Source text used 3 years. Contracts and records schedules may require more.",
        ),
    ),
    purpose=(
        "This plan provides {{organization}} with the roadmap for its incident response "
        "capability: the roles, responsibilities, and procedures for handling security "
        "incidents from preparation through post-incident review, and the reporting "
        "obligations that apply when an incident involves CUI."
    ),
    roles=(
        "The Incident Response Team shall consist of designated members with defined roles "
        "and alternates, including an Incident Commander who leads each response, a Lead "
        "Analyst, a Communications Coordinator, and a Legal Liaison. The ISSM owns this "
        "plan and shall ensure required external notifications are made. The ISSO shall "
        "support detection, analysis, and evidence preservation for the systems they "
        "support. System Owners shall support containment and recovery of their systems. "
        "All personnel shall report suspected incidents to the Incident Response Team "
        "within {{incident_reporting_deadline}} of detection."
    ),
    body=(
        "Preparation. The Incident Response Team shall maintain round-the-clock contact "
        "information and escalation procedures in a secure, accessible location. Team "
        "members shall receive incident response training {{ir_training_frequency}} and "
        "participate in exercises. Playbooks shall be developed for common incident types, "
        "including phishing, malware, unauthorized access, data exfiltration, and insider "
        "threat; each playbook shall include step-by-step response procedures, evidence "
        "collection requirements, and escalation criteria.\n\n"
        "Detection and analysis. Incidents shall be identified through security "
        "monitoring, including the SIEM and endpoint detection and response, and through "
        "personnel reports. Every incident shall be logged with its date, type, severity, "
        "affected systems, and response actions, and assigned a severity that sets its "
        "response timeline and escalation path.\n\n"
        "Containment, eradication, and recovery. Affected systems shall be isolated to "
        "prevent lateral movement, the cause removed, and systems restored to a known good "
        "state and verified before return to service. Forensic evidence shall be preserved "
        "using chain-of-custody procedures.\n\n"
        "Reporting. Cyber incidents involving possible compromise of CUI shall be reported "
        "within {{external_incident_reporting_deadline}} to the authorities required by "
        "contract or regulation, including the Department of Defense through DIBNet where "
        "DFARS 252.204-7012 applies. The Contracting Officer shall be notified of any "
        "incident affecting contract performance. Forensic images and malicious software "
        "samples shall be preserved for investigation by the authorities entitled to "
        "them.\n\n"
        "Post-incident activity. A post-incident review shall be conducted within "
        "{{post_incident_review_deadline}} of incident closure, and lessons learned shall "
        "be documented and used to update this plan, its playbooks, and training.\n\n"
        "Testing and records. This plan shall be tested {{ir_plan_test_frequency}} through "
        "tabletop exercises that simulate realistic scenarios involving CUI compromise, "
        "with lessons learned documented and used to update the plan. Incident records "
        "shall be retained for a minimum of {{incident_records_retention}}, and personally "
        "identifiable information shall be redacted from exported incident logs."
    ),
    compliance=(
        "The ISSM shall track completion of training, exercises, and post-incident "
        "actions under this plan. Failure to report a suspected incident may result in "
        "disciplinary action."
    ),
    review_events="each exercise, any significant incident, and organizational or system "
    "changes that affect response",
    review_source="Source text used annually for the incident response policy.",
    review_control="IR-8",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entries "
        "ir-plan, ir-playbooks, ir-team, incident-log, tabletop-exercise and "
        "breach-notification (SBS Federal), arranged by the NIST SP 800-61 incident "
        "handling phases; product names removed and fixed values parameterized."
    ),
    tags=("incident-response", "playbooks", "dfars", "tabletop", "ir-plan"),
)

CONFIGURATION_MANAGEMENT_PLAN = _template(
    key="configuration_management_plan",
    title="Configuration Management Plan",
    kind="plan",
    family="CM",
    summary=(
        "Configuration items, documented baselines, change control with snapshots, and "
        "drift detection for each system, in NIST SP 800-128 terms."
    ),
    controls=("CM-1", "CM-2", "CM-3", "CM-4", "CM-5", "CM-6", "CM-8", "CM-9"),
    requirements_171=("3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5"),
    parameters=(
        _p(
            "baseline_review_frequency",
            "No source value. NIST SP 800-53 Rev. 5 CM-2 leaves the baseline review "
            "frequency organization-defined.",
        ),
        _p(
            "emergency_change_documentation_deadline",
            "Source policy text used 48 hours. NIST SP 800-53 Rev. 5 CM-3 leaves this "
            "organization-defined.",
        ),
        _p(
            "configuration_scan_frequency",
            "Source policy text used monthly (rendered as 'at least monthly'). NIST SP "
            "800-53 Rev. 5 CM-6 and CA-7 leave monitoring frequency organization-defined.",
        ),
    ),
    purpose=(
        "This plan defines how {{organization}} identifies, baselines, changes, and "
        "monitors the configuration of its information systems, consistent with NIST SP "
        "800-128, so that every system stays in a known, approved, and secure state."
    ),
    roles=(
        "The Change Advisory Board (CAB) shall review and approve changes. System Owners "
        "shall maintain the configuration items and baselines for their systems. The ISSO "
        "shall perform or review the security impact analysis of each change and review "
        "drift alerts. System administrators shall make changes only through the change "
        "control process and capture the baseline snapshots this plan requires."
    ),
    body=(
        "Configuration items. Each system's hardware, software, firmware, and "
        "documentation components shall be identified as configuration items and recorded "
        "in the system component inventory.\n\n"
        "Baselines. Configuration baselines shall be established for every configuration "
        "item using automated configuration management tooling where technically "
        "feasible. Baseline documentation shall record each setting's name, expected "
        "value, validation method, and responsible party, drawing on DISA STIGs, CIS "
        "benchmarks, and organization-specific requirements. Baselines shall be reviewed "
        "{{baseline_review_frequency}} and when system components are installed or "
        "upgraded. Baseline exports shall be retained as the authoritative record of the "
        "approved configuration.\n\n"
        "Change control. All changes to CUI-processing systems shall follow a documented "
        "change request process. Each change request shall include a description, a "
        "security impact analysis, a rollback plan, and approval signatures. Baseline "
        "snapshots shall be captured before and after every authorized change. Emergency "
        "changes shall follow an expedited process with a post-implementation review and "
        "shall be documented within {{emergency_change_documentation_deadline}}.\n\n"
        "Monitoring. Drift detection shall continuously compare current state against "
        "approved baselines and generate alerts, and configuration compliance scans shall "
        "run at least {{configuration_scan_frequency}}. Unauthorized changes shall be "
        "investigated as potential security incidents."
    ),
    compliance=_default_compliance("plan"),
    review_events="significant changes to system architecture or configuration tooling",
    review_source="No source value.",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entries "
        "config-mgmt-plan, baseline-config and change-control-procedures (SBS Federal), "
        "organized with NIST SP 800-128 terminology; the source's named configuration "
        "tools were replaced with capability language and fixed values parameterized."
    ),
    tags=("configuration", "baselines", "change-control", "drift-detection", "cm-plan"),
)

CONTINUOUS_MONITORING_PLAN = _template(
    key="continuous_monitoring_plan",
    title="Continuous Monitoring Plan",
    kind="plan",
    family="CA",
    summary=(
        "The operating plan for ongoing authorization: monitored activities, frequencies "
        "by control priority, alerting, reporting cadence and POA&M feed."
    ),
    controls=("CA-1", "CA-2", "CA-5", "CA-7", "PM-31", "RA-5", "SI-4"),
    requirements_171=("3.12.3", "3.12.1", "3.12.4", "3.14.6", "3.14.7"),
    parameters=(
        _p(
            "vulnerability_scan_frequency",
            "No value in the source plan; source policy text used monthly (rendered as "
            "'at least monthly'). FedRAMP requires monthly scanning.",
        ),
        _p(
            "critical_control_monitoring_frequency",
            "Source text used real time. NIST SP 800-53 Rev. 5 CA-7 leaves monitoring "
            "frequencies organization-defined.",
        ),
        _p(
            "high_control_assessment_frequency",
            "Source plan text used daily (the source policy used weekly). NIST SP 800-53 "
            "Rev. 5 CA-7 leaves monitoring frequencies organization-defined.",
        ),
        _p(
            "standard_control_assessment_frequency",
            "Source text used weekly. NIST SP 800-53 Rev. 5 CA-7 leaves monitoring "
            "frequencies organization-defined.",
        ),
        _p(
            "conmon_report_frequency",
            "Source text used monthly. NIST SP 800-53 Rev. 5 CA-7 leaves the reporting "
            "frequency organization-defined.",
        ),
        _p(
            "leadership_conmon_report_frequency",
            "Source text used quarterly. NIST SP 800-53 Rev. 5 CA-7 leaves the reporting "
            "frequency organization-defined.",
        ),
    ),
    purpose=(
        "This plan describes how {{organization}} monitors its systems on an ongoing "
        "basis, consistent with NIST SP 800-137, to maintain its authorizations and an "
        "accurate, current picture of its security posture."
    ),
    roles=(
        "The ISSO shall operate the monitoring activities in this plan and receive status "
        "reports {{conmon_report_frequency}}. Senior leadership, including the Authorizing "
        "Official (AO), shall receive the Security Status Report "
        "{{leadership_conmon_report_frequency}}. The security operations or incident "
        "response function shall receive and act on automated alerts. System Owners shall "
        "remediate findings or record them in the POA&M."
    ),
    body=(
        "{{organization}} shall operate a continuous monitoring program to maintain "
        "ongoing authorization and security posture awareness. The program shall include "
        "automated baseline drift detection, vulnerability scanning at least "
        "{{vulnerability_scan_frequency}}, and tracking of configuration compliance "
        "against approved baselines.\n\n"
        "Monitoring frequency shall be defined per control family and priority: critical "
        "controls shall be monitored {{critical_control_monitoring_frequency}}, "
        "high-priority controls assessed {{high_control_assessment_frequency}}, and "
        "standard controls assessed {{standard_control_assessment_frequency}}.\n\n"
        "The program shall integrate the SIEM, configuration baseline and drift detection "
        "tooling, endpoint compliance reporting, and vulnerability scanning. Automated "
        "alerting shall notify the security operations or incident response function of "
        "drift events, degradation in compliance with approved baselines, and "
        "unauthorized configuration changes.\n\n"
        "Continuous monitoring metrics shall be reported {{conmon_report_frequency}} to "
        "the ISSO and {{leadership_conmon_report_frequency}} to senior leadership in the "
        "Security Status Report. Findings shall be recorded in the Plan of Action and "
        "Milestones (POA&M) and inform risk acceptance decisions. A program review shall "
        "validate tool effectiveness, metric thresholds, and reporting procedures at each "
        "review of this plan."
    ),
    compliance=_default_compliance("plan"),
    review_events="significant changes to monitoring tools, system architecture, or "
    "authorization requirements",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entry "
        "continuous-monitoring-plan (SBS Federal), with NIST SP 800-137 terminology; "
        "named products and a vendor scoring metric removed and fixed values "
        "parameterized."
    ),
    tags=("continuous-monitoring", "conmon", "ongoing-authorization", "reporting"),
)

CONTINGENCY_PLAN = _template(
    key="contingency_plan",
    title="Contingency Plan",
    kind="plan",
    family="CP",
    summary=(
        "Information system contingency plan with business continuity and disaster "
        "recovery elements: BIA, recovery objectives, activation, recovery, "
        "reconstitution, training and testing (NIST SP 800-34)."
    ),
    controls=("CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-7", "CP-9", "CP-10"),
    requirements_171=("3.8.9",),
    parameters=(
        _p(
            "contingency_training_frequency",
            "No source value. NIST SP 800-53 Rev. 5 CP-3 leaves the refresher frequency "
            "organization-defined.",
        ),
        _p(
            "contingency_plan_test_frequency",
            "Source text used at least annually. NIST SP 800-53 Rev. 5 CP-4 leaves the "
            "test frequency organization-defined.",
        ),
    ),
    purpose=(
        "This plan establishes how {{organization}} continues mission-essential functions "
        "and recovers its information systems after a disruption, consistent with NIST SP "
        "800-34. It serves as the information system contingency plan for each in-scope "
        "system and carries the business continuity and disaster recovery elements that "
        "support it."
    ),
    roles=(
        "The Contingency Planning Coordinator shall maintain this plan, coordinate "
        "activation, and schedule training and tests. System Owners shall maintain the "
        "recovery procedures for their systems. Recovery personnel shall carry out the "
        "recovery and reconstitution procedures assigned to them. The ISSM shall confirm "
        "that security controls are restored before a system returns to normal operation."
    ),
    body=(
        "Business impact analysis. A business impact analysis (BIA) shall identify "
        "critical business functions, the systems that support them, and their recovery "
        "priorities. The plan shall define a Recovery Time Objective (RTO) and Recovery "
        "Point Objective (RPO) for each CUI-processing system.\n\n"
        "Activation and notification. The plan shall define the criteria for activating "
        "it, who may activate it, and how recovery personnel and stakeholders are "
        "notified.\n\n"
        "Recovery. Disaster recovery procedures shall restore CUI-processing systems after "
        "a disruptive event, including recovery of cloud services, restoration of data "
        "from backups, and activation of alternate processing or storage sites, in the "
        "order set by the BIA.\n\n"
        "Reconstitution. Restored systems shall be validated for functionality and "
        "security before returning to normal operation, and the plan deactivated with "
        "its actions documented.\n\n"
        "Training and testing. Personnel with contingency roles shall be trained before "
        "assuming them and {{contingency_training_frequency}} thereafter. Business "
        "continuity and disaster recovery testing shall be conducted "
        "{{contingency_plan_test_frequency}}, with results and lessons learned documented "
        "and used to update this plan."
    ),
    compliance=_default_compliance("plan"),
    review_events="any activation of this plan or test that reveals a deficiency, and "
    "significant changes to systems or the organization",
    review_source="No source value for the plan.",
    review_control="CP-2",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entries "
        "bcp and drp (SBS Federal), organized by the NIST SP 800-34 Rev. 1 plan phases "
        "(activation and notification, recovery, reconstitution); fixed values "
        "parameterized."
    ),
    tags=("contingency", "business-continuity", "disaster-recovery", "bia", "rto", "rpo"),
)

SECURITY_AWARENESS_TRAINING_PLAN = _template(
    key="security_awareness_training_plan",
    title="Security Awareness and Training Plan",
    kind="plan",
    family="AT",
    summary=(
        "Annual curriculum, role-based training, phishing simulations, CUI handling "
        "awareness, completion tracking and consequences for overdue training."
    ),
    controls=("AT-1", "AT-2", "AT-2(1)", "AT-2(2)", "AT-3", "AT-4"),
    requirements_171=("3.2.1", "3.2.2", "3.2.3"),
    parameters=(
        _p(
            "initial_training_deadline",
            "Source plan text used 30 days (the source policy used 5 business days). NIST "
            "SP 800-53 Rev. 5 AT-2 leaves the deadline organization-defined.",
        ),
        _p(
            "awareness_training_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 AT-2 leaves the refresher "
            "frequency organization-defined; at least annually is the common value.",
        ),
        _p("phishing_simulation_frequency", "Source text used at least quarterly."),
        _p("phishing_remedial_training_deadline", "Source text used 7 days."),
        _p("overdue_training_suspension_deadline", "Source text used 30 days past due."),
        _p("training_completion_report_frequency", "Source text used quarterly."),
        _p(
            "training_records_retention",
            "Source policy text used 3 years. NIST SP 800-53 Rev. 5 AT-4 leaves the "
            "retention period organization-defined.",
        ),
    ),
    purpose=(
        "This plan defines the {{organization}} security awareness and training program: "
        "what is taught, to whom, how it is delivered, and how completion is tracked, in "
        "line with NIST SP 800-50."
    ),
    roles=(
        "The ISSM owns this plan and the training curriculum. Supervisors shall ensure "
        "their personnel complete training on time. Training administrators shall "
        "maintain completion records and report completion rates to management "
        "{{training_completion_report_frequency}}. All personnel shall complete the "
        "training assigned to them."
    ),
    body=(
        "Curriculum. The program shall define an annual curriculum, delivery methods, and "
        "completion requirements. Training shall cover CUI handling, phishing recognition, "
        "password hygiene, and incident reporting, and content shall be updated annually "
        "to address emerging threats and lessons learned. CUI handling awareness shall be "
        "included in all training modules, covering identification, marking, storage, "
        "transmission, and destruction.\n\n"
        "Schedule. All personnel shall complete initial security awareness training within "
        "{{initial_training_deadline}} of onboarding and refresher training "
        "{{awareness_training_frequency}} thereafter.\n\n"
        "Role-based training. Role-based training shall be defined for privileged users, "
        "system administrators, incident responders, and CUI handlers. Privileged users "
        "shall be trained on privileged access activation, audit log review, and incident "
        "escalation; system administrators on secure configuration, change management, "
        "and baseline maintenance. Training requirements shall be defined per role and "
        "tracked.\n\n"
        "Phishing simulation. Phishing simulation campaigns shall be conducted "
        "{{phishing_simulation_frequency}} for all users with email access, with click "
        "rates, reporting rates, and repeat offenders tracked. Users who fail a simulation "
        "shall receive additional targeted training within "
        "{{phishing_remedial_training_deadline}}.\n\n"
        "Tracking. Completion shall be tracked in a learning management system with "
        "automated reminders for overdue training. Completion records shall include dates "
        "and scores and shall be retained for {{training_records_retention}}."
    ),
    compliance=(
        "Personnel who have not completed required training within "
        "{{overdue_training_suspension_deadline}} of the due date shall have CUI access "
        "suspended until training is completed."
    ),
    review_events="emerging threats, lessons learned, or assessment findings that affect training",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entries "
        "sat-plan, sat-program, training-completion, phishing-simulation and "
        "role-based-training (SBS Federal); product references removed and fixed values "
        "parameterized."
    ),
    tags=("training", "awareness", "phishing-simulation", "role-based-training", "cui"),
)

RISK_MANAGEMENT_PLAN = _template(
    key="risk_management_plan",
    title="Risk Management Plan",
    kind="plan",
    family="RA",
    summary=(
        "Risk framework, appetite and tolerance, assessment methodology, risk register, "
        "treatment options and AO risk acceptance."
    ),
    controls=("RA-1", "PM-9", "RA-2", "RA-3", "RA-7", "CA-5"),
    requirements_171=("3.11.1", "3.11.2", "3.11.3", "3.12.2"),
    parameters=(
        _p(
            "risk_assessment_frequency",
            "No value in the source plan; source policy text used at least annually. NIST "
            "SP 800-53 Rev. 5 RA-3 leaves the update frequency organization-defined.",
        ),
        _p("risk_register_review_frequency", "No source value."),
    ),
    purpose=(
        "This plan defines how {{organization}} frames, assesses, responds to, and "
        "monitors information security risk, and who may accept it."
    ),
    roles=(
        "Senior leadership shall define and approve risk appetite and risk tolerance. The "
        "Authorizing Official (AO) shall approve risk acceptance decisions. Risk owners "
        "shall be assigned to each risk in the register and shall carry out its treatment. "
        "The ISSM shall maintain the risk register and this plan. The ISSO shall conduct "
        "or support risk assessments for their systems."
    ),
    body=(
        "Framework. {{organization}} shall establish a risk management framework aligned "
        "with NIST SP 800-37 and the NIST Cybersecurity Framework. Risk appetite and risk "
        "tolerance thresholds shall be defined and approved by senior leadership.\n\n"
        "Assessment. Risk assessments shall be conducted using a standardized methodology "
        "(NIST SP 800-30 or FAIR) with quantitative and qualitative analysis, "
        "{{risk_assessment_frequency}} and when significant changes occur.\n\n"
        "Register. A single organization-wide risk register shall track all identified risks with "
        "assigned owners, severity ratings, and mitigation timelines, and shall be "
        "reviewed {{risk_register_review_frequency}}.\n\n"
        "Response. Risk treatment options (mitigate, accept, transfer, avoid) shall be "
        "evaluated for each identified risk. Risk acceptance decisions shall require "
        "documented justification and Authorizing Official approval. Planned mitigations "
        "shall be tracked in the Plan of Action and Milestones (POA&M)."
    ),
    compliance=_default_compliance("plan"),
    review_events="changes in the threat landscape or organizational posture",
    review_control="PM-9",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entry "
        "risk-management-plan (SBS Federal); fixed values parameterized."
    ),
    tags=("risk-management", "risk-register", "risk-acceptance", "rmf"),
)

SUPPLY_CHAIN_RISK_MANAGEMENT_PLAN = _template(
    key="supply_chain_risk_management_plan",
    title="Supply Chain Risk Management Plan",
    kind="plan",
    family="SR",
    summary=(
        "SCRM program: supplier assessment and risk tiers, procurement requirements, "
        "SBOMs, third-party access, notification agreements and periodic review."
    ),
    controls=("SR-1", "SR-2", "SR-3", "SR-5", "SR-6", "SR-8", "SA-9", "RA-3(1)"),
    requirements_171=("3.11.1", "3.1.20"),
    parameters=(
        _p(
            "vendor_incident_notification_deadline",
            "No value in the source plan; source policy text used 72 hours. NIST SP "
            "800-53 Rev. 5 SR-8 leaves notification agreements organization-defined.",
        ),
        _p(
            "supply_chain_risk_review_frequency",
            "Source text used annually. NIST SP 800-53 Rev. 5 SR-6 leaves the supplier "
            "review frequency organization-defined.",
        ),
    ),
    purpose=(
        "This plan establishes the {{organization}} supply chain risk management (SCRM) "
        "program to identify and mitigate risks from third-party providers and supply "
        "chain dependencies, consistent with NIST SP 800-161."
    ),
    roles=(
        "The ISSM owns this plan and the supplier risk register. The contracting office "
        "shall include the procurement security requirements of this plan in "
        "solicitations and contracts. System Owners shall identify the suppliers and "
        "critical components their systems depend on. Supplier sponsors shall request and "
        "justify third-party access."
    ),
    body=(
        "Supplier assessment. All suppliers with access to CUI or CUI-processing systems "
        "shall undergo a security risk assessment before onboarding. Vendor risk tiers "
        "(Critical, High, Medium, Low) shall determine assessment frequency, monitoring "
        "intensity, and contract security clauses; this plan shall record the frequency "
        "chosen for each tier.\n\n"
        "Procurement requirements. Procurement security requirements shall include DFARS "
        "252.204-7012 flow-down where applicable, verification of NIST SP 800-171 "
        "compliance, and FedRAMP authorization status for cloud services. Contracts shall "
        "require suppliers to notify {{organization}} of security incidents within "
        "{{vendor_incident_notification_deadline}}.\n\n"
        "Component transparency. A software bill of materials (SBOM) shall be maintained "
        "for critical software components within the CUI boundary.\n\n"
        "Third-party access. Third-party access shall be restricted to least privilege "
        "through conditional access controls, dedicated service accounts, and time-limited "
        "access.\n\n"
        "Review. Supply chain risk reviews shall be conducted "
        "{{supply_chain_risk_review_frequency}} to evaluate vendor compliance posture, "
        "incident history, and geopolitical risks."
    ),
    compliance=_default_compliance("plan"),
    review_events="significant changes to suppliers, acquisition strategy, or supply chain "
    "threat intelligence",
    review_source="No source value for the plan itself.",
    review_control="SR-2",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entry "
        "scrm-plan (SBS Federal); a product-specific access control reference replaced "
        "with capability language and fixed values parameterized. The source mapped this "
        "plan to 800-171 3.1.22, 3.13.1, 3.4.6 and 3.4.7, which are not supply chain "
        "requirements; those were replaced with 3.11.1."
    ),
    tags=("supply-chain", "scrm", "vendor-risk", "sbom", "procurement"),
)

VULNERABILITY_MANAGEMENT_PROCEDURE = _template(
    key="vulnerability_management_procedure",
    title="Vulnerability Management Procedure",
    kind="procedure",
    family="RA",
    summary=(
        "Step by step: scan, analyze and prioritize, remediate within deadlines, track "
        "with evidence, and verify by re-scanning."
    ),
    controls=("RA-1", "RA-5", "RA-5(2)", "SI-2", "CA-5"),
    requirements_171=("3.11.2", "3.11.3", "3.14.1"),
    parameters=(
        _p(
            "vulnerability_scan_frequency",
            "Source text used monthly (rendered as 'at least monthly'). NIST SP 800-53 "
            "Rev. 5 RA-5 leaves the frequency organization-defined; FedRAMP requires "
            "monthly scanning.",
        ),
        _p(
            "remediation_deadline_critical",
            "Source procedure text used 72 hours, while the source policies used 15 days. "
            + _FEDRAMP_REMEDIATION,
        ),
        _p("remediation_deadline_high", "Source text used 30 days. " + _FEDRAMP_REMEDIATION),
        _p("remediation_deadline_medium", "Source text used 90 days. " + _FEDRAMP_REMEDIATION),
        _p(
            "remediation_deadline_low",
            "No value in the source procedure; source policies used 180 days. "
            + _FEDRAMP_REMEDIATION,
        ),
    ),
    purpose=(
        "This procedure sets out the steps {{organization}} follows to find, prioritize, "
        "remediate, and verify the remediation of vulnerabilities in its systems, carrying "
        "out the vulnerability management and flaw remediation policies."
    ),
    roles=(
        "The ISSO shall run or oversee scans and prioritize results. System Owners and "
        "system administrators shall remediate findings and supply remediation evidence. "
        "The ISSM shall approve POA&M entries for findings that cannot meet their "
        "deadline."
    ),
    body=(
        "1. Scan. Conduct vulnerability scanning at least {{vulnerability_scan_frequency}} "
        "on all systems within the CUI boundary, using authenticated scans where "
        "technically feasible and updating the scanner's vulnerability data before each "
        "scan.\n\n"
        "2. Analyze and prioritize. Analyze scan results and prioritize them by CVSS "
        "score, exploitability (including whether the vulnerability is known to be "
        "exploited), and CUI exposure. Discard confirmed false positives with a recorded "
        "justification.\n\n"
        "3. Remediate. Remediate each finding within its deadline: Critical within "
        "{{remediation_deadline_critical}}, High within {{remediation_deadline_high}}, "
        "Medium within {{remediation_deadline_medium}}, and Low within "
        "{{remediation_deadline_low}}. A finding that cannot meet its deadline shall be "
        "entered in the Plan of Action and Milestones (POA&M) with compensating controls "
        "and a planned completion date.\n\n"
        "4. Track. Track every remediation action from identification through "
        "verification. Collect evidence of remediation and link it to the original "
        "finding.\n\n"
        "5. Verify. Re-scan the affected systems to validate that remediation was "
        "effective, and close the finding only when the re-scan confirms it."
    ),
    compliance=_default_compliance("procedure"),
    review_events="changes to scanning tools or to the vulnerability management policy",
    review_source="No source value.",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entries "
        "vuln-mgmt-process and remediation-tracking (SBS Federal), arranged as steps with "
        "NIST SP 800-40 terminology; fixed values parameterized."
    ),
    tags=("vulnerability-management", "scanning", "remediation", "poam", "procedure"),
)

MEDIA_SANITIZATION_PROCEDURE = _template(
    key="media_sanitization_procedure",
    title="Media Sanitization Procedure",
    kind="procedure",
    family="MP",
    summary=(
        "Step by step: identify media, choose Clear, Purge or Destroy per NIST SP 800-88, "
        "approve, sanitize, verify, and record."
    ),
    controls=("MP-1", "MP-6", "MP-6(1)"),
    requirements_171=("3.8.3",),
    parameters=(_p("sanitization_records_retention", "No source value."),),
    purpose=(
        "This procedure sets out how {{organization}} sanitizes system media before "
        "disposal, release out of organizational control, or reuse, so that CUI and other "
        "sensitive information cannot be recovered from it, following NIST SP 800-88."
    ),
    roles=(
        "The ISSM shall approve sanitization methods and disposal. Media custodians shall "
        "identify media for sanitization and keep it under control until sanitized. "
        "Personnel performing sanitization shall follow this procedure and record each "
        "action. A witness shall observe and attest to each destruction."
    ),
    body=(
        "1. Identify. Record the media type, serial number, the highest sensitivity of "
        "information it held, and whether it will be reused, released, or disposed of.\n\n"
        "2. Select a method. Choose Clear, Purge, or Destroy in accordance with NIST SP "
        "800-88, based on the sensitivity of the information and the media's next "
        "destination. Media that held CUI and is leaving organizational control shall be "
        "purged or destroyed.\n\n"
        "3. Approve. Obtain ISSM approval of the method before sanitizing.\n\n"
        "4. Sanitize. Perform the sanitization with approved tools or an approved "
        "destruction service.\n\n"
        "5. Verify. Verify that the sanitization succeeded before the media is reused, "
        "released, or disposed of.\n\n"
        "6. Record. Record the media type, serial number, sanitization method, date, the "
        "person who performed it, and the verification result. Destruction shall be "
        "witnessed and documented with a certificate of destruction. Sanitization records "
        "shall be retained for {{sanitization_records_retention}}."
    ),
    compliance=_default_compliance("procedure"),
    review_events="the introduction of new media types or changes to NIST SP 800-88 guidance",
    review_source="No source value.",
    provenance=(
        "Adapted from m365-docs-hub supplemental-doc-service.ts POLICY_STATEMENTS entry "
        "media-sanitization (SBS Federal), expanded into steps with NIST SP 800-88 "
        "terminology; the retention period is a parameter the source did not have."
    ),
    tags=("media-sanitization", "nist-800-88", "destruction", "cui", "procedure"),
)

TEMPLATES: tuple[Template, ...] = (
    ACCESS_CONTROL_POLICY,
    REMOTE_ACCESS_POLICY,
    SECURITY_AWARENESS_TRAINING_POLICY,
    AUDIT_ACCOUNTABILITY_POLICY,
    CONFIGURATION_MANAGEMENT_POLICY,
    CONTINGENCY_PLANNING_POLICY,
    IDENTIFICATION_AUTHENTICATION_POLICY,
    INCIDENT_RESPONSE_POLICY,
    INCIDENT_RESPONSE_COMMUNICATIONS_POLICY,
    SYSTEM_MAINTENANCE_POLICY,
    MEDIA_PROTECTION_POLICY,
    PERSONNEL_SECURITY_POLICY,
    PHYSICAL_ENVIRONMENTAL_PROTECTION_POLICY,
    RISK_ASSESSMENT_POLICY,
    SYSTEM_COMMUNICATIONS_PROTECTION_POLICY,
    BOUNDARY_PROTECTION_POLICY,
    SYSTEM_INFORMATION_INTEGRITY_POLICY,
    ACCEPTABLE_USE_POLICY,
    CONTINUOUS_MONITORING_POLICY,
    SUPPLY_CHAIN_RISK_MANAGEMENT_POLICY,
    VULNERABILITY_MANAGEMENT_POLICY,
    DATA_BACKUP_RECOVERY_POLICY,
    ACCOUNT_MANAGEMENT_POLICY,
    INCIDENT_RESPONSE_PLAN,
    CONFIGURATION_MANAGEMENT_PLAN,
    CONTINUOUS_MONITORING_PLAN,
    CONTINGENCY_PLAN,
    SECURITY_AWARENESS_TRAINING_PLAN,
    RISK_MANAGEMENT_PLAN,
    SUPPLY_CHAIN_RISK_MANAGEMENT_PLAN,
    VULNERABILITY_MANAGEMENT_PROCEDURE,
    MEDIA_SANITIZATION_PROCEDURE,
)

BY_KEY: dict[str, Template] = {t.key: t for t in TEMPLATES}
