"""Azure Resource Manager posture checks.

``azure_arm`` already reached five real ARM collections and mapped each to an
800-53 control, but it registered no posture checks and had no ``scan``: the
connector captured parameter *values* for an SSP and produced no verdicts. So a
system whose only connector was Azure scanned nothing at all — ``scan-all``
resolved zero checks for it and reported ``checks_expected: 0``, which reads as
"clean" far more readily than "nothing was assessed".

These reuse the collections the connector already fetches, and the field names
below are taken from the existing ``_map_*`` mappers rather than from the ARM
documentation, so the two halves cannot disagree about what a payload looks
like.

Fleet checks are per-resource, because every storage account genuinely is in
scope for "does it encrypt at rest". The subscription-level questions -- is a
baseline assigned, is workload protection on -- are asked of the subscription,
for the reason ``m365``'s session-lock check is asked of the tenant: a policy
assignment that does not mention encryption is not failing to encrypt.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..types import PostureCheck, ResourceFinding

#: Minimum TLS an Azure storage account must require. ``TLS1_2`` is the ARM
#: spelling. Below it the account still accepts 1.0/1.1, which FedRAMP does not
#: permit; it is organization-defined only in the sense that an organization may
#: require *more*, so this is the floor rather than a guess.
MINIMUM_TLS = "TLS1_2"
_TLS_ORDER = {"TLS1_0": 0, "TLS1_1": 1, "TLS1_2": 2, "TLS1_3": 3}

#: Shortest Log Analytics retention accepted, in days. FedRAMP AU-11 requires a
#: year of audit record retention; 90 days online with the balance in archive is
#: the common reading, and the platform cannot see the archive from ARM. Named
#: as a parameter (see ``posture.parameters``) rather than asserted, because the
#: period is organization-defined and a wrong constant here becomes a false
#: finding on somebody's authorization package.
LOG_RETENTION_MIN_DAYS = 90

LOG_RETENTION_EXPECTED = (
    "every Log Analytics workspace retains audit records for at least "
    "{min_days} days"
)

STORAGE_ENCRYPTION_AT_REST = PostureCheck(
    key="azure.storage.encryption_at_rest",
    title="Storage accounts encrypt blob and file data at rest",
    provider="azure_arm",
    resource_type="azure_storage_account",
    expected="every storage account encrypts both blob and file services at rest",
    control_ids=("SC-28", "SC-28(1)"),
    required_permissions=("Microsoft.Storage/storageAccounts/read",),
)

STORAGE_HTTPS_ONLY = PostureCheck(
    key="azure.storage.https_only",
    title="Storage accounts require HTTPS at a current TLS version",
    provider="azure_arm",
    resource_type="azure_storage_account",
    expected=(
        "every storage account requires HTTPS and a minimum TLS version of "
        f"{MINIMUM_TLS} or higher"
    ),
    control_ids=("SC-8", "SC-8(1)", "SC-23"),
    required_permissions=("Microsoft.Storage/storageAccounts/read",),
)

LOG_RETENTION = PostureCheck(
    key="azure.monitor.log_retention",
    title="Log Analytics workspaces retain audit records long enough",
    provider="azure_arm",
    resource_type="azure_log_analytics_workspace",
    expected=LOG_RETENTION_EXPECTED.format(min_days=LOG_RETENTION_MIN_DAYS),
    control_ids=("AU-11", "AU-4"),
    required_permissions=("Microsoft.OperationalInsights/workspaces/read",),
)

POLICY_BASELINE_ENFORCED = PostureCheck(
    key="azure.policy.baseline_enforced",
    title="An Azure Policy baseline is enforced on the subscription",
    provider="azure_arm",
    resource_type="azure_subscription",
    expected="at least one Azure Policy assignment is enforcing, not audit-only",
    control_ids=("CM-2", "CM-6"),
    required_permissions=("Microsoft.Authorization/policyAssignments/read",),
)

DEFENDER_WORKLOAD_PROTECTION = PostureCheck(
    key="azure.defender.workload_protection",
    title="Defender for Cloud runs workload protection",
    provider="azure_arm",
    resource_type="azure_subscription",
    expected="at least one Defender for Cloud plan is on the Standard tier",
    control_ids=("SI-3", "SI-4", "RA-5"),
    required_permissions=("Microsoft.Security/pricings/read",),
)

CHECKS: tuple[PostureCheck, ...] = (
    STORAGE_ENCRYPTION_AT_REST,
    STORAGE_HTTPS_ONLY,
    LOG_RETENTION,
    POLICY_BASELINE_ENFORCED,
    DEFENDER_WORKLOAD_PROTECTION,
)

#: Check key -> the ARM provider path and api-version the connector fetches.
#: Deliberately the same pinned api-versions the connector already uses: an
#: unpinned ARM call is a 400, and a second pin here would drift from the first.
ENDPOINTS: dict[str, str] = {
    STORAGE_ENCRYPTION_AT_REST.key: "Microsoft.Storage/storageAccounts@2023-01-01",
    STORAGE_HTTPS_ONLY.key: "Microsoft.Storage/storageAccounts@2023-01-01",
    LOG_RETENTION.key: "Microsoft.OperationalInsights/workspaces@2022-10-01",
    POLICY_BASELINE_ENFORCED.key: "Microsoft.Authorization/policyAssignments@2022-06-01",
    DEFENDER_WORKLOAD_PROTECTION.key: "Microsoft.Security/pricings@2023-01-01",
}


def _props(row: dict[str, Any]) -> dict[str, Any]:
    """An ARM resource's ``properties``, or an empty mapping.

    Mirrors ``AzureArmConnector._props``: ARM nests almost everything under
    ``properties``, and a row that arrived without one is malformed rather than
    empty-but-fine.
    """
    props = row.get("properties")
    return props if isinstance(props, dict) else {}


def _ref(row: dict[str, Any]) -> str:
    """The resource's name, falling back to its id -- never empty."""
    name = row.get("name")
    if isinstance(name, str) and name:
        return name
    return str(row.get("id") or "unknown")


def _tls_at_least(value: Any, minimum: str = MINIMUM_TLS) -> bool:
    """Is this ``minimumTlsVersion`` at or above the floor?

    Compared by rank, not lexically: ``"TLS1_10"`` would sort below ``"TLS1_2"``
    as a string, and an unrecognised spelling is treated as *not* meeting the
    floor rather than assumed to be newer.
    """
    if not isinstance(value, str):
        return False
    rank = _TLS_ORDER.get(value)
    return rank is not None and rank >= _TLS_ORDER[minimum]


def evaluate_storage_encryption_at_rest(
    rows: list[dict[str, Any]],
) -> list[ResourceFinding]:
    """One finding per storage account.

    Both blob *and* file must be encrypted, matching the connector's capture: an
    account that encrypts blobs and not files does not protect CUI at rest, and
    passing it would overstate the fleet.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        props = _props(row)
        encryption = props.get("encryption")
        services = encryption.get("services") if isinstance(encryption, dict) else None
        services = services if isinstance(services, dict) else {}
        blob, file_svc = services.get("blob"), services.get("file")
        blob_on = isinstance(blob, dict) and bool(blob.get("enabled"))
        file_on = isinstance(file_svc, dict) and bool(file_svc.get("enabled"))
        missing = [
            name for name, on in (("blob", blob_on), ("file", file_on)) if not on
        ]
        findings.append(
            ResourceFinding(
                resource_id=_ref(row),
                resource_type="azure_storage_account",
                verdict="pass" if not missing else "fail",
                observed=(
                    "blob and file encryption enabled"
                    if not missing
                    else f"{' and '.join(missing)} encryption not enabled"
                ),
                detail={
                    "blob_encrypted": blob_on,
                    "file_encrypted": file_on,
                    "infrastructure_encryption": bool(
                        encryption.get("requireInfrastructureEncryption")
                        if isinstance(encryption, dict)
                        else False
                    ),
                },
            )
        )
    return findings


def evaluate_storage_https_only(rows: list[dict[str, Any]]) -> list[ResourceFinding]:
    """One finding per storage account: HTTPS required, at a current TLS floor."""
    findings: list[ResourceFinding] = []
    for row in rows:
        props = _props(row)
        https = bool(props.get("supportsHttpsTrafficOnly"))
        tls = props.get("minimumTlsVersion")
        tls_ok = _tls_at_least(tls)
        problems: list[str] = []
        if not https:
            problems.append("HTTP traffic permitted")
        if not tls_ok:
            problems.append(f"minimum TLS {tls or 'unset'}, below {MINIMUM_TLS}")
        findings.append(
            ResourceFinding(
                resource_id=_ref(row),
                resource_type="azure_storage_account",
                verdict="pass" if not problems else "fail",
                observed=(
                    f"HTTPS required at minimum TLS {tls}"
                    if not problems
                    else "; ".join(problems)
                ),
                detail={"https_only": https, "minimum_tls_version": tls},
            )
        )
    return findings


def evaluate_log_retention(
    rows: list[dict[str, Any]], *, min_days: int = LOG_RETENTION_MIN_DAYS
) -> list[ResourceFinding]:
    """One finding per Log Analytics workspace.

    Per-workspace rather than the connector's "shortest in the subscription":
    a capture fills one ODP blank and has to pick a number, while a check is
    allowed to name every workspace that falls short, which is what an operator
    needs in order to fix them.

    A workspace whose ``retentionInDays`` is missing or not a positive integer
    is ``manual_review_required``, not a failure: ARM omits the field on some
    workspace SKUs, and absence is not evidence of a short retention.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        days = _props(row).get("retentionInDays")
        if not isinstance(days, int) or isinstance(days, bool) or days <= 0:
            findings.append(
                ResourceFinding(
                    resource_id=_ref(row),
                    resource_type="azure_log_analytics_workspace",
                    verdict="manual_review_required",
                    observed="retentionInDays absent or not a positive integer",
                    detail={"retention_days": days},
                )
            )
            continue
        findings.append(
            ResourceFinding(
                resource_id=_ref(row),
                resource_type="azure_log_analytics_workspace",
                verdict="pass" if days >= min_days else "fail",
                observed=f"retains {days} day(s)",
                detail={"retention_days": days, "expected_min_days": min_days},
            )
        )
    return findings


def _enforcing(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assignments actually enforcing, not audit-only.

    ``DoNotEnforce`` observes drift; it does not maintain a baseline. Counting
    it would overstate CM-2, which is the connector's own reasoning.
    """
    return [
        row
        for row in rows
        if str(_props(row).get("enforcementMode") or "Default").lower() != "donotenforce"
    ]


def evaluate_policy_baseline_enforced(
    rows: list[dict[str, Any]], *, subscription_id: str
) -> list[ResourceFinding]:
    """One finding: the subscription is the resource."""
    enforcing = _enforcing(rows)
    audit_only = len(rows) - len(enforcing)
    if enforcing:
        named = [
            str(_props(r).get("displayName") or r.get("name") or "") for r in enforcing
        ]
        observed = f"{len(enforcing)} enforcing assignment(s)" + (
            f": {', '.join(sorted(n for n in named if n)[:5])}" if any(named) else ""
        )
    else:
        observed = (
            f"no enforcing assignment; {audit_only} audit-only"
            if audit_only
            else "no Azure Policy assignment on the subscription"
        )
    return [
        ResourceFinding(
            resource_id=subscription_id,
            resource_type="azure_subscription",
            verdict="pass" if enforcing else "fail",
            observed=observed,
            detail={"enforcing": len(enforcing), "audit_only": audit_only},
        )
    ]


def evaluate_defender_workload_protection(
    rows: list[dict[str, Any]], *, subscription_id: str
) -> list[ResourceFinding]:
    """One finding: the subscription is the resource.

    ``Free`` is the tier that runs no workload protection, so only ``Standard``
    counts. Unlike the connector's capture -- which stays silent when nothing is
    on Standard rather than asserting a negative -- a check is entitled to
    report the absence, because a failing verdict names what it observed instead
    of filling an SSP blank with it.
    """
    standard = [
        _ref(row)
        for row in rows
        if str(_props(row).get("pricingTier") or "").lower() == "standard"
    ]
    return [
        ResourceFinding(
            resource_id=subscription_id,
            resource_type="azure_subscription",
            verdict="pass" if standard else "fail",
            observed=(
                f"{len(standard)} plan(s) on Standard: {', '.join(sorted(standard)[:6])}"
                if standard
                else f"no Defender plan on Standard ({len(rows)} plan(s) examined)"
            ),
            detail={"standard_plans": sorted(standard), "plans_examined": len(rows)},
        )
    ]


EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    STORAGE_ENCRYPTION_AT_REST.key: evaluate_storage_encryption_at_rest,
    STORAGE_HTTPS_ONLY.key: evaluate_storage_https_only,
    LOG_RETENTION.key: evaluate_log_retention,
    POLICY_BASELINE_ENFORCED.key: evaluate_policy_baseline_enforced,
    DEFENDER_WORKLOAD_PROTECTION.key: evaluate_defender_workload_protection,
}
