"""Google Cloud posture checks.

Like ``azure_arm`` before it, the GCP connector read three real collections,
mapped each to an 800-53 control, and registered no checks: a system whose only
connector was Google Cloud resolved nothing and reported ``checks_expected: 0``,
which reads as clean rather than as unassessed.

**What this is worth, stated plainly.** Of the three controls these evidence,
only ``SC-12`` is not already reached by another provider, so headline coverage
moves 33 to 34 of the 288 Moderate controls. The gain is not the number: it is
that a GCP-only tenant goes from *nothing scanned* to three checks with
verdicts. A coverage figure that counts controls hides that distinction, which
is why it is written down here.

Field names and judgements come from the connector's own ``_map_*`` methods, not
from the Google documentation, so the capture half and the check half cannot
disagree about a payload. The CMEK judgement in particular is the connector's:
Google encrypts every bucket at rest unconditionally, so the question worth
answering is not *whether* but *with whose key*.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..types import PostureCheck, ResourceFinding

#: Shortest Cloud Logging retention accepted, in days. Organization-defined, so
#: it is a parameter with a default rather than a constant -- the same treatment
#: the Azure check gives it, and for the same reason: a wrong number here
#: becomes a false finding on somebody's authorization package.
LOG_RETENTION_MIN_DAYS = 90

LOG_RETENTION_EXPECTED = (
    "every Cloud Logging bucket retains audit records for at least {min_days} days"
)

BUCKET_CMEK = PostureCheck(
    key="gcp.storage.customer_managed_keys",
    title="Storage buckets use customer-managed encryption keys",
    provider="gcp",
    resource_type="gcp_storage_bucket",
    expected=(
        "every Cloud Storage bucket sets a default customer-managed key "
        "(encryption.defaultKmsKeyName), not Google-managed keys"
    ),
    control_ids=("SC-28", "SC-28(1)", "SC-12"),
    required_permissions=("storage.buckets.list",),
)

LOG_RETENTION = PostureCheck(
    key="gcp.logging.retention",
    title="Cloud Logging buckets retain audit records long enough",
    provider="gcp",
    resource_type="gcp_log_bucket",
    expected=LOG_RETENTION_EXPECTED.format(min_days=LOG_RETENTION_MIN_DAYS),
    control_ids=("AU-11", "AU-4"),
    required_permissions=("logging.buckets.list",),
)

ORG_POLICY_ENFORCED = PostureCheck(
    key="gcp.orgpolicy.constraints_enforced",
    title="Organization Policy constraints are in effect on the project",
    provider="gcp",
    resource_type="gcp_project",
    expected="at least one Organization Policy constraint applies to the project",
    control_ids=("CM-2", "CM-6"),
    required_permissions=("orgpolicy.policies.list",),
)

CHECKS: tuple[PostureCheck, ...] = (BUCKET_CMEK, LOG_RETENTION, ORG_POLICY_ENFORCED)

#: Check key -> ``<url template>#<response envelope key>``.
#:
#: Google's REST APIs are full URLs with three different envelopes -- ``items``
#: for Storage, ``buckets`` for Logging, ``policies`` for Organization Policy --
#: so the endpoint token carries both. Registering only the URL would leave the
#: envelope encoded in the connector, in a second place that can drift from this
#: one. ``{project}`` is substituted by the connector from its own credential,
#: never from a caller.
ENDPOINTS: dict[str, str] = {
    BUCKET_CMEK.key: "https://storage.googleapis.com/storage/v1/b?project={project}#items",
    LOG_RETENTION.key: (
        "https://logging.googleapis.com/v2/projects/{project}/locations/global/buckets#buckets"
    ),
    ORG_POLICY_ENFORCED.key: (
        "https://orgpolicy.googleapis.com/v2/projects/{project}/policies#policies"
    ),
}


def _ref(row: dict[str, Any], *keys: str) -> str:
    """The first populated identifier among ``keys``, else ``unknown``.

    Google names a resource differently per API -- ``name`` on a bucket, a
    fully-qualified ``name`` on a log bucket -- so the caller says which to
    prefer rather than this guessing.
    """
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value:
            return value.rsplit("/", 1)[-1] if "/" in value else value
    return "unknown"


def evaluate_bucket_customer_managed_keys(
    rows: list[dict[str, Any]],
) -> list[ResourceFinding]:
    """One finding per bucket: is the default key the organization's?

    Not "is it encrypted" -- Google encrypts every bucket unconditionally, so a
    check answering that would pass every project on earth and tell an assessor
    nothing. The connector draws the same distinction in its capture.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        encryption = row.get("encryption")
        key_name = (
            encryption.get("defaultKmsKeyName") if isinstance(encryption, dict) else None
        )
        # Narrowed to `str` rather than tested for truthiness alone, so the
        # formatting below is reading a string mypy agrees is one.
        cmek = key_name if isinstance(key_name, str) and key_name else None
        findings.append(
            ResourceFinding(
                resource_id=_ref(row, "name", "id"),
                resource_type="gcp_storage_bucket",
                verdict="pass" if cmek else "fail",
                observed=(
                    f"default customer-managed key {cmek.rsplit('/', 1)[-1]}"
                    if cmek
                    else "no default customer-managed key; Google-managed keys in use"
                ),
                detail={"default_kms_key": key_name},
            )
        )
    return findings


def evaluate_log_retention(
    rows: list[dict[str, Any]], *, min_days: int = LOG_RETENTION_MIN_DAYS
) -> list[ResourceFinding]:
    """One finding per log bucket.

    Per-bucket rather than the connector's "shortest in the project": a capture
    fills one ODP blank and must pick a number, while a check may name every
    bucket that falls short, which is what an operator needs to fix them.

    A bucket with no ``retentionDays`` is ``manual_review_required``, not a
    failure -- absence is not evidence of a short retention.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        raw = row.get("retentionDays")
        ref = _ref(row, "name")
        if not isinstance(raw, int | float) or isinstance(raw, bool) or raw <= 0:
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="gcp_log_bucket",
                    verdict="manual_review_required",
                    observed="retentionDays absent or not a positive number",
                    detail={"retention_days": raw},
                )
            )
            continue
        days = int(raw)
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="gcp_log_bucket",
                verdict="pass" if days >= min_days else "fail",
                observed=f"retains {days} day(s)",
                detail={"retention_days": days, "expected_min_days": min_days},
            )
        )
    return findings


def evaluate_org_policy_enforced(
    rows: list[dict[str, Any]], *, project_id: str
) -> list[ResourceFinding]:
    """One finding: the project is the resource."""
    named = sorted(
        _ref(row, "name") for row in rows if isinstance(row.get("name"), str)
    )
    return [
        ResourceFinding(
            resource_id=project_id,
            resource_type="gcp_project",
            verdict="pass" if named else "fail",
            observed=(
                f"{len(named)} constraint(s): {', '.join(named[:6])}"
                if named
                else "no Organization Policy constraint applies to this project"
            ),
            detail={"constraints": named[:20], "total": len(named)},
        )
    ]


EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    BUCKET_CMEK.key: evaluate_bucket_customer_managed_keys,
    LOG_RETENTION.key: evaluate_log_retention,
    ORG_POLICY_ENFORCED.key: evaluate_org_policy_enforced,
}
