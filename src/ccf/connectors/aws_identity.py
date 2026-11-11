"""How Concord authenticates into a customer's AWS account by role.

Access keys and a named profile were the only ways in. A key pair is a
long-lived secret the customer has to mint, hand over and rotate; a named
profile is the *host's* identity, which ``governance.control_tests`` already
refuses to attribute to a tenant. The pattern AWS documents for a third party
reading a customer account is a role the customer creates, trusting Concord's
broker identity, conditioned on an **External ID** -- the confused-deputy
guard: without it, any Concord tenant who learned another customer's role ARN
could ask Concord to assume it.

So:

* The External ID is **Concord's**, generated per organization and never
  accepted from a request (``connectors.credentials.set_credential`` drops one
  and injects the stored value). A customer-chosen ID is exactly the value an
  attacker would choose.
* The broker identity is configured per partition on the host
  (``CCF_AWS_BROKER_PROFILE_GOVCLOUD`` / ``_COMMERCIAL``). There is no
  cross-partition fallback: a GovCloud role is never assumed from commercial
  credentials, and a missing broker is reported as such.
* The broker is meant to hold ``sts:AssumeRole`` on
  ``arn:<partition>:iam::*:role/ConcordConnector*`` and nothing else, so the
  host credential can read nothing without a tenant's trust policy *and* its
  External ID.
* Failures are classified into fixed reasons. A raw AssumeRole error names the
  broker ARN; that is the platform's identity and is not repeated to a tenant.

Design adapted from m365-docs-hub ADR 0002 (merged there as "phase 0"), minus
its Carbøn-specific mechanics (Entra-federated broker, ``CarbonConnector*``).
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Iterable
from typing import Any

#: ``concord-`` + 32 hex characters (16 random bytes).
EXTERNAL_ID_RE = re.compile(r"^concord-[0-9a-f]{32}$")
ROLE_ARN_RE = re.compile(r"^arn:(aws|aws-us-gov):iam::(\d{12}):role/([\w+=,.@/-]{1,512})$")
#: The role name prefix the broker policy permits; customers name roles to it.
ROLE_NAME_PREFIX = "ConcordConnector"
SESSION_SECONDS = 3600
#: Refresh an assumed session this long before it expires.
REFRESH_SKEW_SECONDS = 300

GOVCLOUD_REGIONS = frozenset({"us-gov-west-1", "us-gov-east-1"})


class RoleConfigError(ValueError):
    """A role credential that cannot work -- said before any STS call."""


def new_external_id() -> str:
    return "concord-" + secrets.token_hex(16)


def region_partition(region: str) -> str | None:
    """The partition a region belongs to, or None when Concord does not support it.

    GovCloud is exactly the two ``us-gov-`` regions; China (``cn-``) and the
    isolated regions (``us-iso*``, ``eu-isoe``) are not supported partitions,
    rather than misread as commercial by a prefix test.
    """
    r = (region or "").strip().lower()
    if r in GOVCLOUD_REGIONS:
        return "aws-us-gov"
    if not r or r.startswith(("cn-", "us-iso", "eu-isoe", "us-gov-")):
        return None
    return "aws"


def parse_role_arn(arn: str) -> tuple[str, str, str]:
    """``(partition, account_id, role_name)`` or :class:`RoleConfigError`."""
    m = ROLE_ARN_RE.match((arn or "").strip())
    if m is None:
        raise RoleConfigError(
            "role_arn must be an IAM role ARN: arn:aws-us-gov:iam::<12-digit account>:role/<name>"
        )
    return m.group(1), m.group(2), m.group(3)


def validate_role(role_arn: str, region: str, *, account_id: str | None = None) -> str:
    """Check a role credential before it is stored; return its partition."""
    partition, account, name = parse_role_arn(role_arn)
    expected = region_partition(region)
    if expected is None:
        raise RoleConfigError(f"region {region!r} is not in a supported AWS partition")
    if partition != expected:
        raise RoleConfigError(
            f"the role is in the {partition} partition but the region {region} is in {expected}"
        )
    if account_id and account_id != account:
        raise RoleConfigError("account_id does not match the account in role_arn")
    if not name.split("/")[-1].startswith(ROLE_NAME_PREFIX):
        raise RoleConfigError(
            f"the role's name must start with {ROLE_NAME_PREFIX!r}; the broker may assume "
            "only roles named so"
        )
    return partition


def trust_policy(broker_arn: str, external_id: str) -> dict[str, Any]:
    """The trust policy the customer attaches to their ``ConcordConnector*`` role."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": broker_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def permissions_policy(actions: Iterable[str]) -> dict[str, Any]:
    """Least privilege: exactly the read actions Concord's AWS checks declare."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": sorted(set(actions)), "Resource": "*"}
        ],
    }


#: Read actions the connector makes outside any posture check: ODP capture
#: and the Security Hub attestation read. ``sts:GetCallerIdentity`` needs no
#: permission and is not listed.
CONNECTOR_PERMISSIONS = (
    "logs:DescribeLogGroups",
    "ec2:GetEbsEncryptionByDefault",
    "securityhub:GetEnabledStandards",
    "securityhub:GetFindings",
    # Organizations inventory -- answered only by a management or delegated
    # administrator account; a member account's denial is reported as such.
    "organizations:DescribeOrganization",
    "organizations:ListRoots",
    "organizations:ListOrganizationalUnitsForParent",
    "organizations:ListAccountsForParent",
)


def required_actions(check_permissions: Iterable[str]) -> list[str]:
    """Every IAM action the connector can make: its checks' and its own."""
    return sorted(set(check_permissions) | set(CONNECTOR_PERMISSIONS))


def pretty(policy: dict[str, Any]) -> str:
    return json.dumps(policy, indent=2)


#: AWS error code -> the reason a tenant is shown. Fixed strings: an STS error
#: message can carry the broker's ARN.
_FAILURES = {
    "AccessDenied": "Concord could not assume the role: check the role's trust policy names "
    "Concord's broker and this External ID",
    "AccessDeniedException": "the role is not permitted to make this call",
    "InvalidClientTokenId": "the broker credential on this Concord host is not valid",
    "ExpiredToken": "the broker credential on this Concord host has expired",
    "RegionDisabledException": "STS is not enabled in this region for the account",
    "NoSuchEntity": "the role does not exist",
    "MalformedPolicyDocument": "the role's trust policy is malformed",
}


def classify(error: BaseException) -> str:
    """A fixed, tenant-safe reason for an AWS failure."""
    if isinstance(error, RoleConfigError):
        return str(error)
    code = ""
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        code = str((response.get("Error") or {}).get("Code") or "")
    if code in _FAILURES:
        return _FAILURES[code]
    if code:
        return f"AWS refused the request ({code})"
    name = type(error).__name__
    if name in ("EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"):
        return "AWS could not be reached from this Concord host"
    if name in ("NoCredentialsError", "ProfileNotFound"):
        return "the broker credential is not configured on this Concord host"
    return "the AWS call failed"
