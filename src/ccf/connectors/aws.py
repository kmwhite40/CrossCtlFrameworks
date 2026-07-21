"""AWS GovCloud config-capture connector.

Reads AWS account configuration to inform organization-defined parameters.
Live capture uses ``boto3`` (against ``us-gov-west-1`` by default); boto3 is an
optional dependency, so this connector reports "not configured" unless it is
installed, the deployment has opted in via ``CCF_AWS_CAPTURE_ENABLED``, *and*
the calling organization has its own bound credential (access key or named
profile) passed in as ``credential`` — see :mod:`ccf.connectors.credentials`.
There is no global/env credential fallback (IA-05): an org with no bound
credential never captures under another org's or a shared account's identity.
The provider calls live behind ``_session`` — a single, clearly-marked
integration seam — so wiring real credentials is additive and does not change
the interface the API depends on.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from ..config import get_settings
from ..logging import get_logger
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)

# GovCloud regions live in the aws-us-gov partition; boto3 resolves endpoints
# (sts.<region>.amazonaws.com in-partition) automatically from the region name.
GOVCLOUD_REGIONS = ("us-gov-west-1", "us-gov-east-1")


class AwsGovCloudConnector(ConfigConnector):
    key = "aws_govcloud"
    label = "AWS GovCloud (US)"

    # ODP key → the AWS signal it is (or will be) derived from.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "audit_retention_period": "CloudWatch Logs retention (log group retentionInDays)",
        "encryption_at_rest": "EC2 default EBS encryption (get_ebs_encryption_by_default)",
        "flaw_remediation_timeframe": "Security Hub / Inspector finding SLAs (org policy)",
        "risk_assessment_frequency": "AWS Config conformance-pack evaluation cadence",
        "incident_report_timeframe": "GuardDuty / Security Hub automation (org runbook)",
        "nonlocal_maintenance_mfa": "IAM account MFA + Systems Manager Session Manager policy",
    }

    def _boto3_available(self) -> bool:
        try:
            import boto3  # noqa: F401, PLC0415
        except ImportError:
            return False
        return True

    def _region(self) -> str:
        c = self.credential or {}
        region = c.get("region")
        return region if isinstance(region, str) and region else get_settings().aws_region

    def is_configured(self) -> bool:
        if not (get_settings().aws_capture_enabled and self._boto3_available()):
            return False
        c = self.credential
        if not c:
            return False
        return bool((c.get("access_key_id") and c.get("secret_access_key")) or c.get("profile"))

    def _session(self) -> Any:
        import boto3  # noqa: PLC0415

        c = self.credential or {}
        # This org's own access key pair, or its own named profile — never the
        # ambient credential chain / a global profile (IA-05: no cross-tenant
        # attribution). ``is_configured`` guarantees one of these is present.
        if c.get("access_key_id") and c.get("secret_access_key"):
            return boto3.Session(
                aws_access_key_id=c["access_key_id"],
                aws_secret_access_key=c["secret_access_key"],
                aws_session_token=c.get("session_token"),
            )
        return boto3.Session(profile_name=c["profile"])

    async def verify(self) -> dict[str, Any]:
        """Confirm we can connect into the GovCloud account (STS caller identity)."""
        if not self._boto3_available():
            return {"connected": False, "reason": "boto3 not installed"}
        if not self.is_configured():
            return {
                "connected": False,
                "reason": "AWS credentials not configured for this organization",
            }
        region = self._region()

        def _call() -> dict[str, Any]:
            sts = self._session().client("sts", region_name=region)
            ident = sts.get_caller_identity()
            arn = ident.get("Arn", "")
            partition = arn.split(":")[1] if arn.count(":") >= 2 else "aws"
            return {
                "connected": True,
                "account": ident.get("Account"),
                "arn": arn,
                "region": region,
                "partition": partition,
                "govcloud": partition == "aws-us-gov" or region in GOVCLOUD_REGIONS,
            }

        try:
            return await asyncio.to_thread(_call)
        except Exception as e:
            return {"connected": False, "reason": str(e)[:200], "region": region}

    async def capture(self) -> list[CapturedParameter]:
        if not self.is_configured():
            return []
        out: list[CapturedParameter] = []
        # Isolate each sub-capture: one failing AWS call (throttling, a single
        # service permission gap) must not discard parameters other calls captured.
        for sub in (self._capture_log_retention, self._capture_ebs_encryption):
            try:
                out.extend(await sub())
            except Exception as e:  # best-effort — never break the caller
                log.warning(
                    "connector.aws.capture_failed", capture=sub.__name__, error=str(e)[:200]
                )
        return out

    async def _capture_log_retention(self) -> list[CapturedParameter]:
        """CloudWatch Logs retention → audit record retention ODP.

        Integration seam: run the (blocking) boto3 call in a thread. Wired to
        return the maximum configured log-group retention as the audit period.
        """

        def _read() -> str | None:
            client = self._session().client("logs", region_name=self._region())
            retentions: list[int] = []
            paginator = client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for grp in page.get("logGroups", []):
                    if grp.get("retentionInDays"):
                        retentions.append(int(grp["retentionInDays"]))
            if not retentions:
                return None
            return f"{min(retentions)} days"

        value = await asyncio.to_thread(_read)
        if not value:
            return []
        return [
            CapturedParameter(
                odp_key="audit_retention_period",
                value=value,
                nist_id="3.3.1",
                source="AWS: CloudWatch Logs retentionInDays (minimum across log groups)",
                confidence="medium",
            )
        ]

    async def _capture_ebs_encryption(self) -> list[CapturedParameter]:
        """EC2 default EBS encryption → encryption-at-rest signal (KSI-SVC-03)."""

        def _read() -> bool:
            client = self._session().client("ec2", region_name=self._region())
            return bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))

        if not await asyncio.to_thread(_read):
            return []
        return [
            CapturedParameter(
                odp_key="encryption_at_rest",
                value="enabled",
                nist_id="SC-28",
                source="AWS: EC2 default EBS encryption enabled",
                confidence="high",
            )
        ]
