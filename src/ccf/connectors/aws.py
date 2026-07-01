"""AWS GovCloud config-capture connector.

Reads AWS account configuration to inform organization-defined parameters.
Live capture uses ``boto3`` (against ``us-gov-west-1`` by default); boto3 is an
optional dependency, so this connector reports "not configured" unless it is
installed *and* ``CCF_AWS_CAPTURE_ENABLED`` is set. The provider calls live
behind ``_client`` — a single, clearly-marked integration seam — so wiring real
credentials is additive and does not change the interface the API depends on.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar

from ..config import get_settings
from ..logging import get_logger
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)


class AwsGovCloudConnector(ConfigConnector):
    key = "aws_govcloud"
    label = "AWS GovCloud (US)"

    # ODP key → the AWS signal it is (or will be) derived from.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "audit_retention_period": "CloudWatch Logs retention (log group retentionInDays)",
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

    def is_configured(self) -> bool:
        return bool(get_settings().aws_capture_enabled) and self._boto3_available()

    async def capture(self) -> list[CapturedParameter]:
        if not self.is_configured():
            return []
        out: list[CapturedParameter] = []
        try:
            out.extend(await self._capture_log_retention())
        except Exception as e:  # best-effort — never break the caller
            log.warning("connector.aws.capture_failed", error=str(e)[:200])
            return []
        return out

    async def _capture_log_retention(self) -> list[CapturedParameter]:
        """CloudWatch Logs retention → audit record retention ODP.

        Integration seam: run the (blocking) boto3 call in a thread. Wired to
        return the maximum configured log-group retention as the audit period.
        """

        def _read() -> str | None:
            import boto3  # noqa: PLC0415

            client = boto3.client("logs", region_name=get_settings().aws_region)
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
