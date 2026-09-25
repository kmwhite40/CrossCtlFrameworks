"""Google Cloud config-capture connector.

Reads three organization-defined parameters from live Google Cloud
configuration. Each comes from one REST API, and the connector emits exactly
the three its ``PARAMETER_MAP`` advertises -- ``tests/
test_connector_capture_parity.py`` measures that behaviourally, because a map
that describes no code is a claim made to an operator about the product.

**Scope.** Three parameters, not a survey. Google Cloud exposes far more that
could be read, and a map advertising values nobody implemented is exactly the
defect that guard exists for. Widening it is additive and each addition owes a
mapper and a harness.

Authentication is the service-account JWT grant (RFC 7523): sign an assertion
with the tenant's own private key, exchange it for an access token. No
Application Default Credentials and no metadata-server fallback -- both would
resolve the *host's* identity rather than the organization's, which is the
distinction `governance/control_tests` rung 3 already draws for AWS profiles.
A capture made under the host's identity does not evidence a tenant.
"""

from __future__ import annotations

import base64
import json
import time
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from ..logging import get_logger
from .base import CapturedParameter, ConfigConnector

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass

log = get_logger(__name__)

_TIMEOUT = 20.0
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

#: Read-only. The connector never writes, and a credential scoped wider than
#: this is the operator's choice, not something this code asks for.
_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class GcpConnector(ConfigConnector):
    """Capture from Google Cloud with a tenant service account."""

    key = "gcp"
    label = "Google Cloud (Assured Workloads)"

    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "encryption_at_rest": (
            "Cloud Storage bucket encryption — customer-managed encryption keys "
            "(encryption.defaultKmsKeyName) across the project's buckets"
        ),
        "log_retention_period": (
            "Cloud Logging bucket retention (retentionDays on the project's log "
            "buckets)"
        ),
        "configuration_baseline_enforcement": (
            "Organization Policy constraints in effect on the project "
            "(orgpolicy.googleapis.com policies)"
        ),
    }

    #: The 800-53 equivalent carried in ``detail``, so a project whose entries
    #: are 800-53 rather than 800-171 can still join. Same split the Azure
    #: connector documents: ``nist_id`` is the 800-171 requirement, because
    #: that is the namespace ``governance/automation`` matches against.
    _NIST_80053: ClassVar[dict[str, str]] = {
        "encryption_at_rest": "SC-28",
        "log_retention_period": "AU-11",
        "configuration_baseline_enforcement": "CM-2",
    }

    # ── credentials ──────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """True only with this organization's own service-account bundle.

        ``project_id`` is required alongside the key because every read below
        is project-scoped: a credential without one authenticates and can read
        nothing, which would report configured and capture zero -- the failure
        the Azure connector's own ``is_configured`` docstring names.
        """
        c = self.credential
        return bool(
            c
            and c.get("project_id")
            and c.get("client_email")
            and c.get("private_key")
        )

    def _assertion(self, now: int) -> str | None:
        """A signed JWT bearer assertion (RFC 7523), or ``None`` if unsignable."""
        c = self.credential or {}
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": c.get("client_email"),
            "scope": _SCOPE,
            "aud": _TOKEN_URL,
            "iat": now,
            "exp": now + 3600,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        ).encode("ascii")
        try:
            from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
            from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: PLC0415

            key = serialization.load_pem_private_key(
                str(c.get("private_key", "")).encode("utf-8"), password=None
            )
            if not isinstance(key, rsa.RSAPrivateKey):
                return None
            signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            log.warning("gcp.assertion_failed")
            return None
        return signing_input.decode("ascii") + "." + _b64url(signature)

    async def _token(self, client: httpx.AsyncClient) -> str | None:
        assertion = self._assertion(int(time.time()))
        if assertion is None:
            return None
        resp = await client.post(
            _TOKEN_URL, data={"grant_type": _JWT_GRANT, "assertion": assertion}
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        return token if isinstance(token, str) else None

    # ── capture ──────────────────────────────────────────────────────────────

    def _captured(
        self,
        odp_key: str,
        value: str,
        nist_id: str,
        source: str,
        *,
        confidence: str = "medium",
        detail: dict[str, Any] | None = None,
    ) -> CapturedParameter:
        """One capture, with the 800-53 equivalent carried in ``detail``.

        Built through here rather than at each call site so no mapper can ship
        a capture without its cross-reference -- the field that decides whether
        it ever reaches a narrative.
        """
        return CapturedParameter(
            odp_key=odp_key,
            value=value,
            nist_id=nist_id,
            source=source,
            confidence=confidence,
            detail={**(detail or {}), "nist_80053_id": self._NIST_80053[odp_key]},
        )

    async def capture(self) -> list[CapturedParameter]:
        """Read the three parameters. Best-effort: never raises."""
        if not self.is_configured():
            return []
        c = self.credential or {}
        project = str(c.get("project_id"))
        out: list[CapturedParameter] = []
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                token = await self._token(client)
                if not token:
                    return []
                headers = {"Authorization": f"Bearer {token}"}
                out.extend(await self._map_storage(client, headers, project))
                out.extend(await self._map_logging(client, headers, project))
                out.extend(await self._map_org_policy(client, headers, project))
        except Exception:
            log.warning("gcp.capture_failed", project=project)
            return out
        return out

    async def _map_storage(
        self, client: httpx.AsyncClient, headers: dict[str, str], project: str
    ) -> list[CapturedParameter]:
        """Encryption at rest, across the project's Cloud Storage buckets.

        Google encrypts every bucket at rest unconditionally, so the question
        worth answering is not *whether* but *with whose key*: a bucket with no
        ``defaultKmsKeyName`` uses Google-managed keys, and one with it uses a
        customer-managed key the organization controls. Reporting "encrypted"
        for both would be true and useless to an assessor.
        """
        resp = await client.get(
            "https://storage.googleapis.com/storage/v1/b",
            params={"project": project},
            headers=headers,
        )
        resp.raise_for_status()
        buckets = resp.json().get("items") or []
        if not buckets:
            return []
        with_cmek = [
            b for b in buckets if (b.get("encryption") or {}).get("defaultKmsKeyName")
        ]
        value = (
            "customer-managed encryption keys (Cloud KMS) on all buckets"
            if len(with_cmek) == len(buckets)
            else f"customer-managed keys on {len(with_cmek)} of {len(buckets)} buckets; "
            "the remainder use Google-managed keys"
        )
        return [
            self._captured(
                "encryption_at_rest",
                value,
                "3.13.16",
                "Cloud Storage: buckets.list encryption.defaultKmsKeyName",
                confidence="high" if len(with_cmek) == len(buckets) else "medium",
                detail={"buckets": len(buckets), "cmek": len(with_cmek)},
            )
        ]

    async def _map_logging(
        self, client: httpx.AsyncClient, headers: dict[str, str], project: str
    ) -> list[CapturedParameter]:
        """Audit-log retention, reported as the SHORTEST bucket's retention.

        The shortest, not the longest and not an average: retention is the
        window in which a record still exists, so a project with one 3650-day
        bucket and one 30-day bucket retains some logs for 30 days. Reporting
        the longest would overstate the control to an assessor.
        """
        resp = await client.get(
            f"https://logging.googleapis.com/v2/projects/{project}/locations/global/buckets",
            headers=headers,
        )
        resp.raise_for_status()
        buckets = resp.json().get("buckets") or []
        days = [
            int(b["retentionDays"])
            for b in buckets
            if isinstance(b.get("retentionDays"), int | float)
        ]
        if not days:
            return []
        shortest = min(days)
        return [
            self._captured(
                "log_retention_period",
                f"{shortest} days",
                "3.3.1",
                "Cloud Logging: buckets.list retentionDays (shortest bucket)",
                detail={"buckets": len(days), "shortest_days": shortest, "all_days": sorted(days)},
            )
        ]

    async def _map_org_policy(
        self, client: httpx.AsyncClient, headers: dict[str, str], project: str
    ) -> list[CapturedParameter]:
        """Configuration baseline, as the Organization Policy constraints in effect."""
        resp = await client.get(
            f"https://orgpolicy.googleapis.com/v2/projects/{project}/policies",
            headers=headers,
        )
        resp.raise_for_status()
        policies = resp.json().get("policies") or []
        names = sorted(
            str(p.get("name", "")).rsplit("/", 1)[-1] for p in policies if p.get("name")
        )
        if not names:
            return []
        return [
            self._captured(
                "configuration_baseline_enforcement",
                f"{len(names)} Organization Policy constraint(s) enforced on the project",
                "3.4.1",
                "Organization Policy: projects.policies.list",
                detail={"constraints": names[:20], "total": len(names)},
            )
        ]

    async def verify(self) -> dict[str, Any]:
        """Prove the service account authenticates and the project is readable."""
        if not self.is_configured():
            return {"connected": False, "reason": "no Google Cloud credential is configured"}
        c = self.credential or {}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                token = await self._token(client)
                if not token:
                    return {"connected": False, "reason": "the service-account key did not sign"}
                resp = await client.get(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/{c.get('project_id')}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                resp.raise_for_status()
                body = resp.json()
        except Exception as e:
            return {"connected": False, "reason": f"{type(e).__name__}: {e}"}
        return {
            "connected": True,
            "project_id": body.get("projectId"),
            "project_number": body.get("projectNumber"),
            "service_account": c.get("client_email"),
        }
