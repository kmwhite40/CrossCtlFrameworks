"""Disable a stale Entra ID account.

The first enforcement provider, chosen deliberately. It is bounded -- one
boolean field on one object -- it is the canonical remediation for the
stale-account check, and it is **reversible**: ``accountEnabled`` false goes
back to true.

Just as deliberately *not* first: anything touching Conditional Access policy,
which can lock every administrator out of a tenant. A provider that can cause a
lockout is not the one to learn on.

Writes use a **separate credential** (``msgraph_write``) from the read
connector's ``msgraph``, backed by an app registration holding
``User.ReadWrite.All`` rather than ``User.Read.All``. A deployment that never
created one cannot write, and no code path here falls back to the read
credential.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from ...config import get_settings
from ...logging import get_logger
from ...posture.providers import m365 as m365_checks
from ...posture.types import ResourceFinding
from ..types import ProviderUnavailableError, RemediationStep, StepOutcome, register

log = get_logger(__name__)


@register
class M365AccountProvider:
    """Disable (and re-enable) Entra ID user accounts through Microsoft Graph."""

    key = "m365_account"
    write_credential_type = "msgraph_write"
    required_permissions: tuple[str, ...] = ("User.ReadWrite.All",)
    handled_checks: tuple[str, ...] = (m365_checks.STALE_ACCOUNTS.key,)

    #: The field this provider changes, and the only one it changes.
    FIELD = "accountEnabled"

    def __init__(self, credential: dict[str, Any] | None = None) -> None:
        self.credential = credential

    async def is_write_configured(self) -> bool:
        """True only with a complete **write** credential bundle.

        Not a wrapper over the read connector's ``is_configured``: the point of
        a separate credential is that having one says nothing about having the
        other.
        """
        c = self.credential
        return bool(c and c.get("tenant_id") and c.get("client_id") and c.get("client_secret"))

    async def _token(self, client: httpx.AsyncClient) -> str | None:
        s = get_settings()
        c = self.credential or {}
        resp = await client.post(
            f"{s.graph_login_url}/{c.get('tenant_id')}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": c.get("client_id"),
                "client_secret": c.get("client_secret"),
                "scope": f"{s.graph_base_url}/.default",
            },
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        return token if isinstance(token, str) else None

    async def plan(
        self, findings: Sequence[ResourceFinding]
    ) -> list[RemediationStep]:
        """A step per account, carrying its current ``accountEnabled``.

        Read from Graph **now**, not from the finding: the finding may be hours
        old, and the reversal data has to describe the state this change is
        actually departing from. An account whose current state cannot be read
        gets no step -- ``build_steps`` then drops it, because a change that
        cannot be undone is not one to offer.

        A token or network failure raises :class:`ProviderUnavailableError` rather
        than returning ``[]``. An empty return here reads as "the tenant is
        clean" (``build_steps`` reports "no resources to remediate"); an
        operator must not read that when the truth is "Graph was unreachable
        and nothing was checked". ``build_steps`` turns the exception into its
        own, distinctly worded refusal.
        """
        if not findings or not await self.is_write_configured():
            return []
        s = get_settings()
        steps: list[RemediationStep] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                token = await self._token(client)
                if not token:
                    raise ProviderUnavailableError("Graph did not return an access token")
                headers = {"Authorization": f"Bearer {token}"}
                for finding in findings:
                    current = await self._read_state(
                        client, finding.resource_id, headers, base=s.graph_base_url
                    )
                    if current is None:
                        continue
                    steps.append(
                        RemediationStep(
                            resource_id=finding.resource_id,
                            resource_type="entra_user",
                            action="disable_account",
                            description=(
                                f"Disable {finding.resource_id} "
                                f"({finding.observed})"
                            ),
                            current_state={self.FIELD: current},
                            target_state={self.FIELD: False},
                        )
                    )
        except ProviderUnavailableError:
            raise
        except Exception as e:
            log.warning("enforcement.m365.plan_failed", error=str(e)[:200])
            raise ProviderUnavailableError(str(e)[:300]) from e
        return steps

    async def _read_state(
        self,
        client: httpx.AsyncClient,
        resource_id: str,
        headers: dict[str, str],
        *,
        base: str,
    ) -> bool | None:
        try:
            resp = await client.get(
                f"{base}/v1.0/users/{resource_id}?$select=id,{self.FIELD}",
                headers=headers,
            )
            resp.raise_for_status()
            value = resp.json().get(self.FIELD)
        except Exception as e:
            log.warning(
                "enforcement.m365.read_state_failed",
                resource=resource_id,
                error=str(e)[:200],
            )
            return None
        return bool(value) if isinstance(value, bool) else None

    async def apply(self, step: RemediationStep) -> StepOutcome:
        """Disable the account. The body is exactly one field."""
        return await self._patch(step, {self.FIELD: False}, verb="disabled")

    async def reverse(self, step: RemediationStep) -> StepOutcome:
        """Restore the captured state, rather than assuming it was enabled."""
        target = step.current_state.get(self.FIELD, True)
        return await self._patch(step, {self.FIELD: bool(target)}, verb="restored")

    async def _patch(
        self, step: RemediationStep, body: dict[str, Any], *, verb: str
    ) -> StepOutcome:
        """One PATCH, with a failure reported as an outcome rather than raised.

        A 403 here almost always means the app registration lacks
        ``User.ReadWrite.All``, so the permission is named in the detail: an
        operator reading a failed step should not have to infer it.

        The token fetch and the PATCH are handled in **separate** try/excepts,
        deliberately: a token-fetch failure means the PATCH was never sent, so
        it is unambiguously ``failed``. Only a failure while the PATCH itself
        is in flight is ``uncertain`` -- the request may have reached Graph and
        been applied before the failure arrived (a timeout, a connection
        reset). Collapsing the two into one try/except would report a token
        failure as ``uncertain`` too, and ``reverse_plan`` replays ``uncertain``
        steps -- an unnecessary (if harmless) reversal PATCH for a write that
        provably never happened.
        """
        if not await self.is_write_configured():
            return StepOutcome(
                step.resource_id, "skipped", "no write credential configured"
            )
        s = get_settings()
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                token = await self._token(client)
            except Exception as e:
                return StepOutcome(
                    step.resource_id, "failed", f"could not obtain a Graph token: {str(e)[:250]}"
                )
            if not token:
                return StepOutcome(
                    step.resource_id, "failed", "could not obtain a Graph token"
                )
            try:
                resp = await client.patch(
                    f"{s.graph_base_url}/v1.0/users/{step.resource_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json=body,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                # Graph responded with an error status. A single PATCH is
                # atomic -- an error response means the field did not change --
                # so this is a genuine, known failure, not a maybe.
                status = e.response.status_code
                needed = ", ".join(self.required_permissions)
                return StepOutcome(
                    step.resource_id,
                    "failed",
                    f"{status} from Graph; requires {needed}",
                )
            except Exception as e:
                # A timeout, a connection reset, a malformed response: the
                # request's fate is unknown, so ``reverse_plan`` replays it
                # rather than silently leaving a possibly-applied change
                # unreversed. Safe either way -- reversal restores the
                # captured prior state, a no-op if nothing actually changed.
                return StepOutcome(step.resource_id, "uncertain", str(e)[:300])
        return StepOutcome(step.resource_id, "applied", f"{self.FIELD} {verb}")
