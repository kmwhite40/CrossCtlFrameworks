"""What a remediation is, and the refusals that decide whether it exists.

Deliberately not a method on :class:`ccf.connectors.base.ConfigConnector`.
Read and write are not symmetric, and giving the read abstraction a write verb
would make every existing connector look one override away from mutating a
customer tenant.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..governance.waivers import REQUIRES_COVER
from ..posture.types import ResourceFinding


@dataclass(frozen=True)
class RemediationStep:
    """One resource's change, with the information needed to undo it.

    ``current_state`` is captured from the provider **at plan time**, not read
    from the stored finding, which may be hours stale. It is the reversal data,
    and a step without it is never planned: a change that cannot be undone is
    not one this platform offers to make.
    """

    resource_id: str
    resource_type: str
    action: str
    description: str
    current_state: dict[str, Any]
    target_state: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "action": self.action,
            "description": self.description,
            "current_state": self.current_state,
            "target_state": self.target_state,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> RemediationStep:
        return cls(
            resource_id=str(raw.get("resource_id", "")),
            resource_type=str(raw.get("resource_type", "")),
            action=str(raw.get("action", "")),
            description=str(raw.get("description", "")),
            current_state=dict(raw.get("current_state") or {}),
            target_state=dict(raw.get("target_state") or {}),
        )


@dataclass(frozen=True)
class StepOutcome:
    """What happened to one resource. ``failed`` is a result, never an exception."""

    resource_id: str
    status: str  # applied | failed | skipped
    detail: str
    at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "status": self.status,
            "detail": self.detail,
            "at": self.at,
        }


#: Statuses a step outcome may carry.
OUTCOME_STATUSES = ("applied", "failed", "skipped")


@runtime_checkable
class RemediationProvider(Protocol):
    """A provider that can change one kind of thing in one environment.

    ``is_write_configured`` is separate from a connector's ``is_configured`` on
    purpose, and keyed on a **different** credential
    (:attr:`write_credential_type`). A read-only deployment therefore cannot
    write structurally: the credential the write path asks for does not exist
    unless someone created it with write scopes, and no code path falls back to
    the read one.
    """

    key: str
    write_credential_type: str
    required_permissions: tuple[str, ...]
    #: Check keys this provider can remediate. Used by the registry to refuse
    #: two providers claiming the same check.
    handled_checks: tuple[str, ...]

    def handles(self, check_key: str) -> bool: ...
    async def is_write_configured(self) -> bool: ...
    async def plan(self, findings: Sequence[ResourceFinding]) -> list[RemediationStep]: ...
    async def apply(self, step: RemediationStep) -> StepOutcome: ...
    async def reverse(self, step: RemediationStep) -> StepOutcome: ...


#: Every registered provider. Populated by :mod:`ccf.enforcement.registry`,
#: which is imported for its side effect; kept here so ``types`` has no import
#: back-edge to the provider modules.
PROVIDER_REGISTRY: list[RemediationProvider] = []


def register(provider: RemediationProvider) -> RemediationProvider:
    """Add a provider, refusing a check another provider already claims.

    Two providers handling one check would make the change that gets applied
    depend on registry order -- which is not a property anyone should have to
    reason about when the outcome is a write to a production tenant.
    """
    claimed = {
        check: existing.key
        for existing in PROVIDER_REGISTRY
        for check in existing.handled_checks
    }
    for check in provider.handled_checks:
        if check in claimed:
            raise ValueError(
                f"check {check!r} is already handled by provider {claimed[check]!r}"
            )
    PROVIDER_REGISTRY.append(provider)
    return provider


def provider_for(check_key: str) -> RemediationProvider | None:
    """The provider that can remediate this check, or ``None``."""
    for provider in PROVIDER_REGISTRY:
        if provider.handles(check_key):
            return provider
    return None


@dataclass
class PlanRefusal:
    """Why no plan was produced. Carried so the reason reaches the operator."""

    reason: str
    detail: dict[str, Any] = field(default_factory=dict)


async def build_steps(
    findings: Sequence[ResourceFinding],
    provider: RemediationProvider,
    *,
    max_resources: int,
    only: Sequence[str] | None = None,
) -> tuple[list[RemediationStep], str | None]:
    """The steps a plan would contain, or the reason there is no plan.

    Refusals are decided **here**, at plan time, so an operator never holds an
    approvable plan that will be rejected when applied.

    Three filters, in order:

    1. Only findings needing cover are remediable. A passing resource has
       nothing to remediate, and planning one would mean writing to something
       that was already correct.
    2. ``only`` narrows to named resources -- the intended path for "just this
       one account".
    3. A step whose ``current_state`` is empty is dropped, because it could not
       be undone.

    Then the blast radius. An empty result is a **refusal**, not an empty plan:
    an approvable plan that would do nothing invites an approval that means
    nothing.
    """
    remediable = [f for f in findings if f.verdict in REQUIRES_COVER]
    if only is not None:
        wanted = set(only)
        remediable = [f for f in remediable if f.resource_id in wanted]

    steps = [s for s in await provider.plan(remediable) if s.current_state]
    if not steps:
        return [], "no resources to remediate"
    if len(steps) > max_resources:
        return [], (
            f"{len(steps)} resources exceeds the enforcement limit of {max_resources}"
        )
    return steps, None
