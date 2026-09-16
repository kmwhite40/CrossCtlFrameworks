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


class ProviderUnavailableError(RuntimeError):
    """A provider could not evaluate remediation candidates at all.

    Distinct from an empty plan: an empty plan means the tenant was checked
    and found clean. This means the check itself could not be made -- a token
    or network failure -- and :func:`build_steps` turns it into its own
    refusal, worded differently from "no resources to remediate", so an
    operator does not read "clean" when the truth is "unreachable".
    """


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
    """What happened to one resource. ``failed`` is a result, never an exception.

    ``uncertain`` is distinct from ``failed``: ``failed`` means the provider
    knows the write did not happen (Graph responded with an error status, which
    for a single atomic PATCH means nothing changed). ``uncertain`` means the
    provider does not know -- a timeout or connection error can arrive *after*
    the far end already applied the change. Reversal treats the two
    differently: only ``applied`` and ``uncertain`` steps are replayed, because
    replaying a step that never actually landed is safe (it restores the
    captured prior state, which is a no-op if nothing changed) where silently
    leaving a possibly-applied change unreversed is not.
    """

    resource_id: str
    status: str  # applied | failed | skipped | uncertain
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
OUTCOME_STATUSES = ("applied", "failed", "skipped", "uncertain")


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

    #: Declared so the registry can hold classes and the service can bind one
    #: organization's write credential to a fresh instance -- matching
    #: ``connectors.get_connector``. A provider is never shared between
    #: tenants, because a shared instance would carry a credential across a
    #: tenant boundary.
    def __init__(self, credential: dict[str, Any] | None = None) -> None: ...

    async def is_write_configured(self) -> bool: ...
    async def plan(self, findings: Sequence[ResourceFinding]) -> list[RemediationStep]:
        """May raise :class:`ProviderUnavailableError` if candidates could not be
        evaluated at all (e.g. a token or network failure) -- distinct from
        returning ``[]``, which means the tenant was checked and is clean."""
        ...
    async def apply(self, step: RemediationStep) -> StepOutcome: ...
    async def reverse(self, step: RemediationStep) -> StepOutcome: ...


#: Registered provider **classes**, matching ``connectors.get_connector``'s
#: shape: a provider is instantiated bound to one organization's write
#: credential, never shared. Populated by :mod:`ccf.enforcement.providers`,
#: which is imported for its side effect.
PROVIDER_REGISTRY: list[type[RemediationProvider]] = []


def register(provider: type[RemediationProvider]) -> type[RemediationProvider]:
    """Add a provider class, refusing a check another provider already claims.

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


def provider_for(check_key: str) -> type[RemediationProvider] | None:
    """The provider class that can remediate this check, or ``None``.

    Matched on :attr:`RemediationProvider.handled_checks` rather than a
    ``handles()`` method, so there is one source of truth for what a provider
    claims -- a method that could disagree with the attribute the registry
    guards against is exactly the ambiguity to avoid here.
    """
    for provider in PROVIDER_REGISTRY:
        if check_key in provider.handled_checks:
            return provider
    return None


def write_credential_keys() -> tuple[str, ...]:
    """Distinct ``write_credential_type`` values every registered provider needs.

    Used to extend the connector-settings allow-list (``connector_keys()``
    covers read connectors only) so a write credential can actually be
    created, listed, and revoked -- without which enforcement is dead in any
    real deployment and apply-time re-checking has no revoke path to check
    against.
    """
    seen: dict[str, None] = {}
    for provider in PROVIDER_REGISTRY:
        seen.setdefault(provider.write_credential_type, None)
    return tuple(seen)


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

    Filters, in order:

    1. Only findings needing cover are remediable. A passing resource has
       nothing to remediate, and planning one would mean writing to something
       that was already correct.
    2. ``only`` narrows to named resources -- the intended path for "just this
       one account".
    3. The blast radius, checked against the **candidate count** -- before
       ``provider.plan()`` runs. ``plan()`` is what actually reaches the
       tenant (one Graph call per candidate for the m365 provider); refusing
       first means an over-broad request is refused without making a single
       call, not after issuing thousands of them and refusing on the result.
    4. A step whose ``current_state`` is empty is dropped, because it could not
       be undone. The blast radius is re-checked against what ``plan()``
       actually returned too -- defensive, since nothing requires a provider to
       return at most one step per candidate, and the tenant has already been
       touched by this point regardless.

    An empty result is a **refusal**, not an empty plan: an approvable plan
    that would do nothing invites an approval that means nothing.
    """
    remediable = [f for f in findings if f.verdict in REQUIRES_COVER]
    if only is not None:
        wanted = set(only)
        remediable = [f for f in remediable if f.resource_id in wanted]

    if len(remediable) > max_resources:
        return [], (
            f"{len(remediable)} resources exceeds the enforcement limit of {max_resources}"
        )

    try:
        planned = await provider.plan(remediable)
    except ProviderUnavailableError as e:
        return [], f"could not evaluate remediation candidates: {e}"
    steps = [s for s in planned if s.current_state]
    if not steps:
        return [], "no resources to remediate"
    if len(steps) > max_resources:
        return [], (
            f"{len(steps)} resources exceeds the enforcement limit of {max_resources}"
        )
    return steps, None
