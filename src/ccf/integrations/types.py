"""What an outbound issue-tracker integration is, and what it refuses to do.

Concord is the record of truth for anything a regulator acts on. These
integrations are **push-only**: a POA&M creates and updates a ticket in an
external system, and nothing the external system does ever writes back. That
is a deliberate boundary, not an unfinished half of a sync -- letting a Jira
transition close a POA&M would let an unaudited external actor mutate a filed
deliverable, and the audit chain has no way to attribute such a change.

Kept apart from :mod:`ccf.connectors` (which reads customer tenants) and from
:mod:`ccf.enforcement` (which writes to them) for the reason stated in
``enforcement.types``: read and write are not symmetric, and neither is
"capture evidence about a tenant" and "file a ticket about our own finding".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol, runtime_checkable


class IntegrationError(RuntimeError):
    """Base for every refusal these integrations raise."""


class IntegrationNotConfigured(IntegrationError):
    """No credential, or no project, bound for this organization.

    Distinct from a failed call: nothing was attempted and nothing is wrong
    with the remote system. The caller turns this into a prompt to configure,
    never into a "push failed" that an operator would go debugging.
    """


class IntegrationRefused(IntegrationError):
    """The remote system rejected the request and said why.

    ``detail`` carries the remote's own message. Jira's 400s are specific and
    actionable ("Field 'duedate' cannot be set. It is not on the appropriate
    screen, or unknown."), and discarding them in favour of a generic failure
    is what turns a five-second configuration fix into an afternoon.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class IntegrationUnavailable(IntegrationError):
    """The remote system could not be reached at all.

    Separate from :class:`IntegrationRefused` so a transient outage is never
    recorded as the ticket having been rejected -- the first is worth retrying
    unchanged, the second never is.
    """


@dataclass(frozen=True)
class IssueContent:
    """The provider-neutral shape of a ticket, mapped from a POA&M.

    Deliberately narrow. Every field here exists on every tracker worth
    supporting; anything provider-specific belongs in that provider's module,
    where its absence can be handled rather than assumed.
    """

    key: str
    """Concord's own stable identity for the source record, e.g. ``poam:41``."""

    title: str
    body: str
    due_on: date | None = None
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("an issue must carry a title")


@dataclass(frozen=True)
class PushResult:
    """Where the pushed record now lives in the remote system."""

    external_id: str
    """The remote's identifier, e.g. a Jira issue key ``ABC-123``."""

    url: str
    created: bool
    """True when this call created the ticket, False when it updated one."""


@runtime_checkable
class IssueTracker(Protocol):
    """A system Concord can file and update a ticket in. Never read back from."""

    provider: str
    credential_type: str

    async def create(self, content: IssueContent) -> PushResult: ...

    async def update(self, external_id: str, content: IssueContent) -> PushResult: ...
