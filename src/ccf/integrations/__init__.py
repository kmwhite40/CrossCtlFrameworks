"""Outbound integrations: file Concord records into external trackers.

Push-only. See :mod:`ccf.integrations.types` for why nothing reads back.
"""

from __future__ import annotations

from .jira import CREDENTIAL_TYPE as JIRA_CREDENTIAL_TYPE
from .jira import JiraTracker
from .types import (
    IntegrationError,
    IntegrationNotConfigured,
    IntegrationRefused,
    IntegrationUnavailable,
    IssueContent,
    IssueTracker,
    PushResult,
)

#: Credential types the outbound integrations need stored.
#:
#: Extends the connector-settings allow-list the same way
#: ``enforcement.write_credential_keys`` does, and for the same reason: a
#: credential type absent from that list cannot be created, listed or revoked
#: through the API, which leaves the feature that needs it unreachable in every
#: real deployment while every unit test still passes.
_INTEGRATION_CREDENTIAL_TYPES: tuple[str, ...] = (JIRA_CREDENTIAL_TYPE,)


def integration_credential_keys() -> tuple[str, ...]:
    """Every ``connector_type`` an outbound integration stores a secret under."""
    return _INTEGRATION_CREDENTIAL_TYPES


__all__ = [
    "IntegrationError",
    "IntegrationNotConfigured",
    "IntegrationRefused",
    "IntegrationUnavailable",
    "IssueContent",
    "IssueTracker",
    "JiraTracker",
    "PushResult",
    "integration_credential_keys",
]
