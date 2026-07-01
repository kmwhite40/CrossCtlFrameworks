"""Config-capture connector interface.

A connector reads an organization's *live* cloud configuration and returns
values that populate organization-defined parameters (ODPs) and evidence for
the SSP — so an implementation statement like "session lock after
[organization-defined period]" can be filled from the tenant's actual policy
instead of by hand.

Connectors are provider-agnostic: :class:`ConfigConnector` defines the contract,
and each provider (Microsoft Graph, AWS GovCloud) implements ``capture``. Every
connector advertises a ``PARAMETER_MAP`` (ODP key → where the value comes from)
so the UI can show what a connector *would* pull even before credentials are
configured. Nothing here mutates the SSP; the caller decides what to apply.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass
class CapturedParameter:
    """One value read from live configuration, mapped to an ODP / control."""

    odp_key: str
    value: str
    nist_id: str | None = None  # e.g. "3.1.10" — which requirement it informs
    source: str = ""  # human-readable origin, e.g. "Graph: authenticationMethodsPolicy"
    confidence: str = "medium"  # low | medium | high
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "odp_key": self.odp_key,
            "value": self.value,
            "nist_id": self.nist_id,
            "source": self.source,
            "confidence": self.confidence,
            "detail": self.detail,
        }


class ConfigConnector(abc.ABC):
    """Base class for a provider config-capture connector."""

    #: Stable connector key used in the API (``?connector=<key>``).
    key: str = ""
    #: Human label.
    label: str = ""
    #: ODP key → description of the live source it is derived from.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {}

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """True when credentials/settings needed for a live capture are present."""

    @abc.abstractmethod
    async def capture(self) -> list[CapturedParameter]:
        """Read live configuration and return captured parameters.

        Implementations MUST return ``[]`` (never raise) when not configured or
        on a transient provider error — capture is best-effort enrichment.
        """
