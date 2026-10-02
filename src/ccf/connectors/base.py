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
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..posture.checks import CheckOutcome
    from ..posture.resolve import ResolvedCheck


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

    def __init__(self, credential: dict[str, Any] | None = None) -> None:
        """``credential`` is the caller org's own decrypted secret bundle.

        Resolved by the caller (see :mod:`ccf.connectors.credentials`) — this
        class never falls back to a global/env credential. ``None`` means the
        calling organization has no bound credential for this connector, and
        :meth:`is_configured` MUST return ``False``.
        """
        self.credential = credential

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """True when this org's credential (see ``self.credential``) is usable."""

    @abc.abstractmethod
    async def capture(self) -> list[CapturedParameter]:
        """Read live configuration and return captured parameters.

        Implementations MUST return ``[]`` (never raise) when not configured or
        on a transient provider error — capture is best-effort enrichment.
        """

    async def verify(self) -> dict[str, Any]:
        """Prove connectivity into the target environment (best-effort).

        Returns ``{"connected": bool, ...}`` with provider identity details, or a
        ``reason`` when it cannot connect. Never raises.
        """
        return {"connected": False, "reason": "verification not implemented"}

    async def scan(
        self, checks: tuple[ResolvedCheck, ...] | None = None
    ) -> list[CheckOutcome]:
        """Assess live configuration against posture checks.

        Where :meth:`capture` reads a single value to fill an ODP blank, this
        assesses a fleet: each returned ``CheckOutcome`` carries per-resource
        findings with expected-versus-observed detail.

        ``checks`` are the tenant's resolved checks -- the platform registry
        plus anything its installed packs declared (see
        :func:`ccf.posture.resolve.resolve_checks`). ``None`` means "whatever
        this connector ships with", so a caller written before declared checks
        existed behaves exactly as it did. An **empty tuple is not the same as
        ``None``**: it means this tenant has nothing to scan, and must not
        fall back to the platform registry.

        Defaults to ``[]`` so a connector that has not implemented posture
        scanning is unaffected -- the same courtesy :meth:`verify` extends by
        returning a not-implemented result. Implementations MUST NOT raise;
        return ``[]`` when unconfigured or on a transient provider error, as
        :meth:`capture` does.
        """
        return []

    async def securityhub_attestations(
        self, *, max_pages: int | None = None, sample: bool = False
    ) -> dict[str, Any]:
        """The provider's own control results, with its own framework mapping.

        A third kind of read, distinct from both :meth:`capture` and
        :meth:`scan`. Those two assess configuration against expectations
        *Concord* authored. This returns the provider's assessment of its **own**
        control catalog together with the 800-53 mapping the provider publishes
        for it -- so it reaches controls Concord has no check for, and the
        attribution is the provider's claim rather than Concord's. See
        :mod:`ccf.posture.attested`.

        Declared here rather than only on the connector that implements it
        because ``posture.attested_scan`` resolves a connector through
        ``_connector_for_org``, which is typed to this base class. Without the
        declaration the ingest would need a cast or a ``getattr``, and both of
        those turn "this provider does not publish attestations" into a runtime
        surprise instead of a typed answer.

        The default is the honest negative: available ``False`` with a reason.
        That matters more here than for :meth:`scan`, whose ``[]`` is
        unambiguous -- an empty attestation and a provider that publishes none
        would otherwise be indistinguishable, which is the confusion the whole
        module is shaped to avoid. Implementations MUST NOT raise, for the same
        reason :meth:`scan` must not.
        """
        return {
            "available": False,
            "reason": (
                f"the {self.key} connector reads no provider-published control "
                "attestation; only AWS Security Hub publishes an 800-53 mapping "
                "Concord can read today"
            ),
            "controls": (),
            "unreadable_requirements": [],
            "pages_read": 0,
            "truncated": False,
            "region": None,
            "account_id": None,
            "standard_id": None,
            **({"redacted_findings": []} if sample else {}),
        }
