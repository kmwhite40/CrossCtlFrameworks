"""Posture check definitions and the shapes a scan returns.

A check is *content*: what to look at, what is expected, and which canonical
controls it evidences. The registry here is deliberately the same shape as
``etl.sources.DEFAULT_SOURCES`` so P2b's move into ``packs/`` relocates
content rather than redesigning it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..fedramp20x import VALIDATION_STATUSES
from .rollup import roll_up_findings


@dataclass(frozen=True)
class PostureCheck:
    """One thing to assess in a provider, and what it evidences.

    ``control_ids`` are **canonical** 800-53 ids (``AC-2``), matching
    ``CapabilityControl.control_id`` and ``SSPControlEntry.control_id`` --
    never the zero-padded ``controls.identifier`` form.
    """

    key: str
    title: str
    provider: str
    resource_type: str
    expected: str
    control_ids: tuple[str, ...]
    #: Resolved to a Capability by (organization_id, key) when one exists.
    #: A missing capability is not an error: checks ship as content, while
    #: capabilities are authored per tenant.
    capability_key: str | None = None
    #: Provider permissions this check needs, e.g. ("AuditLog.Read.All",).
    #: Carried so a manual_review_required verdict can name the missing
    #: permission instead of leaving an operator to infer it from a 403.
    required_permissions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResourceFinding:
    """What one resource actually reported."""

    resource_id: str
    resource_type: str
    verdict: str
    observed: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckOutcome:
    """One check's assessment of a fleet."""

    check_key: str
    verdict: str
    expected: str
    findings: tuple[ResourceFinding, ...]

    @property
    def evaluated(self) -> int:
        return len(self.findings)

    @property
    def failing(self) -> int:
        return sum(1 for f in self.findings if f.verdict == "fail")

    @classmethod
    def from_findings(
        cls, check: PostureCheck, findings: tuple[ResourceFinding, ...]
    ) -> CheckOutcome:
        """Build an outcome, rolling the per-resource verdicts up.

        Raises ``ValueError`` on an unrecognised verdict rather than storing a
        value no reader can interpret.
        """
        for f in findings:
            if f.verdict not in VALIDATION_STATUSES:
                raise ValueError(f"unknown verdict: {f.verdict!r}")
        return cls(
            check_key=check.key,
            verdict=roll_up_findings([f.verdict for f in findings]),
            expected=check.expected,
            findings=tuple(findings),
        )


#: Provider key -> its checks. Empty per provider until P3 implements the
#: adapters; the registry exists now so the contract and orchestration are
#: testable, and so P2b has something to relocate into ``packs/``.
CHECK_REGISTRY: dict[str, tuple[PostureCheck, ...]] = {
    "msgraph": (),
    "aws_govcloud": (),
}


def checks_for(provider: str) -> tuple[PostureCheck, ...]:
    """Checks registered for one provider; empty for an unknown provider."""
    return CHECK_REGISTRY.get(provider, ())


# Imported last: providers.m365 depends on PostureCheck/ResourceFinding above,
# so registering from here rather than at the top avoids a circular import.
from .providers import m365 as _m365  # noqa: E402

CHECK_REGISTRY["msgraph"] = _m365.CHECKS
