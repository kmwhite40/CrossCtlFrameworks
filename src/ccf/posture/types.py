"""The shapes a posture check and its findings take.

Deliberately separate from :mod:`ccf.posture.checks`, which owns the *registry*.
Provider modules need these types, and the registry needs the provider modules,
so keeping the two in one file makes a circular import that only manifests
depending on which side is imported first. Types do not depend on the registry;
this file is where that fact lives.

:mod:`ccf.posture.checks` re-exports everything here, so callers keep importing
from one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..fedramp20x import VALIDATION_STATUSES
from .rollup import EXCLUDED_FROM_ROLLUP, roll_up_findings


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
    def considered(self) -> int:
        """Findings that actually entered the rollup verdict.

        ``evaluated`` counts every row fetched, including the ones excluded
        from the rollup (``not_applicable``/``not_tested``). An unlicensed
        tenant makes every user's staleness finding ``not_applicable``, so a
        detail string built from ``evaluated`` would read "0 of 500 failing"
        -- a clean 500-user fleet -- when in truth zero users were actually
        assessed. ``considered`` is honest about what informed the verdict.
        """
        return sum(1 for f in self.findings if f.verdict not in EXCLUDED_FROM_ROLLUP)

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
