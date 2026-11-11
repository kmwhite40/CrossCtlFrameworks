"""Automated methods for a KSI: posture checks that can contradict it.

FRC-CSX-VVK asks a 20x provider for automated methods that persistently verify
and validate each KSI. Most 2026 KSIs state that something is *persistently
reviewed* -- training, procedures, recovery plans -- which no configuration
check can prove. A check can, however, **contradict** one: if phishable
authentication methods are enabled, ``KSI-IAM-APM`` ("phishing-resistant MFA")
is not met, whatever any review says.

So a method is a Concord platform posture check, curated per KSI in
``rules_data/ksi_rules.json`` with a written rationale for why its failure
contradicts the indicator's statement. Sharing a mapped 800-53 control is not
enough to qualify -- stale-account checks share IA-2 with ``KSI-IAM-APM`` and
say nothing about passwordless authentication.

How a method's latest result moves the KSI:

* ``fail`` or ``warn`` -> the KSI moves to ``warn`` (a ``fail`` from its own
  rule stays ``fail``), the failing methods named and ``source`` set to
  ``posture_method``. Note that ``warn`` ranks *above*
  ``manual_review_required`` in ``validation.VERDICT_RANK``; it is the user's
  chosen signal for "automation contradicts this", and readiness keeps such a
  KSI in its manual-review burden and counts it in
  ``contradicted_by_methods`` so it never reads as progress.
* ``pass`` -> recorded as evidence. **Never** ``pass``: a clean configuration
  is not a persistently reviewed practice.
* no usable result for this system -> the method did not run, counts toward
  nothing, and is not cited as evidence. "Usable" is what posture's own
  ``effective_verdict`` believes: a generated, active test, scanned within
  ``STALE_AFTER_DAYS``, and tier 0 (``trust_tier``) -- Concord's own check,
  never a provider-attested, crosswalk or pack row reusing a key.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_grc import ControlTest

if TYPE_CHECKING:
    from .validation import Verdict

#: Method results that contradict the KSI statement.
CONTRADICTS = frozenset({"fail", "warn"})
RAN = frozenset({"pass", "fail", "warn"})


class MethodsError(ValueError):
    """An authored method names no platform check or gives no rationale."""


def platform_checks() -> dict[str, Any]:
    from ..posture.checks import CHECK_REGISTRY  # noqa: PLC0415 -- heavy registry

    out: dict[str, Any] = {}
    values = CHECK_REGISTRY.values() if isinstance(CHECK_REGISTRY, dict) else CHECK_REGISTRY
    for entry in values:
        for check in entry if isinstance(entry, (list, tuple)) else [entry]:
            out[check.key] = check
    return out


def validate_methods(ident: str, methods: Any) -> list[dict[str, str]]:
    """Refuse a method that is not a platform check or carries no rationale."""
    if methods in (None, []):
        return []
    if not isinstance(methods, list):
        raise MethodsError(f"{ident}: methods must be a list")
    known = platform_checks()
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for m in methods:
        check = m.get("check") if isinstance(m, dict) else None
        rationale = m.get("rationale") if isinstance(m, dict) else None
        if check not in known:
            raise MethodsError(f"{ident}: {check!r} is not a Concord platform posture check")
        if not isinstance(rationale, str) or not rationale.strip():
            raise MethodsError(f"{ident}: method {check} has no rationale")
        if check in seen:
            raise MethodsError(f"{ident}: method {check} listed twice")
        seen.add(check)
        out.append({"check": check, "rationale": rationale.strip()})
    return out


@dataclass(frozen=True)
class MethodResult:
    check: str
    status: str | None  # None -> no tier-0 result for this system


def results(
    methods: Iterable[dict[str, Any]], check_status: dict[str, str]
) -> list[MethodResult]:
    return [MethodResult(m["check"], check_status.get(m["check"])) for m in methods]


def methods_run(methods: Iterable[dict[str, Any]], check_status: dict[str, str]) -> int:
    """How many of a KSI's methods actually ran on this system."""
    return sum(1 for r in results(methods, check_status) if r.status in RAN)


def apply(
    verdict: Verdict, methods: list[dict[str, Any]], check_status: dict[str, str]
) -> Verdict:
    """Fold method results into a rule verdict. Never produces ``pass``."""
    if not methods:
        return verdict
    rs = results(methods, check_status)
    # Only methods that ran are evidence; a not_run entry in an evidence
    # manifest would cite a check that never looked at this system.
    refs = [f"method:{r.check}:{r.status}" for r in rs if r.status in RAN]
    contradicting = [r.check for r in rs if r.status in CONTRADICTS]
    updated = replace(verdict, evidence_refs=[*verdict.evidence_refs, *refs])
    if not contradicting:
        return updated
    note = "Automated method(s) contradict this indicator: " + ", ".join(contradicting) + "."
    status = verdict.status if verdict.status == "fail" else "warn"
    reason = f"{verdict.failure_reason} {note}" if verdict.failure_reason else note
    return replace(
        updated,
        status=status,
        source=verdict.source if status == "fail" else "posture_method",
        failure_reason=reason,
        remediation_hint=verdict.remediation_hint
        or "Resolve the failing posture checks, then have the indicator reviewed.",
        assessor_review_required=True,
    )


async def tier0_check_status(session: AsyncSession, system_id: int) -> dict[str, str]:
    """Latest believable status of each Concord platform check for one system.

    The same conditions posture's ``effective_verdict`` applies: generated by
    a scan, still active, fresh within ``STALE_AFTER_DAYS``, tier 0. A connector
    disconnected a year ago must not keep "persistently" validating a KSI.
    """
    from ..posture.scan import STALE_AFTER_DAYS, trust_tier  # noqa: PLC0415

    cutoff = datetime.now(UTC) - timedelta(days=STALE_AFTER_DAYS)
    rows = (
        await session.execute(
            select(ControlTest).where(
                ControlTest.system_id == system_id,
                ControlTest.check_key.is_not(None),
                ControlTest.last_status.is_not(None),
                ControlTest.source == "generated",
                ControlTest.active.is_(True),
                ControlTest.last_tested_at >= cutoff,
            )
        )
    ).scalars().all()
    out: dict[str, str] = {}
    for t in rows:
        if trust_tier(t) == 0 and t.check_key is not None and t.last_status is not None:
            out[t.check_key] = t.last_status
    return out
