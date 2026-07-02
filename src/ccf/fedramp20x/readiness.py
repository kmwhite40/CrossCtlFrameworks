"""FedRAMP 20x readiness scoring — separate from traditional FedRAMP Moderate/High.

Rolls the per-system KSI state, automation coverage, evidence completeness,
assessor review completion, dependency posture, and continuous-monitoring freshness
into a single readiness percentage + lifecycle status. The math is a documented,
deterministic blend (no ML, no external calls) so results are reproducible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    KSI,
    FedRAMP20xProfile,
    FedRAMP20xReadinessSnapshot,
    FedRAMPDependency,
    KSIAssessorReview,
    KSIException,
    KSIState,
)

# Sub-score weights for the overall readiness percentage. Pass-rate dominates;
# the rest are supporting signals. Weights sum to 1.0.
_WEIGHTS = {
    "ksi_pass_rate": 0.40,
    "evidence_completeness": 0.20,
    "assessor_completion": 0.20,
    "dependency_readiness": 0.10,
    "conmon_coverage": 0.10,
}

_ASSESSOR_DONE = ("accepted", "closed")


@dataclass
class Readiness:
    readiness_pct: int
    status: str
    ksi_total: int
    ksi_pass_rate: int | None
    automation_coverage: int | None
    evidence_completeness: int | None
    conmon_coverage: int | None
    assessor_completion: int | None
    dependency_readiness: int | None
    open_exceptions: int
    high_risk_findings: int
    expired_validations: int
    manual_review_burden: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _pct(numer: int, denom: int) -> int | None:
    return round(100 * numer / denom) if denom else None


def _derive_status(r: Readiness, *, has_profile: bool, submitted: str | None) -> str:  # noqa: PLR0911
    if submitted in ("submitted", "authorized", "continuous_monitoring"):
        return submitted
    if r.ksi_total == 0 or (r.ksi_pass_rate is None and not has_profile):
        return "not_started"
    if r.readiness_pct >= 90 and (r.assessor_completion or 0) >= 90 and r.high_risk_findings == 0:
        return "ready_for_submission"
    if (r.assessor_completion or 0) > 0:
        return "assessor_review"
    if (r.ksi_pass_rate or 0) >= 50:
        return "validation_in_progress"
    if (r.evidence_completeness or 0) > 0 or (r.ksi_pass_rate or 0) > 0:
        return "evidence_collection"
    return "initial_build"


def compute_readiness(
    *,
    ksis: list[KSI],
    states: list[KSIState],
    dependencies: list[FedRAMPDependency],
    reviews: list[KSIAssessorReview],
    open_exceptions: int,
    today: date,
    has_profile: bool = False,
    submitted_status: str | None = None,
) -> Readiness:
    """Pure readiness computation from already-loaded aggregates."""
    total = len(ksis)
    state_by_ksi = {s.ksi_id: s for s in states}

    passed = sum(1 for s in states if s.status == "pass")
    failed = sum(1 for s in states if s.status == "fail")
    manual = sum(1 for s in states if s.status == "manual_review_required")
    expired = sum(
        1 for s in states if s.next_validation_due is not None and s.next_validation_due < today
    )
    fresh = sum(
        1
        for s in states
        if s.status not in ("not_tested",)
        and (s.next_validation_due is None or s.next_validation_due >= today)
    )

    automated = sum(1 for k in ksis if (k.automation_level or "") == "automated")

    # Evidence completeness: of the KSIs that require evidence, how many are passing.
    ev_required = [k for k in ksis if k.evidence_required]
    ev_pass = sum(
        1
        for k in ev_required
        if state_by_ksi.get(k.id) is not None and state_by_ksi[k.id].status == "pass"
    )

    # Assessor completion across the whole catalog (unreviewed counts against you).
    latest_review: dict[int, KSIAssessorReview] = {}
    for rv in reviews:
        prev = latest_review.get(rv.ksi_id)
        if prev is None or rv.reviewed_at >= prev.reviewed_at:
            latest_review[rv.ksi_id] = rv
    accepted = sum(1 for rv in latest_review.values() if rv.status in _ASSESSOR_DONE)

    dep_total = len(dependencies)
    dep_ok = sum(1 for d in dependencies if d.fedramp_status == "authorized")
    dep_high_risk = sum(1 for d in dependencies if d.dependency_risk in ("high", "critical"))

    r = Readiness(
        readiness_pct=0,
        status="not_started",
        ksi_total=total,
        ksi_pass_rate=_pct(passed, total),
        automation_coverage=_pct(automated, total),
        evidence_completeness=_pct(ev_pass, len(ev_required)),
        conmon_coverage=_pct(fresh, total),
        assessor_completion=_pct(accepted, total),
        dependency_readiness=_pct(dep_ok, dep_total),
        open_exceptions=open_exceptions,
        high_risk_findings=failed + dep_high_risk,
        expired_validations=expired,
        manual_review_burden=manual,
    )

    # Weighted overall (skip sub-scores that are None and renormalize).
    parts = {key: getattr(r, key) for key in _WEIGHTS if getattr(r, key) is not None}
    if parts:
        wsum = sum(_WEIGHTS[k] for k in parts)
        r.readiness_pct = round(sum(parts[k] * _WEIGHTS[k] for k in parts) / wsum)
    r.status = _derive_status(r, has_profile=has_profile, submitted=submitted_status)
    return r


async def score_system(
    session: AsyncSession, *, system_id: int, persist: bool = True
) -> dict[str, Any]:
    """Load state, compute readiness, and (optionally) persist a snapshot."""
    ksis = list((await session.execute(select(KSI))).scalars().all())
    states = list(
        (await session.execute(select(KSIState).where(KSIState.system_id == system_id)))
        .scalars()
        .all()
    )
    deps = list(
        (
            await session.execute(
                select(FedRAMPDependency).where(FedRAMPDependency.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    reviews = list(
        (
            await session.execute(
                select(KSIAssessorReview).where(KSIAssessorReview.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    open_exc = len(
        [
            e
            for e in (
                await session.execute(
                    select(KSIException).where(
                        KSIException.system_id == system_id, KSIException.status == "open"
                    )
                )
            )
            .scalars()
            .all()
        ]
    )
    profile = (
        await session.execute(
            select(FedRAMP20xProfile).where(FedRAMP20xProfile.system_id == system_id)
        )
    ).scalar_one_or_none()

    r = compute_readiness(
        ksis=ksis,
        states=states,
        dependencies=deps,
        reviews=reviews,
        open_exceptions=open_exc,
        today=datetime.now(UTC).date(),
        has_profile=profile is not None,
        submitted_status=profile.readiness_status if profile else None,
    )
    payload = r.as_dict()
    if persist:
        session.add(
            FedRAMP20xReadinessSnapshot(
                system_id=system_id,
                readiness_pct=r.readiness_pct,
                status=r.status,
                ksi_pass_rate=r.ksi_pass_rate,
                automation_coverage=r.automation_coverage,
                evidence_completeness=r.evidence_completeness,
                conmon_coverage=r.conmon_coverage,
                assessor_completion=r.assessor_completion,
                dependency_readiness=r.dependency_readiness,
                open_exceptions=r.open_exceptions,
                high_risk_findings=r.high_risk_findings,
                expired_validations=r.expired_validations,
                manual_review_burden=r.manual_review_burden,
                payload=payload,
            )
        )
        # Advance the profile's lifecycle status unless a human parked it at a
        # terminal submission state.
        if profile is not None and profile.readiness_status not in (
            "submitted",
            "authorized",
            "continuous_monitoring",
        ):
            profile.readiness_status = r.status
        await session.flush()
        try:
            from ..api.metrics import FEDRAMP20X_READINESS  # noqa: PLC0415

            FEDRAMP20X_READINESS.labels(str(system_id)).set(r.readiness_pct)
        except Exception:
            pass
    return payload
