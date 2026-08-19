"""Evidence confidence scoring + reproducibility.

A pure scorer (:func:`score_evidence`) weighs the assurance dimensions of a piece
of evidence — source type, freshness, digest integrity, review/lock status,
replayability, human-attestation dependence — into a 0-100 score + band, with a
per-dimension breakdown. The service layer scores objects, runs replay checks
(non-fatal), and rolls up dashboard metrics.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_evidence import EvidenceObject, EvidenceVersion
from ..models_evidence_conf import (
    EvidenceConfidenceScore,
    EvidenceReplayRun,
    EvidenceReproducibilityCheck,
)

# Base trust per source type (0..1) — connectors/scans beat manual screenshots.
SOURCE_TRUST = {
    "connector": 0.95,
    "scan": 0.90,
    "api_import": 0.85,
    "signed_upload": 0.80,
    "manual_upload": 0.50,
    "screenshot": 0.35,
    "self_attestation": 0.25,
}
REPLAYABLE = {"connector", "scan", "api_import"}
MANUAL = {"manual_upload", "screenshot", "self_attestation"}

# Dimension weights for the weighted average.
_WEIGHTS = {
    "source_type": 3.0,
    "freshness": 2.0,
    "scope_match": 1.0,
    "digest_integrity": 2.0,
    "review_status": 2.0,
    "object_lock_status": 1.0,
    "package_usage": 1.0,
    "connector_replayability": 2.0,
    "human_attestation_dependency": 1.0,
    "assessor_approval": 1.0,
}
_REVIEW_VALUE = {"approved": 1.0, "submitted": 0.6, "rejected": 0.1, "expired": 0.2, "draft": 0.3}


def band_for(score: float) -> str:
    if score >= 85:
        return "strong"
    if score >= 70:
        return "high"
    if score >= 50:
        return "moderate"
    return "low"


#: Contribution of a prepared classification to an evidence object's confidence.
#: Preparation tells us how well a document's own text supports a control, which
#: is independent of provenance — so it adjusts the score rather than replacing
#: any existing signal, and absence is neutral, never a penalty.
_PREP_WEIGHTS = {"strong": 8.0, "moderate": 4.0, "weak": -2.0}


def prep_signal(strength: str | None) -> float:
    """Score contribution from a prepared classification's evidence strength."""
    return _PREP_WEIGHTS.get(strength or "", 0.0)


def score_evidence(
    *,
    source_type: str,
    status: str,
    immutable_lock: bool,
    expires_on: date | None,
    control_id: str | None,
    framework: str | None,
    has_digest: bool,
    used_in_package: bool = False,
    prep_strength: str | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Pure confidence scorer → ``{score, band, source_type, reproducible, factors}``."""
    today = today or datetime.now(UTC).date()

    if expires_on is None:
        freshness = 0.8
    elif expires_on < today:
        freshness = 0.2
    elif (expires_on - today).days < 30:
        freshness = 0.7
    else:
        freshness = 1.0

    values = {
        "source_type": SOURCE_TRUST.get(source_type, 0.5),
        "freshness": freshness,
        "scope_match": (bool(control_id) + bool(framework)) / 2,
        "digest_integrity": 1.0 if has_digest else 0.0,
        "review_status": _REVIEW_VALUE.get(status, 0.3),
        "object_lock_status": 1.0 if immutable_lock else 0.5,
        "package_usage": 1.0 if used_in_package else 0.8,
        "connector_replayability": 1.0 if source_type in REPLAYABLE else 0.0,
        "human_attestation_dependency": 0.3 if source_type in MANUAL else 1.0,
        "assessor_approval": 1.0 if status == "approved" else 0.6,
    }
    total_w = sum(_WEIGHTS.values())
    raw_score = 100 * sum(_WEIGHTS[k] * v for k, v in values.items()) / total_w
    # The weighted average above is already bounded to [0, 100] by construction
    # (each value is in [0, 1]); prep_signal is an external adjustment that can
    # push past either edge, so it's clamped back into the same bound rather
    # than left to float outside band_for's assumed range.
    score = round(max(0.0, min(100.0, raw_score + prep_signal(prep_strength))), 1)
    factors = {
        k: {"value": round(v, 2), "weight": _WEIGHTS[k],
            "contribution": round(_WEIGHTS[k] * v, 2)}
        for k, v in values.items()
    }
    return {
        "score": score,
        "band": band_for(score),
        "source_type": source_type,
        "reproducible": source_type in REPLAYABLE and has_digest,
        "factors": factors,
    }


async def _has_digest(session: AsyncSession, obj: EvidenceObject) -> bool:
    if obj.current_version_id is None:
        return False
    ver = await session.get(EvidenceVersion, obj.current_version_id)
    return bool(ver and ver.sha256)


async def score_object(session: AsyncSession, obj: EvidenceObject) -> EvidenceConfidenceScore:
    """Compute + upsert the confidence score for one evidence object."""
    has_digest = await _has_digest(session, obj)
    result = score_evidence(
        source_type=obj.source_type,
        status=obj.status,
        immutable_lock=obj.immutable_lock,
        expires_on=obj.expires_on,
        control_id=obj.control_id,
        framework=obj.framework,
        has_digest=has_digest,
    )
    row = (
        await session.execute(
            select(EvidenceConfidenceScore).where(
                EvidenceConfidenceScore.evidence_object_id == obj.id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = EvidenceConfidenceScore(
            organization_id=obj.organization_id, evidence_object_id=obj.id
        )
        session.add(row)
    row.version_id = obj.current_version_id
    row.score = result["score"]
    row.band = result["band"]
    row.source_type = result["source_type"]
    row.reproducible = result["reproducible"]
    row.factors = result["factors"]
    await session.flush()
    return row


async def score_all(session: AsyncSession, *, org_id: int | None = None) -> int:
    stmt = select(EvidenceObject)
    if org_id is not None:
        stmt = stmt.where(EvidenceObject.organization_id == org_id)
    n = 0
    for obj in (await session.execute(stmt)).scalars().all():
        await score_object(session, obj)
        n += 1
    return n


async def replay(session: AsyncSession, obj: EvidenceObject) -> EvidenceReplayRun:
    """Attempt to reproduce an object's evidence; never raises (errors are captured)."""
    from .service import (  # noqa: PLC0415 — avoid import cycle
        EvidenceContentMissingError,
        EvidenceIntegrityError,
        read_version,
    )

    status = "error"
    detail: dict[str, Any] = {}
    method = "none"
    reproducible = False
    try:
        if obj.source_type not in REPLAYABLE:
            status = "not_replayable"
            detail = {"reason": f"source '{obj.source_type}' is not machine-replayable"}
        elif obj.current_version_id is None:
            status = "missing"
            detail = {"reason": "no version to replay"}
        else:
            # read_version already recomputes the digest and raises
            # EvidenceIntegrityError on a mismatch, so recomputing it here made
            # the comparison always true and the "drifted" branch unreachable.
            # Real tampering fell through to the bare ``except`` and was stored
            # as "error" — which is why _check_evidence_replayability, whose
            # whole job is to count drifted/missing, returned PASS on it.
            version, _bytes = await read_version(session, obj)
            status, method, reproducible = "reproduced", "digest", True
            detail = {"sha256": version.sha256}
    except EvidenceIntegrityError as e:
        # The stored bytes no longer hash to the recorded digest.
        status = "drifted"
        detail = {"reason": str(e)[:200]}
    except EvidenceContentMissingError as e:
        # The version record exists but its bytes are unreachable.
        status = "missing"
        detail = {"reason": str(e)[:200]}
    except Exception as e:  # anything unexpected — captured, not fatal
        status = "error"
        detail = {"error": str(e)[:200]}

    session.add(
        EvidenceReproducibilityCheck(
            organization_id=obj.organization_id, evidence_object_id=obj.id,
            reproducible=reproducible, method=method, detail=str(detail)[:1000],
        )
    )
    run = EvidenceReplayRun(
        organization_id=obj.organization_id, evidence_object_id=obj.id,
        status=status, detail=detail,
    )
    session.add(run)
    await session.flush()
    return run


async def confidence_summary(
    session: AsyncSession, *, org_id: int | None = None, today: date | None = None
) -> dict[str, Any]:
    """Dashboard rollup of evidence-confidence metrics."""
    today = today or datetime.now(UTC).date()
    obj_stmt = select(EvidenceObject)
    score_stmt = select(EvidenceConfidenceScore)
    if org_id is not None:
        obj_stmt = obj_stmt.where(EvidenceObject.organization_id == org_id)
        score_stmt = score_stmt.where(EvidenceConfidenceScore.organization_id == org_id)
    objects = (await session.execute(obj_stmt)).scalars().all()
    scores = (await session.execute(score_stmt)).scalars().all()

    n_obj = len(objects)
    n_scores = len(scores)

    def pct(part: int, whole: int) -> float:
        return round(100 * part / whole, 1) if whole else 0.0

    avg_score = round(sum(s.score for s in scores) / n_scores, 1) if n_scores else 0.0
    automated = sum(1 for s in scores if s.source_type in REPLAYABLE)
    reproducible = sum(1 for s in scores if s.reproducible)
    manual = sum(1 for s in scores if s.source_type in MANUAL)
    stale = sum(
        1 for o in objects
        if o.status == "expired" or (o.expires_on is not None and o.expires_on < today)
    )
    return {
        "evidence_objects": n_obj,
        "scored": n_scores,
        "evidence_confidence_pct": avg_score,
        "automated_evidence_coverage_pct": pct(automated, n_scores),
        "reproducible_validation_pct": pct(reproducible, n_scores),
        "manual_evidence_dependency_pct": pct(manual, n_scores),
        "stale_authorization_facts_count": stale,
    }
