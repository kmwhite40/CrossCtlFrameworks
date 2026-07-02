"""Deterministic FedRAMP 20x KSI validation engine.

Evaluates each KSI's machine-readable ``rule`` against data Concord already holds
— control implementation states, evidence records, authorized-dependency
inventory, and the CSO profile — with no dependency on live cloud credentials.
(Connector-backed rules degrade to ``manual_review_required`` when no capture
data is present, so the engine is safe to run in any environment.)

The evaluation core (:func:`evaluate_rule`) is pure so it can be unit-tested
without a database; :func:`validate_system` is the async orchestrator that loads
context, evaluates every KSI, and records the append-only validation history plus
the per-system KSI state.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..logging import get_logger
from ..models import (
    KSI,
    CaptureSnapshot,
    Control,
    ControlImplementation,
    Evidence,
    FedRAMP20xProfile,
    FedRAMPDependency,
    KSIState,
    KSIValidationResult,
    System,
)

# Best-to-worst ranking used to pick the winning verdict of an ``any_of`` rule.
_VERDICT_RANK = {
    "pass": 4,
    "warn": 3,
    "manual_review_required": 2,
    "fail": 1,
    "not_applicable": 0,
    "not_tested": 0,
}

log = get_logger(__name__)

_ACCEPTABLE_DEFAULT = ("implemented", "inherited")

# How long an automated validation stays "fresh" before it should be re-run.
_FREQUENCY_DAYS = {
    "continuous": 1,
    "daily": 1,
    "weekly": 7,
    "monthly": 30,
    "quarterly": 90,
    "annual": 365,
}


def normalize_control(cid: str) -> str:
    """Canonicalize a control id for loose matching: ``AC-06`` / ``AC-6(1)`` -> ``AC-6``."""
    base = cid.strip().upper().split("(")[0]
    m = re.match(r"([A-Z]{2,3})-?0*([0-9]+)", base)
    return f"{m.group(1)}-{int(m.group(2))}" if m else base


@dataclass
class SystemContext:
    """Everything the pure evaluator needs about one system (all optional)."""

    # normalized base control id -> best implementation status seen
    impl_status: dict[str, str] = field(default_factory=dict)
    # normalized base control id -> True if it has at least one unexpired evidence record
    control_evidence: dict[str, bool] = field(default_factory=dict)
    # normalized base control id -> list of evidence reference labels
    evidence_refs: dict[str, list[str]] = field(default_factory=dict)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    captures: set[str] = field(default_factory=set)


@dataclass
class Verdict:
    status: str
    confidence: str
    source: str
    evidence_refs: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    remediation_hint: str | None = None
    assessor_review_required: bool = False


def _status_ok(status: str | None, states: tuple[str, ...]) -> bool:
    return status is not None and status in states


def evaluate_rule(  # noqa: PLR0911
    rule: dict[str, Any], ctx: SystemContext, *, ksi: dict[str, Any]
) -> Verdict:
    """Pure evaluation of a single KSI rule against a system context."""
    kind = (rule or {}).get("kind", "manual")
    states = tuple(rule.get("states") or _ACCEPTABLE_DEFAULT)
    controls = [normalize_control(c) for c in rule.get("controls", [])]
    manual_hint = "Requires assessor review — no deterministic signal available."

    if kind == "manual":
        return Verdict(
            "manual_review_required",
            "low",
            "manual",
            failure_reason=manual_hint,
            assessor_review_required=True,
        )

    if kind == "any_of":
        # Prefer the strongest signal — e.g. a live connector capture over a
        # control-state fallback. Returns the best-ranked sub-verdict.
        sub = [evaluate_rule(r, ctx, ksi=ksi) for r in rule.get("rules", [])]
        if not sub:
            return Verdict(
                "manual_review_required", "low", "any_of",
                failure_reason="any_of rule has no sub-rules.", assessor_review_required=True,
            )
        return max(sub, key=lambda v: _VERDICT_RANK.get(v.status, 0))

    if kind in ("control_state", "control_any"):
        present = {c: ctx.impl_status.get(c) for c in controls}
        refs = [f"{c}:{s}" for c, s in present.items() if s]
        satisfied = [c for c, s in present.items() if _status_ok(s, states)]
        missing = [c for c in controls if not _status_ok(present.get(c), states)]
        need_all = kind == "control_state"
        ok = (len(missing) == 0) if need_all else (len(satisfied) > 0)
        if ok:
            return Verdict("pass", "medium", kind, evidence_refs=refs)
        if satisfied:  # some but not all -> partial signal
            return Verdict(
                "warn",
                "medium",
                kind,
                evidence_refs=refs,
                failure_reason=f"Not all supporting controls satisfied: missing {missing}.",
                remediation_hint=f"Implement or inherit {', '.join(missing)}.",
            )
        return Verdict(
            "fail",
            "medium",
            kind,
            evidence_refs=refs,
            failure_reason=f"Supporting controls not implemented: {missing}.",
            remediation_hint=f"Implement or inherit {', '.join(missing)}.",
        )

    if kind == "evidence_present":
        have = [c for c in controls if ctx.control_evidence.get(c)]
        refs = [r for c in controls for r in ctx.evidence_refs.get(c, [])]
        if have:
            return Verdict("pass", "medium", kind, evidence_refs=refs)
        return Verdict(
            "fail",
            "medium",
            kind,
            failure_reason=f"No current evidence for {controls}.",
            remediation_hint="Collect and attach evidence to a supporting control.",
        )

    if kind == "dependency_authorized":
        deps = ctx.dependencies
        if not deps:
            return Verdict(
                "manual_review_required",
                "low",
                kind,
                failure_reason="No dependency inventory recorded.",
                remediation_hint="Record underlying IaaS/PaaS/SaaS dependencies.",
                assessor_review_required=True,
            )
        unauth = [d["name"] for d in deps if d.get("fedramp_status") != "authorized"]
        refs = [f"{d['name']}:{d.get('fedramp_status')}" for d in deps]
        if not unauth:
            return Verdict("pass", "high", kind, evidence_refs=refs)
        return Verdict(
            "fail",
            "high",
            kind,
            evidence_refs=refs,
            failure_reason=f"Non-authorized dependencies: {unauth}.",
            remediation_hint="Replace with, or obtain authorization for, these services.",
        )

    if kind == "profile_field":
        field_name = rule.get("field", "")
        if ctx.profile.get(field_name):
            return Verdict("pass", "medium", kind, evidence_refs=[f"profile.{field_name}"])
        return Verdict(
            "fail",
            "medium",
            kind,
            failure_reason=f"CSO profile field '{field_name}' is not set.",
            remediation_hint=f"Complete the '{field_name}' field on the 20x profile.",
        )

    if kind == "connector_capture":
        needed = set(rule.get("captures", []))
        if needed and needed.issubset(ctx.captures):
            return Verdict("pass", "high", kind, evidence_refs=sorted(needed))
        return Verdict(
            "manual_review_required",
            "low",
            kind,
            failure_reason="No connector capture data available.",
            remediation_hint="Configure a cloud connector or import capture data.",
            assessor_review_required=True,
        )

    # Unknown rule kind -> conservative manual review.
    return Verdict(
        "manual_review_required",
        "low",
        "manual",
        failure_reason=f"Unknown rule kind '{kind}'.",
        assessor_review_required=True,
    )


async def build_context(session: AsyncSession, system_id: int) -> SystemContext:
    """Gather a :class:`SystemContext` for a system from Concord's existing data."""
    ctx = SystemContext()
    today = datetime.now(UTC).date()

    impls = (
        (
            await session.execute(
                select(ControlImplementation)
                .options(
                    selectinload(ControlImplementation.control),
                    selectinload(ControlImplementation.evidence),
                )
                .where(ControlImplementation.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    # Rank so the "best" status wins when several objectives share a base control.
    rank = {
        "implemented": 5,
        "inherited": 4,
        "partial": 3,
        "planned": 2,
        "not_applicable": 1,
        "not_implemented": 0,
    }
    for impl in impls:
        control: Control | None = impl.control
        if control is None or not control.identifier:
            continue
        key = normalize_control(control.identifier)
        cur = ctx.impl_status.get(key)
        if cur is None or rank.get(impl.status, 0) > rank.get(cur, 0):
            ctx.impl_status[key] = impl.status
        for ev in impl.evidence or []:
            if _evidence_current(ev, today):
                ctx.control_evidence[key] = True
                ctx.evidence_refs.setdefault(key, []).append(_evidence_ref(ev))

    deps = (
        (
            await session.execute(
                select(FedRAMPDependency).where(FedRAMPDependency.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    ctx.dependencies = [
        {"name": d.name, "fedramp_status": d.fedramp_status, "provider": d.provider} for d in deps
    ]

    profile = (
        await session.execute(
            select(FedRAMP20xProfile).where(FedRAMP20xProfile.system_id == system_id)
        )
    ).scalar_one_or_none()
    if profile is not None:
        ctx.profile = {
            "boundary_description": profile.boundary_description,
            "cryptographic_boundary": profile.cryptographic_boundary,
            "logging_boundary": profile.logging_boundary,
            "incident_response_boundary": profile.incident_response_boundary,
            "backup_recovery_boundary": profile.backup_recovery_boundary,
            "administrative_access_boundary": profile.administrative_access_boundary,
        }

    # Live connector-capture signal (org-scoped): what the cloud connectors last
    # captured. Keyed by odp_key and NIST id so connector_capture rules can match
    # either. Empty when no connector is configured -> those rules stay manual.
    org_id = (
        await session.execute(select(System.organization_id).where(System.id == system_id))
    ).scalar_one_or_none()
    if org_id is not None:
        caps = (
            await session.execute(
                select(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_id)
            )
        ).scalars().all()
        for c in caps:
            ctx.captures.add(c.odp_key)
            if c.nist_id:
                ctx.captures.add(c.nist_id)
    return ctx


def _evidence_current(ev: Evidence, today: date) -> bool:
    return ev.expires_on is None or ev.expires_on >= today


def _evidence_ref(ev: Evidence) -> str:
    return f"evidence:{ev.id}:{ev.title}"


def _next_due(frequency: str | None, when: datetime) -> date | None:
    days = _FREQUENCY_DAYS.get((frequency or "").lower())
    return (when + timedelta(days=days)).date() if days else None


async def validate_system(
    session: AsyncSession, *, system_id: int, ksis: list[KSI] | None = None
) -> list[dict[str, Any]]:
    """Validate every KSI for a system; record history + state. Returns result dicts."""
    if ksis is None:
        ksis = list((await session.execute(select(KSI).order_by(KSI.sort_order))).scalars().all())
    started = time.perf_counter()
    ctx = await build_context(session, system_id)
    now = datetime.now(UTC)

    existing_states = {
        s.ksi_id: s
        for s in (await session.execute(select(KSIState).where(KSIState.system_id == system_id)))
        .scalars()
        .all()
    }

    results: list[dict[str, Any]] = []
    for ksi in ksis:
        verdict = evaluate_rule(
            ksi.rule or {}, ctx, ksi={"identifier": ksi.identifier, "category": ksi.category}
        )
        session.add(
            KSIValidationResult(
                system_id=system_id,
                ksi_id=ksi.id,
                ksi_identifier=ksi.identifier,
                status=verdict.status,
                confidence=verdict.confidence,
                source=verdict.source,
                evidence_refs=verdict.evidence_refs,
                failure_reason=verdict.failure_reason,
                remediation_hint=verdict.remediation_hint,
                assessor_review_required=verdict.assessor_review_required,
                validated_at=now,
            )
        )
        state = existing_states.get(ksi.id)
        if state is None:
            state = KSIState(system_id=system_id, ksi_id=ksi.id)
            session.add(state)
            existing_states[ksi.id] = state
        state.status = verdict.status
        state.last_validated_at = now
        state.next_validation_due = _next_due(ksi.validation_frequency, now)
        results.append(
            {
                "ksi_identifier": ksi.identifier,
                "category": ksi.category,
                "system_id": system_id,
                "validation_status": verdict.status,
                "validated_at": now.isoformat(),
                "confidence": verdict.confidence,
                "source": verdict.source,
                "evidence_refs": verdict.evidence_refs,
                "failure_reason": verdict.failure_reason,
                "remediation_hint": verdict.remediation_hint,
                "assessor_review_required": verdict.assessor_review_required,
            }
        )
    await session.flush()

    # Observability: per-status counts, run duration, and a structured event.
    counts: dict[str, int] = {}
    for r in results:
        counts[r["validation_status"]] = counts.get(r["validation_status"], 0) + 1
    try:
        from ..api.metrics import KSI_VALIDATION_DURATION, KSI_VALIDATIONS  # noqa: PLC0415

        KSI_VALIDATION_DURATION.observe(time.perf_counter() - started)
        for status, n in counts.items():
            KSI_VALIDATIONS.labels(status).inc(n)
    except Exception:
        pass
    log.info(
        "fedramp20x.validated",
        system_id=system_id,
        ksis=len(results),
        by_status=counts,
        duration_ms=round((time.perf_counter() - started) * 1000),
    )
    return results
