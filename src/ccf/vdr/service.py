"""Record evaluations and assemble a system's VDR status.

The arithmetic lives in :mod:`ccf.vdr.timeframes`; this module only reads and
writes rows around it. Two rules:

* **Flaws are the VER deliverables' flaws.** :data:`ccf.patching.sla.FLAW_SOURCES`
  decides, exactly as :func:`ccf.cr26.ver.render_all` does, so the page and
  the filed VDT count the same POA&Ms.
* **Relaxing needs a second person.** An evaluation that would loosen a
  deadline (:func:`ccf.vdr.timeframes.relaxes`) is held until someone other
  than its author confirms it, when auth is on -- the same separation of
  duties closures, acceptances and extensions have. Every read here sees
  **effective** evaluations only, so a pending one moves no deadline and
  reaches no deliverable.
* **A due date only moves earlier.** Recording an evaluation, or a KEV due
  date, may tighten ``POAM.due_on``; moving it later is an extension, which
  needs an approval (``ccf.ato.extensions``) and is never done here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..config import get_settings
from ..constants import POAM_CLOSED_STATUSES
from ..intel.kev import cve_ids
from ..models import POAM, ScanIngestion, System
from ..models_program import KevEntry
from ..models_vdr import VulnerabilityEvaluation
from ..patching.sla import FLAW_SOURCES
from . import timeframes as tf


class EvaluationError(ValueError):
    """An evaluation that cannot be recorded; ``status`` is the HTTP code."""

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def as_evaluation(row: VulnerabilityEvaluation) -> tf.Evaluation:
    return tf.Evaluation(
        pain_rating=row.pain_rating,
        internet_reachable=row.internet_reachable,
        likely_exploitable=row.likely_exploitable,
        false_positive=row.false_positive,
        evaluated_at=row.evaluated_at,
    )


async def history(session: AsyncSession, poam_id: int) -> list[VulnerabilityEvaluation]:
    """Every evaluation of one POA&M, oldest first."""
    return list(
        (
            await session.execute(
                select(VulnerabilityEvaluation)
                .where(VulnerabilityEvaluation.poam_id == poam_id)
                .order_by(VulnerabilityEvaluation.evaluated_at, VulnerabilityEvaluation.id)
            )
        ).scalars()
    )


async def evaluations_by_poam(
    session: AsyncSession, poam_ids: Sequence[int]
) -> dict[int, list[tf.Evaluation]]:
    out: dict[int, list[tf.Evaluation]] = defaultdict(list)
    if not poam_ids:
        return out
    rows = (
        await session.execute(
            select(VulnerabilityEvaluation)
            .where(VulnerabilityEvaluation.poam_id.in_(poam_ids))
            .order_by(VulnerabilityEvaluation.evaluated_at, VulnerabilityEvaluation.id)
        )
    ).scalars()
    for row in rows:
        if row.effective:
            out[row.poam_id].append(as_evaluation(row))
    return out


async def pending_by_poam(
    session: AsyncSession, poam_ids: Sequence[int]
) -> dict[int, list[VulnerabilityEvaluation]]:
    """The evaluation awaiting a second person's confirmation, per POA&M.

    Only the latest evaluation of a POA&M can be pending: an older held one
    was superseded by whatever was recorded after it, and cannot be confirmed.
    """
    out: dict[int, list[VulnerabilityEvaluation]] = defaultdict(list)
    if not poam_ids:
        return out
    rows = (
        await session.execute(
            select(VulnerabilityEvaluation)
            .where(
                VulnerabilityEvaluation.poam_id.in_(poam_ids),
                VulnerabilityEvaluation.requires_confirmation.is_(True),
                VulnerabilityEvaluation.confirmed_at.is_(None),
            )
            .order_by(VulnerabilityEvaluation.evaluated_at, VulnerabilityEvaluation.id)
        )
    ).scalars()
    latest = {
        pid: last_id
        for pid, last_id in (
            await session.execute(
                select(VulnerabilityEvaluation.poam_id, func.max(VulnerabilityEvaluation.id))
                .where(VulnerabilityEvaluation.poam_id.in_(poam_ids))
                .group_by(VulnerabilityEvaluation.poam_id)
            )
        ).all()
    }
    for row in rows:
        if latest.get(row.poam_id) == row.id:
            out[row.poam_id].append(row)
    return out


async def kev_due_by_poam(session: AsyncSession, poams: Sequence[POAM]) -> dict[int, date]:
    """The earliest CISA due date among the CVE ids each POA&M names.

    A text match on title and weakness -- the same one the KEV page makes and
    states, because a scan finding's CVE ids are stored in that text.
    """
    named = {p.id: cve_ids(p.title, p.weakness) for p in poams}
    wanted = {c for ids in named.values() for c in ids}
    if not wanted:
        return {}
    due = {
        cve: d
        for cve, d in (
            await session.execute(
                select(KevEntry.cve_id, KevEntry.due_date).where(KevEntry.cve_id.in_(wanted))
            )
        ).all()
        if d is not None
    }
    out: dict[int, date] = {}
    for pid, ids in named.items():
        dates = [due[c] for c in ids if c in due]
        if dates:
            out[pid] = min(dates)
    return out


def _is_flaw(poam: POAM) -> bool:
    return (poam.source or "") in FLAW_SOURCES


def _tighter(current: date | None, *candidates: date | None) -> date | None:
    """The earliest candidate when it is earlier than ``current``, else ``None``."""
    found = [c for c in candidates if c is not None]
    if not found:
        return None
    best = min(found)
    return best if current is None or best < current else None


@dataclass
class Recorded:
    evaluation: VulnerabilityEvaluation
    status: tf.FlawStatus
    #: The previous ``due_on`` when this evaluation moved it earlier.
    tightened_from: date | None
    due_on_changed: bool
    #: Held for a second person: it relaxes a deadline and is not yet in effect.
    pending_confirmation: bool = False


async def record_evaluation(
    session: AsyncSession,
    *,
    poam: POAM,
    pain_rating: int,
    internet_reachable: bool,
    likely_exploitable: bool,
    false_positive: bool,
    rationale: str,
    principal: Principal,
    now: datetime | None = None,
) -> Recorded:
    """Append one evaluation and tighten the POA&M's due date if it now must be.

    The caller has already scope-checked ``poam``. Does not commit.
    """
    now = now or datetime.now(UTC)
    if not _is_flaw(poam):
        raise EvaluationError(
            "only scan-derived POA&Ms are vulnerabilities under the VER rules; "
            "this one is a control deficiency"
        )
    if str(poam.status) in POAM_CLOSED_STATUSES:
        raise EvaluationError("this POA&M is closed; there is nothing left to evaluate", 409)
    if not 0 <= pain_rating <= 5:
        raise EvaluationError("pain_rating must be 0 to 5 (VER-EVA-EPA)")
    if false_positive and pain_rating != 0:
        raise EvaluationError(
            "a false positive is not present, so it has no impact to rate; use pain_rating 0"
        )
    if not (rationale or "").strip():
        raise EvaluationError("an evaluation needs a rationale (VER-EVA-EFA)")

    system = await session.get(System, poam.system_id)
    assert system is not None
    in_effect = (await evaluations_by_poam(session, [poam.id])).get(poam.id, [])
    candidate = tf.Evaluation(
        pain_rating, internet_reachable, likely_exploitable, false_positive, now
    )
    held = get_settings().auth_enabled and tf.relaxes(
        in_effect[-1] if in_effect else None, candidate
    )
    row = VulnerabilityEvaluation(
        organization_id=system.organization_id,
        poam_id=poam.id,
        pain_rating=pain_rating,
        internet_reachable=internet_reachable,
        likely_exploitable=likely_exploitable,
        false_positive=false_positive,
        rationale=rationale.strip(),
        evaluated_by=principal.email,
        evaluated_at=now,
        requires_confirmation=held,
    )
    session.add(row)
    await session.flush()
    status, changed, previous = await _apply(session, poam, system, principal, now)
    return Recorded(row, status, previous, changed, pending_confirmation=held)


async def confirm_evaluation(
    session: AsyncSession,
    *,
    poam: POAM,
    evaluation_id: int,
    principal: Principal,
    now: datetime | None = None,
) -> Recorded:
    """Put a held evaluation into effect. Its author cannot. Does not commit."""
    now = now or datetime.now(UTC)
    row = await session.get(VulnerabilityEvaluation, evaluation_id)
    if row is None or row.poam_id != poam.id:
        raise EvaluationError("evaluation not found", 404)
    if not row.requires_confirmation:
        raise EvaluationError("this evaluation took effect when recorded", 409)
    if row.confirmed_at is not None:
        raise EvaluationError("this evaluation is already confirmed", 409)
    if (principal.email or "") == (row.evaluated_by or ""):
        raise EvaluationError(
            "an evaluation that relaxes a deadline is confirmed by someone other than "
            "its author (separation of duties)",
            403,
        )
    if str(poam.status) in POAM_CLOSED_STATUSES:
        raise EvaluationError("this POA&M is closed; there is nothing left to confirm", 409)
    # Recorded order, by id: the same notion of 'latest' pending_by_poam uses.
    latest = max(await history(session, poam.id), key=lambda e: e.id)
    if latest.id != row.id:
        raise EvaluationError(
            f"evaluation #{latest.id} was recorded after this one and supersedes it", 409
        )
    row.confirmed_by, row.confirmed_at = principal.email, now
    await session.flush()
    system = await session.get(System, poam.system_id)
    assert system is not None
    status, changed, previous = await _apply(session, poam, system, principal, now)
    return Recorded(row, status, previous, changed)


async def _apply(
    session: AsyncSession, poam: POAM, system: System, principal: Principal, now: datetime
) -> tuple[tf.FlawStatus, bool, date | None]:
    """Recompute from effective evaluations; tighten ``due_on`` if it must be.

    Returns the status, whether ``due_on`` moved, and its previous value.
    """
    evaluations = (await evaluations_by_poam(session, [poam.id])).get(poam.id, [])
    kev_due = (await kev_due_by_poam(session, [poam])).get(poam.id)
    status = tf.assess(
        poam,
        evaluations,
        cls=tf.class_timeframes(system.certification_class),
        kev_due=kev_due,
        now=now,
    )
    mitigation_day = status.mitigation_due.date() if status.mitigation_due else None
    new_due = _tighter(poam.due_on, mitigation_day, status.kev_due)
    previous = poam.due_on
    if new_due is None:
        return status, False, None
    poam.due_on = new_due
    await _audit_tightening(
        session, poam, system=system, previous=previous, new_due=new_due, principal=principal
    )
    return status, True, previous


async def _audit_tightening(
    session: AsyncSession,
    poam: POAM,
    *,
    system: System,
    previous: date | None,
    new_due: date,
    principal: Principal,
) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 -- avoid an import cycle

    await record_event(
        session,
        actor=principal.email or "system",
        action="vdr_due_tightened",
        entity_type="poam",
        entity_id=str(poam.id),
        diff={
            "due_on": [previous.isoformat() if previous else None, new_due.isoformat()],
            "reason": "VDR evaluation or KEV due date requires an earlier deadline",
        },
        organization_id=system.organization_id,
    )


# ── a system's view ───────────────────────────────────────────────────────


def _cadence_out(c: tf.Cadence) -> dict[str, Any]:
    return {
        "scanner": c.scanner,
        "last_at": c.last_at,
        "age_days": round(c.age.total_seconds() / 86400, 1),
        "required_days": None if c.required is None else c.required.days,
        "stale": c.stale,
    }


def _pending_out(e: VulnerabilityEvaluation) -> dict[str, Any]:
    return {
        "id": e.id,
        "pain_rating": e.pain_rating,
        "internet_reachable": e.internet_reachable,
        "likely_exploitable": e.likely_exploitable,
        "false_positive": e.false_positive,
        "rationale": e.rationale,
        "evaluated_by": e.evaluated_by,
        "evaluated_at": e.evaluated_at,
    }


def status_out(
    poam: POAM, s: tf.FlawStatus, pending: Sequence[VulnerabilityEvaluation] = ()
) -> dict[str, Any]:
    cur = s.current
    return {
        "pending": [_pending_out(e) for e in pending],
        "poam_id": poam.id,
        "title": poam.title,
        "severity": poam.severity,
        "poam_status": poam.status,
        "due_on": poam.due_on,
        "state": s.state,
        "detected_at": s.detected_at,
        "evaluation_due": s.evaluation_due,
        "evaluation": None
        if cur is None
        else {
            "pain_rating": cur.pain_rating,
            "internet_reachable": cur.internet_reachable,
            "likely_exploitable": cur.likely_exploitable,
            "false_positive": cur.false_positive,
            "evaluated_at": cur.evaluated_at,
        },
        "first_evaluated_at": s.first_evaluated_at,
        "clock_start": s.clock_start,
        "mitigation_column": s.mitigation_column,
        "mitigation_due": s.mitigation_due,
        "kev_due": s.kev_due,
        "accept_by": s.accept_by,
        "breaches": [
            {"rule": b.rule, "due": b.due, "explanation": b.explanation} for b in s.breaches
        ],
        "note": s.note,
    }


async def system_vdr(
    session: AsyncSession, system: System, *, now: datetime | None = None
) -> dict[str, Any]:
    """Every flaw on ``system`` against its class, plus detection cadence."""
    now = now or datetime.now(UTC)
    cls = tf.class_timeframes(system.certification_class)
    poams = [
        p
        for p in (
            await session.execute(select(POAM).where(POAM.system_id == system.id).order_by(POAM.id))
        ).scalars()
        if _is_flaw(p)
    ]
    evals = await evaluations_by_poam(session, [p.id for p in poams])
    pending = await pending_by_poam(session, [p.id for p in poams])
    kev = await kev_due_by_poam(session, poams)
    statuses = [
        (p, tf.assess(p, evals.get(p.id, []), cls=cls, kev_due=kev.get(p.id), now=now))
        for p in poams
    ]
    counts = dict.fromkeys(tf.STATES, 0)
    for _, s in statuses:
        counts[s.state] += 1
    runs = (
        await session.execute(
            select(ScanIngestion.scanner, ScanIngestion.created_at).where(
                ScanIngestion.system_id == system.id
            )
        )
    ).all()
    return {
        "system_id": system.id,
        "certification_class": system.certification_class,
        "rules_version": tf.rules_version(),
        "as_of": now,
        "counts": counts,
        "flaws": [status_out(p, s, pending.get(p.id, [])) for p, s in statuses],
        "cadence": [
            _cadence_out(c)
            for c in tf.detection_cadence([(scanner, at) for scanner, at in runs], cls=cls, now=now)
        ],
    }
