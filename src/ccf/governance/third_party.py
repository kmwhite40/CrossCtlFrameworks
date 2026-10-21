"""Third parties beyond questionnaires: contracts, due diligence, findings, score.

Nothing here decides anything about a vendor. Contracts, obligations,
due-diligence items and findings are records people keep; the vendor risk
score is arithmetic over those records with its formula printed beside it,
and it is ``None`` -- rendered ``—`` -- when a vendor has none of the inputs.
A vendor with no questionnaire, no findings and no due-diligence items has
not been measured, and a number there would read as a finding (or worse, as
an all-clear) that nobody made.

The standard due-diligence checklist creates **requests**: each item starts
``requested`` and carries no evidence. Applying it says what the organization
intends to collect, never that anything was collected.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_program import ContractObligation, DueDiligenceItem, VendorContract, VendorFinding
from ..models_tprm import VendorQuestionnaire

# ── vocabularies (enforced here and by the tests, not by the database) ──────

CONTRACT_STATUSES: tuple[str, ...] = ("draft", "active", "expired", "terminated")
OBLIGATION_CATEGORIES: tuple[str, ...] = (
    "security",
    "privacy",
    "sla",
    "audit_right",
    "breach_notice",
    "other",
)
#: ``waived`` is a decision to stop holding the vendor to a term, so only an
#: admin records it; the rest are observations a contract owner makes.
OBLIGATION_STATUSES: tuple[str, ...] = ("pending", "met", "missed", "waived")
DD_STATUSES: tuple[str, ...] = ("requested", "received", "accepted", "rejected", "not_applicable")
#: What a reviewer may decide about an item.
DD_DECISIONS: tuple[str, ...] = ("accepted", "rejected", "not_applicable")
FINDING_SEVERITIES: tuple[str, ...] = ("critical", "high", "moderate", "low")
#: ``accepted`` is a risk acceptance -- a decision, so admin only.
FINDING_STATUSES: tuple[str, ...] = ("open", "remediating", "closed", "accepted")
FINDING_OPEN_STATUSES: tuple[str, ...] = ("open", "remediating")

#: The standard checklist, as (item, category). Each becomes a ``requested``
#: item: a request to the vendor, not a statement that the document exists.
STANDARD_CHECKLIST: tuple[tuple[str, str], ...] = (
    ("SOC 2 report", "assurance"),
    ("Penetration test summary", "assurance"),
    ("Insurance certificate", "financial"),
    ("BCP/DR plan", "resilience"),
    ("Privacy policy", "privacy"),
    ("Sub-processor list", "supply_chain"),
    ("Security questionnaire", "security"),
)

RENEWAL_WINDOW_DAYS = 90


# ── the vendor risk score ────────────────────────────────────────────────────

#: Criticality multiplies the measured risk; it is not itself a measurement,
#: so a vendor with only a criticality has no score.
CRITICALITY_WEIGHTS: dict[str, float] = {
    "low": 0.75,
    "medium": 1.0,
    "moderate": 1.0,
    "high": 1.25,
    "critical": 1.5,
}
FINDING_POINTS: dict[str, int] = {"critical": 15, "high": 10, "moderate": 5, "low": 2}
QUESTIONNAIRE_MAX = 50
FINDINGS_CAP = 30
DD_POINTS = 5
DD_CAP = 20

#: The formula, as shown on the page. Kept beside the code that computes it so
#: the two are read together; the tests compare a rendered breakdown with it.
FORMULA: tuple[str, ...] = (
    "Q = (100 - latest scored questionnaire) ÷ 2, from 0 to 50",
    "F = 15 per open critical finding, 10 per high, 5 per moderate, 2 per low; at most 30",
    "D = 5 per overdue required due-diligence item (requested or rejected, past its due "
    "date); at most 20",
    "Score = (Q + F + D) x criticality weight (low 0.75, medium 1.0, high 1.25, "
    "critical 1.5), at most 100. Higher is riskier.",
    "A vendor with no scored questionnaire, no findings and no due-diligence items has no "
    "score (—): nothing about it has been measured.",
)


@dataclass
class VendorInputs:
    """What is recorded about one vendor that the score reads."""

    criticality: str
    questionnaire_score: float | None = None
    questionnaire_id: int | None = None
    findings_recorded: int = 0
    open_findings: Counter[str] = field(default_factory=Counter)
    dd_items: int = 0
    dd_overdue: int = 0


def vendor_score(inputs: VendorInputs) -> dict[str, Any] | None:
    """The composite score and its parts, or ``None`` with no inputs.

    ``q + f + d == subtotal`` always holds, and ``score`` is the subtotal
    times ``weight``, capped at 100: the breakdown on the page is the
    computation, not a description of it."""
    has_q = inputs.questionnaire_score is not None
    if not has_q and inputs.findings_recorded == 0 and inputs.dd_items == 0:
        return None
    q = (
        round((100.0 - float(inputs.questionnaire_score)) / 2, 1)  # type: ignore[arg-type]
        if has_q
        else 0.0
    )
    q = max(0.0, min(float(QUESTIONNAIRE_MAX), q))
    f_raw = sum(FINDING_POINTS.get(s, 0) * n for s, n in inputs.open_findings.items())
    f = float(min(FINDINGS_CAP, f_raw))
    d = float(min(DD_CAP, DD_POINTS * inputs.dd_overdue))
    weight_known = inputs.criticality in CRITICALITY_WEIGHTS
    weight = CRITICALITY_WEIGHTS.get(inputs.criticality, 1.0)
    subtotal = round(q + f + d, 1)
    score = min(100, int(subtotal * weight + 0.5))
    missing = []
    if not has_q:
        missing.append("no scored questionnaire")
    if inputs.findings_recorded == 0:
        missing.append("no findings recorded")
    if inputs.dd_items == 0:
        missing.append("no due-diligence items")
    return {
        "score": score,
        "q": q,
        "f": f,
        "d": d,
        "subtotal": subtotal,
        "weight": weight,
        "weight_known": weight_known,
        "criticality": inputs.criticality,
        "questionnaire_score": inputs.questionnaire_score,
        "questionnaire_id": inputs.questionnaire_id,
        "open_findings": dict(inputs.open_findings),
        "dd_overdue": inputs.dd_overdue,
        "missing": missing,
    }


def dd_is_overdue(item: Any, today: date) -> bool:
    """A required item the vendor still owes, past its due date."""
    return bool(
        item.required
        and item.status in ("requested", "rejected")
        and item.due_on is not None
        and item.due_on < today
    )


async def vendor_scores(
    session: AsyncSession, vendors: list[Any], today: date
) -> dict[int, dict[str, Any] | None]:
    """Score each vendor in ``vendors`` (already scoped to the caller's org).

    Child rows are read by ``vendor_id`` *and* by the vendor's own
    organization, so a row whose organization disagrees with its vendor's
    (a bad import) is not counted."""
    if not vendors:
        return {}
    ids = [v.id for v in vendors]
    org_of = {v.id: v.organization_id for v in vendors}
    inputs = {v.id: VendorInputs(criticality=(v.criticality or "").lower()) for v in vendors}

    for q in (
        (
            await session.execute(
                select(VendorQuestionnaire)
                .where(
                    VendorQuestionnaire.vendor_id.in_(ids),
                    VendorQuestionnaire.score.is_not(None),
                )
                .order_by(VendorQuestionnaire.created_at.desc(), VendorQuestionnaire.id.desc())
            )
        )
        .scalars()
        .all()
    ):
        i = inputs[q.vendor_id]
        # A questionnaire written by a global principal carries no org of its
        # own; one carrying a *different* org than its vendor is not this one's.
        if q.organization_id not in (None, org_of[q.vendor_id]):
            continue
        if i.questionnaire_score is not None:
            continue
        i.questionnaire_score = float(q.score)  # type: ignore[arg-type]
        i.questionnaire_id = q.id

    for fnd in (
        (await session.execute(select(VendorFinding).where(VendorFinding.vendor_id.in_(ids))))
        .scalars()
        .all()
    ):
        if fnd.organization_id != org_of[fnd.vendor_id]:
            continue
        i = inputs[fnd.vendor_id]
        i.findings_recorded += 1
        if fnd.status in FINDING_OPEN_STATUSES:
            i.open_findings[fnd.severity] += 1

    for item in (
        (await session.execute(select(DueDiligenceItem).where(DueDiligenceItem.vendor_id.in_(ids))))
        .scalars()
        .all()
    ):
        if item.organization_id != org_of[item.vendor_id]:
            continue
        i = inputs[item.vendor_id]
        i.dd_items += 1
        if dd_is_overdue(item, today):
            i.dd_overdue += 1

    return {vid: vendor_score(i) for vid, i in inputs.items()}


# ── due diligence ────────────────────────────────────────────────────────────


async def apply_standard_checklist(
    session: AsyncSession, vendor: Any, *, due_on: date | None
) -> list[DueDiligenceItem]:
    """Create each standard item the vendor does not already have, as a request.

    Idempotent on the item name: applying twice adds nothing the second time,
    and an item already reviewed is never reset to ``requested``."""
    have = {
        n.lower()
        for n in (
            await session.execute(
                select(DueDiligenceItem.item).where(
                    DueDiligenceItem.vendor_id == vendor.id,
                    DueDiligenceItem.organization_id == vendor.organization_id,
                )
            )
        )
        .scalars()
        .all()
    }
    created = []
    for name, category in STANDARD_CHECKLIST:
        if name.lower() in have:
            continue
        item = DueDiligenceItem(
            organization_id=vendor.organization_id,
            vendor_id=vendor.id,
            item=name,
            category=category,
            required=True,
            status="requested",
            due_on=due_on,
        )
        session.add(item)
        created.append(item)
    await session.flush()
    return created


# ── contracts ────────────────────────────────────────────────────────────────


def renewal_date(contract: VendorContract) -> date | None:
    """The date the contract next needs a decision: renewal, else its end."""
    return contract.renewal_on or contract.end_on


def renewal_due(contract: VendorContract, today: date) -> bool:
    """An active contract whose renewal (or end) falls within the window,
    or has already passed without the contract being closed out."""
    when = renewal_date(contract)
    return (
        contract.status == "active"
        and when is not None
        and when <= today + timedelta(days=RENEWAL_WINDOW_DAYS)
    )


def obligation_state(ob: ContractObligation, today: date) -> str:
    """``missed`` as recorded, ``overdue`` when still pending past its due date
    (not recorded as missed -- nobody has said so), else the status."""
    if ob.status == "pending" and ob.due_on is not None and ob.due_on < today:
        return "overdue"
    return ob.status
