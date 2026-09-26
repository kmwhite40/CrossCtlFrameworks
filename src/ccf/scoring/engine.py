"""SPRS scoring engine for CMMC Level 2 (NIST SP 800-171 DoD methodology).

Pure, side-effect-free functions so the same math runs in the API, the CLI, and
tests. Mirrors 32 CFR 170.24 / the NIST SP 800-171 DoD Assessment Methodology:

- Perfect score is **110**. Each requirement carries a weighted value of 5, 3,
  or 1 points that is *subtracted* when the requirement is NOT MET.
- Three requirements allow partial credit (point value ``"3/5"``): a full miss
  costs 5, a partial implementation costs 3.
- ``CA.L2-3.12.4`` (the System Security Plan) is a ``"Special"`` prerequisite —
  it carries no numeric weight, but its absence means the assessment cannot be
  scored. We surface that as ``ssp_present`` rather than a deduction.
- The score is allowed to go negative (SPRS floors at ``-203`` in practice).

SPRS is a self-assessment, so counting a *claimed* state is correct by design.
What is not correct is being unable to tell a claim someone made from one
Concord computed for them. The profile derivation writes ``inherited`` and
``partial`` states from an intake answer and a vendor placemat
(``ccf.governance.automation.derive_system``), and those states earn SPRS credit
identically to assessed ones — so a score projected from a questionnaire
rendered as though an assessor had produced it. ``sources`` carries the
distinction through the math: the summary reports how many points were credited
without anyone assessing the practice (``derived_credit``), and whether the SSP
prerequisite is asserted by a placemat rather than by an SSP
(``ssp_present_source``). The score itself is unchanged — the reader is told
what it rests on.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

MAX_SPRS_SCORE = 110
SPRS_FLOOR = -203
SSP_CONTROL_ID = "CA.L2-3.12.4"

# Implementation states an assessor can record for a control.
STATES = (
    "not_assessed",
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
)

# States that count as satisfied (zero deduction).
_MET = {"implemented", "inherited", "not_applicable"}
# States that count as a full miss.
_MISS = {"not_assessed", "not_implemented", "planned"}

# Base point value (full-miss deduction) for each scoring bucket.
_BASE: dict[str, int] = {"5": 5, "3": 3, "1": 1, "3/5": 5, "Special": 0}
# Partial-implementation deduction (only the 3/5 rows earn partial credit).
_PARTIAL: dict[str, int] = {"5": 5, "3": 3, "1": 1, "3/5": 3, "Special": 0}

#: Where a recorded state came from. ``derived`` means the profile derivation
#: computed it; ``assessed`` means a person or a piece of evidence set it. Any
#: other value is treated as ``assessed`` — over-reporting derived credit would
#: be its own false claim.
SOURCES = ("assessed", "derived")
DERIVED = "derived"
ASSESSED = "assessed"


def normalize_point_value(point_value: str | None) -> str:
    pv = (point_value or "").strip()
    return pv if pv in _BASE else "1"


def deduction_for(point_value: str | None, state: str | None) -> int:
    """Points subtracted from 110 for a single control in the given state."""
    pv = normalize_point_value(point_value)
    st = (state or "not_assessed").strip()
    if st in _MET:
        return 0
    if st == "partial":
        return _PARTIAL[pv]
    if st in _MISS:
        return _BASE[pv]
    return _BASE[pv]


def credit_for(point_value: str | None, state: str | None) -> int:
    """Points this state keeps that ``not_assessed`` would have cost.

    The honest measure of what a state is *worth*: a met 5-pointer keeps 5, a
    partially implemented ``3/5`` keeps 2, and a ``partial`` on any other row
    keeps nothing, because partial credit exists only for the three ``3/5``
    requirements. Used to report how much of a score rests on states nobody
    assessed.
    """
    pv = normalize_point_value(point_value)
    return _BASE[pv] - deduction_for(pv, state)


@dataclass(frozen=True)
class ControlScore:
    control_id: str
    domain: str
    point_value: str
    state: str
    deduction: int
    #: ``"assessed"`` or ``"derived"`` — see :data:`SOURCES`.
    source: str = ASSESSED
    #: Points this row keeps relative to ``not_assessed``.
    credited: int = 0


@dataclass
class ScoreSummary:
    score: int
    max_score: int = MAX_SPRS_SCORE
    deductions_total: int = 0
    percentage: float = 0.0
    total_controls: int = 0
    met_controls: int = 0
    ssp_present: bool = True
    #: How ``ssp_present`` was decided: ``"assessed"`` when a person recorded
    #: the SSP practice, ``"derived"`` when the profile derivation asserted it
    #: from a platform placemat, ``None`` when the practice is not in the
    #: matrix. A derived ``True`` is a claim that an SSP exists made by an
    #: intake answer — and the SSP is the one prerequisite a DoD assessment
    #: cannot be scored without, so a view must be able to say which it is.
    ssp_present_source: str | None = None
    #: States a person or a piece of evidence set (excludes ``not_assessed``).
    assessed_controls: int = 0
    #: States the profile derivation computed. Nobody assessed these.
    derived_controls: int = 0
    #: SPRS points kept by derived states — the share of the score that rests
    #: on an intake answer rather than on an assessment.
    derived_credit: int = 0
    state_counts: dict[str, int] = field(default_factory=dict)
    by_domain: dict[str, dict[str, int]] = field(default_factory=dict)
    by_point_value: dict[str, dict[str, int]] = field(default_factory=dict)
    controls: list[ControlScore] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "max_score": self.max_score,
            "deductions_total": self.deductions_total,
            "percentage": self.percentage,
            "total_controls": self.total_controls,
            "met_controls": self.met_controls,
            "ssp_present": self.ssp_present,
            "ssp_present_source": self.ssp_present_source,
            "assessed_controls": self.assessed_controls,
            "derived_controls": self.derived_controls,
            "derived_credit": self.derived_credit,
            "state_counts": self.state_counts,
            "by_domain": self.by_domain,
            "by_point_value": self.by_point_value,
        }


def score_system(
    controls: Iterable[Mapping[str, object]],
    states: Mapping[str, str],
    *,
    sources: Mapping[str, str] | None = None,
    default_state: str = "not_assessed",
) -> ScoreSummary:
    """Compute a live SPRS summary.

    ``controls`` is the reference matrix (each item exposes ``control_id``,
    ``domain``, ``point_value``). ``states`` maps a control_id to its recorded
    implementation state; anything absent falls back to ``default_state``.
    ``sources`` maps a control_id to ``"assessed"`` or ``"derived"``; a control
    absent from it, or carrying an unrecognised value, counts as assessed, so
    the derived share is never overstated.
    """
    summary = ScoreSummary(score=MAX_SPRS_SCORE)
    state_counts: dict[str, int] = dict.fromkeys(STATES, 0)
    sources = sources or {}

    for ref in controls:
        cid = str(ref.get("control_id", ""))
        if not cid:
            continue
        domain = str(ref.get("domain", "") or "?")
        pv = normalize_point_value(str(ref.get("point_value", "") or "1"))
        state = states.get(cid, default_state)
        if state not in STATES:
            state = default_state
        ded = deduction_for(pv, state)
        # A control nobody has recorded is neither assessed nor derived,
        # whatever the source map says: with no state there is no decision to
        # attribute. Counting it as derived would inflate `derived_controls`
        # with rows that carry no claim at all.
        src = sources.get(cid, ASSESSED)
        if src != DERIVED or state == "not_assessed":
            src = ASSESSED
        credited = credit_for(pv, state)

        summary.total_controls += 1
        state_counts[state] = state_counts.get(state, 0) + 1
        if state in _MET:
            summary.met_controls += 1
        if src == DERIVED:
            summary.derived_controls += 1
            summary.derived_credit += credited
        elif state != "not_assessed":
            summary.assessed_controls += 1
        summary.deductions_total += ded
        summary.controls.append(
            ControlScore(
                control_id=cid,
                domain=domain,
                point_value=pv,
                state=state,
                deduction=ded,
                source=src,
                credited=credited,
            )
        )

        dom = summary.by_domain.setdefault(domain, {"controls": 0, "met": 0, "deductions": 0})
        dom["controls"] += 1
        dom["met"] += 1 if state in _MET else 0
        dom["deductions"] += ded

        pvb = summary.by_point_value.setdefault(pv, {"controls": 0, "met": 0, "deductions": 0})
        pvb["controls"] += 1
        pvb["met"] += 1 if state in _MET else 0
        pvb["deductions"] += ded

        if cid == SSP_CONTROL_ID:
            summary.ssp_present = state in _MET or state == "partial"
            # Only a present SSP needs its provenance qualified. `False` is not
            # a claim anyone is relying on, so leaving the source unset keeps
            # "no SSP" from reading as "an SSP asserted by a placemat".
            summary.ssp_present_source = src if summary.ssp_present else None

    summary.score = max(SPRS_FLOOR, MAX_SPRS_SCORE - summary.deductions_total)
    summary.percentage = round(summary.score / MAX_SPRS_SCORE * 100, 1)
    summary.state_counts = state_counts
    return summary
