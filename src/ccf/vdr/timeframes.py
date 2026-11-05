"""FedRAMP 20x VDR deadlines for one flaw, from the pinned rules.

See docs/superpowers/specs/2026-11-05-vdr-engine-design.md.

Pure: a POA&M, its evaluations, a class, a KEV due date and ``now`` in; a
status out. No database, no clock. Every number comes from the vendored
``fedramp-consolidated-rules.json`` through :func:`ccf.fedramp20x.rules.load_rules`
-- none is typed here -- and ``tests/test_vdr_timeframes.py`` pins what is
read to the fedramp.gov text.

Three refusals carry the integrity of the result:

* **No class, no class timeframes.** A system without a certification class
  gets no evaluation, mitigation or detection window. Choosing one for it
  would be a claim about the system nobody made.
* **Unevaluated is never on time.** Every mitigation window runs "from
  evaluation" (VDR-TFR-PVR), so a flaw nobody evaluated has no window to be
  within. It awaits evaluation until VER-TFR-EVU passes, then it is late.
* **N0 and N1 have no row in the table.** They are VDR-TFR-RMN's "routine
  operations", reported as ``no_timeframe`` rather than ``within``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from functools import lru_cache
from typing import Any

from ..constants import CERTIFICATION_CLASSES, POAM_CLOSED_STATUSES
from ..fedramp20x.rules import ConsolidatedRules, load_rules

#: The PVR table's three columns, in the order fedramp.gov prints them.
COLUMNS = ("irv_lev", "nirv_lev", "nlev")
COLUMN_LABELS = {
    "irv_lev": "likely exploitable, internet-reachable",
    "nirv_lev": "likely exploitable, not internet-reachable",
    "nlev": "not likely exploitable",
}

#: Every state :func:`assess` returns. Closed, so a page can count them all.
STATES = (
    "overdue",
    "awaiting_evaluation",
    "within",
    "no_timeframe",
    "class_not_set",
    "false_positive",
    "accepted",
    "closed",
)

_UNITS = {"days": "days", "hours": "hours"}


def _rules() -> ConsolidatedRules:
    return load_rules()


def _frr(family: str, group: str, rule_id: str) -> dict[str, Any]:
    rule: dict[str, Any] = _rules().data["FRR"][family]["data"]["all"][group][rule_id]
    return rule


def _delta(entry: dict[str, Any], rule_id: str) -> timedelta:
    unit, num = entry.get("timeframe_type"), entry.get("timeframe_num")
    if unit not in _UNITS or not isinstance(num, int | float):
        # Months appear in other VDR rules; none of the ones converted here use
        # them. A unit this code does not convert must fail, not become days.
        raise ValueError(f"{rule_id}: cannot convert timeframe {num!r} {unit!r}")
    return timedelta(**{_UNITS[unit]: num})


def _variant(rule: dict[str, Any], cls: str) -> dict[str, Any]:
    variant: dict[str, Any] = rule["varies_by_class"][cls.lower()]
    return variant


def rules_version() -> str:
    """The pinned dataset version every number here comes from."""
    return _rules().version


#: VER-TFR-MAV: not fully mitigated or remediated within this long of
#: evaluation means accepted. Class-independent.
ACCEPT_WITHIN: timedelta = _delta(_frr("VER", "TFR", "VER-TFR-MAV"), "VER-TFR-MAV")


@dataclass(frozen=True)
class ClassTimeframes:
    """The windows one certification class gets."""

    certification_class: str
    #: VER-TFR-EVU: evaluate within this long of detection.
    evaluate_within: timedelta
    #: VDR-TFR-PVR: {N-rating: {column: window}}. N0 and N1 are absent.
    mitigation: dict[int, dict[str, timedelta]]
    #: VDR-TFR-PSD: detect on representative samples at least this often.
    sample_detection: timedelta


@lru_cache(maxsize=8)
def _class_timeframes(cls: str) -> ClassTimeframes:
    pvr = _variant(_frr("VDR", "TFR", "VDR-TFR-PVR"), cls)
    mitigation: dict[int, dict[str, timedelta]] = {}
    for rating, row in pvr["pain_timeframes"].items():
        if not row:
            continue
        mitigation[int(rating)] = {c: _delta(row[c], "VDR-TFR-PVR") for c in COLUMNS}
    return ClassTimeframes(
        certification_class=cls,
        evaluate_within=_delta(_variant(_frr("VER", "TFR", "VER-TFR-EVU"), cls), "VER-TFR-EVU"),
        mitigation=mitigation,
        sample_detection=_delta(_variant(_frr("VDR", "TFR", "VDR-TFR-PSD"), cls), "VDR-TFR-PSD"),
    )


def class_timeframes(cls: str | None) -> ClassTimeframes | None:
    """The class's windows, or ``None`` when no class is set.

    An unknown class raises rather than falling back to any other.
    """
    if cls is None:
        return None
    if cls not in CERTIFICATION_CLASSES:
        raise ValueError(f"unknown certification class {cls!r}")
    return _class_timeframes(cls)


# ── one flaw ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Evaluation:
    """One recorded evaluation (VER-EVA-EPA / -EIR / -ELX / -EFP)."""

    pain_rating: int
    internet_reachable: bool
    likely_exploitable: bool
    false_positive: bool
    evaluated_at: datetime

    @property
    def column(self) -> str:
        if not self.likely_exploitable:
            return "nlev"
        return "irv_lev" if self.internet_reachable else "nirv_lev"

    def same_finding_as(self, other: Evaluation) -> bool:
        """Whether two evaluations put the flaw in the same table cell.

        ``false_positive`` is not compared: a false positive is always N0 (a
        CHECK constraint enforces it), and N0 has no cell to be in.
        """
        return (self.pain_rating, self.column) == (other.pain_rating, other.column)


#: Strictness of each PVR column, strictest first: a move rightward lengthens
#: every window in the table.
_COLUMN_ORDER = {c: i for i, c in enumerate(COLUMNS)}


def relaxes(previous: Evaluation | None, new: Evaluation) -> bool:
    """Whether ``new`` would loosen a deadline, so needs a second person.

    Against the evaluation in effect: a lower rating, a less exposed column,
    or a false positive (which also lifts the KEV deadline). With none in
    effect, a first rating of N0 or N1 -- the ones with no mitigation
    timeframe -- relaxes too: FedRAMP's own default for an unknown effect is
    to treat it as debilitating (FRD-DCE), not as negligible.
    """
    if new.false_positive:
        return True
    if previous is None:
        return new.pain_rating <= 1
    if previous.false_positive:
        return False
    return (
        new.pain_rating < previous.pain_rating
        or _COLUMN_ORDER[new.column] > _COLUMN_ORDER[previous.column]
    )


@dataclass(frozen=True)
class Breach:
    rule: str
    due: datetime
    explanation: str


@dataclass
class FlawStatus:
    poam_id: int
    state: str
    detected_at: datetime | None
    evaluation_due: datetime | None = None
    current: Evaluation | None = None
    first_evaluated_at: datetime | None = None
    clock_start: datetime | None = None
    mitigation_column: str | None = None
    mitigation_due: datetime | None = None
    kev_due: date | None = None
    accept_by: datetime | None = None
    breaches: list[Breach] = field(default_factory=list)
    #: Why a deadline is absent, in words a page can show as-is.
    note: str = ""

    @property
    def overdue_explanation(self) -> str | None:
        return "; ".join(b.explanation for b in self.breaches) or None


def detected_at(identified_on: date | None) -> datetime | None:
    """``identified_on`` at 00:00Z -- the convention ``ccf.cr26.ver`` declares
    for ``detection.detectedAt``, so this page and the deliverable agree."""
    return None if identified_on is None else datetime.combine(identified_on, time(), UTC)


def _human(delta: timedelta) -> str:
    if delta % timedelta(days=1):
        hours = int(delta / timedelta(hours=1))
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{delta.days} day{'s' if delta.days != 1 else ''}"


def _clock_start(ordered: Sequence[Evaluation]) -> datetime:
    """The start of the trailing run of evaluations that agree with the latest.

    A re-save of the same rating and reachability does not restart the clock;
    a change does, including a change back to an earlier rating.
    """
    start = ordered[-1].evaluated_at
    for ev in reversed(ordered[:-1]):
        if not ev.same_finding_as(ordered[-1]):
            break
        start = ev.evaluated_at
    return start


def _kev_breach(kev_due: date | None, now: datetime) -> list[Breach]:
    if kev_due is None or now.date() <= kev_due:
        return []
    return [
        Breach(
            "VDR-TFR-KEV",
            datetime.combine(kev_due, time.max, UTC),
            f"CISA's KEV due date {kev_due.isoformat()} has passed (VDR-TFR-KEV: "
            "remediate by the catalog's date even if fully mitigated)",
        )
    ]


def assess(
    poam: Any,
    evaluations: Iterable[Evaluation],
    *,
    cls: ClassTimeframes | None,
    kev_due: date | None,
    now: datetime,
) -> FlawStatus:
    """Where one flaw stands against the rules for ``cls``.

    ``kev_due`` is the earliest CISA due date among the CVE ids the flaw
    names, or ``None``. ``now`` must be timezone-aware: a 12-hour window
    measured against a naive clock is off by the server's UTC offset.
    """
    if now.tzinfo is None:
        raise ValueError("now must carry a timezone")
    ordered = sorted(evaluations, key=lambda e: e.evaluated_at)
    status = FlawStatus(poam_id=poam.id, state="", detected_at=detected_at(poam.identified_on))
    status.kev_due = kev_due
    if ordered:
        status.current = ordered[-1]
        status.first_evaluated_at = ordered[0].evaluated_at

    if str(poam.status) in POAM_CLOSED_STATUSES:
        status.state = "closed"
        return status
    if status.current is not None and status.current.false_positive:
        status.state = "false_positive"
        status.note = "Evaluated as a false positive; close the POA&M to finish it."
        return status

    status.breaches.extend(_kev_breach(kev_due, now))
    if str(poam.status) == "risk_accepted":
        status.state = "overdue" if status.breaches else "accepted"
        return status

    if status.current is None:
        _unevaluated(status, cls, now)
    else:
        _evaluated(status, ordered, cls, now)

    if status.breaches:
        status.state = "overdue"
    return status


def _unevaluated(status: FlawStatus, cls: ClassTimeframes | None, now: datetime) -> None:
    status.state = "awaiting_evaluation"
    if status.detected_at is None:
        status.note = "No identification date, so the evaluation deadline cannot be computed."
        return
    if cls is None:
        status.note = "No certification class is set, so there is no evaluation deadline."
        return
    status.evaluation_due = status.detected_at + cls.evaluate_within
    if now > status.evaluation_due:
        status.breaches.append(
            Breach(
                "VER-TFR-EVU",
                status.evaluation_due,
                f"not evaluated within {_human(cls.evaluate_within)} of detection "
                f"(VER-TFR-EVU, Class {cls.certification_class})",
            )
        )


def _evaluated(
    status: FlawStatus,
    ordered: Sequence[Evaluation],
    cls: ClassTimeframes | None,
    now: datetime,
) -> None:
    current = ordered[-1]
    assert status.first_evaluated_at is not None
    if current.pain_rating > 0:
        status.accept_by = status.first_evaluated_at + ACCEPT_WITHIN
        if now > status.accept_by:
            status.breaches.append(
                Breach(
                    "VER-TFR-MAV",
                    status.accept_by,
                    f"not fully mitigated within {_human(ACCEPT_WITHIN)} of evaluation; "
                    "VER-TFR-MAV requires categorizing it as an accepted vulnerability",
                )
            )

    if cls is None:
        status.state = "class_not_set"
        status.note = "No certification class is set, so there is no mitigation deadline."
        return
    row = cls.mitigation.get(current.pain_rating)
    if row is None:
        status.state = "no_timeframe"
        status.note = (
            f"N{current.pain_rating} has no mitigation timeframe; VDR-TFR-RMN leaves it "
            "to routine operations."
        )
        return
    status.clock_start = _clock_start(ordered)
    status.mitigation_column = current.column
    window = row[current.column]
    status.mitigation_due = status.clock_start + window
    status.state = "within"
    if now > status.mitigation_due:
        status.breaches.append(
            Breach(
                "VDR-TFR-PVR",
                status.mitigation_due,
                f"N{current.pain_rating} {COLUMN_LABELS[current.column]} not reduced within "
                f"{_human(window)} of evaluation (VDR-TFR-PVR, Class {cls.certification_class})",
            )
        )


# ── detection cadence ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Cadence:
    scanner: str
    last_at: datetime
    age: timedelta
    #: VDR-TFR-PSD for the class, or ``None`` with no class.
    required: timedelta | None
    #: ``None`` when there is no class to judge against.
    stale: bool | None


def detection_cadence(
    runs: Iterable[tuple[str, datetime]],
    *,
    cls: ClassTimeframes | None,
    now: datetime,
) -> list[Cadence]:
    """The latest run per scanner against VDR-TFR-PSD, sorted by scanner."""
    latest: dict[str, datetime] = {}
    for scanner, at in runs:
        if scanner not in latest or at > latest[scanner]:
            latest[scanner] = at
    out: list[Cadence] = []
    for scanner in sorted(latest):
        at = latest[scanner]
        age = now - at
        required = cls.sample_detection if cls is not None else None
        out.append(
            Cadence(
                scanner=scanner,
                last_at=at,
                age=age,
                required=required,
                stale=None if required is None else age > required,
            )
        )
    return out
