"""How long flaws actually take to remediate, against the declared timeframe.

Pure: POA&Ms, a window and ``today`` in, buckets out. No database, no clock --
so the same calculation serves a dashboard, a report and a campaign's
completion record, and every boundary is testable.

Two decisions carry the integrity of the number:

* **``unknown`` is its own bucket and never folded into a passing one.** A
  finding with no identification date, a closed one with no closure date, or a
  closure that predates identification cannot be *shown* to have been
  remediated in time. Counting any of them as on-time would overstate the exact
  figure SI-2 is about, and poor record-keeping would improve the score.
* **The buckets sum to the measured count.** Nothing is silently dropped --
  the same invariant ``analytics.posture.poam_aging`` maintains across
  ``on_track``/``overdue``/``no_due_date``, and a test asserts it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from statistics import median
from typing import Any

from ..constants import POAM_CLOSED_STATUSES

#: FedRAMP's flaw-remediation timeframes, in days. Adopted rather than invented:
#: different numbers in a federal product would be worse than the ones
#: assessors already expect. A test pins them so a change is deliberate.
FEDRAMP_TIMEFRAMES: dict[str, int] = {
    "critical": 30,
    "high": 30,
    "moderate": 90,
    "low": 180,
}

#: CR26 (Vulnerability Evaluation and Reporting): a provider MUST categorize any
#: vulnerability not -- or that will not be -- fully mitigated or remediated
#: within this many days of evaluation as an accepted vulnerability. Mandatory
#: for offerings obtaining or maintaining FedRAMP Certification from 2026-12-07.
ACCEPTED_WEAKNESS_DAYS = 192

#: Every state a weakness can be in under the CR26 rule. Closed, and parallel
#: to :data:`SLA_BUCKETS`, because a projection that cannot say "unknown" has
#: to call an unmeasurable row something it is not.
ACCEPTED_WEAKNESS_STATES = ("accepted", "not_accepted", "unknown")

#: Every bucket a measured POA&M lands in. Closed, because the sum invariant
#: depends on it.
SLA_BUCKETS = (
    "within_sla",
    "breached",
    "accepted",
    "closed_on_time",
    "closed_late",
    "unknown",
)

#: Only scanner-derived POA&Ms are flaws. An assessment finding is a control
#: deficiency, and measuring it here would distort the SI-2 number.
FLAW_SOURCES = ("scan",)


@dataclass(frozen=True)
class RemediationWindow:
    """The organization's declared timeframe, in days, per severity."""

    critical: int = FEDRAMP_TIMEFRAMES["critical"]
    high: int = FEDRAMP_TIMEFRAMES["high"]
    moderate: int = FEDRAMP_TIMEFRAMES["moderate"]
    low: int = FEDRAMP_TIMEFRAMES["low"]

    def days_for(self, severity: str | None) -> int:
        """Days allowed for a severity.

        An unrecognised severity gets the **strictest** window, not the most
        generous: a severity this build does not know about must not be treated
        as low-urgency by default.
        """
        mapped = {
            "critical": self.critical,
            "high": self.high,
            "moderate": self.moderate,
            "low": self.low,
        }
        value = mapped.get((severity or "").lower())
        return value if value is not None else min(mapped.values())

    def as_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "moderate": self.moderate,
            "low": self.low,
        }


@dataclass
class SlaReport:
    """What the measurement found."""

    measured: int = 0
    #: POA&Ms skipped because they are not flaws (see :data:`FLAW_SOURCES`).
    excluded: int = 0
    buckets: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    #: The open, breaching POA&M ids. A count nobody can act on is a worse
    #: artefact than a list.
    breaching_ids: list[int] = field(default_factory=list)
    median_closed_latency_days: int | None = None
    #: On-time closures plus within-window openings, over everything measured.
    #: ``None`` when nothing was measured -- no findings is not 100% compliance
    #: with a remediation timeframe.
    compliance_pct: float | None = None
    window: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "measured": self.measured,
            "excluded": self.excluded,
            "buckets": self.buckets,
            "by_severity": self.by_severity,
            "breaching_ids": self.breaching_ids,
            "median_closed_latency_days": self.median_closed_latency_days,
            "compliance_pct": self.compliance_pct,
            "window": self.window,
        }


def _latency(poam: Any) -> int | None:
    """Days from identification to closure, or ``None`` if unmeasurable."""
    identified, closed = poam.identified_on, poam.closed_on
    if identified is None or closed is None:
        return None
    days = (closed - identified).days
    # Negative latency is corrupt data, not perfect performance.
    return days if days >= 0 else None


def classify(poam: Any, *, allowed_days: int, today: date) -> str:
    """Which bucket one POA&M falls in.

    ``allowed_days`` is passed already resolved, so this needs no policy
    lookup and stays trivially testable at both boundaries. **At** the limit is
    within SLA: an organization that says 30 days means 30, not 29.
    ``accepted`` short-circuits ahead of every date check -- see below.
    """
    if str(poam.status) == "risk_accepted":
        # Residual risk formally accepted, not work outstanding. constants.py
        # excludes it from POAM_ACTIVE_STATUSES for exactly this reason, and
        # analytics.posture already buckets it separately; sla.py had diverged,
        # reporting it as an SLA breach when old and as within_sla when young.
        # Under CR26 it is the outcome the rule defines -- see
        # accepted_weakness_state. Checked before the identified_on guard
        # because the bucket does not depend on a date, and
        # accepted_weakness_state's first branch agrees.
        # It stays OUT of compliance_pct's numerator: it was not remediated in
        # time. It stays IN the denominator: otherwise accepting risk would
        # improve the score.
        return "accepted"
    if poam.identified_on is None:
        return "unknown"
    closed = str(poam.status) in POAM_CLOSED_STATUSES
    if closed:
        latency = _latency(poam)
        if latency is None:
            # Closed without a (usable) closure date: a data-quality signal,
            # never on-time.
            return "unknown"
        return "closed_on_time" if latency <= allowed_days else "closed_late"
    if poam.closed_on is not None:
        # Reopened after being closed: a stale closed_on left behind by a
        # status change (e.g. PATCH /api/poams/{id} setting status="open"
        # without clearing closed_on). It is neither honestly "closed" nor
        # cleanly "open" -- unknown, not a free pass back to within_sla.
        return "unknown"
    age = (today - poam.identified_on).days
    return "within_sla" if age <= allowed_days else "breached"


def accepted_weakness_state(poam: Any, *, today: date) -> str:
    """Which CR26 state one weakness is in -- see :data:`ACCEPTED_WEAKNESS_STATES`.

    An Accepted Weakness is a union of two **disjoint** halves, because the rule
    says "is not **or will not be**" fully mitigated or remediated within the
    window:

    - **declared** -- ``status == "risk_accepted"``, at any age, dated or not.
      This is the forward-looking half: a provider may accept a weakness on day
      3, and no elapsed-time arithmetic can represent a decision not yet made.
      A projection keyed only to age would report an already-accepted weakness
      as open remediation work for up to 191 days.
    - **elapsed** -- still in the remediation backlog more than
      :data:`ACCEPTED_WEAKNESS_DAYS` after identification. Inclusive at the
      limit, like :func:`classify`: 192 days means 192, not 191.

    The elapsed branch is reached only by a row that is neither
    ``risk_accepted`` nor in ``POAM_CLOSED_STATUSES``, which for any value the
    ``ccf.poam_status`` enum permits is exactly ``POAM_ACTIVE_STATUSES`` -- the
    remediation backlog, which *excludes* ``risk_accepted`` by design (see
    :mod:`ccf.constants`). So the halves cannot overlap and a row is reached by
    exactly one. An unrecognised status falls through to the elapsed
    arithmetic, as it does in :func:`classify`, rather than escaping the rule.

    **Why three states rather than a boolean.** ``unknown`` is its own answer
    here for the same reason it is a bucket in :func:`classify`: a row with no
    ``identified_on``, or a closure that predates identification, cannot be
    *shown* to fall outside the window. Under a rule that obliges a provider to
    report its accepted weaknesses, "not accepted" is the *favourable* answer,
    so returning it for an unmeasurable row would let poor record-keeping shrink
    the reported list -- the inversion this module's header refuses.

    The branch order mirrors :func:`classify` step for step, so the two cannot
    disagree about which rows are unmeasurable. In particular, **status is
    consulted before any closure date**: a closed status is judged on its
    closure latency, and only after that does a leftover ``closed_on`` on a row
    whose status is *not* closed -- a reopened weakness -- read as ``unknown``
    rather than as resolved. Shipping that comparison the other way round was a
    Critical in the flaw-remediation work.

    This deliberately does **not** share a threshold with :func:`classify`.
    ``classify`` measures an organization's own declared remediation window, per
    severity; this applies FedRAMP's fixed 192 days. They agree on which rows are
    declared-accepted and on which are unmeasurable, and must stay free to
    disagree about *when* an open row crosses a line.

    **Stated assumption:** the 192 days run from *evaluation*, and ``POAM``
    records ``identified_on``. These may not be the same act -- evaluation is
    VER-defined. ``identified_on`` is the closest existing field, and that
    substitution is an explicit assumption to confirm against the VER ruleset
    when it publishes, not a silent equivalence. If they differ, only the key
    changes; the shape of the rule does not.

    ``today`` is injected so the rule is testable at both boundaries, as
    everything else in this module is.
    """
    if str(poam.status) == "risk_accepted":
        # The declared half. Date-independent, exactly as classify's first
        # branch is, so an undated accepted row cannot read as unknown here and
        # accepted there.
        return "accepted"
    if poam.identified_on is None:
        # Never invent a date: an unknown age cannot satisfy a 192-day rule,
        # and it cannot refute one either.
        return "unknown"
    if str(poam.status) in POAM_CLOSED_STATUSES:
        # Closed without a usable closure date (missing, or before
        # identification) is a data-quality signal, never a clean "not
        # accepted".
        return "unknown" if _latency(poam) is None else "not_accepted"
    if poam.closed_on is not None:
        # Reopened after being closed: a stale closed_on left behind by a status
        # change. Neither honestly closed nor cleanly open, so neither half of
        # the rule can be applied to it honestly either.
        return "unknown"
    age = (today - poam.identified_on).days
    return "accepted" if age > ACCEPTED_WEAKNESS_DAYS else "not_accepted"


def measure(
    poams: Sequence[Any], *, window: RemediationWindow, today: date
) -> SlaReport:
    """Bucket every flaw POA&M against the declared window."""
    report = SlaReport(
        buckets=dict.fromkeys(SLA_BUCKETS, 0), window=window.as_dict()
    )
    latencies: list[int] = []
    for poam in poams:
        if (poam.source or "") not in FLAW_SOURCES:
            report.excluded += 1
            continue
        allowed = window.days_for(poam.severity)
        bucket = classify(poam, allowed_days=allowed, today=today)
        report.measured += 1
        report.buckets[bucket] += 1
        severity = (poam.severity or "unknown").lower()
        per = report.by_severity.setdefault(severity, dict.fromkeys(SLA_BUCKETS, 0))
        per[bucket] += 1
        if bucket == "breached":
            report.breaching_ids.append(poam.id)
        if bucket in ("closed_on_time", "closed_late"):
            latency = _latency(poam)
            if latency is not None:
                latencies.append(latency)

    report.breaching_ids.sort()
    if latencies:
        report.median_closed_latency_days = int(median(latencies))
    if report.measured:
        compliant = report.buckets["within_sla"] + report.buckets["closed_on_time"]
        # Unknowns stay in the denominator: they cannot be shown to comply, and
        # excluding them would let poor record-keeping improve the score.
        # ``accepted`` stays in it too, for the reason the branch in classify
        # gives. NOTE the deliberate asymmetry with the executive
        # overview: analytics/posture.py's poam_aging excludes risk_accepted from
        # open_total, so analytics/overview.py's sla.on_track_pct has accepted
        # risk OUT of its denominator, while compliance_pct keeps it IN. Both are
        # right for what they measure -- on_track_pct asks "how much outstanding
        # work is on schedule", and accepted risk is not outstanding work;
        # compliance_pct asks "what share of flaws was remediated inside the
        # declared timeframe", and accepting risk must never be able to raise
        # that number. Do NOT "fix" one to match the other: this codebase has
        # already paid for two surfaces quantifying the same rows differently
        # (see queries/registry.py).
        report.compliance_pct = round(100 * compliant / report.measured, 1)
    return report
