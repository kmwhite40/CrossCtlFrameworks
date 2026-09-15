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

#: FedRAMP's flaw-remediation timeframes, in days. Adopted rather than invented:
#: different numbers in a federal product would be worse than the ones
#: assessors already expect. A test pins them so a change is deliberate.
FEDRAMP_TIMEFRAMES: dict[str, int] = {
    "critical": 30,
    "high": 30,
    "moderate": 90,
    "low": 180,
}

#: Every bucket a measured POA&M lands in. Closed, because the sum invariant
#: depends on it.
SLA_BUCKETS = ("within_sla", "breached", "closed_on_time", "closed_late", "unknown")

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
    """
    if poam.identified_on is None:
        return "unknown"
    if poam.closed_on is not None:
        latency = _latency(poam)
        if latency is None:
            return "unknown"
        return "closed_on_time" if latency <= allowed_days else "closed_late"
    if str(poam.status) in ("completed", "closed"):
        # Closed without a closure date: a data-quality signal, never on-time.
        return "unknown"
    age = (today - poam.identified_on).days
    return "within_sla" if age <= allowed_days else "breached"


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
        report.compliance_pct = round(100 * compliant / report.measured, 1)
    return report
