"""Evaluations reach the CR26 VER deliverables (VDR spec §9).

The 2026-09-18 VER spec omitted six fields for want of a source. These tests
pin what each now claims once an evaluation exists, and that a document
carrying them still passes FedRAMP's schema.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from ccf.cr26.validation import validate_document
from ccf.cr26.ver import VdrFacts, render_vulnerability, seed_vdr
from ccf.db import session_scope
from ccf.models import POAM, Organization, System
from ccf.models_vdr import VulnerabilityEvaluation
from ccf.patching.sla import RemediationWindow
from ccf.vdr import timeframes as tf

TODAY = date(2026, 12, 3)
WINDOW = RemediationWindow()
T0 = datetime(2026, 12, 1, 9, 30, tzinfo=UTC)


class _Poam:
    def __init__(self, **kw: object) -> None:
        self.id = kw.get("id", 42)
        self.title = kw.get("title", "Outdated OpenSSL on web tier")
        self.weakness = kw.get("weakness")
        self.severity = kw.get("severity", "high")
        self.status = kw.get("status", "open")
        self.identified_on = kw.get("identified_on", date(2026, 12, 1))
        self.closed_on = kw.get("closed_on")
        self.scanner = kw.get("scanner", "nessus")
        self.source = kw.get("source", "scan")


def _ev(pain: int, at: datetime = T0, *, fp: bool = False, irv: bool = True) -> tf.Evaluation:
    return tf.Evaluation(pain, irv, True, fp, at)


def _facts(poam: _Poam, evs: list[tf.Evaluation], cls: str | None = "C") -> VdrFacts:
    now = datetime.combine(TODAY, datetime.max.time(), UTC)
    c = tf.class_timeframes(cls)
    status = None if c is None else tf.assess(poam, evs, cls=c, kev_due=None, now=now)
    return VdrFacts(evaluations=evs, status=status)


def test_an_evaluation_supplies_the_fields_the_ver_spec_omitted() -> None:
    p = _Poam()
    evs = [_ev(5, T0), _ev(3, T0 + timedelta(hours=6), irv=False)]
    detail, reasons = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, evs))
    assert reasons == []
    assert detail["currentRating"] == 3
    assert detail["isInternetReachable"] is False
    assert detail["isLikelyExploitable"] is True
    assert detail["evaluationCompletedAt"] == "2026-12-01T09:30:00Z"  # the FIRST evaluation
    assert detail["painReductionEvents"] == [{"reducedAt": "2026-12-01T15:30:00Z", "rating": 3}]


def test_only_reductions_are_reduction_events() -> None:
    p = _Poam()
    evs = [_ev(3, T0), _ev(5, T0 + timedelta(hours=1)), _ev(4, T0 + timedelta(hours=2))]
    detail, _ = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, evs))
    assert detail["painReductionEvents"] == [{"reducedAt": "2026-12-01T11:30:00Z", "rating": 4}]


def test_n0_is_outside_the_schema_enum_so_no_rating_is_claimed() -> None:
    p = _Poam()
    evs = [_ev(4, T0), _ev(0, T0 + timedelta(hours=1))]
    detail, _ = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, evs))
    assert "currentRating" not in detail
    assert "painReductionEvents" not in detail


def test_no_evaluation_adds_no_evaluation_fields() -> None:
    p = _Poam()
    detail, _ = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, []))
    for key in (
        "currentRating",
        "isInternetReachable",
        "isLikelyExploitable",
        "evaluationCompletedAt",
        "painReductionEvents",
        "finalDisposition",
    ):
        assert key not in detail


def test_a_late_flaw_is_overdue_by_the_class_rule_with_the_explanation() -> None:
    p = _Poam()
    detail, _ = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, [_ev(5)]))
    # Class C, N5 LEV+IRV: 2 days from 2026-12-01 09:30, judged at the end of 12-03.
    assert detail["overdueStatus"]["isOverdue"] is True
    assert "VDR-TFR-PVR" in detail["overdueStatus"]["explanation"]


def test_an_unevaluated_flaw_inside_evu_is_not_overdue() -> None:
    p = _Poam(identified_on=TODAY)
    detail, _ = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, []))
    assert detail["overdueStatus"] == {"isOverdue": False}


def test_without_a_class_the_severity_window_still_decides() -> None:
    p = _Poam(identified_on=date(2026, 1, 1))
    detail, _ = render_vulnerability(
        p, today=TODAY, window=WINDOW, vdr=_facts(p, [_ev(1)], cls=None)
    )
    assert detail["overdueStatus"] == {"isOverdue": True}
    assert detail["currentRating"] == 1


def test_a_closed_false_positive_says_so() -> None:
    p = _Poam(status="closed", closed_on=TODAY)
    detail, _ = render_vulnerability(
        p, today=TODAY, window=WINDOW, vdr=_facts(p, [_ev(0, fp=True)])
    )
    assert detail["finalDisposition"] == "False Positive"
    assert "overdueStatus" not in detail


def test_an_open_false_positive_has_no_final_disposition_yet() -> None:
    p = _Poam()
    detail, _ = render_vulnerability(
        p, today=TODAY, window=WINDOW, vdr=_facts(p, [_ev(0, fp=True)])
    )
    assert "finalDisposition" not in detail


def test_a_document_carrying_every_evaluation_field_passes_the_schema() -> None:
    p = _Poam()
    evs = [_ev(5, T0), _ev(3, T0 + timedelta(hours=6))]
    detail, _ = render_vulnerability(p, today=TODAY, window=WINDOW, vdr=_facts(p, evs))
    doc = {
        "certificationPackageOverviewUri": "https://example.gov/cpo.json",
        "reportPeriod": {"from": "2026-12-01T00:00:00Z", "to": "2026-12-31T00:00:00Z"},
        "vulnerabilities": [detail],
    }
    report = validate_document(doc, "vdr")
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_a_seeded_vdr_carries_the_recorded_evaluation() -> None:
    async with session_scope() as s:
        org = Organization(name="vdr-ver-seed org")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="vdr-ver-seed", certification_class="C")
        s.add(system)
        await s.flush()
        poam = POAM(
            system_id=system.id,
            title="Outdated OpenSSL",
            severity="high",
            status="open",
            identified_on=date(2026, 12, 1),
            scanner="nessus",
            source="scan",
        )
        s.add(poam)
        await s.flush()
        s.add(
            VulnerabilityEvaluation(
                organization_id=org.id,
                poam_id=poam.id,
                pain_rating=4,
                internet_reachable=False,
                likely_exploitable=True,
                rationale="Reachable only from the admin VPC.",
                evaluated_at=T0,
            )
        )
        system_id = system.id
    async with session_scope() as s:
        result = await seed_vdr(
            s,
            system_id=system_id,
            period_from=datetime(2026, 12, 1, tzinfo=UTC),
            period_to=datetime(2026, 12, 31, tzinfo=UTC),
            today=TODAY,
        )
    (detail,) = result.document.document["vulnerabilities"]
    assert detail["currentRating"] == 4
    assert detail["isInternetReachable"] is False
    # Class C N4 LEV+NIRV is 8 days: not overdue on 12-03.
    assert detail["overdueStatus"] == {"isOverdue": False}
    # The only error is the URI the operator has not supplied yet.
    assert result.document.validation_errors == [
        "<root>: 'certificationPackageOverviewUri' is a required property"
    ]


@pytest.mark.asyncio
async def test_a_pending_evaluation_does_not_reach_the_deliverable() -> None:
    async with session_scope() as s:
        org = Organization(name="vdr-ver-pending org")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="vdr-ver-pending", certification_class="C")
        s.add(system)
        await s.flush()
        poam = POAM(
            system_id=system.id,
            title="Outdated OpenSSL",
            severity="high",
            status="open",
            identified_on=date(2026, 12, 1),
            scanner="nessus",
            source="scan",
        )
        s.add(poam)
        await s.flush()
        common = {
            "organization_id": org.id,
            "poam_id": poam.id,
            "likely_exploitable": True,
            "internet_reachable": True,
            "rationale": "r",
        }
        s.add(VulnerabilityEvaluation(pain_rating=5, evaluated_at=T0, **common))
        s.add(
            VulnerabilityEvaluation(
                pain_rating=1,
                evaluated_at=T0 + timedelta(hours=1),
                requires_confirmation=True,
                evaluated_by="a@x",
                **common,
            )
        )
        system_id = system.id
    async with session_scope() as s:
        result = await seed_vdr(
            s,
            system_id=system_id,
            period_from=datetime(2026, 12, 1, tzinfo=UTC),
            period_to=datetime(2026, 12, 31, tzinfo=UTC),
            today=TODAY,
        )
    (detail,) = result.document.document["vulnerabilities"]
    assert detail["currentRating"] == 5
    assert "painReductionEvents" not in detail
    assert detail["overdueStatus"]["isOverdue"] is True
