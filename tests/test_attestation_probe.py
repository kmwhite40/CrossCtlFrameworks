"""A dry run that measures what an attestation ingest would do, and writes nothing.

The attestation ingest has never run against a live AWS account -- no
organization here has a credential bound. Two numbers therefore cannot be
stated, and were deliberately left out of the runbook rather than estimated:
how many of a baseline's controls AWS's own mapping actually reaches, and what
share of ``RelatedRequirements`` Concord cannot place.

This probe is how somebody with a credential gets those numbers in one command,
without first deciding whether they trust the thing to write to their database.

**It shares the ingest's code path.** ``write=False`` is a parameter on
``ingest_attestations``, not a second function, because a separate probe is free
to drift from the ingest it is supposed to be verifying -- and a probe that
measures something the real path does not do is worse than no probe at all. The
tests below pin that: the same inputs must produce the same counts whether or not
rows are written, and the only difference must be the rows.

The coverage measurement is the probe's reason to exist. ``written`` alone says
how many rows the ingest would create; it does not say how much of the
*framework* that is, which is the question being asked.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Control, Organization, System
from ccf.models_grc import ControlTest
from ccf.posture import attested_scan as ingest_mod
from ccf.posture.attested import (
    NIST_80053_R5_STANDARD_ID,
    REQUIREMENT_PREFIX,
    attested_controls,
)
from ccf.posture.attested_scan import ingest_attestations

_SEQ = itertools.count()


def _finding(control_id: str, status: str, related: list[str]) -> dict[str, Any]:
    return {
        "Id": f"{control_id}/r",
        "Title": f"{control_id} title",
        "Compliance": {
            "Status": status,
            "SecurityControlId": control_id,
            "RelatedRequirements": related,
            "AssociatedStandards": [{"StandardsId": NIST_80053_R5_STANDARD_ID}],
        },
    }


def _patch(monkeypatch: pytest.MonkeyPatch, findings: list[dict[str, Any]]) -> None:
    controls = attested_controls(findings)
    unreadable: list[str] = []
    for c in controls:
        for entry in c.unreadable_requirements:
            if entry not in unreadable:
                unreadable.append(entry)

    async def _attestations(**kwargs: object) -> dict[str, Any]:
        return {
            "available": True,
            "reason": None,
            "controls": controls,
            "unreadable_requirements": unreadable,
            "pages_read": 1,
            "truncated": False,
            "region": "us-gov-west-1",
            "account_id": "123456789012",
            "standard_id": NIST_80053_R5_STANDARD_ID,
        }

    class _Conn:
        key = "aws_govcloud"

        def is_configured(self) -> bool:
            return True

        securityhub_attestations = staticmethod(_attestations)

    async def _conn(*a: object, **k: object) -> _Conn:
        return _Conn()

    monkeypatch.setattr(ingest_mod, "_connector_for_org", _conn)


async def _moderate_system(session: Any, controls: list[str]) -> System:
    n = next(_SEQ)
    for identifier in controls:
        existing = (
            await session.execute(select(Control).where(Control.identifier == identifier))
        ).scalars().first()
        if existing is None:
            session.add(
                Control(
                    identifier=identifier,
                    sequence_control=identifier,
                    fisma_mod=True,
                    # Moderate implies High: FIPS-199 baselines nest and these
                    # rows are shared catalog state.
                    fisma_high=True,
                )
            )
        else:
            existing.fisma_mod = True
            existing.fisma_high = True
    await session.flush()
    org = Organization(name=f"ProbeOrg{n}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"ProbeSys{n}", baseline="moderate")
    session.add(sys_)
    await session.flush()
    return sys_


_FINDINGS = [
    _finding("S3.8", "PASSED", [f"{REQUIREMENT_PREFIX} AC-3", f"{REQUIREMENT_PREFIX} SC-7"]),
    _finding("IAM.4", "FAILED", [f"{REQUIREMENT_PREFIX} IA-2"]),
    # Outside the Moderate baseline seeded below, so the probe has something to
    # report as reached-but-not-counted.
    _finding("Backup.1", "PASSED", [f"{REQUIREMENT_PREFIX} CP-9"]),
    # Unplaceable: a statement part, not a control id.
    _finding("IAM.8", "PASSED", [f"{REQUIREMENT_PREFIX} AC-2(j)"]),
]


# --------------------------------------------------------------------------
# It writes nothing
# --------------------------------------------------------------------------


async def test_a_probe_writes_no_control_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        out = await ingest_attestations(session, system_id=sys_.id, write=False)
        rows = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()

    assert rows == []
    assert out["dry_run"] is True


async def test_a_probe_does_not_disturb_rows_a_previous_ingest_wrote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case an operator actually runs it in: there is already data.

    A probe that silently refreshed ``last_tested_at`` would change the evidence
    record's answer to "when was this verified", which is a date an assessor
    reads.
    """
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        await ingest_attestations(session, system_id=sys_.id)
        before = {
            t.check_key: (t.last_status, t.last_tested_at)
            for t in (
                await session.execute(
                    select(ControlTest).where(ControlTest.system_id == sys_.id)
                )
            ).scalars().all()
        }
        assert before, "the harness did not write anything to probe against"

        await ingest_attestations(session, system_id=sys_.id, write=False)

        after = {
            t.check_key: (t.last_status, t.last_tested_at)
            for t in (
                await session.execute(
                    select(ControlTest).where(ControlTest.system_id == sys_.id)
                )
            ).scalars().all()
        }

    assert after == before, "a dry run modified existing rows"


# --------------------------------------------------------------------------
# It measures the same thing the real path does
# --------------------------------------------------------------------------


async def test_the_probe_and_the_ingest_agree_on_every_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The property that makes the probe worth trusting.

    If these could differ, the numbers an operator reads from the probe would not
    be the numbers the ingest goes on to produce -- which is the whole failure
    mode a separate probe function invites.
    """
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        probe = await ingest_attestations(session, system_id=sys_.id, write=False)
        real = await ingest_attestations(session, system_id=sys_.id)

    ignored = {"dry_run"}
    assert {k: v for k, v in probe.items() if k not in ignored} == {
        k: v for k, v in real.items() if k not in ignored
    }


async def test_the_probe_reports_what_would_be_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`written` is a count of rows the ingest *would* create, not of rows made."""
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        out = await ingest_attestations(session, system_id=sys_.id, write=False)

    # S3.8 -> AC-3, SC-7; IAM.4 -> IA-2; Backup.1 -> CP-9. IAM.8 places nothing.
    assert out["written"] == 4
    assert out["controls_read"] == 4
    assert out["controls_without_a_requirement"] == ["IAM.8"]
    assert out["unreadable_requirements"] == [f"{REQUIREMENT_PREFIX} AC-2(j)"]


# --------------------------------------------------------------------------
# The coverage measurement, which is the reason the probe exists
# --------------------------------------------------------------------------


async def test_the_probe_measures_coverage_against_the_system_s_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The number the runbook refuses to estimate.

    Three of the four requirements reached are in this system's Moderate
    baseline; CP-9 is not seeded into it. "4 rows written" does not answer "how
    much of the framework is that", and the second question is the one being
    asked.
    """
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        out = await ingest_attestations(session, system_id=sys_.id, write=False)

    cov = out["coverage"]
    assert cov["baseline"] == "moderate"
    assert cov["requirements_reached"] == ["AC-3", "CP-9", "IA-2", "SC-7"]
    assert cov["in_baseline"] == ["AC-3", "IA-2", "SC-7"]
    assert cov["outside_baseline"] == ["CP-9"]
    assert cov["baseline_total"] >= 3
    # A percentage of the baseline, so the figure is comparable with the
    # runbook's own "n of 288" rather than being a bare count.
    assert cov["in_baseline_pct"] == round(
        100 * len(cov["in_baseline"]) / cov["baseline_total"], 1
    )


async def test_a_control_outside_the_baseline_is_named_not_discarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A requirement AWS attests that this baseline does not hold is not waste --
    a High system is held to it -- but it must not be counted as coverage of a
    Moderate baseline either. Reported on its own, like the runbook's three
    out-of-baseline checks."""
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        out = await ingest_attestations(session, system_id=sys_.id, write=False)

    assert "CP-9" in out["coverage"]["outside_baseline"]
    assert "CP-9" not in out["coverage"]["in_baseline"]


async def test_coverage_is_reported_for_a_system_with_no_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A system with no declared baseline has no denominator.

    Reported as ``None`` with the requirements still listed, never as 0% -- which
    would read as a finding about the account rather than a missing baseline.
    """
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        n = next(_SEQ)
        org = Organization(name=f"ProbeNoBaseOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ProbeNoBaseSys{n}")
        session.add(sys_)
        await session.flush()
        out = await ingest_attestations(session, system_id=sys_.id, write=False)

    cov = out["coverage"]
    assert cov["baseline"] is None
    assert cov["baseline_total"] is None
    assert cov["in_baseline_pct"] is None
    assert cov["requirements_reached"], "the reached set is still measurable"
    assert cov["in_baseline"] == []


async def test_an_unavailable_read_probes_to_a_reason_not_a_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The state every organization here is in: nothing bound.

    A probe returning 0% with no reason is the output that makes an operator
    think the account is bad rather than the credential missing.
    """

    async def _none(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(ingest_mod, "_connector_for_org", _none)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        out = await ingest_attestations(session, system_id=sys_.id, write=False)

    assert out["available"] is False
    assert out["dry_run"] is True
    assert "not configured" in out["reason"]
    assert out["coverage"]["in_baseline_pct"] is None


async def test_the_real_ingest_still_reports_coverage_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not probe-only: the same measurement on the writing path, so a scheduled
    ingest records how much of the framework it reached rather than only how many
    rows it touched."""
    _patch(monkeypatch, _FINDINGS)
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "SC-07", "IA-02"])
        out = await ingest_attestations(session, system_id=sys_.id)

    assert out["dry_run"] is False
    assert out["coverage"]["in_baseline"] == ["AC-3", "IA-2", "SC-7"]
