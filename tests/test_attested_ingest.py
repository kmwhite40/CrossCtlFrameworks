"""Landing provider attestations on the existing spine, and what must not land.

The ingest writes ``ControlTest`` + ``ControlTestResult`` rows through
``governance.control_tests.record_result`` -- the only writer of results -- so
attested evidence reaches the posture rollups, the SSP and the drilldown by the
same path a posture scan does. No parallel store, no second rollup.

Two things it must refuse:

**A partial account.** A read that is not ``available`` (standard off, standard
not ``READY``, a refusal, a truncated page walk) writes nothing. Writing the
part that was read would overwrite last week's complete assessment with three
pages of this week's, and nothing downstream could tell.

**A remediation queue fan-out.** One Security Hub control relating to three
requirements is three rows by construction -- that split is what stops one
automated check crediting three controls. But the shared writer opens a
notification, a remediation Task and a POA&M for every failing row, so identical
behaviour here would file three weaknesses for one misconfigured bucket. An
assessor reading that POA&M list sees three times the work that exists. Attested
rows therefore record evidence only; the remediation queue stays fed by
Concord's own checks and by scanner ingest, which already group by finding.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from sqlalchemy import func, select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import POAM, Organization, System, Task
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture import attested_scan as ingest_mod
from ccf.posture.attested import (
    CHECK_SOURCE,
    NIST_80053_R5_STANDARD_ID,
    REQUIREMENT_PREFIX,
    attested_controls,
)
from ccf.posture.attested_scan import ingest_attestations

_SEQ = itertools.count()


def _finding(
    control_id: str,
    status: str,
    *,
    related: list[str],
    resource: str = "r1",
) -> dict[str, Any]:
    return {
        "Id": f"{control_id}/{resource}",
        "Title": f"{control_id} title",
        "Compliance": {
            "Status": status,
            "SecurityControlId": control_id,
            "RelatedRequirements": related,
            "AssociatedStandards": [{"StandardsId": NIST_80053_R5_STANDARD_ID}],
        },
    }


class _StubConnector:
    """Answers ``securityhub_attestations`` with a canned result."""

    key = "aws_govcloud"

    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result
        self.calls = 0

    def is_configured(self) -> bool:
        return True

    async def securityhub_attestations(self, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return self._result


def _available(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """A result shaped exactly as the connector returns one.

    Built by calling the real pure layer rather than hand-writing controls, so a
    change to ``attested_controls``' output shape breaks here instead of being
    papered over by a fixture that drifted from it.
    """
    controls = attested_controls(findings)
    unreadable: list[str] = []
    for c in controls:
        for entry in c.unreadable_requirements:
            if entry not in unreadable:
                unreadable.append(entry)
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


def _unavailable(reason: str, *, truncated: bool = False) -> dict[str, Any]:
    return {
        "available": False,
        "reason": reason,
        "controls": (),
        "unreadable_requirements": [],
        "pages_read": 0,
        "truncated": truncated,
        "region": "us-gov-west-1",
        "account_id": "123456789012",
        "standard_id": NIST_80053_R5_STANDARD_ID,
    }


def _patch(monkeypatch: pytest.MonkeyPatch, conn: _StubConnector | None) -> None:
    async def _fake(*a: object, **k: object) -> _StubConnector | None:
        return conn

    monkeypatch.setattr(ingest_mod, "_connector_for_org", _fake)
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()


async def _system(session: Any) -> System:
    n = next(_SEQ)
    org = Organization(name=f"AttestedOrg{n}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"AttestedSys{n}")
    session.add(sys_)
    await session.flush()
    return sys_


async def _tests_for(session: Any, system_id: int) -> list[ControlTest]:
    return list(
        (
            await session.execute(
                select(ControlTest)
                .where(ControlTest.system_id == system_id)
                .order_by(ControlTest.check_key)
            )
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------
# The happy path, and the shape of what lands
# --------------------------------------------------------------------------


async def test_each_requirement_becomes_its_own_control_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _StubConnector(
        _available(
            [
                _finding(
                    "S3.8",
                    "PASSED",
                    related=[
                        f"{REQUIREMENT_PREFIX} AC-3",
                        f"{REQUIREMENT_PREFIX} SC-7",
                    ],
                )
            ]
        )
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_attestations(session, system_id=sys_.id)
        tests = await _tests_for(session, sys_.id)

    assert out["written"] == 2
    assert [t.check_key for t in tests] == [
        "aws.securityhub.S3.8::AC-3",
        "aws.securityhub.S3.8::SC-7",
    ]
    assert [t.control_id for t in tests] == ["AC-3", "SC-7"]
    assert [t.control_ids for t in tests] == [["AC-3"], ["SC-7"]]


async def test_the_rows_are_labelled_as_provider_attested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``check_source`` is what an assessor reads to tell who asserted this, and
    what ``trust_tier`` reads to rank it."""
    conn = _StubConnector(
        _available([_finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_attestations(session, system_id=sys_.id)
        (test,) = await _tests_for(session, sys_.id)

    assert test.check_source == CHECK_SOURCE
    assert test.source == "generated"
    assert test.method == "connector"
    assert test.connector_type == "aws_govcloud"


async def test_the_verdict_is_recorded_as_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _StubConnector(
        _available([_finding("IAM.4", "FAILED", related=[f"{REQUIREMENT_PREFIX} IA-2"])])
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_attestations(session, system_id=sys_.id)
        (test,) = await _tests_for(session, sys_.id)
        results = (
            await session.execute(
                select(ControlTestResult).where(
                    ControlTestResult.control_test_id == test.id
                )
            )
        ).scalars().all()

    assert test.last_status == "fail"
    assert len(results) == 1
    assert results[0].status == "fail"


async def test_a_second_ingest_updates_rather_than_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``(system_id, check_key)`` is unique, and the keys are deterministic, so
    re-ingest is an update. Without this a nightly ingest multiplies every row."""
    conn = _StubConnector(
        _available([_finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_attestations(session, system_id=sys_.id)
        await ingest_attestations(session, system_id=sys_.id)
        tests = await _tests_for(session, sys_.id)
        results = (
            await session.execute(
                select(func.count())
                .select_from(ControlTestResult)
                .where(ControlTestResult.control_test_id == tests[0].id)
            )
        ).scalar_one()

    assert len(tests) == 1, "re-ingest duplicated the control test"
    assert results == 2, "each ingest must record its own result, for history"


async def test_a_verdict_that_changed_is_the_one_stored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The row carries today's verdict, not the one it was created with."""
    _patch(
        monkeypatch,
        _StubConnector(
            _available([_finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
        ),
    )
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_attestations(session, system_id=sys_.id)
        _patch(
            monkeypatch,
            _StubConnector(
                _available(
                    [_finding("S3.8", "FAILED", related=[f"{REQUIREMENT_PREFIX} AC-3"])]
                )
            ),
        )
        await ingest_attestations(session, system_id=sys_.id)
        (test,) = await _tests_for(session, sys_.id)

    assert test.last_status == "fail"


# --------------------------------------------------------------------------
# What must not land
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "truncated"),
    [
        ("the NIST SP 800-53 Rev 5 standard is not enabled in Security Hub", False),
        ("AccessDeniedException: could not read Security Hub", False),
        ("the findings read was truncated after 60 pages", True),
    ],
)
async def test_an_unavailable_read_writes_nothing(
    reason: str, truncated: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Including the truncated case, which is the one that looks like data.

    Writing the part that was read would overwrite a complete assessment with a
    prefix of the next one, and nothing downstream could tell the difference.
    """
    _patch(monkeypatch, _StubConnector(_unavailable(reason, truncated=truncated)))
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_attestations(session, system_id=sys_.id)
        tests = await _tests_for(session, sys_.id)

    assert tests == []
    assert out["written"] == 0
    assert out["available"] is False
    assert out["reason"] == reason


async def test_an_unavailable_read_leaves_an_earlier_assessment_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Last week's complete read stays as it is, and staleness -- not deletion --
    is what eventually stops it being believed (``STALE_AFTER_DAYS``)."""
    _patch(
        monkeypatch,
        _StubConnector(
            _available([_finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
        ),
    )
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_attestations(session, system_id=sys_.id)
        _patch(monkeypatch, _StubConnector(_unavailable("ThrottlingException", truncated=True)))
        await ingest_attestations(session, system_id=sys_.id)
        tests = await _tests_for(session, sys_.id)

    assert len(tests) == 1
    assert tests[0].last_status == "pass"


async def test_no_connector_configured_is_reported_not_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, None)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_attestations(session, system_id=sys_.id)

    assert out["available"] is False
    assert out["written"] == 0
    assert "not configured" in out["reason"].lower()


async def test_an_unknown_system_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, None)
    async with session_scope() as session:
        with pytest.raises(ValueError, match="unknown system"):
            await ingest_attestations(session, system_id=-1)


# --------------------------------------------------------------------------
# The remediation fan-out, which is the thing most likely to be got wrong
# --------------------------------------------------------------------------


async def test_a_failing_attestation_opens_no_poam_or_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One misconfigured bucket is one weakness, not three.

    S3.8 failing relates to AC-3, AC-4 and SC-7, so it is three rows -- the
    split that stops one automated check crediting three controls. The shared
    writer opens a Task and a POA&M per failing row, so inheriting that
    behaviour files three weaknesses for one finding and an assessor reads three
    times the work that exists.

    Attested rows are coverage evidence. The remediation queue stays fed by
    Concord's own checks and by scanner ingest, both of which group by finding.
    """
    conn = _StubConnector(
        _available(
            [
                _finding(
                    "S3.8",
                    "FAILED",
                    related=[
                        f"{REQUIREMENT_PREFIX} AC-3",
                        f"{REQUIREMENT_PREFIX} AC-4",
                        f"{REQUIREMENT_PREFIX} SC-7",
                    ],
                )
            ]
        )
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_attestations(session, system_id=sys_.id)
        tests = await _tests_for(session, sys_.id)
        poams = (
            await session.execute(select(POAM).where(POAM.system_id == sys_.id))
        ).scalars().all()
        tasks = (
            await session.execute(select(Task).where(Task.system_id == sys_.id))
        ).scalars().all()

    assert out["written"] == 3
    assert len(tests) == 3
    assert [t.last_status for t in tests] == ["fail", "fail", "fail"], (
        "the verdict must still be recorded -- suppressing the queue must not "
        "suppress the evidence"
    )
    assert poams == [], f"{len(poams)} POA&Ms opened for one Security Hub finding"
    assert tasks == [], f"{len(tasks)} remediation tasks opened for one finding"


async def test_concord_s_own_failing_check_still_opens_a_poam() -> None:
    """The other half of the flag: suppression is per-call, not global.

    If this were turned off everywhere, the posture scan would stop opening
    POA&Ms and the loss would be invisible until somebody noticed an empty
    remediation queue.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        test = ControlTest(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-3",
            name="Concord's own check",
            method="connector",
            source="generated",
            check_key="aws.s3.public_access_blocked",
            check_source="platform",
        )
        session.add(test)
        await session.flush()
        await record_result(session, test, status="fail", detail="a bucket is public")
        poams = (
            await session.execute(select(POAM).where(POAM.system_id == sys_.id))
        ).scalars().all()

    assert len(poams) == 1


# --------------------------------------------------------------------------
# What the report says
# --------------------------------------------------------------------------


async def test_the_report_names_what_could_not_be_attributed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coverage AWS published that Concord could not place must be countable.

    Otherwise the only way to notice that a third of AWS's mapping is being
    dropped is to compare totals against the console by hand.
    """
    conn = _StubConnector(
        _available(
            [
                _finding("IAM.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-2(j)"]),
                _finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"]),
            ]
        )
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_attestations(session, system_id=sys_.id)

    assert out["controls_read"] == 2
    assert out["written"] == 1
    assert out["unreadable_requirements"] == [f"{REQUIREMENT_PREFIX} AC-2(j)"]
    assert out["controls_without_a_requirement"] == ["IAM.8"]


async def test_the_report_names_the_account_and_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _StubConnector(
        _available([_finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await ingest_attestations(session, system_id=sys_.id)

    assert out["region"] == "us-gov-west-1"
    assert out["account_id"] == "123456789012"


async def test_the_rows_belong_to_the_system_s_own_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``organization_id`` is what RLS and every org predicate filter on. A row
    written under the wrong org is a cross-tenant leak."""
    conn = _StubConnector(
        _available([_finding("S3.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        other = Organization(name=f"OtherOrg{next(_SEQ)}")
        session.add(other)
        await session.flush()
        await ingest_attestations(session, system_id=sys_.id)
        (test,) = await _tests_for(session, sys_.id)

    assert test.organization_id == sys_.organization_id
    assert test.organization_id != other.id


async def test_a_human_deactivated_row_stops_being_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deactivation has to actually stop validation.

    Setting ``active = False`` on a generated test is a supported human edit --
    ``_upsert_generated_test`` preserves it across re-scans precisely so it
    survives. A field that is preserved and then ignored is worse than no field:
    the operator believes they switched something off, and every ingest keeps
    recording results against it.

    Found by mutation: removing the ``active`` check left all sixteen tests in
    this file passing, because none of them ever deactivated a row.
    """
    conn = _StubConnector(
        _available([_finding("S3.8", "FAILED", related=[f"{REQUIREMENT_PREFIX} AC-3"])])
    )
    _patch(monkeypatch, conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        await ingest_attestations(session, system_id=sys_.id)
        (test,) = await _tests_for(session, sys_.id)
        test.active = False
        test.last_status = "fail"
        await session.flush()
        before = (
            await session.execute(
                select(func.count())
                .select_from(ControlTestResult)
                .where(ControlTestResult.control_test_id == test.id)
            )
        ).scalar_one()

        out = await ingest_attestations(session, system_id=sys_.id)

        after = (
            await session.execute(
                select(func.count())
                .select_from(ControlTestResult)
                .where(ControlTestResult.control_test_id == test.id)
            )
        ).scalar_one()

    assert after == before, "a deactivated test still recorded a result"
    assert out["written"] == 0
