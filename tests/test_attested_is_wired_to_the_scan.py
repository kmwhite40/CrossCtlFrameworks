"""The attestation ingest has to run on the path people and the scheduler use.

A feature reachable only from a route nobody calls is a feature that does not
exist. ``scan_all_providers`` is the end-user path (``POST
/systems/{id}/scan-all``) *and* the scheduler's path, so the ingest runs there --
which is also what makes attested verdicts refresh on their own rather than
sitting at whatever date somebody last clicked.

Two properties the wiring must not break:

**Containment.** The provider loop's comment says it plainly: one provider's
failure must not discard the providers that worked, and the rollback in that
path is load-bearing rather than tidy. The ingest runs after that loop, before
the commit, so a bare ``session.rollback()`` on an ingest failure would throw
away every scan the loop just recorded. It runs in a SAVEPOINT instead.

**Honesty about not running.** An organization with no AWS credential -- which is
every organization in this deployment today -- must see a reason, not an absent
key. "No attestations" and "the standard is off" and "we never looked" are three
different facts.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest
from ccf.posture import attested_scan as ingest_mod
from ccf.posture import scan_all as scan_all_mod
from ccf.posture.attested import (
    CHECK_SOURCE,
    NIST_80053_R5_STANDARD_ID,
    attested_controls,
)
from ccf.posture.scan_all import scan_all_providers

_SEQ = itertools.count()


async def _system(session: Any) -> System:
    n = next(_SEQ)
    org = Organization(name=f"WiredOrg{n}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"WiredSys{n}")
    session.add(sys_)
    await session.flush()
    return sys_


def _quiet_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """No posture providers, so these tests measure only the ingest step.

    The provider loop has its own tests; running it here would make every
    assertion below depend on fourteen connectors' readiness.
    """
    monkeypatch.setattr(scan_all_mod, "known_providers", set)


def _ingest(monkeypatch: pytest.MonkeyPatch, result: Any) -> dict[str, int]:
    """Replace the ingest with a double; ``result`` may be an exception."""
    calls = {"n": 0}

    async def _fake(session: object, **kwargs: object) -> dict[str, Any]:
        calls["n"] += 1
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(scan_all_mod, "ingest_attestations", _fake)
    return calls


def _report(**over: Any) -> dict[str, Any]:
    base = {
        "system_id": 0,
        "connector": "aws_govcloud",
        "available": True,
        "reason": None,
        "written": 4,
        "controls_read": 2,
        "controls_without_a_requirement": [],
        "unreadable_requirements": [],
        "region": "us-gov-west-1",
        "account_id": "123456789012",
        "pages_read": 1,
        "truncated": False,
    }
    return {**base, **over}


async def test_the_ingest_runs_on_the_scan_all_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _quiet_providers(monkeypatch)
    calls = _ingest(monkeypatch, _report())
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )

    assert calls["n"] == 1
    assert out["attestations"]["written"] == 4


async def test_the_summary_says_when_nothing_was_attested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every organization here is in this state: no AWS credential bound.

    An absent key renders as nothing and reads as "no problem"; a reason reads as
    a thing to go and configure.
    """
    _quiet_providers(monkeypatch)
    _ingest(
        monkeypatch,
        _report(
            available=False,
            written=0,
            controls_read=0,
            reason="the aws_govcloud connector is not configured for this organization",
        ),
    )
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )

    assert out["attestations"]["available"] is False
    assert out["attestations"]["written"] == 0
    assert "not configured" in out["attestations"]["reason"]


async def test_an_ingest_failure_does_not_discard_the_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The containment property, driven rather than asserted.

    A row is written before the ingest runs and must survive the ingest blowing
    up. A bare ``session.rollback()`` in that handler -- the obvious thing to
    write, and what the provider loop legitimately does because it runs *before*
    anything is committed -- would take this row with it.
    """
    _quiet_providers(monkeypatch)
    _ingest(monkeypatch, RuntimeError("boto3 exploded"))
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            ControlTest(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                control_id="AC-3",
                name="recorded before the ingest",
                method="connector",
                source="generated",
                check_key="aws.s3.public_access_blocked",
                check_source="platform",
                last_status="pass",
            )
        )
        await session.flush()
        out = await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )
        survivors = (
            await session.execute(
                select(ControlTest.check_key).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()

    assert list(survivors) == ["aws.s3.public_access_blocked"], (
        "the ingest's failure discarded a scan result recorded before it"
    )
    assert out["attestations"]["available"] is False
    assert "RuntimeError" in out["attestations"]["reason"]
    assert out["attestations"]["written"] == 0


async def test_an_ingest_failure_leaves_the_session_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed flush aborts the transaction unless it is savepoint-scoped.

    ``record_result``'s waiver block documents this: ``AsyncSession.rollback()``
    is not savepoint-scoped, so an unguarded database error partway through
    leaves the *outer* transaction aborted and takes everything down on the
    caller's eventual commit. This writes after the failure to prove the session
    is still usable.
    """
    _quiet_providers(monkeypatch)
    _ingest(monkeypatch, RuntimeError("boto3 exploded"))
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )
        session.add(
            ControlTest(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                control_id="AU-2",
                name="written after the failure",
                method="connector",
                source="generated",
                check_key="aws.cloudtrail.multi_region_logging",
                check_source="platform",
                last_status="pass",
            )
        )
        await session.flush()
        keys = (
            await session.execute(
                select(ControlTest.check_key).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()

    assert "aws.cloudtrail.multi_region_logging" in keys


async def test_the_real_ingest_is_the_one_that_is_wired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every test above replaces the ingest, so one must not.

    Without this, ``scan_all`` could import a function that does not exist, or a
    different one, and the doubles would never notice. The connector resolves to
    None here (no credential bound), so the real ingest runs its real
    "not configured" path end to end.
    """
    _quiet_providers(monkeypatch)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )

    assert out["attestations"]["connector"] == "aws_govcloud"
    assert out["attestations"]["available"] is False
    assert "not configured" in out["attestations"]["reason"]


async def test_a_successful_ingest_writes_rows_reachable_from_the_posture_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end through the real ingest, with only the AWS API stubbed.

    This is the assertion that the pieces are connected: a Security Hub finding
    goes in at the connector seam and a ``ControlTest`` labelled as attested comes
    out, by the same path a posture scan's evidence takes.
    """
    controls = attested_controls(
        [
            {
                "Id": "S3.8/bucket",
                "Title": "S3 buckets should block public access",
                "Compliance": {
                    "Status": "PASSED",
                    "SecurityControlId": "S3.8",
                    "RelatedRequirements": ["NIST.800-53.r5 AC-3"],
                    "AssociatedStandards": [{"StandardsId": NIST_80053_R5_STANDARD_ID}],
                },
            }
        ]
    )

    async def _attestations(**kwargs: object) -> dict[str, Any]:
        return {
            "available": True,
            "reason": None,
            "controls": controls,
            "unreadable_requirements": [],
            "pages_read": 1,
            "truncated": False,
            "region": "us-gov-west-1",
            "account_id": "123456789012",
            "standard_id": NIST_80053_R5_STANDARD_ID,
        }

    async def _conn(*a: object, **k: object) -> object:
        return SimpleNamespace(
            key="aws_govcloud",
            is_configured=lambda: True,
            securityhub_attestations=_attestations,
        )

    _quiet_providers(monkeypatch)
    monkeypatch.setattr(ingest_mod, "_connector_for_org", _conn)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )
        rows = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()

    assert out["attestations"]["written"] == 1
    assert [r.check_key for r in rows] == ["aws.securityhub.S3.8::AC-3"]
    assert rows[0].check_source == CHECK_SOURCE
    assert rows[0].control_id == "AC-3"
    assert rows[0].last_status == "pass"


async def test_a_failed_flush_inside_the_ingest_does_not_abort_the_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why the SAVEPOINT is there rather than a plain try/except.

    Found by mutation: removing ``begin_nested`` entirely passed every other test
    in this file, because the doubles all raise a plain Python exception before
    touching the database -- and a plain exception does not abort a Postgres
    transaction. A *database* error does. Without the savepoint, an
    ``IntegrityError`` partway through the ingest leaves the outer transaction
    aborted, every later statement fails with "current transaction is aborted",
    and the caller's commit takes down every scan result the provider loop
    recorded.

    This double writes a row that violates NOT NULL and flushes, which is the
    realistic shape of the failure: the ingest writes many rows, and one of them
    going wrong must not cost the rest of the scan.
    """
    async def _fake(session: Any, **kwargs: object) -> dict[str, Any]:
        session.add(ControlTest(control_id=None, name=None, method="connector"))
        await session.flush()
        return _report()

    _quiet_providers(monkeypatch)
    monkeypatch.setattr(scan_all_mod, "ingest_attestations", _fake)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_all_providers(
            session, system_id=sys_.id, organization_id=sys_.organization_id, commit=False
        )
        # The session must still be usable: this is the statement that fails with
        # "current transaction is aborted" when the savepoint is gone.
        session.add(
            ControlTest(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                control_id="AU-2",
                name="written after a failed flush",
                method="connector",
                source="generated",
                check_key="aws.cloudtrail.multi_region_logging",
                check_source="platform",
                last_status="pass",
            )
        )
        await session.flush()
        keys = (
            await session.execute(
                select(ControlTest.check_key).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()

    assert "aws.cloudtrail.multi_region_logging" in keys
    assert out["attestations"]["available"] is False
