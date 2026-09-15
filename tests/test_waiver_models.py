"""The waiver row, and the constraints that keep it meaningful."""

from __future__ import annotations

import itertools
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.models_waivers import Waiver

_SEQ = itertools.count()


async def _system(session) -> System:
    org = Organization(name=f"WaiverOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"WaiverSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


async def test_a_waiver_round_trips() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        w = Waiver(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            check_key="m365.identity.mfa_registered",
            rationale="Break-glass account is exempt by design; compensating control in place.",
            status="approved",
            requested_by="isso@acme.gov",
            approved_by="ao@acme.gov",
            approved_at=datetime.now(UTC),
            expires_on=date(2027, 1, 1),
            resource_id="breakglass@acme.gov",
        )
        session.add(w)
        await session.flush()
        got = (await session.execute(select(Waiver).where(Waiver.id == w.id))).scalar_one()
        assert got.check_key == "m365.identity.mfa_registered"
        assert got.resource_id == "breakglass@acme.gov"
        assert got.status == "approved"


async def test_status_defaults_to_requested() -> None:
    """A waiver must not arrive already in force."""
    async with session_scope() as session:
        sys_ = await _system(session)
        w = Waiver(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-2",
            rationale="pending review",
        )
        session.add(w)
        await session.flush()
        assert w.status == "requested"


async def test_a_waiver_targeting_neither_a_check_nor_a_control_is_rejected() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            Waiver(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                rationale="targets nothing",
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        # session_scope commits on exit; a poisoned session would fail there
        # and mask which assertion actually held.
        await session.rollback()


async def test_a_waiver_targeting_both_is_rejected() -> None:
    """Two scopes would mean the applied one depends on resolver order."""
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            Waiver(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                check_key="some.check",
                control_id="AC-2",
                rationale="targets both",
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        # session_scope commits on exit; a poisoned session would fail there
        # and mask which assertion actually held.
        await session.rollback()


async def test_an_unknown_status_is_rejected_by_the_database() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            Waiver(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                control_id="AC-2",
                rationale="r",
                status="accepted",  # KSIException's vocabulary, not a waiver's
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        # session_scope commits on exit; a poisoned session would fail there
        # and mask which assertion actually held.
        await session.rollback()


async def test_waived_defaults_to_zero_on_a_result() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        test = ControlTest(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-2",
            name="t",
            method="connector",
        )
        session.add(test)
        await session.flush()
        res = ControlTestResult(control_test_id=test.id, status="fail")
        session.add(res)
        await session.flush()
        assert res.waived == 0


async def test_deleting_a_waiver_keeps_the_evidence_it_accepted() -> None:
    """ON DELETE SET NULL, never CASCADE. The observation outlives the waiver."""
    async with session_scope() as session:
        sys_ = await _system(session)
        test = ControlTest(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-2",
            name="t",
            method="connector",
        )
        session.add(test)
        await session.flush()
        res = ControlTestResult(control_test_id=test.id, status="fail", failing=1, waived=1)
        session.add(res)
        w = Waiver(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            check_key="c",
            rationale="r",
            status="approved",
        )
        session.add(w)
        await session.flush()
        row = ControlTestResourceResult(
            result_id=res.id,
            resource_id="res-0",
            resource_type="entra_user",
            verdict="fail",
            observed="observed",
            waiver_id=w.id,
        )
        session.add(row)
        await session.flush()

        # Captured before expiring: reading row.id afterwards would trigger a
        # lazy refresh and raise MissingGreenlet inside the async session.
        row_id = row.id
        await session.execute(text("DELETE FROM ccf.waivers WHERE id = :i"), {"i": w.id})
        await session.flush()
        session.expire(row)
        kept = (
            await session.execute(
                select(ControlTestResourceResult).where(ControlTestResourceResult.id == row_id)
            )
        ).scalar_one()
        assert kept.verdict == "fail"
        assert kept.observed == "observed"
        assert kept.waiver_id is None
