"""Posture schema: widened vocabulary, provenance, and two-hop tenancy."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult

_SEQ = itertools.count()


async def _test_row(session, *, check_key: str | None = None, source: str = "authored"):
    org = Organization(name=f"PostOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"PostSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    t = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="AC-3",
        name="demo",
        method="connector",
        source=source,
        check_key=check_key,
    )
    session.add(t)
    await session.flush()
    return org, sys_, t


async def test_status_accepts_the_widened_vocabulary() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        session.add(
            ControlTestResult(
                control_test_id=t.id, status="manual_review_required", detail="needs a human"
            )
        )
        await session.flush()  # varchar(8) would have rejected this


async def test_legacy_statuses_still_round_trip() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        for status in ("pass", "warn", "fail"):
            session.add(ControlTestResult(control_test_id=t.id, status=status))
        await session.flush()


async def test_source_defaults_to_authored() -> None:
    """Every pre-existing row must read as authored, not generated."""
    async with session_scope() as session:
        org = Organization(name=f"PostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        t = ControlTest(organization_id=org.id, control_id="AC-3", name="bare")
        session.add(t)
        await session.flush()
        assert t.source == "authored"


async def test_generated_check_key_is_unique_per_system() -> None:
    async with session_scope() as session:
        org, sys_, _ = await _test_row(session, check_key="aws.s3.block", source="generated")
        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id="AC-3",
                name="dup",
                source="generated",
                check_key="aws.s3.block",
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_authored_tests_are_not_constrained_by_check_key() -> None:
    """check_key is null for authored tests, and Postgres treats nulls as
    distinct -- so any number may coexist for one system."""
    async with session_scope() as session:
        org, sys_, _ = await _test_row(session)
        for n in range(3):
            session.add(
                ControlTest(
                    organization_id=org.id,
                    system_id=sys_.id,
                    control_id="AC-3",
                    name=f"authored-{n}",
                )
            )
        await session.flush()


async def test_resource_results_attach_to_a_result() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        r = ControlTestResult(control_test_id=t.id, status="fail", evaluated=47, failing=3)
        session.add(r)
        await session.flush()
        for i in range(3):
            session.add(
                ControlTestResourceResult(
                    result_id=r.id,
                    resource_id=f"arn:aws:s3:::bucket-{i}",
                    resource_type="s3_bucket",
                    verdict="fail",
                    observed="public access allowed",
                )
            )
        await session.flush()
        rows = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == r.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3
        assert r.evaluated == 47 and r.failing == 3


async def test_resource_results_have_a_two_hop_tenant_policy() -> None:
    """No organization_id column -- scoped through control_tests, like
    control_test_results and poam_milestones."""
    async with session_scope() as session:
        has_org = (
            await session.execute(
                text(
                    "SELECT EXISTS(SELECT 1 FROM information_schema.columns "
                    "WHERE table_schema='ccf' "
                    "AND table_name='control_test_resource_results' "
                    "AND column_name='organization_id')"
                )
            )
        ).scalar()
        assert has_org is False

        policied = (
            await session.execute(
                text(
                    "SELECT EXISTS(SELECT 1 FROM pg_policy p "
                    "JOIN pg_class c ON c.oid = p.polrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname='ccf' AND p.polname='tenant_isolation' "
                    "AND c.relname='control_test_resource_results')"
                )
            )
        ).scalar()
        assert policied is True


async def test_deleting_a_result_cascades_its_resources() -> None:
    async with session_scope() as session:
        _, _, t = await _test_row(session)
        r = ControlTestResult(control_test_id=t.id, status="fail")
        session.add(r)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=r.id, resource_id="x", resource_type="y", verdict="fail", observed="z"
            )
        )
        await session.flush()
        rid = r.id
        await session.delete(r)
        await session.flush()
        left = (
            await session.execute(
                select(ControlTestResourceResult).where(
                    ControlTestResourceResult.result_id == rid
                )
            )
        ).scalars().all()
        assert left == []
