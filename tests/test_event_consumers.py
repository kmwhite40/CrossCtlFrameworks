"""The consumer registry and scope resolution for the outbox worker.

``scope_org`` runs on an UNSCOPED session (the worker resolves the tenant
before it sets one), so these tests do too -- RLS would otherwise mask a
missing org filter.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from ccf.db import session_scope
from ccf.events import consumers
from ccf.events.consumers import Consumer, register, scope_org
from ccf.models import Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _noop(session, scope_key, job):  # type: ignore[no-untyped-def]
    return {}


def _consumer(name: str) -> Consumer:
    return Consumer(name=name, matches=lambda e, v: True, scope=lambda ev: None, run=_noop)


async def _mk(deleted_system: bool = False, deleted_org: bool = False) -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(
            name=f"cons-{tag}", deleted_at=datetime.now(UTC) if deleted_org else None
        )
        s.add(org)
        await s.flush()
        sysm = System(
            organization_id=org.id,
            name=f"cons {tag}",
            certification_class="C",
            deleted_at=datetime.now(UTC) if deleted_system else None,
        )
        s.add(sysm)
        await s.flush()
        ids = (org.id, sysm.id)
    return ids


async def test_scope_org_resolves_systems_and_orgs() -> None:
    org_id, sys_id = await _mk()
    async with session_scope() as s:
        assert await scope_org(s, f"system:{sys_id}") == org_id
        assert await scope_org(s, f"org:{org_id}") == org_id


async def test_scope_org_reports_a_deleted_system_as_gone() -> None:
    org_id, live_sys = await _mk()
    _, dead_sys = await _mk(deleted_system=True)
    async with session_scope() as s:
        assert await scope_org(s, f"system:{dead_sys}") == "gone"
        assert await scope_org(s, f"system:{live_sys}") == org_id  # positive control
        assert await scope_org(s, "system:999999999") == "gone"


async def test_scope_org_reports_a_deleted_or_missing_org_as_gone() -> None:
    live, _ = await _mk()
    dead, _ = await _mk(deleted_org=True)
    async with session_scope() as s:
        assert await scope_org(s, f"org:{dead}") == "gone"
        assert await scope_org(s, f"org:{live}") == live
        assert await scope_org(s, "org:999999999") == "gone"


async def test_scope_org_ignores_kinds_it_does_not_own_and_rejects_garbage() -> None:
    async with session_scope() as s:
        assert await scope_org(s, "event:5") is None
        for bad in (
            "garbage",
            "system:",
            "system:abc",
            "org:-",
            "",
            "system:1:2",
            "system:-5",
            "system: 5",
            "org:+5",
            "org:1_0",
        ):
            with pytest.raises(ValueError):
                await scope_org(s, bad)


def test_register_refuses_a_duplicate_name() -> None:
    name = f"dup-{uuid.uuid4().hex[:6]}"
    c = _consumer(name)
    try:
        assert register(c) is c
        assert consumers.REGISTRY[name] is c
        with pytest.raises(ValueError):
            register(_consumer(name))
        assert consumers.REGISTRY[name] is c  # the first one survives
    finally:
        consumers.REGISTRY.pop(name, None)
