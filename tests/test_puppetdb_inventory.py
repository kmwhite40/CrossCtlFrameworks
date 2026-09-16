"""Syncing PuppetDB nodes into the component inventory -- additively."""

from __future__ import annotations

import itertools
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from ccf.connectors import puppetdb as puppetdb_mod
from ccf.connectors.puppetdb import PuppetDbConnector, sync_inventory
from ccf.db import session_scope
from ccf.models import InventoryItem, Organization, System

_SEQ = itertools.count()
CRED = {"base_url": "https://puppetdb.acme.gov:8081"}


def _node(certname: str, *, status: str = "unchanged") -> dict[str, Any]:
    return {
        "certname": certname,
        "report_timestamp": "2026-09-15T11:30:00Z",
        "latest_report_status": status,
    }


class _Fake:
    def __init__(self, nodes: list[dict], facts: list[dict]) -> None:
        self.nodes = nodes
        self.facts = facts

    async def __aenter__(self) -> _Fake:
        return self

    async def __aexit__(self, *a: object) -> None:
        return None

    async def get(self, url: str, headers: dict, params: dict | None = None) -> httpx.Response:
        body = self.facts if "/facts" in url else self.nodes
        return httpx.Response(200, json=body, request=httpx.Request("GET", url))


def _patch(monkeypatch: pytest.MonkeyPatch, fake: _Fake) -> None:
    monkeypatch.setattr(puppetdb_mod.httpx, "AsyncClient", lambda **k: fake)


def _facts(certname: str, **kw: Any) -> list[dict]:
    return [{"certname": certname, "name": k, "value": v} for k, v in kw.items()]


async def _system(session) -> System:
    org = Organization(name=f"PdbOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"PdbSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


async def _items(session, system_id: int) -> list[InventoryItem]:
    return list(
        (
            await session.execute(
                select(InventoryItem)
                .where(InventoryItem.system_id == system_id)
                .order_by(InventoryItem.asset_id)
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_a_node_becomes_an_inventory_item(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake(
        [_node("web01.acme.gov")],
        _facts("web01.acme.gov", os="RedHat", ipaddress="10.0.0.5",
               operatingsystemrelease="9.4", virtual="kvm"),
    )
    _patch(monkeypatch, fake)
    async with session_scope() as session:
        sys_ = await _system(session)
        conn = PuppetDbConnector(credential=CRED)
        out = await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        assert out == {"seen": 1, "created": 1, "updated": 0}
        (item,) = await _items(session, sys_.id)
        assert item.asset_id == "web01.acme.gov"
        assert item.hostname == "web01.acme.gov"
        assert item.ip_address == "10.0.0.5"
        assert item.version == "9.4"
        assert item.source == "puppetdb"
        assert item.last_seen_at is not None
        assert item.props["os"] == "RedHat"
        assert item.virtual is True


@pytest.mark.asyncio
async def test_a_physical_node_is_not_marked_virtual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _Fake([_node("bare01")], _facts("bare01", virtual="physical"))
    _patch(monkeypatch, fake)
    async with session_scope() as session:
        sys_ = await _system(session)
        await sync_inventory(
            session, PuppetDbConnector(credential=CRED),
            system_id=sys_.id, org_id=sys_.organization_id,
        )
        (item,) = await _items(session, sys_.id)
        assert item.virtual is False


@pytest.mark.asyncio
async def test_syncing_twice_yields_one_row(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _Fake([_node("web01")], _facts("web01", os="RedHat"))
    _patch(monkeypatch, fake)
    async with session_scope() as session:
        sys_ = await _system(session)
        conn = PuppetDbConnector(credential=CRED)
        first = await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        second = await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        assert first["created"] == 1
        assert second == {"seen": 1, "created": 0, "updated": 1}
        assert len(await _items(session, sys_.id)) == 1


@pytest.mark.asyncio
async def test_a_changed_fact_updates_rather_than_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        conn = PuppetDbConnector(credential=CRED)
        _patch(monkeypatch, _Fake([_node("web01")], _facts("web01", ipaddress="10.0.0.5")))
        await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        _patch(monkeypatch, _Fake([_node("web01")], _facts("web01", ipaddress="10.0.0.9")))
        await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        (item,) = await _items(session, sys_.id)
        assert item.ip_address == "10.0.0.9"


@pytest.mark.asyncio
async def test_a_vanished_node_is_kept_with_its_old_last_seen_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence is not removal. A node missing from a query was decommissioned,
    moved out of scope, or the query truncated -- indistinguishable at the API
    boundary. last_seen_at going cold IS the signal, and deleting the row
    would destroy it."""
    async with session_scope() as session:
        sys_ = await _system(session)
        conn = PuppetDbConnector(credential=CRED)
        _patch(
            monkeypatch,
            _Fake([_node("keeper"), _node("goner")], _facts("keeper", os="RedHat")),
        )
        await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        before = {i.asset_id: i.last_seen_at for i in await _items(session, sys_.id)}
        assert set(before) == {"goner", "keeper"}

        # "goner" disappears from the query.
        _patch(monkeypatch, _Fake([_node("keeper")], _facts("keeper", os="RedHat")))
        out = await sync_inventory(
            session, conn, system_id=sys_.id, org_id=sys_.organization_id
        )
        assert out["seen"] == 1
        after = {i.asset_id: i.last_seen_at for i in await _items(session, sys_.id)}
        assert set(after) == {"goner", "keeper"}, "a vanished node must not be deleted"
        assert after["goner"] == before["goner"], "its last_seen_at must go cold"
        assert after["keeper"] >= before["keeper"]


@pytest.mark.asyncio
async def test_a_manually_created_item_is_not_clobbered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A human's row for the same asset keeps its own source and description --
    the discipline _upsert_generated_test applies to human-edited fields."""
    fake = _Fake([_node("web01")], _facts("web01", os="RedHat"))
    _patch(monkeypatch, fake)
    async with session_scope() as session:
        sys_ = await _system(session)
        session.add(
            InventoryItem(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                asset_id="web01",
                asset_type="hardware",
                description="Primary web tier, documented in the SSP",
                source="manual",
            )
        )
        await session.flush()
        await sync_inventory(
            session, PuppetDbConnector(credential=CRED),
            system_id=sys_.id, org_id=sys_.organization_id,
        )
        (item,) = await _items(session, sys_.id)
        assert item.source == "manual", "a human's provenance is not overwritten"
        assert item.description == "Primary web tier, documented in the SSP"
        # But the machine-observed facts are refreshed.
        assert item.props["os"] == "RedHat"
        assert item.last_seen_at is not None


@pytest.mark.asyncio
async def test_another_systems_inventory_is_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two systems with a node of the same name; the match is per system."""
    fake = _Fake([_node("shared01")], _facts("shared01", os="RedHat"))
    _patch(monkeypatch, fake)
    async with session_scope() as session:
        mine = await _system(session)
        theirs = await _system(session)
        session.add(
            InventoryItem(
                organization_id=theirs.organization_id,
                system_id=theirs.id,
                asset_id="shared01",
                asset_type="hardware",
                source="manual",
            )
        )
        await session.flush()
        out = await sync_inventory(
            session, PuppetDbConnector(credential=CRED),
            system_id=mine.id, org_id=mine.organization_id,
        )
        assert out == {"seen": 1, "created": 1, "updated": 0}
        (theirs_item,) = await _items(session, theirs.id)
        assert theirs_item.source == "manual"
        assert theirs_item.last_seen_at is None, "the other system was not synced"


@pytest.mark.asyncio
async def test_an_unconfigured_connector_syncs_nothing() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await sync_inventory(
            session, PuppetDbConnector(), system_id=sys_.id, org_id=sys_.organization_id
        )
        assert out == {"seen": 0, "created": 0, "updated": 0}
        assert await _items(session, sys_.id) == []


@pytest.mark.asyncio
async def test_a_node_with_no_certname_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An inventory row keyed on nothing cannot be matched on a later sync, so
    it would duplicate forever."""
    fake = _Fake([{"report_timestamp": "2026-09-15T11:30:00Z"}], [])
    _patch(monkeypatch, fake)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await sync_inventory(
            session, PuppetDbConnector(credential=CRED),
            system_id=sys_.id, org_id=sys_.organization_id,
        )
        assert out == {"seen": 0, "created": 0, "updated": 0}
        assert await _items(session, sys_.id) == []
