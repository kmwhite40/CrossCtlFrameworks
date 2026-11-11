"""AWS Organizations -> boundary inventory."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.connectors import credentials as connector_credentials
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.connectors.aws_inventory import sync_organization_inventory
from ccf.db import session_scope
from ccf.models import InventoryItem, Organization, System, SystemComponent, User
from ccf.models_grc import ConnectorConfig

pytestmark = pytest.mark.usefixtures("fresh_engine")

ORG_ARN = "arn:aws-us-gov:organizations::111111111111:organization/o-abc"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _Denied(Exception):  # noqa: N818 -- mirrors botocore's ClientError shape
    response = {"Error": {"Code": "AccessDeniedException"}}  # noqa: RUF012


def _org_session(*, deny: bool = False, accounts: dict[str, list[dict[str, Any]]] | None = None,
                 ous: dict[str, list[dict[str, Any]]] | None = None) -> Any:
    accounts = accounts if accounts is not None else {
        "r-1": [{"Id": "111111111111", "Name": "mgmt", "Status": "ACTIVE",
                 "Email": "root@corp.example", "Arn": "arn:aws-us-gov:organizations::1:account/x"}],
        "ou-a": [{"Id": "222222222222", "Name": "prod", "Status": "ACTIVE",
                  "Email": "prod@corp.example", "Arn": "arn:aws:organizations::1:account/y"}],
    }
    ous = ous if ous is not None else {"r-1": [{"Id": "ou-a", "Name": "Workloads"}]}

    class _Pager:
        def __init__(self, op: str) -> None:
            self.op = op

        def paginate(self, **kw: Any) -> list[dict[str, Any]]:
            if self.op == "list_roots":
                return [{"Roots": [{"Id": "r-1"}]}]
            if self.op == "list_accounts_for_parent":
                return [{"Accounts": accounts.get(kw["ParentId"], [])}]
            return [{"OrganizationalUnits": ous.get(kw["ParentId"], [])}]

    class _Org:
        def describe_organization(self) -> dict[str, Any]:
            if deny:
                raise _Denied()
            return {"Organization": {"Id": "o-abc", "Arn": ORG_ARN,
                                     "MasterAccountId": "111111111111", "FeatureSet": "ALL"}}

        def get_paginator(self, op: str) -> _Pager:
            return _Pager(op)

    class _S:
        def client(self, name: str, region_name: str | None = None) -> Any:
            return _Org()

    return _S()


def _connector(monkeypatch: pytest.MonkeyPatch, **kw: Any) -> AwsGovCloudConnector:
    session = _org_session(**kw)
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: session)
    return AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x"})


def test_the_walk_reads_ous_and_keeps_only_email_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inv = _connector(monkeypatch).organization_inventory()
    assert inv["organization"]["id"] == "o-abc"
    assert inv["organization"]["partition"] == "aws-us-gov"
    by_id = {a["id"]: a for a in inv["accounts"]}
    assert by_id["222222222222"]["ou_path"] == "/Workloads/"
    assert by_id["222222222222"]["email_domain"] == "corp.example"
    assert all("@" not in str(v) for a in inv["accounts"] for v in a.values())
    assert inv["indeterminate"] == [] and inv["truncated"] is False


def test_a_member_account_is_unreadable_not_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    inv = _connector(monkeypatch, deny=True).organization_inventory()
    assert inv["organization"] is None and inv["accounts"] == []
    assert inv["indeterminate"] == ["organization:AccessDeniedException"]


def test_the_walk_says_when_it_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AwsGovCloudConnector, "ORG_MAX_ACCOUNTS", 1)
    inv = _connector(monkeypatch).organization_inventory()
    assert len(inv["accounts"]) == 1 and inv["truncated"] is True


async def _system() -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"AwsInv-{uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="aws sys")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


@pytest.mark.asyncio
async def test_sync_is_additive_idempotent_and_keeps_human_edits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, sys_id = await _system()
    conn = _connector(monkeypatch)
    async with session_scope() as s:
        first = await sync_organization_inventory(s, conn, system_id=sys_id, org_id=org_id)
    assert (first["seen"], first["created"]) == (2, 2)
    async with session_scope() as s:
        item = (await s.execute(select(InventoryItem).where(
            InventoryItem.system_id == sys_id, InventoryItem.asset_id == "222222222222"
        ))).scalar_one()
        assert item.props["partition_mismatch"] is True  # aws account in an aws-us-gov org
        item.description = "Production workloads -- ISSO note"
        item.props = {**item.props, "ticket": "CHG-1"}
    # The next read still has prod (updated in place) and no longer has the
    # management account: that one keeps its row.
    conn2 = _connector(monkeypatch, accounts={"r-1": [
        {"Id": "222222222222", "Name": "prod-renamed", "Status": "ACTIVE",
         "Arn": "arn:aws:organizations::1:account/y"}]}, ous={})
    async with session_scope() as s:
        second = await sync_organization_inventory(s, conn2, system_id=sys_id, org_id=org_id)
        items = (await s.execute(select(InventoryItem).where(
            InventoryItem.system_id == sys_id))).scalars().all()
        comps = (await s.execute(select(SystemComponent).where(
            SystemComponent.system_id == sys_id))).scalars().all()
    assert (second["created"], second["updated"]) == (0, 1)
    assert len(items) == 2 and len(comps) == 1
    prod = next(i for i in items if i.asset_id == "222222222222")
    assert prod.description == "Production workloads -- ISSO note"
    assert prod.props["ticket"] == "CHG-1"
    assert prod.props["name"] == "prod-renamed"  # the machine fact did refresh


@pytest.mark.asyncio
async def test_an_unreadable_organization_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, sys_id = await _system()
    async with session_scope() as s:
        out = await sync_organization_inventory(
            s, _connector(monkeypatch, deny=True), system_id=sys_id, org_id=org_id
        )
        items = (await s.execute(select(InventoryItem).where(
            InventoryItem.system_id == sys_id))).scalars().all()
    assert out["seen"] == 0 and items == []


@pytest.mark.asyncio
async def test_the_page_binds_a_system_and_counts_real_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_AUTH_ENABLED", "true")
    monkeypatch.setenv("CCF_AUTH_SESSION_SECRET", "test-secret")
    get_settings.cache_clear()
    session_fake = _org_session()
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: session_fake)
    org_id, sys_id = await _system()
    _, other_sys = await _system()
    async with session_scope() as s:
        admin = User(email=f"{uuid.uuid4().hex[:6]}@inv.test", organization_id=org_id,
                     role="admin", active=True, password_hash=hash_password("pw"),
                     api_token=new_api_token())
        s.add(admin)
        cfg = ConnectorConfig(organization_id=org_id, connector_type="aws_govcloud", name="a")
        s.add(cfg)
        await s.flush()
        await connector_credentials.set_credential(
            s, org_id, "aws_govcloud", {"access_key_id": "AKIA", "secret_access_key": "x"},
            config=cfg,
        )
        hdr, cfg_id = {"Authorization": f"Bearer {admin.api_token}"}, cfg.id
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post(f"/connectors/{cfg_id}/aws-inventory", data={"system_id": other_sys},
                         headers=hdr)
        assert "error" in r.headers["location"]
        r = await c.post(f"/connectors/{cfg_id}/aws-inventory", data={"system_id": sys_id},
                         headers=hdr)
        assert r.status_code == 303 and "error" not in r.headers["location"]
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg is not None
        assert cfg.config["system_id"] == sys_id and cfg.objects_discovered == 2


@pytest.mark.asyncio
async def test_the_inventory_route_refuses_another_orgs_or_a_deleted_system(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With auth off nothing scopes the session, so the route's own check is
    the only thing between a connector and another tenant's system."""
    session_fake = _org_session()
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: session_fake)
    org_id, sys_id = await _system()
    _, foreign = await _system()
    async with session_scope() as s:
        cfg = ConnectorConfig(organization_id=org_id, connector_type="aws_govcloud", name="a")
        s.add(cfg)
        await s.flush()
        await connector_credentials.set_credential(
            s, org_id, "aws_govcloud", {"access_key_id": "AKIA", "secret_access_key": "x"},
            config=cfg,
        )
        gone = await s.get(System, sys_id)
        assert gone is not None
        from datetime import UTC, datetime  # noqa: PLC0415
        gone.deleted_at = datetime.now(UTC)
        cfg_id = cfg.id
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        for target in (foreign, sys_id):
            r = await c.post(f"/connectors/{cfg_id}/aws-inventory", data={"system_id": target})
            assert "error" in r.headers["location"], target
    async with session_scope() as s:
        assert (await s.execute(select(InventoryItem).where(
            InventoryItem.system_id.in_([foreign, sys_id])))).scalars().all() == []
