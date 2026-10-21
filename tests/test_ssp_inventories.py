"""Ports/protocols/services and cryptographic modules on the system boundary."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import IntegrityError

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, SystemComponent
from ccf.models_boundary import CryptoModule

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _systems(name: str) -> tuple[int, int, int, int]:
    """Two systems in one org, and a component of the second."""
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        a = System(organization_id=org.id, name=f"{name} A")
        b = System(organization_id=org.id, name=f"{name} B")
        s.add_all([a, b])
        await s.flush()
        comp = SystemComponent(organization_id=org.id, system_id=b.id, type="software",
                               title="B's web tier")
        s.add(comp)
        await s.flush()
        return org.id, a.id, b.id, comp.id


@pytest.mark.asyncio
async def test_ports_are_validated() -> None:
    _, a, _, other_comp = await _systems("PpsA")
    url = f"/api/systems/{a}/boundary/ports"
    async with _client() as c:
        ok = await c.post(url, json={"protocol": "tcp", "port": "443", "service": "HTTPS",
                                     "direction": "inbound"})
        assert ok.status_code == 201, ok.text
        assert (await c.post(url, json={"protocol": "tcp", "service": "x",
                                         "direction": "inbound"})).status_code == 422
        assert (await c.post(url, json={"protocol": "udp", "port": "70000", "service": "x",
                                         "direction": "inbound"})).status_code == 422
        assert (await c.post(url, json={"protocol": "tcp", "port": "9-1", "service": "x",
                                         "direction": "inbound"})).status_code == 422
        icmp = await c.post(url, json={"protocol": "icmp", "service": "ping",
                                       "direction": "internal"})
        assert icmp.status_code == 201, icmp.text
        # A component of another system cannot be named as the user of a port.
        r = await c.post(url, json={"protocol": "tcp", "port": "22", "service": "SSH",
                                    "direction": "inbound", "component_id": other_comp})
        assert r.status_code == 422
        listed = (await c.get(url)).json()
    assert {r["service"] for r in listed} == {"HTTPS", "ping"}


@pytest.mark.asyncio
async def test_validated_needs_a_certificate_number() -> None:
    _, a, _, _ = await _systems("CryptoA")
    url = f"/api/systems/{a}/boundary/crypto-modules"
    base = {"module_name": "OpenSSL FIPS Provider", "usage": "data_in_transit"}
    async with _client() as c:
        r = await c.post(url, json={**base, "validation_status": "validated"})
        assert r.status_code == 422 and "certificate" in r.json()["detail"]
        r = await c.post(url, json={**base, "validation_status": "validated",
                                    "cmvp_certificate": "abc"})
        assert r.status_code == 422
        r = await c.post(url, json={**base, "validation_status": "validated",
                                    "cmvp_certificate": "4282", "security_level": 5})
        assert r.status_code == 422
        r = await c.post(url, json={**base, "validation_status": "validated",
                                    "cmvp_certificate": "4282", "security_level": 1})
        assert r.status_code == 201, r.text
        r = await c.post(url, json={**base, "module_name": "Legacy lib",
                                    "validation_status": "not_validated"})
        assert r.status_code == 201, r.text
        listed = (await c.get(url)).json()
    linked = [m for m in listed if m["cmvp_certificate"] == "4282"]
    assert linked and linked[0]["cmvp_url"].endswith("/certificate/4282")


@pytest.mark.asyncio
async def test_the_database_refuses_validated_without_a_certificate() -> None:
    """The API check is not the only one: a direct write cannot claim it either."""
    org, a, _, _ = await _systems("CryptoB")
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(CryptoModule(organization_id=org, system_id=a, module_name="x",
                               validation_status="validated", usage="other"))
            await s.flush()


@pytest.mark.asyncio
async def test_rows_of_another_system_cannot_be_deleted_through_this_one() -> None:
    _, a, b, _ = await _systems("PpsB")
    async with _client() as c:
        row = (await c.post(f"/api/systems/{b}/boundary/ports",
                            json={"protocol": "tcp", "port": "443", "service": "HTTPS",
                                  "direction": "inbound"})).json()
        r = await c.delete(f"/api/systems/{a}/boundary/ports/{row['id']}")
        assert r.status_code == 404
        r = await c.delete(f"/api/systems/{b}/boundary/ports/{row['id']}")
        assert r.status_code == 204


@pytest.mark.asyncio
async def test_the_boundary_page_shows_both_inventories() -> None:
    _, a, _, _ = await _systems("PpsC")
    async with _client() as c:
        await c.post(f"/api/systems/{a}/boundary/ports",
                     json={"protocol": "tcp", "port": "8443", "service": "Admin API",
                           "direction": "internal"})
        page = await c.get(f"/systems/{a}/boundary")
    assert page.status_code == 200
    assert "Admin API" in page.text and "Cryptographic modules" in page.text
