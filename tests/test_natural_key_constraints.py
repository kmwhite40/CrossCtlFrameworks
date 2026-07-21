"""Unique constraints on natural keys (DATA-08 / DATA-10).

``vendors``, ``policies``, ``fedramp_dependencies``, ``pack_mappings``, and
``people`` each carry a natural key that create/reconcile flows already treat
as identifying, but the schema never enforced it — so a retried request or a
racing writer could accumulate duplicate rows. Migration
``0040_natural_key_unique_constraints`` adds the missing ``UniqueConstraint``s
(after deduplicating any pre-existing violators); these tests prove a second
insert with the same natural key now raises ``IntegrityError`` for each table.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import IntegrityError

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import FedRAMPDependency, Organization, Policy, System, Vendor
from ccf.models_packs import CompliancePack, PackMapping
from ccf.models_people import Person

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


@pytest.mark.asyncio
async def test_duplicate_vendor_org_name_raises_integrity_error() -> None:
    org_id = await _make_org("NatKeyVendorOrg")
    async with session_scope() as s:
        s.add(Vendor(organization_id=org_id, name="Acme Corp"))
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(Vendor(organization_id=org_id, name="Acme Corp"))
            await s.flush()


@pytest.mark.asyncio
async def test_duplicate_policy_org_name_raises_integrity_error() -> None:
    org_id = await _make_org("NatKeyPolicyOrg")
    async with session_scope() as s:
        s.add(Policy(organization_id=org_id, name="Access Control Policy"))
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(Policy(organization_id=org_id, name="Access Control Policy"))
            await s.flush()


@pytest.mark.asyncio
async def test_duplicate_fedramp_dependency_system_name_raises_integrity_error() -> None:
    org_id = await _make_org("NatKeyFedRAMPOrg")
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name="NatKeySys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        sys_id = sysm.id
    async with session_scope() as s:
        s.add(FedRAMPDependency(system_id=sys_id, name="AWS RDS"))
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(FedRAMPDependency(system_id=sys_id, name="AWS RDS"))
            await s.flush()


@pytest.mark.asyncio
async def test_duplicate_pack_mapping_raises_integrity_error() -> None:
    org_id = await _make_org("NatKeyPackOrg")
    async with session_scope() as s:
        pack = CompliancePack(
            organization_id=org_id, pack_key="natkey-pack", name="NatKeyPack", version="1"
        )
        s.add(pack)
        await s.flush()
        pack_id = pack.id
    async with session_scope() as s:
        s.add(PackMapping(pack_id=pack_id, control_id="AC-1", framework="nist-800-53"))
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(PackMapping(pack_id=pack_id, control_id="AC-1", framework="nist-800-53"))
            await s.flush()


@pytest.mark.asyncio
async def test_duplicate_person_org_email_raises_integrity_error() -> None:
    org_id = await _make_org("NatKeyPeopleOrg")
    async with session_scope() as s:
        s.add(Person(organization_id=org_id, full_name="Jane Doe", email="jane@example.com"))
        await s.flush()
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(Person(organization_id=org_id, full_name="Jane D.", email="jane@example.com"))
            await s.flush()


@pytest.mark.asyncio
async def test_null_organization_vendors_are_not_deduplicated_or_blocked() -> None:
    """Postgres treats each NULL as distinct for uniqueness, so two org-less
    vendors sharing a name is not a constraint violation — the migration's
    dedupe must not have swept these up, and inserts must still succeed."""
    async with session_scope() as s:
        s.add(Vendor(organization_id=None, name="NatKeyOrphanVendor"))
        s.add(Vendor(organization_id=None, name="NatKeyOrphanVendor"))
        await s.flush()  # must not raise
