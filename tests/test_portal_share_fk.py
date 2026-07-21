"""External-portal share foreign keys (DATA-02).

``external_package_shares.package_id`` and ``external_evidence_shares.
evidence_object_id`` used to be plain integers with no FK — the highest-exposure
surface (external portal) could reference a deleted/foreign artifact and would
dangle silently when the artifact was removed. Migration ``0042_portal_share_fks``
adds real ``ForeignKey``s (``ON DELETE CASCADE``) after deleting any orphaned
share rows. These tests prove: (1) a share referencing a non-existent
package/evidence object now fails fast with ``IntegrityError`` instead of
silently persisting a dangling reference, and (2) deleting the parent
package/evidence object cascades to remove the share rather than leaving it
behind.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import IntegrityError

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import service as ev_service
from ccf.models import Organization, System
from ccf.models_evidence import EvidenceObject
from ccf.models_packages import AuthorizationPackage
from ccf.models_portal import ExternalEvidenceShare, ExternalPackageShare
from ccf.packages import service as pkg_service
from ccf.portal import service as portal

pytestmark = pytest.mark.usefixtures("fresh_engine")

# An id guaranteed not to exist — tests run against a fresh, low-cardinality DB.
_BOGUS_ID = 999_999_999


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name, description="portal fk test")
        s.add(org)
        await s.flush()
        return org.id


async def _system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name=name, baseline="moderate")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def _grant(org_id: int, name: str) -> int:
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org_id, principal_name=name)
        return grant.id


@pytest.mark.asyncio
async def test_package_share_rejects_nonexistent_package() -> None:
    org = await _org("PortalFkPkgOrg")
    grant_id = await _grant(org, "Bogus pkg cust")
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(ExternalPackageShare(grant_id=grant_id, package_id=_BOGUS_ID))
            await s.flush()


@pytest.mark.asyncio
async def test_evidence_share_rejects_nonexistent_evidence_object() -> None:
    org = await _org("PortalFkEvOrg")
    grant_id = await _grant(org, "Bogus ev cust")
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(ExternalEvidenceShare(grant_id=grant_id, evidence_object_id=_BOGUS_ID))
            await s.flush()


@pytest.mark.asyncio
async def test_deleting_package_cascades_to_package_share() -> None:
    org = await _org("PortalFkPkgCascadeOrg")
    system = await _system(org, "PkgCascadeSys")
    async with session_scope() as s:
        pkg = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Cascade pkg"
        )
        pkg_id = pkg.id
    grant_id = await _grant(org, "Cascade pkg cust")
    async with session_scope() as s:
        share = ExternalPackageShare(grant_id=grant_id, package_id=pkg_id)
        s.add(share)
        await s.flush()
        share_id = share.id

    async with session_scope() as s:
        pkg = await s.get(AuthorizationPackage, pkg_id)
        assert pkg is not None
        await s.delete(pkg)

    async with session_scope() as s:
        assert await s.get(ExternalPackageShare, share_id) is None


@pytest.mark.asyncio
async def test_deleting_evidence_object_cascades_to_evidence_share() -> None:
    org = await _org("PortalFkEvCascadeOrg")
    system = await _system(org, "EvCascadeSys")
    async with session_scope() as s:
        ev = await ev_service.create_object(
            s, org_id=org, title="Cascade evidence", system_id=system
        )
        ev_id = ev.id
    grant_id = await _grant(org, "Cascade ev cust")
    async with session_scope() as s:
        share = ExternalEvidenceShare(grant_id=grant_id, evidence_object_id=ev_id)
        s.add(share)
        await s.flush()
        share_id = share.id

    async with session_scope() as s:
        ev = await s.get(EvidenceObject, ev_id)
        assert ev is not None
        await s.delete(ev)

    async with session_scope() as s:
        assert await s.get(ExternalEvidenceShare, share_id) is None
