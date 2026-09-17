"""CR26 deliverable endpoints: read, author, seed -- and the verdict every time.

The response carrying ``validation_errors`` is the point of these routes, not a
detail. ``put_document`` already records *why* a document is invalid; surfacing
that on every write is what lets an author work against the schema instead of
guessing which of the CPO's ten required fields are still missing.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import Organization, System

_SEQ = itertools.count()

_VALID_SDR = {
    "certificationPackageOverviewUri": "https://example.gov/cpo.json",
    "fedRampRequirements": [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["Implemented."]}],
}


class _Session:
    """A client whose identity and role can change between calls."""

    def __init__(self, *, org_id: int | None = None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email="isso@acme.gov", org_id=self.org_id, role=self.role)

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


async def _system(name: str, *, description: str | None = None) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"{name}-{next(_SEQ)} Provider")
        s.add(org)
        await s.flush()
        sysm = System(
            organization_id=org.id, name=f"{name} Service", description=description
        )
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def test_authoring_a_document_returns_the_verdict_with_it() -> None:
    """The reason these routes exist. A caller must not have to guess."""
    org_id, system_id = await _system("verdict")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.put(f"/api/systems/{system_id}/cr26-documents/cpo", json={"document": {}})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_valid"] is False
    assert body["kind"] == "cpo"
    # Not merely that it failed -- WHICH required fields are still owed.
    joined = " ".join(body["validation_errors"])
    for field in ("serviceIdentification", "serviceProperties", "contactInformation"):
        assert field in joined, body["validation_errors"]


async def test_a_valid_document_reports_valid() -> None:
    """The complement: is_valid must be computed, not always False."""
    org_id, system_id = await _system("valid")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.put(
            f"/api/systems/{system_id}/cr26-documents/sdr", json={"document": _VALID_SDR}
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_valid"] is True
    assert body["validation_errors"] == []
    assert body["ruleset_version"] == "2026-06-24"
    assert body["schema_version"] == "1.1.1"


async def test_control_owner_may_not_author() -> None:
    """The gate is admin ALONE.

    Deliberately tries ``control_owner``, not ``viewer``: viewer 403s under
    either gate, so it could not tell an admin-only gate from an
    admin+control_owner one. This is the assertion that pins the decision.
    """
    org_id, system_id = await _system("gate")
    async with _Session(org_id=org_id, role="control_owner").client() as c:
        resp = await c.put(f"/api/systems/{system_id}/cr26-documents/cpo", json={"document": {}})
    assert resp.status_code == 403, resp.text


async def test_reading_is_open_to_any_authenticated_role() -> None:
    org_id, system_id = await _system("read")
    async with _Session(org_id=org_id).client() as c:
        await c.put(f"/api/systems/{system_id}/cr26-documents/sdr", json={"document": _VALID_SDR})
    async with _Session(org_id=org_id, role="viewer").client() as c:
        resp = await c.get(f"/api/systems/{system_id}/cr26-documents/sdr")
    assert resp.status_code == 200, resp.text
    assert resp.json()["document"] == _VALID_SDR


async def test_a_document_that_was_never_authored_is_404() -> None:
    org_id, system_id = await _system("absent")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.get(f"/api/systems/{system_id}/cr26-documents/sdr")
    assert resp.status_code == 404, resp.text


async def test_another_tenants_system_is_404_not_403() -> None:
    """Confirming an id exists is itself a disclosure -- matching
    api/routes/posture.py's _owned_test.

    The owning tenant must author a document FIRST. Without one, a reader gets
    404 from the "no such document" branch whether or not the tenant check
    exists, so the test would pass for the wrong reason -- verified: deleting
    the ownership check left an earlier version of this test green. With a
    document present, dropping the check returns 200 and its body, which is
    the leak this pins.
    """
    owner_org, system_id = await _system("tenant-a")
    other_org, _other_system = await _system("tenant-b")
    async with _Session(org_id=owner_org).client() as c:
        authored = await c.put(
            f"/api/systems/{system_id}/cr26-documents/sdr", json={"document": _VALID_SDR}
        )
        assert authored.status_code == 200, authored.text

    async with _Session(org_id=other_org).client() as c:
        read = await c.get(f"/api/systems/{system_id}/cr26-documents/sdr")
        listed = await c.get(f"/api/systems/{system_id}/cr26-documents")
        written = await c.put(
            f"/api/systems/{system_id}/cr26-documents/cpo", json={"document": {}}
        )
    assert read.status_code == 404, read.text
    assert listed.status_code == 404, listed.text
    assert written.status_code == 404, written.text


async def test_a_non_deliverable_kind_is_refused() -> None:
    """``common`` is the shared $defs target the other ten schemas reference,
    not a document any system files."""
    org_id, system_id = await _system("common")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.put(
            f"/api/systems/{system_id}/cr26-documents/common", json={"document": {}}
        )
    assert resp.status_code == 400, resp.text
    assert "deliverable" in resp.text


async def test_an_unknown_kind_is_refused() -> None:
    org_id, system_id = await _system("unknown-kind")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.put(
            f"/api/systems/{system_id}/cr26-documents/not-a-kind", json={"document": {}}
        )
    assert resp.status_code == 400, resp.text


async def test_seeding_a_cpo_names_what_is_still_owed() -> None:
    """The seeder fills three of ten required fields; the response must make
    the other seven visible rather than merely reporting failure."""
    org_id, system_id = await _system("seed", description="A seeded service.")
    async with _Session(org_id=org_id).client() as c:
        resp = await c.post(f"/api/systems/{system_id}/cr26-documents/cpo/seed")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_valid"] is False
    ident = body["document"]["serviceIdentification"]
    assert ident["serviceName"] == "seed Service"
    assert ident["serviceDescription"] == "A seeded service."
    assert "certificationType" not in ident
    joined = " ".join(body["validation_errors"])
    for field in ("serviceAcronym", "fedRampPackageId", "website", "logo"):
        assert field in joined, body["validation_errors"]


async def test_seeding_is_admin_gated_too() -> None:
    org_id, system_id = await _system("seed-gate")
    async with _Session(org_id=org_id, role="control_owner").client() as c:
        resp = await c.post(f"/api/systems/{system_id}/cr26-documents/cpo/seed")
    assert resp.status_code == 403, resp.text


async def test_listing_shows_every_kind_present_with_its_verdict() -> None:
    org_id, system_id = await _system("list")
    async with _Session(org_id=org_id).client() as c:
        await c.put(f"/api/systems/{system_id}/cr26-documents/sdr", json={"document": _VALID_SDR})
        await c.put(f"/api/systems/{system_id}/cr26-documents/cpo", json={"document": {}})
        resp = await c.get(f"/api/systems/{system_id}/cr26-documents")
    assert resp.status_code == 200, resp.text
    by_kind = {row["kind"]: row for row in resp.json()}
    assert sorted(by_kind) == ["cpo", "sdr"]
    assert by_kind["sdr"]["is_valid"] is True
    assert by_kind["cpo"]["is_valid"] is False
    # The list is a summary -- it must not ship every document body.
    assert "document" not in by_kind["sdr"]

async def test_a_soft_deleted_system_is_404() -> None:
    """DATA-04 soft delete. The row still exists and the FK still cascades from
    it, so a document authored against one would be unreachable and permanent
    -- and the system is invisible to every list view, so 404 is the honest
    answer rather than 200.
    """
    org_id, system_id = await _system("soft-deleted")
    async with session_scope() as s:
        sysm = await s.get(System, system_id)
        sysm.deleted_at = datetime.now(UTC)

    async with _Session(org_id=org_id).client() as c:
        read = await c.get(f"/api/systems/{system_id}/cr26-documents/cpo")
        write = await c.put(
            f"/api/systems/{system_id}/cr26-documents/cpo", json={"document": {}}
        )
        seed = await c.post(f"/api/systems/{system_id}/cr26-documents/cpo/seed")
    assert read.status_code == 404, read.text
    assert write.status_code == 404, write.text
    assert seed.status_code == 404, seed.text
