"""Compliance pack runtime — validate, install idempotency, coverage, tests, RLS."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.models import Control, ControlImplementation, Organization, System
from ccf.models_packs import CompliancePack, PackControl
from ccf.packs import catalog, service

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


# --- catalog + validation ----------------------------------------------------


def test_bundled_packs_are_valid() -> None:
    available = catalog.list_available()
    assert any(p["id"] == "ai-agent-governance" for p in available)
    for p in available:
        manifest = catalog.load_pack(p["id"])
        assert catalog.validate_manifest(manifest) == []


def test_invalid_manifest_fails_clearly() -> None:
    errors = catalog.validate_manifest({"name": "x"})  # missing id/version/controls
    assert errors
    assert any("id" in e for e in errors)
    assert any("controls" in e for e in errors)


# --- install idempotency + content ------------------------------------------


@pytest.mark.asyncio
async def test_install_is_idempotent_and_materializes_controls() -> None:
    async with session_scope() as s:
        org = Organization(name="PackInstallOrg")
        s.add(org)
        await s.flush()
        org_id = org.id
    manifest = catalog.load_pack("ai-agent-governance")
    async with session_scope() as s:
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")
    async with session_scope() as s:
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")  # again
    async with session_scope() as s:
        packs = (
            await s.execute(select(CompliancePack).where(CompliancePack.organization_id == org_id))
        ).scalars().all()
        assert len(packs) == 1  # idempotent — one pack, not two
        n_controls = (
            await s.execute(
                select(func.count()).select_from(PackControl).where(
                    PackControl.pack_id == packs[0].id
                )
            )
        ).scalar_one()
        assert n_controls == len(manifest["controls"])  # no duplication on re-install


# --- routes: install, coverage, test ----------------------------------------


@pytest.mark.asyncio
async def test_install_coverage_and_test_via_api() -> None:
    async with session_scope() as s:
        org = Organization(name="PackApiOrg")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="PackSys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        control = Control(identifier="AIG-1", control_name="AI agent inventory")
        s.add(control)
        await s.flush()
        s.add(ControlImplementation(
            system_id=sysm.id, control_id=control.id, status="implemented"))
        sys_id = sysm.id
    async with _client() as c:
        inst = await c.post("/api/packs/install", json={"pack_id": "ai-agent-governance"})
        assert inst.status_code == 201, inst.text

        cov = await c.get(f"/api/packs/ai-agent-governance/coverage?system_id={sys_id}")
        assert cov.status_code == 200
        assert cov.json()["total_controls"] == 5
        assert cov.json()["covered"] == 1  # only AIG-1 implemented

        tst = await c.post("/api/packs/ai-agent-governance/test")
        assert tst.json()["failed"] == 0
        assert tst.json()["passed"] >= 1


@pytest.mark.asyncio
async def test_validate_route() -> None:
    async with _client() as c:
        ok = await c.post("/api/packs/validate", json=catalog.load_pack("nist-ssdf-genai"))
        assert ok.json()["valid"] is True
        bad = await c.post("/api/packs/validate", json={"name": "nope"})
        assert bad.json()["valid"] is False


# --- RLS ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pack_install_is_tenant_scoped() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    manifest = catalog.load_pack("nist-ssdf-genai")
    async with session_scope() as s:
        a = Organization(name="PackRlsA")
        b = Organization(name="PackRlsB")
        s.add_all([a, b])
        await s.flush()
        await service.install_pack(s, org_id=a.id, manifest=manifest, actor="t")
        await service.install_pack(s, org_id=b.id, manifest=manifest, actor="t")
        org_a = a.id
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        orgs = {
            p.organization_id
            for p in (await s.execute(select(CompliancePack))).scalars().all()
        }
        assert orgs == {org_a}  # tenant A cannot see B's installed packs


# --- cross-pack posture rule key collisions -----------------------------------
# catalog.validate_manifest's `seen_keys` only catches a duplicate *within* one
# manifest. Two separately installed packs declaring the same key would
# otherwise collapse to one ControlTest (unique on system_id, check_key),
# silently discarding whichever pack's verdict did not run last.


def _posture_manifest(pack_id: str, rule_key: str) -> dict:
    return {
        "id": pack_id,
        "name": pack_id,
        "version": "1.0.0",
        "schema_version": "1",
        "controls": [{"control_id": "ZP-2", "title": "Account Management"}],
        "rules": [
            {
                "key": rule_key,
                "kind": "posture",
                "definition": {
                    "provider": "msgraph",
                    "resource_type": "entra_user",
                    "endpoint": "/v1.0/users?$select=id,userPrincipalName,userType",
                    "expected": "no guest account exists",
                    "control_ids": ["ZP-2"],
                    "predicate": {"op": "not_equals", "path": "userType", "value": "Guest"},
                },
            }
        ],
    }


@pytest.mark.asyncio
async def test_a_second_pack_cannot_claim_another_installed_packs_rule_key() -> None:
    async with session_scope() as s:
        org = Organization(name="PackKeyCollisionOrg")
        s.add(org)
        await s.flush()
        org_id = org.id
    async with session_scope() as s:
        await service.install_pack(
            s, org_id=org_id, manifest=_posture_manifest("pack-one", "org.shared_key"), actor="t"
        )
    async with session_scope() as s:
        with pytest.raises(service.PackError, match=r"org\.shared_key"):
            await service.install_pack(
                s,
                org_id=org_id,
                manifest=_posture_manifest("pack-two", "org.shared_key"),
                actor="t",
            )


@pytest.mark.asyncio
async def test_reinstalling_the_same_pack_does_not_collide_with_its_own_key() -> None:
    async with session_scope() as s:
        org = Organization(name="PackKeySelfOrg")
        s.add(org)
        await s.flush()
        org_id = org.id
    manifest = _posture_manifest("pack-self", "org.self_key")
    async with session_scope() as s:
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")
    async with session_scope() as s:
        # A reinstall/upgrade of the SAME pack must not conflict with its own
        # previously-installed rule key.
        await service.install_pack(s, org_id=org_id, manifest=manifest, actor="t")


@pytest.mark.asyncio
async def test_the_same_rule_key_is_fine_across_different_organizations() -> None:
    async with session_scope() as s:
        a = Organization(name="PackKeyOrgA")
        b = Organization(name="PackKeyOrgB")
        s.add_all([a, b])
        await s.flush()
        org_a, org_b = a.id, b.id
    async with session_scope() as s:
        await service.install_pack(
            s, org_id=org_a, manifest=_posture_manifest("pack-a", "org.same_key"), actor="t"
        )
    async with session_scope() as s:
        await service.install_pack(
            s, org_id=org_b, manifest=_posture_manifest("pack-b", "org.same_key"), actor="t"
        )


# --- coverage: padded catalog vs canonical pack ids ---------------------------
# ``controls.identifier`` in the real 800-53 catalog is zero-padded (``AC-01``,
# and 3747 of the dev catalog's 5430 rows carry that form) while pack manifests
# declare the canonical unpadded id (``AC-2``). A raw string compare matches
# nothing, so every pack control reported as a gap and coverage_pct was 0.
# The fixture below deliberately puts the two forms on opposite sides -- the
# way production does -- rather than using one spelling on both.


def _coverage_manifest(pack_id: str, control_ids: list[str]) -> dict:
    return {
        "id": pack_id,
        "name": pack_id,
        "version": "1.0.0",
        "schema_version": "1",
        "controls": [{"control_id": c, "title": c} for c in control_ids],
    }


async def _coverage_fixture(
    *,
    org_name: str,
    pack_id: str,
    catalog_identifiers: list[tuple[str, str]],
    pack_control_ids: list[str],
) -> tuple[int, int, list[int]]:
    """Seed one org/system, a catalog spelled as production spells it, and a pack.

    ``catalog_identifiers`` is ``(identifier, implementation status)`` -- the
    identifier is written to ``controls`` exactly as given, so a padded catalog
    stays padded. Returns ``(system_id, pack_row_id, control_row_ids)``.
    """
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{org_name}Sys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        control_ids = []
        for identifier, status in catalog_identifiers:
            ctl = Control(identifier=identifier, control_name=identifier)
            s.add(ctl)
            await s.flush()
            control_ids.append(ctl.id)
            s.add(ControlImplementation(
                system_id=sysm.id, control_id=ctl.id, status=status))
        org_id, sys_id = org.id, sysm.id
    async with session_scope() as s:
        pack = await service.install_pack(
            s,
            org_id=org_id,
            manifest=_coverage_manifest(pack_id, pack_control_ids),
            actor="t",
        )
        pack_row_id = pack.id
    return sys_id, pack_row_id, control_ids


async def _coverage_of(pack_row_id: int, system_id: int) -> dict:
    async with session_scope() as s:
        pack = (
            await s.execute(select(CompliancePack).where(CompliancePack.id == pack_row_id))
        ).scalars().one()
        return await service.coverage(s, pack=pack, system_id=system_id)


@pytest.mark.asyncio
async def test_coverage_matches_a_padded_catalog_against_canonical_pack_ids() -> None:
    """The production shape: catalog zero-padded, manifest canonical."""
    sys_id, pack_row_id, ctl_ids = await _coverage_fixture(
        org_name="PackCovPadded",
        pack_id="cov-padded",
        catalog_identifiers=[
            ("ZP-01", "implemented"),
            ("ZP-02", "inherited"),
            ("ZP-03", "planned"),  # a genuine gap -- present but not satisfied
        ],
        pack_control_ids=["ZP-1", "ZP-2", "ZP-3"],
    )
    try:
        out = await _coverage_of(pack_row_id, sys_id)
        assert out["total_controls"] == 3
        assert out["covered"] == 2, out
        assert out["coverage_pct"] == 66.7, out
        assert out["gaps"] == ["ZP-3"], out  # still reported -- not papered over
        assert out["unparseable_control_ids"] == []
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(ControlImplementation).where(
                    ControlImplementation.control_id.in_(ctl_ids)))
            await s.execute(delete(Control).where(Control.id.in_(ctl_ids)))


@pytest.mark.asyncio
async def test_coverage_is_correct_across_padded_unpadded_and_mixed_spellings() -> None:
    """Padding is not consistent even within one catalog; enhancements too."""
    sys_id, pack_row_id, ctl_ids = await _coverage_fixture(
        org_name="PackCovMixed",
        pack_id="cov-mixed",
        catalog_identifiers=[
            ("AU-06", "implemented"),      # padded catalog, unpadded pack
            ("SI-4", "implemented"),       # unpadded both sides
            ("CM-07 (1)", "inherited"),    # padded + spaced enhancement
            ("IA-05", "not_implemented"),  # genuine gap
        ],
        pack_control_ids=["AU-6", "SI-04", "CM-7(1)", "IA-5", "PE-3"],
    )
    try:
        out = await _coverage_of(pack_row_id, sys_id)
        assert out["total_controls"] == 5
        assert out["covered"] == 3, out
        # IA-5 is present but unsatisfied; PE-3 is absent entirely. Both gaps.
        assert sorted(out["gaps"]) == ["IA-5", "PE-3"], out
        assert out["coverage_pct"] == 60.0, out
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(ControlImplementation).where(
                    ControlImplementation.control_id.in_(ctl_ids)))
            await s.execute(delete(Control).where(Control.id.in_(ctl_ids)))


@pytest.mark.asyncio
async def test_an_unparseable_pack_control_id_is_reported_and_matched_by_identity() -> None:
    """A pack-native id (``AIG-90``, ``PS.90``) is outside the 800-53 key space.

    It is neither a gap by default nor covered by default: it falls back to
    exact catalog identity, and is listed in ``unparseable_control_ids`` so an
    operator is told the platform could not canonicalize it.
    """
    sys_id, pack_row_id, ctl_ids = await _coverage_fixture(
        org_name="PackCovUnparseable",
        pack_id="cov-unparseable",
        catalog_identifiers=[
            ("AIG-90", "implemented"),
            ("PS.90", "planned"),
            ("ZP-095", "implemented"),  # padded, as production spells it
        ],
        pack_control_ids=["AIG-90", "PS.90", "CSA-RLS-90", "ZP-95"],
    )
    try:
        out = await _coverage_of(pack_row_id, sys_id)
        # Reported to the caller, every one of them, in manifest order.
        assert out["unparseable_control_ids"] == ["AIG-90", "PS.90", "CSA-RLS-90"], out
        # Not automatically covered: PS.90 is planned, CSA-RLS-90 is absent.
        assert sorted(out["gaps"]) == ["CSA-RLS-90", "PS.90"], out
        # Not automatically a gap: AIG-90 matches by identity and is implemented.
        assert out["covered"] == 2, out  # AIG-90 + AC-95
        assert out["total_controls"] == 4
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(ControlImplementation).where(
                    ControlImplementation.control_id.in_(ctl_ids)))
            await s.execute(delete(Control).where(Control.id.in_(ctl_ids)))
