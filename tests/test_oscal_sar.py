"""Tests for the OSCAL Assessment-Results (SAR) export (Keystone #3, Task 2).

Mirrors ``tests/test_ato.py`` for DB setup (``session_scope``/``fresh_engine``,
module-scoped Alembic migration) and ``tests/test_oscal_validation.py`` for
hitting the route and validating the resulting document.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    POAM,
    Assessment,
    AssessmentResult,
    Control,
    ControlImplementation,
    Organization,
    System,
    User,
)
from ccf.models_evidence import EvidenceObject
from ccf.oscal import validate_document

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _build_fixture(org_name: str) -> tuple[int, int, int]:
    """Build Organization + System + 3 ControlImplementations (AC-2, AU-2,
    SC-7) + an Assessment with one satisfied/other_than_satisfied/not_applicable
    AssessmentResult each + an EvidenceObject on the satisfied impl + an open
    POA&M. Returns (org_id, system_id, assessment_id)."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{org_name} system")
        s.add(sysrow)
        await s.flush()

        impls: dict[str, ControlImplementation] = {}
        for identifier in ("AC-2", "AU-2", "SC-7"):
            # Control.identifier is globally unique — reuse an existing row
            # across the multiple fixtures this module builds.
            ctrl = (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if ctrl is None:
                ctrl = Control(identifier=identifier, control_name=f"{identifier} control title")
                s.add(ctrl)
                await s.flush()
            impl = ControlImplementation(
                system_id=sysrow.id,
                control_id=ctrl.id,
                status="implemented",
            )
            s.add(impl)
            await s.flush()
            impls[identifier] = impl

        assessment = Assessment(
            system_id=sysrow.id,
            name=f"{org_name} internal assessment",
            kind="internal",
            assessor="Jane 3PAO",
            started_on=date.today() - timedelta(days=10),
            finished_on=date.today(),
            summary="Internal control assessment.",
        )
        s.add(assessment)
        await s.flush()

        s.add(
            AssessmentResult(
                assessment_id=assessment.id,
                implementation_id=impls["AC-2"].id,
                finding="satisfied",
                rationale="Account management procedures verified.",
                observed_on=date.today(),
            )
        )
        s.add(
            AssessmentResult(
                assessment_id=assessment.id,
                implementation_id=impls["AU-2"].id,
                finding="other_than_satisfied",
                rationale="Audit events not fully enumerated.",
                observed_on=date.today(),
            )
        )
        s.add(
            AssessmentResult(
                assessment_id=assessment.id,
                implementation_id=impls["SC-7"].id,
                finding="not_applicable",
                rationale="No boundary protection in scope for this system.",
                observed_on=date.today(),
            )
        )

        s.add(
            EvidenceObject(
                organization_id=org.id,
                title="AC-2 screenshot",
                description="Screenshot of account review.",
                system_id=sysrow.id,
                implementation_id=impls["AC-2"].id,
                control_id="AC-2",
            )
        )

        s.add(
            POAM(
                system_id=sysrow.id,
                title="Audit log gaps",
                weakness="Audit events are not fully enumerated per AU-2.",
                severity="moderate",
                status="open",
            )
        )
        await s.flush()

        return org.id, sysrow.id, assessment.id


@pytest.mark.asyncio
async def test_sar_export_has_expected_shape_and_validates() -> None:
    _org_id, _sys_id, assessment_id = await _build_fixture("SAR Golden Org")

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/api/oscal/sar/{assessment_id}")
        assert r.status_code == 200
        doc = r.json()

    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert "import-ap" in ar
    results = ar["results"]
    assert len(results) == 1
    result = results[0]
    assert "reviewed-controls" in result
    include_controls = result["reviewed-controls"]["control-selections"][0]["include-controls"]
    cids = {c["control-id"] for c in include_controls}
    assert cids == {"ac-2", "au-2", "sc-7"}

    findings = result["findings"]
    assert len(findings) == 3
    states = {f["target"]["status"]["state"] for f in findings}
    assert "satisfied" in states
    assert "not-satisfied" in states

    na_finding = next(
        f
        for f in findings
        if any(
            p.get("name") == "applicability" and p.get("value") == "not-applicable"
            for p in f.get("props", [])
        )
    )
    assert na_finding["target"]["status"]["state"] == "not-satisfied"

    satisfied_finding = next(
        f for f in findings if f["target"]["status"]["state"] == "satisfied"
    )

    observations = result["observations"]
    assert len(observations) == 1
    obs = observations[0]
    assert obs["methods"] == ["EXAMINE"]
    assert obs["relevant-evidence"][0]["description"] == "AC-2 screenshot"

    assert satisfied_finding["related-observations"] == [{"observation-uuid": obs["uuid"]}]

    risks = result["risks"]
    assert len(risks) == 1
    assert risks[0]["title"] == "Audit log gaps"

    report = validate_document(doc)
    # Conformance is machine-proven against the vendored official NIST OSCAL
    # assessment-results schema (not Concord's structural fallback).
    assert report.mode == "official", report.warnings
    assert report.ok, report.errors


@pytest.mark.asyncio
async def test_sar_system_route_returns_latest_assessment() -> None:
    _org_id, sys_id, assessment_id = await _build_fixture("SAR System Latest Org")

    # A second, earlier-finished assessment should NOT be picked.
    async with session_scope() as s:
        older = Assessment(
            system_id=sys_id,
            name="Older assessment",
            kind="self",
            started_on=date.today() - timedelta(days=100),
            finished_on=date.today() - timedelta(days=90),
        )
        s.add(older)
        await s.flush()

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/api/oscal/sar/system/{sys_id}")
        assert r.status_code == 200
        doc = r.json()

    async with session_scope() as s:
        expected = await s.get(Assessment, assessment_id)
        assert expected is not None
        assert doc["assessment-results"]["results"][0]["title"] == expected.name


@pytest.mark.asyncio
async def test_sar_system_route_404_when_no_assessment() -> None:
    async with session_scope() as s:
        org = Organization(name="SAR No Assessment Org")
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name="SAR No Assessment System")
        s.add(sysrow)
        await s.flush()
        sys_id = sysrow.id

    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/api/oscal/sar/system/{sys_id}")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_sar_unknown_assessment_404() -> None:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/api/oscal/sar/999999999")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_sar_out_of_org_is_404() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        _org_id, _sys_id, assessment_id = await _build_fixture("SAR Owner Org")

        async with session_scope() as s:
            other_org = Organization(name="SAR Other Org")
            s.add(other_org)
            await s.flush()
            outsider = User(
                email="outsider@sar-other.test",
                organization_id=other_org.id,
                role="admin",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(outsider)
            await s.flush()
            token = outsider.api_token

        transport = ASGITransport(app=create_app())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get(
                f"/api/oscal/sar/{assessment_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 404

            r_anon = await c.get(f"/api/oscal/sar/{assessment_id}")
            assert r_anon.status_code == 401
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()
