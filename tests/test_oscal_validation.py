"""OSCAL validation — kind detection, structural fallback, official schema, route."""

from __future__ import annotations

import json
import re

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.oscal import detect_kind, official_schema_available, validate_document

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _ssp(uuid: str = "11111111-1111-1111-1111-111111111111") -> dict:
    return {
        "system-security-plan": {
            "uuid": uuid,
            "metadata": {"title": "T", "last-modified": "2026-07-02T00:00:00Z",
                         "oscal-version": "1.1.2"},
            "system-characteristics": {"system-name": "S"},
            "control-implementation": {"implemented-requirements": [{"uuid": "x"}]},
        }
    }


def _poam() -> dict:
    return {
        "plan-of-action-and-milestones": {
            "uuid": "22222222-2222-2222-2222-222222222222",
            "metadata": {"title": "P", "last-modified": "2026-07-02T00:00:00Z",
                         "oscal-version": "1.1.2"},
            "poam-items": [{"uuid": "i1", "title": "t", "description": "d"}],
        }
    }


# --- kind detection + structural fallback ------------------------------------


def test_detect_kind() -> None:
    assert detect_kind(_ssp()) == "ssp"
    assert detect_kind(_poam()) == "poam"
    assert detect_kind({"component-definition": {}}) == "component"
    assert detect_kind({"nope": {}}) == "unknown"


def test_valid_ssp_passes_structural() -> None:
    r = validate_document(_ssp())
    assert r.kind == "ssp"
    assert r.mode == "structural"
    assert r.ok is True
    assert r.errors == []
    assert r.warnings  # warns that official schema was not used


def test_invalid_ssp_reports_useful_errors() -> None:
    doc = _ssp()
    del doc["system-security-plan"]["uuid"]
    doc["system-security-plan"]["metadata"].pop("oscal-version")
    doc["system-security-plan"]["control-implementation"] = None
    r = validate_document(doc)
    assert r.ok is False
    joined = " ".join(r.errors)
    assert "uuid" in joined
    assert "oscal-version" in joined
    assert "control-implementation" in joined


def test_unknown_document_kind() -> None:
    r = validate_document({"foo": 1})
    assert r.kind == "unknown"
    assert r.ok is False


def test_poam_and_explicit_kind() -> None:
    assert validate_document(_poam(), kind="poam").ok is True
    # empty required array fails
    bad = _poam()
    bad["plan-of-action-and-milestones"]["poam-items"] = []
    assert validate_document(bad).ok is False


# --- official schema + require flag ------------------------------------------


def test_official_schema_used_when_present(tmp_path, monkeypatch) -> None:
    schema = {
        "type": "object",
        "required": ["system-security-plan"],
        "properties": {
            "system-security-plan": {"type": "object", "required": ["uuid"]},
        },
    }
    (tmp_path / "oscal_ssp_schema.json").write_text(json.dumps(schema))
    monkeypatch.setenv("CCF_OSCAL_SCHEMA_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        assert official_schema_available("ssp") is True
        r = validate_document(_ssp())
        assert r.mode == "official"
        assert r.ok is True
        bad = _ssp()
        del bad["system-security-plan"]["uuid"]
        rb = validate_document(bad)
        assert rb.mode == "official"
        assert rb.ok is False
    finally:
        get_settings.cache_clear()


def test_require_official_fails_closed_without_schema(monkeypatch) -> None:
    monkeypatch.setenv("CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA", "true")
    monkeypatch.delenv("CCF_OSCAL_SCHEMA_DIR", raising=False)
    get_settings.cache_clear()
    try:
        r = validate_document(_ssp())
        assert r.ok is False
        assert any("required but not available" in e for e in r.errors)
    finally:
        get_settings.cache_clear()


# --- route -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_route() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://t"
    ) as c:
        r = await c.post("/api/oscal/validate", json=_ssp())
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["kind"] == "ssp"
        assert body["ok"] is True

        bad = await c.post(
            "/api/oscal/validate?kind=poam", json={"plan-of-action-and-milestones": {}}
        )
        assert bad.json()["ok"] is False


# --- SSP export sourced from project.metadata_json, matching the docx SSP ----


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


_METADATA = {
    "system_type": "Cloud information system (CUI)",
    "operational_status": "Under Development",
    "fips199": {
        "confidentiality": "moderate",
        "integrity": "moderate",
        "availability": "low",
        "overall": "moderate",
    },
    "authorization_boundary": (
        "The authorization boundary is the AWS GovCloud tenant and its managed "
        "endpoints, identities, and security tooling."
    ),
    "roles": {
        "system_owner": {"name": "Jane Owner", "email": "jane@example.com"},
        "isso": {"name": "Ian Security"},
        "authorizing_official": {"name": "Amy AO"},
    },
}


@pytest.mark.asyncio
async def test_ssp_export_reflects_project_metadata() -> None:
    """The OSCAL SSP must report the same categorization, boundary, and roles
    as the docx SSP — both read project.metadata_json, not a hardcoded value."""
    async with _client() as c:
        await c.post("/api/scoring/seed")
        pid = (
            await c.post(
                "/api/ssp/projects",
                json={
                    "customer_name": "MetaCo",
                    "system_name": "MetaSys",
                    "platform": "aws_govcloud",
                },
            )
        ).json()["id"]
        meta_resp = await c.put(
            f"/api/ssp/projects/{pid}/metadata",
            json={"metadata_json": _METADATA, "autofill": False},
        )
        assert meta_resp.status_code == 200, meta_resp.text

        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()
        ssp = doc["system-security-plan"]
        sysc = ssp["system-characteristics"]

        # Categorization comes from fips199.overall, not a hardcoded "cui".
        assert sysc["security-sensitivity-level"] == "moderate"
        # Status comes from operational_status, not a hardcoded "operational".
        assert sysc["status"]["state"] == "under-development"
        # Authorization boundary is present and matches the docx source text.
        assert (
            sysc["authorization-boundary"]["description"]
            == _METADATA["authorization_boundary"]
        )
        info_type = sysc["system-information"]["information-types"][0]
        assert info_type["confidentiality-impact"]["base"] == "moderate"
        assert info_type["availability-impact"]["base"] == "low"
        # Every impact "base" present must be a valid OSCAL token (no
        # whitespace) — a human-readable placeholder sentence is never valid.
        for key in ("confidentiality-impact", "integrity-impact", "availability-impact"):
            assert re.fullmatch(r"\S+", info_type[key]["base"])

        # Roles come from metadata_json["roles"] — same keys the docx "1.2 Roles
        # and Responsibilities" table reads.
        names = {p["name"] for p in ssp["metadata"]["parties"]}
        assert {"Jane Owner", "Ian Security", "Amy AO"} <= names
        role_ids = {rp["role-id"] for rp in ssp["metadata"]["responsible-parties"]}
        assert {"system-owner", "isso", "authorizing-official"} <= role_ids

        # A minimal but present system-implementation makes this structurally
        # an SSP: at least the one system component and the roles' users.
        impl = ssp["system-implementation"]
        assert impl["components"]
        assert impl["components"][0]["title"] == "MetaSys"
        assert len(impl["users"]) == 3

        report = validate_document(doc)
        assert report.ok, report.errors


@pytest.mark.asyncio
async def test_ssp_export_placeholders_when_metadata_absent() -> None:
    """Absent metadata must surface a clearly-marked placeholder, never a false
    constant like "cui"/"operational"."""
    async with _client() as c:
        await c.post("/api/scoring/seed")
        pid = (
            await c.post("/api/ssp/projects", json={"customer_name": "BareCo"})
        ).json()["id"]
        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()
        sysc = doc["system-security-plan"]["system-characteristics"]

        assert sysc["security-sensitivity-level"] != "cui"
        assert "UNSPECIFIED" in sysc["security-sensitivity-level"]
        assert sysc["status"]["state"] == "other"
        assert "UNSPECIFIED" in sysc["status"]["remarks"]
        assert "UNSPECIFIED" in sysc["authorization-boundary"]["description"]

        # An unset categorization must never fabricate an impact "base" token —
        # the confidentiality/integrity/availability-impact objects are omitted
        # entirely (never a placeholder sentence with spaces/em-dash, which is
        # not a valid OSCAL token) and the gap is noted in a props entry instead
        # (the OSCAL "information-type" object has no "remarks" property).
        info_type = sysc["system-information"]["information-types"][0]
        for key in ("confidentiality-impact", "integrity-impact", "availability-impact"):
            assert key not in info_type
        info_type_props = {p["name"]: p["value"] for p in info_type.get("props", [])}
        assert "UNSPECIFIED" in info_type_props.get("categorization-gap", "")

        # No roles filled in metadata -> no responsible-parties/parties claimed.
        meta = doc["system-security-plan"]["metadata"]
        assert not meta.get("parties")
        assert not meta.get("responsible-parties")
        # OSCAL requires system-implementation.users to be non-empty — with no
        # named responsible role, one honestly-flagged placeholder user is
        # emitted instead of an empty (schema-invalid) array.
        users = doc["system-security-plan"]["system-implementation"]["users"]
        assert len(users) == 1
        assert "UNSPECIFIED" in users[0]["remarks"]

        report = validate_document(doc)
        assert report.ok, report.errors


@pytest.mark.asyncio
async def test_ssp_and_component_definition_cite_same_baseline() -> None:
    """The SSP and component-definition exports must agree on which catalog the
    system is actually built against (CMMC L2 / NIST SP 800-171 Rev. 2 today) —
    not have the SSP claim a different baseline than the component definition."""
    async with session_scope() as s:
        org = Organization(name="BaselineOrg")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="BaselineSys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        sys_id = sysm.id

    async with _client() as c:
        await c.post("/api/scoring/seed")
        pid = (
            await c.post("/api/ssp/projects", json={"customer_name": "BaselineCo"})
        ).json()["id"]

        ssp_doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()
        comp_doc = (await c.get(f"/api/oscal/component-definition/{sys_id}")).json()

    ssp_href = ssp_doc["system-security-plan"]["import-profile"]["href"]
    comp_source = (
        comp_doc["component-definition"]["components"][0]["control-implementations"][0]["source"]
    )
    assert "800-171" in ssp_href
    assert comp_source == ssp_href
    assert "800-53" not in comp_source
