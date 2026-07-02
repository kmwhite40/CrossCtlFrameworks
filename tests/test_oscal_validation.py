"""OSCAL validation — kind detection, structural fallback, official schema, route."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
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
