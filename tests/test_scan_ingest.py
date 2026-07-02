"""Scanner ingestion: parsers, severity normalization, and POA&M reconciliation."""

from __future__ import annotations

import io

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.ingest import (
    SEVERITY_SLA_DAYS,
    detect_format,
    normalize_severity,
    parse_scan,
)
from ccf.models import POAM, Organization, ScanIngestion, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# --- parser + normalization unit tests --------------------------------------

NESSUS_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report name="scan">
  <ReportHost name="web01.example.gov">
    <ReportItem severity="4" pluginID="99001" pluginName="Critical RCE">
      <synopsis>Remote code execution.</synopsis>
      <solution>Patch to 2.5.1.</solution>
      <cve>CVE-2026-0001</cve>
    </ReportItem>
    <ReportItem severity="2" pluginID="99002" pluginName="TLS 1.0 enabled">
      <description>Weak protocol.</description>
    </ReportItem>
    <ReportItem severity="0" pluginID="99003" pluginName="Informational note"/>
  </ReportHost>
</Report></NessusClientData_v2>"""

# Same host, only the moderate finding remains (the critical was remediated).
IMPROVED_NESSUS_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report name="scan">
  <ReportHost name="web01.example.gov">
    <ReportItem severity="2" pluginID="99002" pluginName="TLS 1.0 enabled">
      <description>Weak protocol.</description>
    </ReportItem>
  </ReportHost>
</Report></NessusClientData_v2>"""

INSPECTOR_JSON = b"""{"findings": [
  {"findingArn": "arn:aws:inspector2:...:f1", "title": "openssl CVE-2026-1",
   "severity": "HIGH", "description": "vuln pkg",
   "remediation": {"recommendation": {"text": "yum update openssl"}},
   "resources": [{"id": "i-0abc"}],
   "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2026-1"}},
  {"title": "info", "severity": "INFORMATIONAL", "resources": []}
]}"""

QUALYS_CSV = (
    "QID,Title,Severity,Host,Solution\n"
    "38173,SSL Certificate expired,4,db01.example.gov,Renew the certificate\n"
    "90210,Missing patch,2,app01.example.gov,Apply vendor patch\n"
)


def test_normalize_severity_scales() -> None:
    assert normalize_severity("Critical") == "critical"
    assert normalize_severity("medium") == "moderate"
    assert normalize_severity(4) == "critical"  # Nessus risk factor
    assert normalize_severity(2) == "moderate"
    assert normalize_severity(9.8) == "critical"  # CVSS
    assert normalize_severity(5.5) == "moderate"
    assert normalize_severity("informational") is None
    assert normalize_severity(0) is None
    assert normalize_severity(True) is None  # bool guard


def test_parse_nessus_skips_informational() -> None:
    scanner, findings = parse_scan("nessus", NESSUS_XML, "scan.nessus")
    assert scanner == "nessus"
    assert len(findings) == 2  # severity 0 dropped
    crit = next(f for f in findings if f.severity == "critical")
    assert crit.asset == "web01.example.gov"
    assert crit.refs == ["CVE-2026-0001"]
    assert "Patch" in crit.solution


def test_parse_inspector_maps_severity_and_resource() -> None:
    scanner, findings = parse_scan("inspector", INSPECTOR_JSON, "inspector.json")
    assert scanner == "inspector"
    assert len(findings) == 1  # informational dropped
    f = findings[0]
    assert f.severity == "high"
    assert f.asset == "i-0abc"
    assert f.native_id == "CVE-2026-1"


def test_parse_qualys_csv_fuzzy_headers() -> None:
    scanner, findings = parse_scan("qualys", QUALYS_CSV.encode(), "qualys.csv")
    assert scanner == "qualys"
    assert {f.severity for f in findings} == {"critical", "moderate"}
    assert any(f.asset == "db01.example.gov" for f in findings)


def test_detect_format_sniffs() -> None:
    assert detect_format(None, NESSUS_XML) == "nessus"
    assert detect_format(None, INSPECTOR_JSON) == "inspector"
    assert detect_format("x.csv", QUALYS_CSV.encode()) == "csv"


def test_fingerprint_stable_and_asset_sensitive() -> None:
    _, a = parse_scan("nessus", NESSUS_XML)
    _, b = parse_scan("nessus", NESSUS_XML)
    assert a[0].fingerprint() == b[0].fingerprint()
    assert a[0].fingerprint() != a[1].fingerprint()


# --- reconciliation integration tests ---------------------------------------


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _fresh_system(name: str = "ScanSys") -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "ScanOrg"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="ScanOrg")
            s.add(org)
            await s.flush()
        sys = System(organization_id=org.id, name=name, baseline="moderate")
        s.add(sys)
        await s.flush()
        return sys.id


def _upload(content: bytes, name: str, ctype: str) -> dict:
    return {"file": (name, io.BytesIO(content), ctype)}


@pytest.mark.asyncio
async def test_ingest_creates_updates_reopens_and_autocloses() -> None:
    sid = await _fresh_system()
    async with _client() as c:
        # First ingest: 2 findings → 2 new POA&Ms.
        r1 = await c.post(
            "/api/scans/ingest",
            data={"system_id": sid, "scanner": "nessus"},
            files=_upload(NESSUS_XML, "scan.nessus", "text/xml"),
        )
        assert r1.status_code == 201, r1.text
        body1 = r1.json()
        assert body1["scanner"] == "nessus"
        assert body1["created"] == 2
        assert body1["findings_total"] == 2

        # Re-ingest identical scan → idempotent (no new/changed POA&Ms).
        r2 = await c.post(
            "/api/scans/ingest",
            data={"system_id": sid, "scanner": "nessus"},
            files=_upload(NESSUS_XML, "scan.nessus", "text/xml"),
        )
        b2 = r2.json()
        assert b2["created"] == 0
        assert b2["unchanged"] == 2

        # Improved scan (only the moderate finding remains) → critical auto-closes.
        r3 = await c.post(
            "/api/scans/ingest",
            data={"system_id": sid, "scanner": "nessus"},
            files=_upload(IMPROVED_NESSUS_XML, "scan.nessus", "text/xml"),
        )
        assert r3.json()["closed"] == 1

        # Regression: full scan again → the critical reopens.
        r4 = await c.post(
            "/api/scans/ingest",
            data={"system_id": sid, "scanner": "nessus"},
            files=_upload(NESSUS_XML, "scan.nessus", "text/xml"),
        )
        assert r4.json()["reopened"] == 1

    # A critical POA&M exists with a 15-day SLA due date and scan provenance.
    async with session_scope() as s:
        poams = (
            await s.execute(select(POAM).where(POAM.system_id == sid))
        ).scalars().all()
        assert len(poams) == 2
        crit = next(p for p in poams if p.severity == "critical")
        assert crit.source == "scan"
        assert crit.scanner == "nessus"
        assert crit.finding_uid is not None
        assert crit.status == "open"
        assert (crit.due_on - crit.identified_on).days == SEVERITY_SLA_DAYS["critical"]

        ingestions = (
            await s.execute(select(ScanIngestion).where(ScanIngestion.system_id == sid))
        ).scalars().all()
        assert len(ingestions) == 4


@pytest.mark.asyncio
async def test_oscal_poam_export_reflects_scanned_findings() -> None:
    sid = await _fresh_system("ScanSys3")
    async with _client() as c:
        await c.post(
            "/api/scans/ingest",
            data={"system_id": sid, "scanner": "nessus"},
            files=_upload(NESSUS_XML, "scan.nessus", "text/xml"),
        )
        r = await c.get(f"/api/oscal/poam/{sid}")
        assert r.status_code == 200, r.text
        doc = r.json()["plan-of-action-and-milestones"]
        assert doc["metadata"]["oscal-version"].startswith("1.1")
        assert doc["system-id"]["id"] == str(sid)
        items = doc["poam-items"]
        assert len(items) == 2
        props = {p["name"]: p["value"] for p in items[0]["props"]}
        assert props["status"] == "open"
        assert props["origin"] == "scan"
        assert props["scanner"] == "nessus"
        assert "severity" in props

        # 404 for a system in no accessible org is covered by auth-off (global);
        # a non-existent system must 404.
        assert (await c.get("/api/oscal/poam/999999")).status_code == 404


@pytest.mark.asyncio
async def test_ingest_rejects_missing_file_and_bad_system() -> None:
    sid = await _fresh_system("ScanSys2")
    async with _client() as c:
        r = await c.post("/api/scans/ingest", data={"system_id": sid, "scanner": "nessus"})
        assert r.status_code == 400
        r2 = await c.post(
            "/api/scans/ingest",
            data={"system_id": 999999, "scanner": "nessus"},
            files=_upload(NESSUS_XML, "s.nessus", "text/xml"),
        )
        assert r2.status_code == 404
