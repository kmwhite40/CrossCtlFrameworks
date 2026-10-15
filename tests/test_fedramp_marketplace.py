"""FedRAMP Marketplace as reference data for dependency status.

The fixture is FedRAMP's real ``data.json`` trimmed to four products and
validated against FedRAMP's own schema; nothing here touches the network.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace as N

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.etl import sources
from ccf.fedramp20x import marketplace, package, readiness
from ccf.models import (
    CatalogSource,
    FedRAMPDependency,
    MarketplaceProduct,
    Organization,
    System,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
_FIXTURE = Path(__file__).parent / "fixtures" / "marketplace_data.json"
CLOUD_GOV = "F1607067912"  # FedRAMP Authorized, Moderate, JAB
IN_PROCESS = "FR2617641654"  # Agency In Process, Moderate, Agency
READY = "FR2616957286"  # FedRAMP Ready, Moderate, Agency
HIGH = "FR2413241182"  # FedRAMP Authorized, High, Agency


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _write(tmp: Path, mutate=None) -> Path:  # type: ignore[no-untyped-def]
    doc = json.loads(_FIXTURE.read_text())
    if mutate:
        mutate(doc)
    path = tmp / f"data-{next(_SEQ)}.json"
    path.write_text(json.dumps(doc))
    return path


@pytest.fixture
async def source(tmp_path: Path) -> AsyncIterator[CatalogSource]:
    """The registered Marketplace row, pointed at a local copy of the fixture."""
    async with session_scope() as s:
        await s.execute(delete(MarketplaceProduct))
        await s.execute(delete(CatalogSource).where(CatalogSource.key == marketplace.SOURCE_KEY))
        spec = next(x for x in sources.DEFAULT_SOURCES if x["key"] == marketplace.SOURCE_KEY)
        row = CatalogSource(**{**spec, "url": f"file://{_write(tmp_path)}"})
        s.add(row)
    yield row
    async with session_scope() as s:
        await s.execute(delete(MarketplaceProduct))
        await s.execute(delete(CatalogSource).where(CatalogSource.key == marketplace.SOURCE_KEY))


async def _point(url: str) -> None:
    async with session_scope() as s:
        row = (
            await s.execute(
                select(CatalogSource).where(CatalogSource.key == marketplace.SOURCE_KEY)
            )
        ).scalar_one()
        row.url = url


async def _refresh() -> dict:
    async with session_scope() as s:
        return await marketplace.refresh(s)


# --- registration and parsing ----------------------------------------------


def test_the_marketplace_is_a_registered_ingesting_source() -> None:
    spec = next(x for x in sources.DEFAULT_SOURCES if x["key"] == marketplace.SOURCE_KEY)
    assert spec["kind"] == "marketplace" and spec["auto_ingest"] is True
    assert spec["url"].startswith(
        "https://raw.githubusercontent.com/FedRAMP/marketplace-fedramp-gov-data/"
    )


def test_parse_reads_fedramp_s_data_and_its_sentinels() -> None:
    rows = {r["fedramp_id"]: r for r in marketplace.parse(_FIXTURE.read_bytes())}
    assert set(rows) == {CLOUD_GOV, IN_PROCESS, READY, HIGH}
    cg = rows[CLOUD_GOV]
    assert (cg["status"], cg["impact_level"], cg["auth_type"]) == (
        "FedRAMP Authorized",
        "Moderate",
        "JAB",
    )
    assert cg["auth_date"].isoformat() == "2017-02-02"
    assert rows[READY]["auth_date"] is None  # "Not Active", not a date


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d["data"]["Products"][0].pop("id"), "schema violation"),
        (lambda d: d["data"].__setitem__("Products", []), "refusing to delist all"),
    ],
)
def test_parse_refuses_bad_data(tmp_path: Path, mutate, match: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(marketplace.MarketplaceDataError, match=match):
        marketplace.parse(_write(tmp_path, mutate).read_bytes())


def test_a_tampered_vendored_schema_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    d = tmp_path / "marketplace_data"
    d.mkdir()
    for name in ("MANIFEST.json", "data.schema.json"):
        (d / name).write_bytes((marketplace._DATA_DIR / name).read_bytes())
    (d / "data.schema.json").write_text("{}")
    monkeypatch.setattr(marketplace, "_DATA_DIR", d)
    with pytest.raises(marketplace.MarketplaceDataError, match="MANIFEST pin"):
        marketplace.parse(_FIXTURE.read_bytes())


# --- refresh through the shared poller ----------------------------------------


async def test_refresh_ingests_then_is_a_no_op_then_delists_and_relists(
    source: CatalogSource, tmp_path: Path
) -> None:
    first = await _refresh()
    assert first["status"] == "ingested" and first["created"] == 4
    again = await _refresh()
    assert again["status"] == "unchanged"  # same content: nothing re-applied

    def drop_ready(doc: dict) -> None:
        doc["data"]["Products"] = [p for p in doc["data"]["Products"] if p["id"] != READY]

    await _point(f"file://{_write(tmp_path, drop_ready)}")
    gone = await _refresh()
    assert gone["delisted"] == 1
    async with session_scope() as s:
        ready = (
            await s.execute(
                select(MarketplaceProduct).where(MarketplaceProduct.fedramp_id == READY)
            )
        ).scalar_one()
        assert ready.delisted_at is not None  # delisted, never deleted
    await _point(f"file://{_write(tmp_path)}")
    back = await _refresh()
    assert back["relisted"] == 1
    async with session_scope() as s:
        ready = (
            await s.execute(
                select(MarketplaceProduct).where(MarketplaceProduct.fedramp_id == READY)
            )
        ).scalar_one()
        assert ready.delisted_at is None  # listed again means listed


async def test_a_failed_parse_keeps_the_old_etag_so_the_next_poll_retries(
    source: CatalogSource, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with session_scope() as s:
        row = (
            await s.execute(
                select(CatalogSource).where(CatalogSource.key == marketplace.SOURCE_KEY)
            )
        ).scalar_one()
        row.etag = "etag-old"

    async def fake_fetch(_url: str, _etag: str | None) -> tuple[int, bytes, str]:
        return 200, b'{"meta": {}, "data": {}}', "etag-new"

    monkeypatch.setattr(sources, "_fetch", fake_fetch)
    result = await _refresh()
    assert result["status"] == "error"
    async with session_scope() as s:
        row = (
            await s.execute(
                select(CatalogSource).where(CatalogSource.key == marketplace.SOURCE_KEY)
            )
        ).scalar_one()
        assert row.etag == "etag-old"
        assert row.last_sha256 is None


async def test_a_disabled_source_is_not_fetched(source: CatalogSource) -> None:
    async with session_scope() as s:
        row = (
            await s.execute(
                select(CatalogSource).where(CatalogSource.key == marketplace.SOURCE_KEY)
            )
        ).scalar_one()
        row.enabled = False
    assert (await _refresh())["status"] == "skipped"


# --- comparing ---------------------------------------------------------------


def _dep(**kw: object) -> N:
    base = {
        "marketplace_id": CLOUD_GOV,
        "fedramp_status": "authorized",
        "impact_level": "moderate",
        "authorization_level": "jab",
    }
    return N(**{**base, **kw})


def _product(**kw: object) -> N:
    base = {
        "status": "FedRAMP Authorized",
        "impact_level": "Moderate",
        "auth_type": "JAB",
        "delisted_at": None,
        "cso": "Cloud.Gov",
    }
    return N(**{**base, **kw})


def test_agreement_raises_nothing() -> None:
    assert marketplace.compare(_dep(), _product()) == []  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("dep", "product", "field"),
    [
        ({}, {"status": "FedRAMP Ready"}, "fedramp_status"),  # Ready is not authorized
        ({}, {"impact_level": "High"}, "impact_level"),
        ({"impact_level": "low"}, {"impact_level": "20x Moderate"}, "impact_level"),
        ({"authorization_level": "agency"}, {}, "authorization_level"),
        ({}, {"delisted_at": __import__("datetime").datetime(2026, 9, 1)}, "listing"),
    ],
)
def test_each_disagreement_is_named(dep: dict, product: dict, field: str) -> None:
    found = marketplace.compare(_dep(**dep), _product(**product))  # type: ignore[arg-type]
    assert [f.field for f in found] == [field]


@pytest.mark.parametrize(
    ("dep", "product"),
    [
        ({"fedramp_status": "unknown"}, {"status": "FedRAMP Ready"}),  # unknown claims nothing
        ({"fedramp_status": "in_process"}, {"status": "Agency In Process"}),
        ({"impact_level": "low"}, {"impact_level": "LI-SaaS"}),
        ({"authorization_level": "li-saas"}, {"auth_type": "Agency"}),  # different axis
        ({"authorization_level": "agency"}, {"auth_type": "Program"}),  # no counterpart
    ],
)
def test_what_is_not_a_disagreement(dep: dict, product: dict) -> None:
    assert marketplace.compare(_dep(**dep), _product(**product)) == []  # type: ignore[arg-type]


def test_an_unlinked_dependency_has_no_findings_and_an_unheld_link_one() -> None:
    assert marketplace.compare(_dep(marketplace_id=None), None) == []  # type: ignore[arg-type]
    assert [f.field for f in marketplace.compare(_dep(), None)] == ["marketplace_id"]  # type: ignore[arg-type]


# --- end to end --------------------------------------------------------------


async def _system_with_dep(**dep: object) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=f"Mkt Org {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"Mkt {next(_SEQ)}")
        s.add(sysm)
        await s.flush()
        d = FedRAMPDependency(system_id=sysm.id, name="Cloud.gov", **dep)
        s.add(d)
        await s.flush()
        return sysm.id, d.id


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def test_link_search_and_show_beside_the_recorded_value(source: CatalogSource) -> None:
    await _refresh()
    sid, did = await _system_with_dep(fedramp_status="authorized", impact_level="moderate")
    async with _client() as c:
        found = (await c.get("/api/fedramp/20x/marketplace/products?q=cloud.gov")).json()
        assert [p["fedramp_id"] for p in found] == [CLOUD_GOV]
        bad = await c.put(
            f"/api/fedramp/20x/systems/{sid}/dependencies/{did}/marketplace",
            json={"marketplace_id": "F0000000000"},
        )
        assert bad.status_code == 422
        ok = await c.put(
            f"/api/fedramp/20x/systems/{sid}/dependencies/{did}/marketplace",
            json={"marketplace_id": READY},  # recorded authorized; FedRAMP says Ready
        )
        assert ok.status_code == 200
        listed = (await c.get(f"/api/fedramp/20x/systems/{sid}/dependencies")).json()
    dep = listed["dependencies"][0]
    assert dep["fedramp_status"] == "authorized"  # never rewritten
    assert dep["marketplace"]["status"] == "FedRAMP Ready"
    assert [f["field"] for f in dep["marketplace_findings"]] == ["fedramp_status"]
    assert listed["marketplace_disagreements"] == 1
    async with session_scope() as s:
        score = await readiness.score_system(s, system_id=sid, persist=False)
        pkg = await package.build_package(s, system_id=sid)
    assert score["marketplace_disagreements"] == 1
    assert score["dependency_readiness"] == 100  # the score still reads the record
    assert pkg["dependencies"][0]["marketplace_status"] == "FedRAMP Ready"
    assert pkg["dependencies"][0]["marketplace_findings"][0]["field"] == "fedramp_status"


async def test_the_page_links_and_shows_a_finding(source: CatalogSource) -> None:
    from ccf.fedramp20x import catalog  # noqa: PLC0415

    async with session_scope() as s:
        await catalog.seed_ksis(s)  # the page renders a system only over a catalog
    await _refresh()
    sid, did = await _system_with_dep(fedramp_status="authorized", impact_level="moderate")
    async with _client() as c:
        unknown = await c.post(
            f"/fedramp20x/{sid}/dependencies/{did}/marketplace",
            data={"marketplace_id": "F0000000000"},
            follow_redirects=False,
        )
        assert unknown.status_code == 303
        async with session_scope() as s:
            assert (await s.get(FedRAMPDependency, did)).marketplace_id is None  # type: ignore[union-attr]
        await c.post(
            f"/fedramp20x/{sid}/dependencies/{did}/marketplace",
            data={"marketplace_id": HIGH},
            follow_redirects=False,
        )
        page = (await c.get(f"/fedramp20x?system_id={sid}")).text
    assert "FedRAMP Authorized · High" in page
    assert "Recorded impact &#39;moderate&#39;; the Marketplace lists &#39;High&#39;." in page
