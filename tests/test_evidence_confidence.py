"""Evidence confidence — scoring order, freshness/approval effects, replay, summary."""

from __future__ import annotations

import io
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import confidence, service
from ccf.evidence.confidence import score_evidence
from ccf.models import Organization
from ccf.models_evidence_conf import EvidenceReplayRun

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "ev"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


TODAY = date(2026, 7, 1)


# --- pure scorer -------------------------------------------------------------


def _score(**kw) -> float:
    base = dict(
        source_type="manual_upload", status="draft", immutable_lock=False,
        expires_on=None, control_id="AC-2", framework="FEDRAMP", has_digest=True,
        today=TODAY,
    )
    base.update(kw)
    return score_evidence(**base)["score"]


def test_connector_evidence_scores_higher_than_screenshot() -> None:
    connector = _score(source_type="connector")
    screenshot = _score(source_type="screenshot")
    assert connector > screenshot


def test_stale_evidence_scores_lower() -> None:
    fresh = _score(expires_on=TODAY + timedelta(days=200))
    stale = _score(expires_on=TODAY - timedelta(days=1))
    assert stale < fresh


def test_approved_evidence_scores_higher() -> None:
    approved = _score(status="approved", immutable_lock=True)
    draft = _score(status="draft", immutable_lock=False)
    assert approved > draft


def test_connector_is_reproducible_manual_is_not() -> None:
    assert score_evidence(
        source_type="connector", status="approved", immutable_lock=True, expires_on=None,
        control_id="AC-2", framework="FEDRAMP", has_digest=True, today=TODAY,
    )["reproducible"] is True
    assert score_evidence(
        source_type="screenshot", status="approved", immutable_lock=True, expires_on=None,
        control_id="AC-2", framework="FEDRAMP", has_digest=True, today=TODAY,
    )["reproducible"] is False


# --- integration -------------------------------------------------------------


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org() -> int:
    async with session_scope() as s:
        org = Organization(name="ConfOrg")
        s.add(org)
        await s.flush()
        return org.id


@pytest.mark.asyncio
async def test_confidence_route_and_summary() -> None:
    async with _client() as c:
        oid = (
            await c.post(
                "/api/evidence-repo",
                json={"title": "IAM export", "source_type": "connector",
                      "control_id": "IA-2", "framework": "FEDRAMP"},
            )
        ).json()["id"]
        await c.post(f"/api/evidence-repo/{oid}/versions", files={
            "file": ("iam.json", io.BytesIO(b'{"mfa": true}'), "application/json")})

        conf = await c.get(f"/api/evidence-repo/{oid}/confidence")
        assert conf.status_code == 200
        assert conf.json()["reproducible"] is True
        assert "source_type" in conf.json()["factors"]

        summary = (await c.get("/api/evidence-repo/confidence/summary")).json()
        assert summary["scored"] >= 1
        assert summary["automated_evidence_coverage_pct"] > 0


@pytest.mark.asyncio
async def test_replay_reproduces_then_records() -> None:
    async with _client() as c:
        oid = (
            await c.post(
                "/api/evidence-repo",
                json={"title": "scan out", "source_type": "scan"},
            )
        ).json()["id"]
        await c.post(f"/api/evidence-repo/{oid}/versions", files={
            "file": ("s.txt", io.BytesIO(b"finding data"), "text/plain")})
        replay = await c.post(f"/api/evidence-repo/{oid}/replay")
        assert replay.status_code == 200
        assert replay.json()["status"] == "reproduced"
    async with session_scope() as s:
        runs = (
            await s.execute(
                select(EvidenceReplayRun).where(EvidenceReplayRun.evidence_object_id == oid)
            )
        ).scalars().all()
        assert runs and runs[0].status == "reproduced"


@pytest.mark.asyncio
async def test_manual_evidence_replay_is_not_fatal() -> None:
    org_id = await _org()
    async with session_scope() as s:
        obj = await service.create_object(
            s, org_id=org_id, title="screenshot", source_type="screenshot"
        )
        await service.add_version(s, obj, data=b"png-bytes", filename="s.png")
        run = await confidence.replay(s, obj)
        assert run.status == "not_replayable"  # captured, not an error
