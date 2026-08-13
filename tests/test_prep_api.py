"""Prep REST surface and confidence-scorer integration."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence.confidence import prep_signal
from ccf.models import Organization, Policy, PolicyVersion
from ccf.models_prep import PrepJob, PrepRun

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _prep_enabled() -> Iterator[None]:
    """``/api/prep/*`` is only registered when ``CCF_PREP_ENABLED`` is set —
    it's off by default, matching every other billable-AI-call feature in
    this app. Set here rather than flipping the default.
    """
    os.environ["CCF_PREP_ENABLED"] = "true"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_PREP_ENABLED", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _clean_prep_queue() -> AsyncIterator[None]:
    """``prep_jobs``/``prep_runs`` are a genuinely global queue (see
    ``test_prep_jobs.py``'s identical ``_clean_job_queue``): the schema is reset
    only once per pytest session, not per test, so runs this module enqueues via
    the live API would otherwise leak into ``ccf.prep_jobs`` for the rest of the
    session — including into ``test_prep_jobs.py``'s unfiltered
    ``select(PrepJob).scalars().one()`` assertions, which then see this module's
    rows too and fail on ordering, not behavior. Scoped to this module's own
    ``prep-api-*``-named organizations only.
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            org_ids = (
                (
                    await s.execute(
                        select(Organization.id).where(Organization.name.like("prep-api-%"))
                    )
                )
                .scalars()
                .all()
            )
            if org_ids:
                # ON DELETE CASCADE on PrepJob.run_id -> PrepRun.id removes the
                # dependent jobs too.
                await s.execute(delete(PrepRun).where(PrepRun.organization_id.in_(org_ids)))

    await _wipe()
    yield
    await _wipe()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _uri_only_policy_version(org_id: int) -> int:
    """A real, same-org PolicyVersion with no inline body -- see the identical
    helper (and its full rationale) in ``test_prep_jobs.py``: ``jobs.enqueue``
    now refuses a ``source_id`` that does not resolve to a real source owned by
    the requested organization, so these tests need a real source, not the
    literal ``source_id=1`` the brief originally used.
    """
    async with session_scope() as s:
        policy = Policy(organization_id=org_id, name="Uri Only Policy")
        s.add(policy)
        await s.flush()
        version = PolicyVersion(policy_id=policy.id, version="1.0")
        s.add(version)
        await s.flush()
        return int(version.id)


def test_prep_signal_rewards_stronger_evidence_monotonically() -> None:
    assert prep_signal("strong") > prep_signal("moderate") > prep_signal("weak")


def test_prep_signal_is_neutral_when_unclassified() -> None:
    """An unprepared evidence object must not be penalised for lacking a signal."""
    assert prep_signal(None) == 0.0
    assert prep_signal("nonsense") == 0.0


async def test_post_runs_enqueues_and_returns_identifiers() -> None:
    org_id = await _org("prep-api-post")
    source_id = await _uri_only_policy_version(org_id)
    async with _client() as client:
        response = await client.post(
            "/api/prep/runs",
            json={
                "organization_id": org_id,
                "source_kind": "policy_version",
                "source_id": source_id,
            },
        )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "pending"
    async with session_scope() as s:
        assert (
            await s.execute(select(PrepRun).where(PrepRun.id == body["run_id"]))
        ).scalar_one_or_none() is not None
        assert (
            await s.execute(select(PrepJob).where(PrepJob.id == body["job_id"]))
        ).scalar_one_or_none() is not None


async def test_post_runs_rejects_an_unknown_source_kind() -> None:
    org_id = await _org("prep-api-bad-kind")
    async with _client() as client:
        response = await client.post(
            "/api/prep/runs",
            json={"organization_id": org_id, "source_kind": "nonsense", "source_id": 1},
        )
    assert response.status_code == 422


async def test_get_run_reports_every_stage_status() -> None:
    org_id = await _org("prep-api-get")
    source_id = await _uri_only_policy_version(org_id)
    async with _client() as client:
        created = (
            await client.post(
                "/api/prep/runs",
                json={
                    "organization_id": org_id,
                    "source_kind": "policy_version",
                    "source_id": source_id,
                },
            )
        ).json()
        response = await client.get(f"/api/prep/runs/{created['run_id']}")
    assert response.status_code == 200
    body = response.json()
    assert set(body["stages"]) == {"parse", "screen", "expand", "classify", "embed"}
    assert body["stages"]["parse"] == "pending"


async def test_get_run_returns_404_for_an_unknown_run() -> None:
    async with _client() as client:
        assert (await client.get("/api/prep/runs/999999")).status_code == 404


async def test_retrieve_endpoint_returns_an_empty_list_for_an_empty_corpus() -> None:
    org_id = await _org("prep-api-retrieve")
    async with _client() as client:
        response = await client.get(
            "/api/prep/retrieve", params={"organization_id": org_id, "control": "AC-2"}
        )
    assert response.status_code == 200
    assert response.json()["results"] == []
