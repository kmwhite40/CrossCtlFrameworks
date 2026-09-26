"""Posture endpoints, including the org-wide failing-resources query."""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

from ccf.api.main import create_app
from ccf.cli import app as cli_app
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_openapi_lists_posture_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/systems/{system_id}/scan" in paths
        assert "/api/systems/{system_id}/scan-all" in paths
        assert "/api/posture/failing-resources" in paths
        assert "/api/controls/{control_id}/effective-verdict" in paths
        assert "/api/control-tests/{test_id}/results/{result_id}/resources" in paths


@pytest.mark.asyncio
async def test_existing_posture_rollups_still_served() -> None:
    """The prefix now means two things; the original endpoints must survive."""
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/posture/summary" in paths
        assert "/api/posture/evidence-freshness" in paths


@pytest.mark.asyncio
async def test_failing_resources_returns_only_failures() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ApiPostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        t = ControlTest(
            organization_id=org.id, system_id=sys_.id, control_id="AC-3", name="demo"
        )
        session.add(t)
        await session.flush()
        r = ControlTestResult(control_test_id=t.id, status="fail", evaluated=2, failing=1)
        session.add(r)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=r.id,
                resource_id="bad-bucket",
                resource_type="s3_bucket",
                verdict="fail",
                observed="public",
            )
        )
        session.add(
            ControlTestResourceResult(
                result_id=r.id,
                resource_id="good-bucket",
                resource_type="s3_bucket",
                verdict="pass",
                observed="blocked",
            )
        )
        await session.flush()
        result_id, test_id = r.id, t.id

    async with _client() as client:
        failing = await client.get("/api/posture/failing-resources")
        assert failing.status_code == 200
        ids = [row["resource_id"] for row in failing.json()]
        assert "bad-bucket" in ids
        assert "good-bucket" not in ids

        detail = await client.get(
            f"/api/control-tests/{test_id}/results/{result_id}/resources"
        )
        assert detail.status_code == 200
        assert len(detail.json()) == 2  # the per-result view shows all of them


@pytest.mark.asyncio
async def test_failing_resources_excludes_a_remediated_resource() -> None:
    """A resource that failed an older run and passed a newer run of the same
    test must not show up as "currently failing" -- the endpoint's docstring
    promise. Two results on one control test: an older fail, then a newer
    pass for the same resource.
    """
    async with session_scope() as session:
        org = Organization(name=f"ApiPostRecoverOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostRecoverSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        t = ControlTest(
            organization_id=org.id, system_id=sys_.id, control_id="AC-3", name="demo"
        )
        session.add(t)
        await session.flush()

        old = ControlTestResult(control_test_id=t.id, status="fail", evaluated=1, failing=1)
        session.add(old)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=old.id,
                resource_id="bucket-x",
                resource_type="s3_bucket",
                verdict="fail",
                observed="public",
            )
        )
        await session.flush()

        new = ControlTestResult(control_test_id=t.id, status="pass", evaluated=1, failing=0)
        session.add(new)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=new.id,
                resource_id="bucket-x",
                resource_type="s3_bucket",
                verdict="pass",
                observed="blocked",
            )
        )
        await session.flush()

    async with _client() as client:
        failing = await client.get("/api/posture/failing-resources")
        assert failing.status_code == 200
        ids = [row["resource_id"] for row in failing.json()]
        assert "bucket-x" not in ids


@pytest.mark.asyncio
async def test_failing_resources_survives_a_zero_finding_scan() -> None:
    """A connector outcome with zero findings (a permissions error, an empty
    page) must not displace an earlier, informative result as "latest" -- or
    the endpoint would go silent about a collection failure, reading it as a
    clean scan instead.
    """
    async with session_scope() as session:
        org = Organization(name=f"ApiPostEmptyOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostEmptySys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        t = ControlTest(
            organization_id=org.id, system_id=sys_.id, control_id="AC-3", name="demo"
        )
        session.add(t)
        await session.flush()

        good = ControlTestResult(control_test_id=t.id, status="fail", evaluated=1, failing=1)
        session.add(good)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=good.id,
                resource_id="bucket-y",
                resource_type="s3_bucket",
                verdict="fail",
                observed="public",
            )
        )
        await session.flush()

        # A later scan that found nothing to evaluate -- a collection failure,
        # not a clean posture.
        empty = ControlTestResult(control_test_id=t.id, status="fail", evaluated=0, failing=0)
        session.add(empty)
        await session.flush()

    async with _client() as client:
        failing = await client.get("/api/posture/failing-resources")
        assert failing.status_code == 200
        ids = [row["resource_id"] for row in failing.json()]
        assert "bucket-y" in ids, "the empty scan must not silently clear the prior failure"


@pytest.mark.asyncio
async def test_failing_resources_filters_by_resource_type() -> None:
    async with _client() as client:
        r = await client.get("/api/posture/failing-resources?resource_type=no_such_type")
        assert r.status_code == 200
        assert r.json() == []


@pytest.mark.asyncio
async def test_scan_on_an_unconfigured_connector_reports_the_reason() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ApiPostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        sid = sys_.id

    async with _client() as client:
        r = await client.post(f"/api/systems/{sid}/scan?connector=aws_govcloud")
        assert r.status_code == 200
        assert r.json()["checks_run"] == 0
        assert "not configured" in r.json()["reason"]


@pytest.mark.asyncio
async def test_scan_on_an_unknown_system_is_404() -> None:
    async with _client() as client:
        r = await client.post("/api/systems/999999/scan?connector=aws_govcloud")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_unknown_result_for_a_test_is_404() -> None:
    async with _client() as client:
        r = await client.get("/api/control-tests/999999/results/999999/resources")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_effective_verdict_reports_no_source_when_unobserved() -> None:
    async with session_scope() as session:
        org = Organization(name=f"ApiPostOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ApiPostSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        sid = sys_.id

    async with _client() as client:
        r = await client.get(f"/api/controls/AC-3/effective-verdict?system_id={sid}")
        assert r.status_code == 200
        assert r.json()["source"] is None


def test_posture_cli_is_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(cli_app, ["posture", "scan", "--help"])
    assert result.exit_code == 0
    assert "connector" in result.stdout


@pytest.mark.asyncio
async def test_scan_all_keeps_the_providers_that_worked_when_one_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One broken provider must not discard the providers that succeeded.

    Without per-provider isolation the whole request raised, the commit never
    ran, and a tenant with a healthy Microsoft 365 connector and a broken AWS one
    recorded nothing at all -- while the error named only the broken half.
    """
    from ccf.api.routes import posture as posture_routes

    async with session_scope() as s:
        org = Organization(name=f"ScanAllOrg-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"ScanAllSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        system_id = sys_.id

    calls: list[str] = []

    async def _fake_scan(session, *, system_id: int, connector_key: str, actor: str):
        calls.append(connector_key)
        if connector_key == "aws_govcloud":
            raise RuntimeError("credential rejected")
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_expected": 2,
            "checks_run": 1,
            "results": [{"check_key": "k", "verdict": "pass"}],
            "skipped_checks": [{"check_key": "other", "reason": "no outcome"}],
            "unexpected_outcomes": [],
        }

    import ccf.posture.scan as scan_module

    monkeypatch.setattr(scan_module, "scan_for_system", _fake_scan)
    monkeypatch.setattr(posture_routes, "connector_keys", lambda: ("msgraph", "aws_govcloud"))

    async with _client() as client:
        r = await client.post(f"/api/systems/{system_id}/scan-all")
    assert r.status_code == 200, r.text
    body = r.json()

    assert calls == ["msgraph", "aws_govcloud"], "a failure stopped the remaining providers"
    # The healthy provider's work survived.
    assert body["checks_run"] == 1
    assert body["providers_scanned"] == 1
    # And the broken one is named, with a reason, rather than vanishing.
    unavailable = {u["connector"]: u["reason"] for u in body["providers_unavailable"]}
    assert "aws_govcloud" in unavailable
    assert "RuntimeError" in unavailable["aws_govcloud"]
    assert "nothing was recorded" in unavailable["aws_govcloud"]


@pytest.mark.asyncio
async def test_scan_all_does_not_reuse_the_per_provider_key_for_its_own_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`skipped_checks` is a list per provider, so the aggregate needs its own name.

    One key holding an int at the top level and a list one level down forces a
    consumer to branch on where it happens to be looking.
    """
    from ccf.api.routes import posture as posture_routes

    async with session_scope() as s:
        org = Organization(name=f"ScanAllShape-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"ScanAllShapeSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        system_id = sys_.id

    async def _fake_scan(session, *, system_id: int, connector_key: str, actor: str):
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_expected": 3,
            "checks_run": 1,
            "results": [],
            "skipped_checks": [{"check_key": "a"}, {"check_key": "b"}],
            "unexpected_outcomes": [],
        }

    import ccf.posture.scan as scan_module

    monkeypatch.setattr(scan_module, "scan_for_system", _fake_scan)
    monkeypatch.setattr(posture_routes, "connector_keys", lambda: ("msgraph",))

    async with _client() as client:
        body = (await client.post(f"/api/systems/{system_id}/scan-all")).json()

    assert body["skipped_checks_total"] == 2
    assert "skipped_checks" not in body, "the aggregate shadows the per-provider list"
    assert isinstance(body["connectors"][0]["skipped_checks"], list)
    assert body["checks_expected"] == 3
