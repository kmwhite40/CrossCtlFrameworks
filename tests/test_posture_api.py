"""Posture endpoints, including the org-wide failing-resources query."""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from typer.testing import CliRunner

import ccf.posture.scan_all as scan_all_module
from ccf.api.main import create_app
from ccf.cli import app as cli_app
from ccf.db import session_scope
from ccf.governance.control_tests import GENERATED_PLAN
from ccf.models import POAM, Organization, System
from ccf.models_grc import (
    ConnectorConfig,
    ControlTest,
    ControlTestResourceResult,
    ControlTestResult,
)
from ccf.posture import audit_plan as audit_plan_module

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_openapi_lists_posture_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/systems/{system_id}/scan" in paths
        assert "/api/systems/{system_id}/scan-all" in paths
        assert "/api/systems/{system_id}/provider-readiness" in paths
        assert "/api/systems/{system_id}/audit-plan" in paths
        assert "/api/systems/{system_id}/control-evaluations" in paths
        assert "/api/systems/{system_id}/live-audit-workflow" in paths
        assert "/api/control-tests/{test_id}/poam" in paths
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
        assert r.json()["readiness"]["status"] == "not_configured"
        assert r.json()["reason"]


@pytest.mark.asyncio
async def test_scan_on_an_unknown_system_is_404() -> None:
    async with _client() as client:
        r = await client.post("/api/systems/999999/scan?connector=aws_govcloud")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_live_audit_workflow_starts_with_connector_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with session_scope() as session:
        org = Organization(name=f"WorkflowOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"WorkflowSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        system_id = sys_.id

    async def _ready(session, *, organization_id: int | None, connector_key: str, persist: bool):
        return {
            "connector": connector_key,
            "status": "not_configured",
            "ready": False,
            "configured": False,
            "connected": False,
            "checks_expected": 1,
            "checks": [
                {
                    "check_key": f"{connector_key}.api",
                    "title": "API check",
                    "control_ids": ["AC-2"],
                    "resource_type": "tenant",
                    "source": "platform",
                    "required_permissions": [],
                    "responsibility": {"responsibility": "customer"},
                    "scan_applicability": "scan",
                }
            ],
            "required_permissions": [],
            "reason": "not configured",
        }

    monkeypatch.setattr(audit_plan_module, "provider_readiness", _ready)
    monkeypatch.setattr(audit_plan_module, "known_providers", lambda: frozenset({"msgraph"}))

    async with _client() as client:
        r = await client.get(f"/api/systems/{system_id}/live-audit-workflow")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["next_action"] == "verify_connectors"
    assert body["steps"][0]["key"] == "verify_connectors"
    assert body["steps"][0]["status"] == "needs_attention"
    assert body["control_evaluations"]["total"] == 0
    assert body["ssp"] is None


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
    async with session_scope() as s:
        org = Organization(name=f"ScanAllOrg-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"ScanAllSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        # Every provider these tests exercise is put *in scope* explicitly.
        # `scan_all_providers` now resolves provider scope per environment
        # (ccf.posture.scope): a system with no declared cloud platform and no
        # configured connector is assessed against nothing, because a
        # Microsoft-only tenant was being given thirteen AWS verdicts. The
        # subject of this test is unchanged -- it is about the scan's own
        # behaviour, not about scope -- so it declares an environment the way a
        # real organization does.
        for connector_type in ("msgraph", "aws_govcloud", "azure_arm", "gcp", "puppetdb"):
            s.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{connector_type} fixture",
                    connector_type=connector_type,
                )
            )
        await s.flush()
        system_id = sys_.id

    calls: list[str] = []

    async def _fake_scan(
        session,
        *,
        system_id: int,
        connector_key: str,
        actor: str,
        check_keys: set[str] | None = None,
    ):
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

    async def _ready(session, *, organization_id: int | None, connector_key: str, persist: bool):
        return {
            "connector": connector_key,
            "status": "ready",
            "ready": True,
            "configured": True,
            "connected": True,
            "checks_expected": 2,
            "checks": [],
            "required_permissions": [],
        }

    monkeypatch.setattr(scan_all_module, "scan_for_system", _fake_scan)
    monkeypatch.setattr(scan_all_module, "provider_readiness", _ready)
    monkeypatch.setattr(
        scan_all_module, "known_providers", lambda: frozenset({"msgraph", "aws_govcloud"})
    )

    async with _client() as client:
        r = await client.post(f"/api/systems/{system_id}/scan-all")
    assert r.status_code == 200, r.text
    body = r.json()

    assert calls == ["aws_govcloud", "msgraph"], "a failure stopped the remaining providers"
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
    async with session_scope() as s:
        org = Organization(name=f"ScanAllShape-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"ScanAllShapeSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        # Every provider these tests exercise is put *in scope* explicitly.
        # `scan_all_providers` now resolves provider scope per environment
        # (ccf.posture.scope): a system with no declared cloud platform and no
        # configured connector is assessed against nothing, because a
        # Microsoft-only tenant was being given thirteen AWS verdicts. The
        # subject of this test is unchanged -- it is about the scan's own
        # behaviour, not about scope -- so it declares an environment the way a
        # real organization does.
        for connector_type in ("msgraph", "aws_govcloud", "azure_arm", "gcp", "puppetdb"):
            s.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{connector_type} fixture",
                    connector_type=connector_type,
                )
            )
        await s.flush()
        system_id = sys_.id

    async def _fake_scan(
        session,
        *,
        system_id: int,
        connector_key: str,
        actor: str,
        check_keys: set[str] | None = None,
    ):
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_expected": 3,
            "checks_run": 1,
            "results": [],
            "skipped_checks": [{"check_key": "a"}, {"check_key": "b"}],
            "unexpected_outcomes": [],
        }

    async def _ready(session, *, organization_id: int | None, connector_key: str, persist: bool):
        return {
            "connector": connector_key,
            "status": "ready",
            "ready": True,
            "configured": True,
            "connected": True,
            "checks_expected": 3,
            "checks": [],
            "required_permissions": [],
        }

    monkeypatch.setattr(scan_all_module, "scan_for_system", _fake_scan)
    monkeypatch.setattr(scan_all_module, "provider_readiness", _ready)
    monkeypatch.setattr(scan_all_module, "known_providers", lambda: frozenset({"msgraph"}))

    async with _client() as client:
        body = (await client.post(f"/api/systems/{system_id}/scan-all")).json()

    assert body["skipped_checks_total"] == 2
    assert "skipped_checks" not in body, "the aggregate shadows the per-provider list"
    assert isinstance(body["connectors"][0]["skipped_checks"], list)
    assert body["checks_expected"] == 3


@pytest.mark.asyncio
async def test_audit_plan_separates_api_checks_from_manual_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with session_scope() as s:
        org = Organization(name=f"AuditPlanOrg-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"AuditPlanSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        system_id = sys_.id

    async def _ready(session, *, organization_id: int | None, connector_key: str, persist: bool):
        return {
            "connector": connector_key,
            "status": "ready" if connector_key == "msgraph" else "not_configured",
            "ready": connector_key == "msgraph",
            "configured": connector_key == "msgraph",
            "connected": connector_key == "msgraph",
            "checks_expected": 2,
            "checks": [
                {
                    "check_key": f"{connector_key}.scan",
                    "title": "scan check",
                    "control_ids": ["AC-2"],
                    "resource_type": "tenant",
                    "source": "platform",
                    "required_permissions": [],
                    "responsibility": {"responsibility": "shared"},
                    "scan_applicability": "scan",
                },
                {
                    "check_key": f"{connector_key}.inherited",
                    "title": "inherited check",
                    "control_ids": ["PE-2"],
                    "resource_type": "tenant",
                    "source": "platform",
                    "required_permissions": [],
                    "responsibility": {"responsibility": "inherited"},
                    "scan_applicability": "inherited_evidence",
                },
            ],
            "required_permissions": [],
            "reason": None if connector_key == "msgraph" else "not configured",
        }

    async def _framework_posture(session, *, org_id: int | None, system_id: int):
        return {
            "framework": "fedramp_moderate",
            "framework_label": "NIST SP 800-53 Moderate",
            "framework_source": "system.baseline",
            "denominator": "fips199_baseline",
            "unit": "control",
            "baseline": "moderate",
            "total": 4,
            "passing": ["AC-2"],
            "failing": [],
            "documented": ["PE-2"],
            "unaddressed": ["AU-2", "CM-2"],
            "addressed_pct": 50.0,
            "assessed_pct": 25.0,
            "unmappable_controls": [],
            "unreachable": [],
            "practice_ids": {},
            "reason": None,
            "system_id": system_id,
            "system": "AuditPlanSys",
        }

    monkeypatch.setattr(
        scan_all_module, "known_providers", lambda: frozenset({"msgraph", "aws_govcloud"})
    )
    monkeypatch.setattr(
        audit_plan_module,
        "known_providers",
        lambda: frozenset({"msgraph", "aws_govcloud"}),
    )
    monkeypatch.setattr(audit_plan_module, "provider_readiness", _ready)
    monkeypatch.setattr(audit_plan_module, "system_framework_posture", _framework_posture)

    async with _client() as client:
        r = await client.get(f"/api/systems/{system_id}/audit-plan")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["summary"]["api_checks"] == 1
    assert body["summary"]["framework_total"] == 4
    assert body["summary"]["framework_automated"] == 1
    assert body["summary"]["framework_manual_review_required"] == 2
    assert body["api_checks"][0]["check_key"] == "msgraph.scan"
    assert {c["id"] for c in body["framework_manual_review_required"]} == {"AU-2", "CM-2"}
    manual = {c["check_key"]: c["reason"] for c in body["manual_review_required"]}
    assert manual["msgraph.inherited"] == "inherited_evidence"
    assert manual["aws_govcloud.scan"] == "not configured"


@pytest.mark.asyncio
async def test_scan_all_scans_only_api_applicable_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with session_scope() as s:
        org = Organization(name=f"ScanAllApplicableOrg-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"ScanAllApplicableSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        # Every provider these tests exercise is put *in scope* explicitly.
        # `scan_all_providers` now resolves provider scope per environment
        # (ccf.posture.scope): a system with no declared cloud platform and no
        # configured connector is assessed against nothing, because a
        # Microsoft-only tenant was being given thirteen AWS verdicts. The
        # subject of this test is unchanged -- it is about the scan's own
        # behaviour, not about scope -- so it declares an environment the way a
        # real organization does.
        for connector_type in ("msgraph", "aws_govcloud", "azure_arm", "gcp", "puppetdb"):
            s.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{connector_type} fixture",
                    connector_type=connector_type,
                )
            )
        await s.flush()
        system_id = sys_.id

    scanned_keys: set[str] | None = None

    async def _fake_scan(
        session,
        *,
        system_id: int,
        connector_key: str,
        actor: str,
        check_keys: set[str] | None = None,
    ):
        nonlocal scanned_keys
        scanned_keys = check_keys
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_expected": len(check_keys or set()),
            "checks_run": len(check_keys or set()),
            "results": [{"check_key": key, "verdict": "pass"} for key in sorted(check_keys or [])],
            "skipped_checks": [],
            "unexpected_outcomes": [],
        }

    async def _ready(session, *, organization_id: int | None, connector_key: str, persist: bool):
        return {
            "connector": connector_key,
            "status": "ready",
            "ready": True,
            "configured": True,
            "connected": True,
            "checks_expected": 2,
            "checks": [
                {
                    "check_key": "msgraph.api",
                    "title": "API check",
                    "expected": "API verifies this control",
                    "control_ids": ["AC-2"],
                    "resource_type": "tenant",
                    "source": "platform",
                    "required_permissions": [],
                    "responsibility": {"responsibility": "customer"},
                    "scan_applicability": "scan",
                },
                {
                    "check_key": "msgraph.inherited",
                    "title": "Inherited check",
                    "expected": "provider CRM evidences this control",
                    "control_ids": ["PE-2"],
                    "resource_type": "tenant",
                    "source": "platform",
                    "required_permissions": [],
                    "responsibility": {"responsibility": "inherited"},
                    "scan_applicability": "inherited_evidence",
                },
            ],
            "required_permissions": [],
        }

    monkeypatch.setattr(scan_all_module, "scan_for_system", _fake_scan)
    monkeypatch.setattr(scan_all_module, "provider_readiness", _ready)
    monkeypatch.setattr(scan_all_module, "known_providers", lambda: frozenset({"msgraph"}))

    async with _client() as client:
        r = await client.post(f"/api/systems/{system_id}/scan-all")
    assert r.status_code == 200, r.text
    body = r.json()
    assert scanned_keys == {"msgraph.api"}
    assert body["checks_run"] == 1
    assert body["connectors"][0]["manual_review_results"][0]["check_key"] == (
        "msgraph.inherited"
    )


@pytest.mark.asyncio
async def test_scan_all_records_manual_review_required_for_unavailable_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with session_scope() as s:
        org = Organization(name=f"ManualReviewOrg-{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"ManualReviewSys-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        # Every provider these tests exercise is put *in scope* explicitly.
        # `scan_all_providers` now resolves provider scope per environment
        # (ccf.posture.scope): a system with no declared cloud platform and no
        # configured connector is assessed against nothing, because a
        # Microsoft-only tenant was being given thirteen AWS verdicts. The
        # subject of this test is unchanged -- it is about the scan's own
        # behaviour, not about scope -- so it declares an environment the way a
        # real organization does.
        for connector_type in ("msgraph", "aws_govcloud", "azure_arm", "gcp", "puppetdb"):
            s.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{connector_type} fixture",
                    connector_type=connector_type,
                )
            )
        await s.flush()
        system_id = sys_.id

    async def _ready(session, *, organization_id: int | None, connector_key: str, persist: bool):
        return {
            "connector": connector_key,
            "status": "not_configured",
            "ready": False,
            "configured": False,
            "connected": False,
            "checks_expected": 1,
            "checks": [
                {
                    "check_key": f"{connector_key}.blocked",
                    "title": "Blocked provider check",
                    "expected": "provider API can evaluate the control",
                    "control_ids": ["AC-2"],
                    "resource_type": "tenant",
                    "source": "platform",
                    "required_permissions": [],
                    "responsibility": {"responsibility": "shared"},
                    "scan_applicability": "scan",
                }
            ],
            "required_permissions": [],
            "reason": "not configured",
        }

    monkeypatch.setattr(scan_all_module, "provider_readiness", _ready)
    monkeypatch.setattr(scan_all_module, "known_providers", lambda: frozenset({"msgraph"}))

    async with _client() as client:
        r = await client.post(f"/api/systems/{system_id}/scan-all")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["connectors"][0]["manual_review_results"][0]["verdict"] == (
        "manual_review_required"
    )

    async with session_scope() as s:
        row = (
            await s.execute(
                select(ControlTestResult, ControlTest)
                .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
                .where(ControlTest.system_id == system_id)
            )
        ).one()
        result, test = row
        assert test.check_key == "msgraph.blocked"
        assert result.status == "manual_review_required"
        assert result.detail == "not configured"


@pytest.mark.asyncio
async def test_control_evaluations_include_resources_and_poam_link() -> None:
    async with session_scope() as session:
        org = Organization(name=f"EvalOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"EvalSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-2",
            name="MFA check",
            source="generated",
            check_key="m365.identity.mfa_registered",
            connector_type="msgraph",
            expected="every user has MFA",
        )
        session.add(test)
        await session.flush()
        result = ControlTestResult(
            control_test_id=test.id,
            status="fail",
            detail="1 of 2 users failing",
            evaluated=2,
            failing=1,
            expected="every user has MFA",
            evidence_ref="graph://result/1",
        )
        session.add(result)
        await session.flush()
        session.add(
            ControlTestResourceResult(
                result_id=result.id,
                resource_id="user-1",
                resource_type="entra_user",
                verdict="fail",
                observed="no registered method",
            )
        )
        session.add(
            POAM(
                system_id=sys_.id,
                title="Control test failed: MFA check (AC-2)",
                weakness="MFA missing",
                severity="high",
                status="open",
                source="control_test",
                source_ref=f"control_test:{test.id}",
            )
        )
        await session.flush()
        system_id = sys_.id

    async with _client() as client:
        r = await client.get(f"/api/systems/{system_id}/control-evaluations")
    assert r.status_code == 200, r.text
    rows = r.json()
    row = next(e for e in rows if e["check_key"] == "m365.identity.mfa_registered")
    assert row["expected"] == "every user has MFA"
    assert row["status"] == "fail"
    assert row["evidence_ref"] == "graph://result/1"
    assert row["resources"][0]["resource_id"] == "user-1"
    assert row["resources"][0]["waiver_id"] is None
    assert row["poam"]["severity"] == "high"


@pytest.mark.asyncio
async def test_control_evaluation_can_open_a_poam_with_guidance() -> None:
    async with session_scope() as session:
        org = Organization(name=f"EvalPoamOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"EvalPoamSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-2",
            name="MFA check",
            source="generated",
            check_key="m365.identity.mfa_registered",
            connector_type="msgraph",
            expected="every user has MFA registered",
        )
        session.add(test)
        await session.flush()
        session.add(
            ControlTestResult(
                control_test_id=test.id,
                status="manual_review_required",
                detail="provider not configured; API evidence unavailable",
                evaluated=0,
                failing=0,
                expected="every user has MFA registered",
            )
        )
        await session.flush()
        test_id = test.id

    async with _client() as client:
        r = await client.post(f"/api/control-tests/{test_id}/poam")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] is True
    assert body["poam"]["source_ref"] == f"control_test:{test_id}"
    assert body["poam"]["remediation_plan_source"] == GENERATED_PLAN
    assert "provider not configured" in body["poam"]["weakness"]
    assert "SSP impact" in body["poam"]["remediation_plan"]


@pytest.mark.asyncio
async def test_control_evaluation_poam_action_is_idempotent_and_preserves_analyst_plan() -> None:
    async with session_scope() as session:
        org = Organization(name=f"EvalPoamIdemOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"EvalPoamIdemSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-3",
            name="Public access check",
            source="generated",
            check_key="aws.s3.public_access_block",
            connector_type="aws_govcloud",
            expected="public access is blocked",
        )
        session.add(test)
        await session.flush()
        session.add(
            ControlTestResult(
                control_test_id=test.id,
                status="fail",
                detail="1 of 3 buckets failing",
                evaluated=3,
                failing=1,
                expected="public access is blocked",
            )
        )
        await session.flush()
        test_id = test.id

    async with _client() as client:
        first = await client.post(f"/api/control-tests/{test_id}/poam")
    assert first.status_code == 200, first.text
    poam_id = first.json()["poam"]["id"]

    async with session_scope() as session:
        poam = (await session.execute(select(POAM).where(POAM.id == poam_id))).scalars().one()
        poam.remediation_plan = "Analyst-approved plan"
        poam.remediation_plan_source = "analyst"
        test = (
            await session.execute(select(ControlTest).where(ControlTest.id == test_id))
        ).scalars().one()
        session.add(
            ControlTestResult(
                control_test_id=test.id,
                status="fail",
                detail="2 of 3 buckets failing",
                evaluated=3,
                failing=2,
                expected="public access is blocked",
            )
        )

    async with _client() as client:
        second = await client.post(f"/api/control-tests/{test_id}/poam")
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["created"] is False
    assert body["poam"]["id"] == poam_id
    assert "2 of 3 buckets failing" in body["poam"]["weakness"]
    assert body["poam"]["remediation_plan"] == "Analyst-approved plan"
    assert body["poam"]["remediation_plan_source"] == "analyst"


@pytest.mark.asyncio
async def test_control_evaluation_poam_action_rejects_passing_latest_result() -> None:
    async with session_scope() as session:
        org = Organization(name=f"EvalPoamPassOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"EvalPoamPassSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-2",
            name="MFA check",
            source="generated",
            check_key="m365.identity.mfa_registered",
        )
        session.add(test)
        await session.flush()
        session.add(
            ControlTestResult(
                control_test_id=test.id,
                status="pass",
                detail="all users passing",
                evaluated=2,
                failing=0,
            )
        )
        await session.flush()
        test_id = test.id

    async with _client() as client:
        r = await client.post(f"/api/control-tests/{test_id}/poam")
    assert r.status_code == 409
    assert "no POA&M is needed" in r.json()["detail"]
