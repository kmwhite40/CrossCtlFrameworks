"""The live-audit plan measures only the providers a system's environment selects.

``live_audit_plan`` used to verify every registered provider. On a Microsoft 365
system that read "1 of 5 provider(s) ready" on the system page, set the next
action to "Verify connectors" permanently -- AWS, GCP, Azure and PuppetDB can
never become ready on a tenant that has none of them -- and marked framework
items ``covered_by_automated_check`` because an AWS check exists in the registry,
though no AWS check is ever run against that system.

The scan was fixed first (``ccf.posture.scope``); this is the plan beside it,
which is what the system page actually renders.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from ccf.db import session_scope
from ccf.models import Organization, System, SystemProfile
from ccf.models_grc import ConnectorConfig
from ccf.posture import audit_plan as audit_plan_module
from ccf.posture.audit_plan import live_audit_plan

_SEQ = itertools.count()


async def _readiness(
    session: Any, *, organization_id: int | None, connector_key: str, persist: bool
) -> dict[str, Any]:
    """Every provider ready, each with one scan check on its own control.

    "Ready" for all of them on purpose: a plan that consulted scope only through
    readiness would pass with an honest-looking unready list.
    """
    return {
        "connector": connector_key,
        "status": "ready",
        "ready": True,
        "configured": True,
        "connected": True,
        "checks_expected": 1,
        "checks": [
            {
                "check_key": f"{connector_key}.scan",
                "title": "scan check",
                "control_ids": [f"X-{connector_key}"],
                "resource_type": "tenant",
                "source": "platform",
                "required_permissions": [],
                "responsibility": {"responsibility": "customer"},
                "scan_applicability": "scan",
            }
        ],
        "required_permissions": [],
        "reason": None,
    }


async def _plan(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cloud_platform: str | None,
    configured: tuple[str, ...] = (),
) -> dict[str, Any]:
    monkeypatch.setattr(audit_plan_module, "provider_readiness", _readiness)
    async with session_scope() as session:
        org = Organization(name=f"PlanScopeOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"plan-{next(_SEQ)}")
        session.add(system)
        await session.flush()
        if cloud_platform is not None:
            session.add(
                SystemProfile(
                    system_id=system.id,
                    answers={},
                    environment_type="cloud",
                    cloud_platform=cloud_platform,
                )
            )
        for connector in configured:
            session.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{connector} fixture",
                    connector_type=connector,
                )
            )
        await session.flush()
        return await live_audit_plan(session, system=system, org_id=org.id)


async def test_an_m365_system_plans_only_msgraph(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every cloud connector configured org-wide; the system says M365."""
    plan = await _plan(
        monkeypatch,
        cloud_platform="m365_gcc_high",
        configured=("msgraph", "aws_govcloud", "azure_arm", "gcp"),
    )
    assert [p["connector"] for p in plan["providers"]] == ["msgraph"]
    assert plan["summary"]["providers"] == 1
    assert {c["check_key"] for c in plan["api_checks"]} == {"msgraph.scan"}


async def test_excluded_providers_are_named_with_a_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dropped from the count, not from the page: a reader can see what was
    excluded and which setting excluded it."""
    plan = await _plan(
        monkeypatch, cloud_platform="m365_gcc_high", configured=("aws_govcloud",)
    )
    excluded = {p["connector"]: p["reason"] for p in plan["providers_out_of_scope"]}
    assert "aws_govcloud" in excluded
    assert "m365_gcc_high" in excluded["aws_govcloud"]
    assert "msgraph" not in excluded


async def test_an_off_environment_check_does_not_mark_a_framework_item_automated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The quieter half of the defect: ``automated_control_ids`` was built from
    every provider's checks, so an AWS check that never runs here still claimed
    a framework item was covered by automation."""
    plan = await _plan(
        monkeypatch, cloud_platform="m365_gcc_high", configured=("aws_govcloud",)
    )
    claimed = {c["connector"] for c in plan["api_checks"]} | {
        c["connector"] for c in plan["manual_review_required"]
    }
    assert "aws_govcloud" not in claimed


async def test_no_environment_and_no_connector_plans_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = await _plan(monkeypatch, cloud_platform=None)
    assert plan["providers"] == []
    assert plan["summary"]["providers"] == 0
    assert plan["summary"]["providers_ready"] == 0
