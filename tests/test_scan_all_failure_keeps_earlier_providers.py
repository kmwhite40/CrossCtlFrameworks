"""One provider's failure must not discard what the providers before it recorded.

``scan_all_providers`` says so in its docstring and in the comment on its
exception handler. The handler calls ``session.rollback()``, and nothing commits
between providers -- so whether the earlier providers' results survive is a
question about transactions, not about the comment.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from sqlalchemy import select

import ccf.posture.scan_all as scan_all_module
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ConnectorConfig, ControlTest, ControlTestResult
from ccf.posture.scan_all import scan_all_providers

_SEQ = itertools.count()


async def _ready(session: Any, *, organization_id: int | None, connector_key: str, persist: bool):
    return {
        "connector": connector_key,
        "status": "ready",
        "ready": True,
        "configured": True,
        "connected": True,
        "checks_expected": 1,
        "checks": [
            {
                "check_key": f"{connector_key}.probe",
                "title": "probe",
                "control_ids": ["AC-2"],
                "resource_type": "tenant",
                "source": "platform",
                "required_permissions": [],
                "responsibility": {"responsibility": "customer"},
                "scan_applicability": "scan",
            }
        ],
        "required_permissions": [],
    }


@pytest.mark.parametrize("failure", ["exception", "database_error"])
async def test_a_later_providers_failure_keeps_an_earlier_providers_result(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``database_error`` is the case the old bare rollback existed for: a flush
    that fails leaves the transaction aborted. Rolling back to the provider's
    savepoint must recover it, or the commit at the end fails and takes every
    provider down -- the "one provider's fault becomes all of them" shape."""
    async with session_scope() as s:
        org = Organization(name=f"ContainOrg{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"contain-{next(_SEQ)}")
        s.add(sys_)
        # Two providers in scope by configuration; sorted order is
        # aws_govcloud, then msgraph.
        for key in ("aws_govcloud", "msgraph"):
            s.add(ConnectorConfig(organization_id=org.id, name=key, connector_type=key))
        await s.flush()
        org_id, system_id = org.id, sys_.id

    async def _scan(
        session: Any, *, system_id: int, connector_key: str, actor: str, check_keys=None
    ):
        if connector_key == "msgraph":
            if failure == "exception":
                raise RuntimeError("provider blew up")
            # A foreign-key violation at flush: the transaction is now aborted.
            session.add(
                ControlTest(
                    organization_id=org_id,
                    system_id=10**9,
                    control_id="AC-2",
                    name="orphan",
                    method="connector",
                    source="generated",
                    check_key="msgraph.orphan",
                    connector_type="msgraph",
                )
            )
            await session.flush()
        test = ControlTest(
            organization_id=org_id,
            system_id=system_id,
            control_id="AC-2",
            control_ids=["AC-2"],
            name="aws probe",
            method="connector",
            source="generated",
            check_key="aws_govcloud.probe",
            check_source="platform",
            connector_type="aws_govcloud",
        )
        session.add(test)
        await session.flush()
        await record_result(session, test, status="pass", detail="ok", evaluated=1)
        return {
            "system_id": system_id,
            "connector": connector_key,
            "checks_expected": 1,
            "checks_run": 1,
            "results": [{"check_key": "aws_govcloud.probe", "verdict": "pass"}],
            "skipped_checks": [],
        }

    async def _no_attestations(session: Any, **_: Any) -> dict[str, Any]:
        raise RuntimeError("not under test")

    monkeypatch.setattr(scan_all_module, "provider_readiness", _ready)
    monkeypatch.setattr(scan_all_module, "scan_for_system", _scan)
    monkeypatch.setattr(scan_all_module, "ingest_attestations", _no_attestations)

    async with session_scope() as session:
        out = await scan_all_providers(session, system_id=system_id, organization_id=org_id)

    reported = {c["connector"]: c.get("checks_run") for c in out["connectors"]}
    assert reported.get("aws_govcloud") == 1, out["connectors"]

    async with session_scope() as session:
        stored = (
            await session.execute(
                select(ControlTestResult.status)
                .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
                .where(ControlTest.system_id == system_id)
            )
        ).scalars().all()
    assert stored == ["pass"], (
        "the response reports the AWS result as recorded, and it is not in the database"
    )
