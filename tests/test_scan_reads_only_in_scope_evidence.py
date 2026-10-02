"""The two evidence reads beside the provider loop follow the environment too.

``scan_all`` gained per-environment scope for its provider loop, and the AWS
Security Hub read beside it still ran unconditionally: an M365 system in an
organization with AWS bound for a different system was given AWS verdicts. The
Secure Score read was added in the same place. Both are gated on the same scope.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

import ccf.posture.scan_all as scan_all_module
from ccf.db import session_scope
from ccf.models import Organization, System, SystemProfile
from ccf.models_grc import ConnectorConfig
from ccf.posture.scan_all import scan_all_providers

_SEQ = itertools.count()


async def _not_ready(session: Any, *, organization_id: int | None, connector_key: str,
                     persist: bool) -> dict[str, Any]:
    return {"connector": connector_key, "status": "not_configured", "ready": False,
            "configured": False, "connected": False, "checks_expected": 0, "checks": [],
            "required_permissions": [], "reason": "fixture"}


async def _scan(monkeypatch: pytest.MonkeyPatch, cloud_platform: str) -> tuple[list[str], dict]:
    calls: list[str] = []

    async def _attest(session: Any, **k: Any) -> dict[str, Any]:
        calls.append("attestations")
        return {"available": False, "reason": "fixture", "written": 0}

    async def _score(session: Any, **k: Any) -> dict[str, Any]:
        calls.append("securescore")
        return {"available": False, "reason": "fixture", "written": 0}

    monkeypatch.setattr(scan_all_module, "provider_readiness", _not_ready)
    monkeypatch.setattr(scan_all_module, "ingest_attestations", _attest)
    monkeypatch.setattr(scan_all_module, "ingest_securescore", _score)
    async with session_scope() as s:
        org = Organization(name=f"EvidenceScopeOrg{next(_SEQ)}")
        s.add(org)
        await s.flush()
        sys_ = System(organization_id=org.id, name=f"evs-{next(_SEQ)}")
        s.add(sys_)
        await s.flush()
        s.add(SystemProfile(system_id=sys_.id, answers={}, cloud_platform=cloud_platform))
        # Both clouds bound org-wide: the case a configuration-based scope widens.
        for key in ("aws_govcloud", "msgraph"):
            s.add(ConnectorConfig(organization_id=org.id, name=key, connector_type=key))
        await s.flush()
        org_id, system_id = org.id, sys_.id
    async with session_scope() as session:
        out = await scan_all_providers(session, system_id=system_id, organization_id=org_id)
    return calls, out


async def test_an_m365_system_reads_secure_score_and_not_security_hub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, out = await _scan(monkeypatch, "m365_gcc_high")
    assert calls == ["securescore"]
    assert out["attestations"]["available"] is False
    assert out["attestations"]["reason"].startswith("not read:")


async def test_an_aws_system_reads_security_hub_and_not_secure_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, out = await _scan(monkeypatch, "aws_govcloud")
    assert calls == ["attestations"]
    assert out["securescore"]["reason"].startswith("not read:")


async def test_a_system_with_no_cloud_reads_neither(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, out = await _scan(monkeypatch, "none")
    assert calls == []
    assert out["securescore"]["available"] is False


async def test_the_unread_reports_keep_their_full_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A skipped read is reported in the same shape as a real one, so a consumer
    indexing a key does not KeyError on exactly the out-of-scope systems."""
    from ccf.posture.securescore_scan import report  # noqa: PLC0415

    _calls, out = await _scan(monkeypatch, "none")
    assert set(out["securescore"]) == set(report(0, available=False, reason="x"))
    assert {"controls_read", "region", "truncated"} <= set(out["attestations"])
