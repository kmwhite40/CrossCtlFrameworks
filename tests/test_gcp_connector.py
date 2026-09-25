"""The Google Cloud capture connector.

``tests/test_connector_capture_parity.py`` already proves this connector emits
exactly the three parameters it advertises, behaviourally. This file covers
what parity cannot see: whether each captured VALUE is true of the fixture it
was read from, and whether the connector fails closed.

Every provider call is stubbed over ``httpx.MockTransport``. No Google Cloud
project is touched, and the JWT assertion is really signed with a real RSA key
-- signing is the step that turns a credential into a token, and stubbing it
out would pass a connector whose key handling was broken.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from functools import lru_cache
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ccf.connectors.gcp import GcpConnector


@lru_cache(maxsize=1)
def _pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


CREDENTIAL = {
    "project_id": "proj-1",
    "client_email": "cap@proj-1.iam.gserviceaccount.com",
    "private_key": "",  # filled per test from _pem()
}


def _cred(**over: Any) -> dict[str, Any]:
    return {**CREDENTIAL, "private_key": _pem(), **over}


def _connector(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
    credential: dict[str, Any] | None = None,
) -> GcpConnector:
    real = httpx.AsyncClient

    def factory(*a: Any, **kw: Any) -> httpx.AsyncClient:
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr("ccf.connectors.gcp.httpx.AsyncClient", factory)
    return GcpConnector(credential=credential if credential is not None else _cred())


def _ok_token(request: httpx.Request) -> httpx.Response | None:
    if request.method == "POST" and "oauth2.googleapis.com/token" in str(request.url):
        return httpx.Response(200, json={"access_token": "t", "expires_in": 3599})
    return None


def _handler(
    *, buckets: Any = None, logs: Any = None, policies: Any = None
) -> Callable[[httpx.Request], httpx.Response]:
    def handle(request: httpx.Request) -> httpx.Response:
        tok = _ok_token(request)
        if tok is not None:
            return tok
        url = str(request.url)
        if "storage.googleapis.com" in url:
            return httpx.Response(200, json={"items": buckets if buckets is not None else []})
        if "logging.googleapis.com" in url:
            return httpx.Response(200, json={"buckets": logs if logs is not None else []})
        if "orgpolicy.googleapis.com" in url:
            return httpx.Response(200, json={"policies": policies if policies is not None else []})
        return httpx.Response(404, json={"error": url})

    return handle


def _by_key(caps: list[Any]) -> dict[str, Any]:
    return {c.odp_key: c for c in caps}


# ── configuration, and failing closed ───────────────────────────────────────


@pytest.mark.parametrize(
    "missing", ["project_id", "client_email", "private_key"]
)
def test_a_partial_credential_is_not_configured(missing: str) -> None:
    """A credential missing any one field authenticates or scopes to nothing.

    ``project_id`` matters as much as the key: every read below is
    project-scoped, so a bundle without one would report configured and capture
    zero -- which is worse than reporting unconfigured.
    """
    cred = _cred()
    cred.pop(missing)
    assert GcpConnector(credential=cred).is_configured() is False


def test_no_credential_captures_nothing_and_does_not_raise() -> None:
    assert GcpConnector().is_configured() is False


@pytest.mark.asyncio
async def test_an_unconfigured_connector_captures_nothing(monkeypatch) -> None:
    conn = _connector(monkeypatch, _handler(), credential={})
    assert await conn.capture() == []


@pytest.mark.asyncio
async def test_an_unusable_private_key_captures_nothing_rather_than_raising(
    monkeypatch,
) -> None:
    """Capture is best-effort enrichment; the base class requires it never
    raises. A mistyped key is a configuration problem, not a crash."""
    conn = _connector(
        monkeypatch, _handler(), credential=_cred(private_key="-----BEGIN PRIVATE KEY-----\nno")
    )
    assert await conn.capture() == []


@pytest.mark.asyncio
async def test_a_provider_error_captures_nothing_rather_than_raising(monkeypatch) -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        tok = _ok_token(request)
        return tok if tok is not None else httpx.Response(503, json={"error": "unavailable"})

    conn = _connector(monkeypatch, broken)
    assert await conn.capture() == []


@pytest.mark.asyncio
async def test_the_assertion_is_a_real_signed_jwt(monkeypatch) -> None:
    """Read off the wire, not off the source: the connector must send a
    three-part assertion whose claims name the service account and the token
    endpoint. A connector that sent an unsigned or malformed one would still
    "work" against a stub that did not look."""
    seen: dict[str, str] = {}

    def handle(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "oauth2.googleapis.com/token" in str(request.url):
            body = dict(
                p.split("=", 1) for p in request.content.decode().split("&") if "=" in p
            )
            seen.update(body)
            return httpx.Response(200, json={"access_token": "t"})
        return _handler()(request)

    await _connector(monkeypatch, handle).capture()

    from urllib.parse import unquote  # noqa: PLC0415

    assertion = unquote(seen["assertion"])
    parts = assertion.split(".")
    assert len(parts) == 3, assertion[:60]
    pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
    header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
    claims = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    assert header["alg"] == "RS256"
    assert claims["iss"] == CREDENTIAL["client_email"]
    assert claims["aud"] == "https://oauth2.googleapis.com/token"
    assert claims["exp"] > claims["iat"]
    assert base64.urlsafe_b64decode(pad(parts[2]))  # a signature is present


# ── the values, which parity cannot check ───────────────────────────────────


@pytest.mark.asyncio
async def test_encryption_reports_whose_key_not_merely_that_it_is_encrypted(
    monkeypatch,
) -> None:
    """Google encrypts every bucket at rest unconditionally, so "encrypted" is
    true of every project and useless to an assessor. What varies is whether
    the organization holds the key."""
    conn = _connector(
        monkeypatch,
        _handler(
            buckets=[
                {"name": "a", "encryption": {"defaultKmsKeyName": "projects/p/k"}},
                {"name": "b"},
            ]
        ),
    )
    cap = _by_key(await conn.capture())["encryption_at_rest"]
    assert "1 of 2" in cap.value
    assert "Google-managed" in cap.value
    assert cap.confidence == "medium"
    assert cap.detail["cmek"] == 1 and cap.detail["buckets"] == 2


@pytest.mark.asyncio
async def test_full_cmek_coverage_reads_as_high_confidence(monkeypatch) -> None:
    conn = _connector(
        monkeypatch,
        _handler(buckets=[{"name": "a", "encryption": {"defaultKmsKeyName": "k"}}]),
    )
    cap = _by_key(await conn.capture())["encryption_at_rest"]
    assert "all buckets" in cap.value
    assert cap.confidence == "high"


@pytest.mark.asyncio
async def test_log_retention_reports_the_shortest_bucket(monkeypatch) -> None:
    """The shortest, not the longest and not an average.

    Retention is the window in which a record still exists. A project with a
    3650-day bucket and a 30-day bucket retains some logs for 30 days, and
    reporting 3650 would overstate the control to an assessor.
    """
    conn = _connector(
        monkeypatch,
        _handler(
            logs=[
                {"name": "_Default", "retentionDays": 3650},
                {"name": "short", "retentionDays": 30},
                {"name": "no-field"},
            ]
        ),
    )
    cap = _by_key(await conn.capture())["log_retention_period"]
    assert cap.value == "30 days"
    assert cap.detail["shortest_days"] == 30
    assert cap.detail["all_days"] == [30, 3650]


@pytest.mark.asyncio
async def test_org_policy_counts_the_constraints_in_effect(monkeypatch) -> None:
    conn = _connector(
        monkeypatch,
        _handler(
            policies=[
                {"name": "projects/p/policies/compute.requireOsLogin"},
                {"name": "projects/p/policies/storage.uniformBucketLevelAccess"},
            ]
        ),
    )
    cap = _by_key(await conn.capture())["configuration_baseline_enforcement"]
    assert "2 Organization Policy constraint" in cap.value
    assert cap.detail["constraints"] == [
        "compute.requireOsLogin",
        "storage.uniformBucketLevelAccess",
    ]


@pytest.mark.asyncio
async def test_a_source_with_nothing_to_say_emits_nothing_for_it(monkeypatch) -> None:
    """An empty project must not produce "0 buckets are encrypted" or "0 days".

    A capture is a claim about the tenant's configuration; a fabricated zero
    would be a claim the connector cannot support, and the ODP is better left
    blank for a human than filled with a number nobody measured.
    """
    conn = _connector(monkeypatch, _handler(buckets=[], logs=[], policies=[]))
    assert await conn.capture() == []


@pytest.mark.asyncio
async def test_every_capture_carries_both_namespaces(monkeypatch) -> None:
    """``nist_id`` is the 800-171 requirement the join matches on, and the
    800-53 equivalent rides in ``detail`` -- the pair that decides whether a
    value ever reaches a narrative. One AWS capture was silently discarded at
    that join for emitting the wrong namespace."""
    conn = _connector(
        monkeypatch,
        _handler(
            buckets=[{"name": "a", "encryption": {"defaultKmsKeyName": "k"}}],
            logs=[{"name": "d", "retentionDays": 400}],
            policies=[{"name": "projects/p/policies/compute.requireOsLogin"}],
        ),
    )
    caps = await conn.capture()
    assert len(caps) == 3
    for cap in caps:
        assert cap.nist_id and cap.nist_id.startswith("3."), cap.odp_key
        assert cap.detail.get("nist_80053_id"), cap.odp_key
        assert cap.source


# ── verify ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_reports_the_project_it_reached(monkeypatch) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        tok = _ok_token(request)
        if tok is not None:
            return tok
        if "cloudresourcemanager" in str(request.url):
            return httpx.Response(200, json={"projectId": "proj-1", "projectNumber": "42"})
        return httpx.Response(404)

    result = await _connector(monkeypatch, handle).verify()
    assert result["connected"] is True
    assert result["project_id"] == "proj-1"
    assert result["service_account"] == CREDENTIAL["client_email"]


@pytest.mark.asyncio
async def test_verify_says_why_when_it_cannot_connect(monkeypatch) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        tok = _ok_token(request)
        return tok if tok is not None else httpx.Response(403, json={"error": "denied"})

    result = await _connector(monkeypatch, handle).verify()
    assert result["connected"] is False
    assert result["reason"]


@pytest.mark.asyncio
async def test_verify_without_a_credential_says_so() -> None:
    result = await GcpConnector().verify()
    assert result["connected"] is False
    assert "no Google Cloud credential" in result["reason"]
