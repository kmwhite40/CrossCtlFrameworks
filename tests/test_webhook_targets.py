"""Webhooks may only be sent to public HTTP(S) endpoints, and only admins add them.

A webhook makes the server POST to a URL a user chose. Before this, any
non-viewer could create one, to any URL -- including loopback, private ranges
and the link-local metadata service -- which is server-side request forgery.
"""

from __future__ import annotations

import itertools
import os
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import bus, webhook_url
from ccf.models import Organization, User

pytestmark = pytest.mark.usefixtures("fresh_engine")
_SEQ = itertools.count()


# ── the rule, pure ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://localhost:8080/x",
        "http://api.localhost/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[::1]/x",
        "http://[::ffff:127.0.0.1]/x",
        "http://0.0.0.0/x",
        "http://10.0.0.5/x",
        "http://192.168.1.10/x",
        "ftp://example.com/x",
        "file:///etc/passwd",
        "https://user:pw@example.com/x",
        "https:///nohost",
    ],
)
def test_internal_and_malformed_targets_are_refused(url: str) -> None:
    assert webhook_url.refusal(url) is not None


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
        "2002:7f00:1::1",  # 6to4 of 127.0.0.1
        "::7f00:1",  # IPv4-compatible 127.0.0.1
        "2001:0:4136:e378:8000:63bf:80ff:fffe",  # Teredo
        "100.64.1.1",  # carrier-grade NAT
        "100.100.100.200",  # Alibaba metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
        "192.0.2.1",  # documentation range: not global
    ],
)
def test_addresses_that_reach_inward_by_another_spelling_are_refused(address: str) -> None:
    assert webhook_url.blocked_address(address)


def test_metadata_and_cgnat_stay_refused_even_with_private_targets_allowed(monkeypatch) -> None:
    monkeypatch.setenv("CCF_WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")
    get_settings.cache_clear()
    try:
        for address in ("169.254.169.254", "100.64.0.1", "fd00:ec2::254", "127.0.0.1"):
            assert webhook_url.blocked_address(address), address
        assert not webhook_url.blocked_address("10.0.0.5")
    finally:
        monkeypatch.delenv("CCF_WEBHOOK_ALLOW_PRIVATE_TARGETS")
        get_settings.cache_clear()


def test_delivery_is_pinned_to_the_checked_address(monkeypatch) -> None:
    """Resolve once, check, connect to that address: the name is kept for the
    Host header and TLS (SNI and certificate check), never re-resolved."""
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["93.184.216.34"])
    reason, target = webhook_url.pinned_target("https://hooks.example:8443/p?q=1")
    assert reason is None
    assert target["url"] == "https://93.184.216.34:8443/p?q=1"
    assert target["headers"] == {"Host": "hooks.example:8443"}
    assert target["extensions"] == {"sni_hostname": "hooks.example"}


def test_a_public_address_is_allowed() -> None:
    assert webhook_url.refusal("https://1.1.1.1/hook") is None


def test_an_unresolved_name_is_accepted_on_create_and_refused_on_delivery(monkeypatch) -> None:
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: [])
    assert webhook_url.refusal("https://not-yet.example/h") is None
    assert webhook_url.refusal("https://not-yet.example/h", require_resolution=True) is not None


def test_a_name_that_resolves_inward_is_refused(monkeypatch) -> None:
    """DNS rebinding: the name is checked by what it resolves to now."""
    monkeypatch.setattr(webhook_url, "_resolve", lambda host: ["93.184.216.34", "10.1.2.3"])
    assert "10.1.2.3" in (webhook_url.refusal("https://rebind.example/h") or "")


def test_private_targets_need_the_explicit_setting(monkeypatch) -> None:
    monkeypatch.setenv("CCF_WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")
    get_settings.cache_clear()
    try:
        assert webhook_url.refusal("http://10.0.0.5/x") is None
        # Loopback and metadata stay refused even then.
        assert webhook_url.refusal("http://127.0.0.1/x") is not None
        assert webhook_url.refusal("http://169.254.169.254/x") is not None
    finally:
        monkeypatch.delenv("CCF_WEBHOOK_ALLOW_PRIVATE_TARGETS")
        get_settings.cache_clear()


# ── the dispatcher re-checks every send ──────────────────────────────────────


async def test_dispatch_never_posts_to_a_refused_target(monkeypatch) -> None:
    posted: list[str] = []

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, url, **k):
            posted.append((url, k.get("headers", {}).get("Host")))

    monkeypatch.setattr(bus.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(
        webhook_url,
        "_resolve",
        lambda host: ["10.9.9.9"] if host == "rebind.example" else ["93.184.216.34"],
    )
    hooks = [
        SimpleNamespace(id=1, url="http://127.0.0.1/x", events=[], secret=None),
        SimpleNamespace(id=2, url="https://rebind.example/x", events=[], secret=None),
        SimpleNamespace(id=3, url="https://1.1.1.1/ok", events=[], secret=None),
        SimpleNamespace(id=4, url="https://hooks.example/ok", events=[], secret=None),
    ]

    class _Session:
        async def execute(self, stmt):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: hooks))

    ev = SimpleNamespace(
        organization_id=1,
        verb="created",
        entity_type="poam",
        entity_id="1",
        summary="s",
        payload={},
    )
    await bus._dispatch_webhooks(_Session(), ev)  # type: ignore[arg-type]
    assert posted == [
        ("https://1.1.1.1/ok", "1.1.1.1"),
        ("https://93.184.216.34/ok", "hooks.example"),
    ]


# ── the API: admin only, URL checked ─────────────────────────────────────────


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _tokens() -> dict[str, str]:
    tag = f"wh{next(_SEQ)}x{os.getpid()}{os.urandom(2).hex()}"
    async with session_scope() as s:
        org = Organization(name=f"Webhook-org-{tag}")
        s.add(org)
        await s.flush()
        out = {}
        for role in ("admin", "control_owner", "assessor"):
            u = User(
                email=f"{role}-{tag}@wh.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            out[role] = u.api_token
        await s.flush()
        return out


@pytest.mark.usefixtures("_auth_enabled")
async def test_only_an_admin_may_add_a_webhook_and_only_to_a_public_target() -> None:
    tokens = await _tokens()
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:

        def post(role: str, url: str):
            return c.post(
                "/api/webhooks",
                json={"url": url, "events": []},
                headers={"Authorization": f"Bearer {tokens[role]}"},
            )

        assert (await post("control_owner", "https://1.1.1.1/h")).status_code == 403
        assert (await post("assessor", "https://1.1.1.1/h")).status_code == 403
        internal = await post("admin", "http://169.254.169.254/latest/")
        assert internal.status_code == 422
        assert "refused" in internal.json()["detail"]
        created = await post("admin", "https://1.1.1.1/h")
        assert created.status_code == 201
        gone = await c.delete(
            f"/api/webhooks/{created.json()['id']}",
            headers={"Authorization": f"Bearer {tokens['control_owner']}"},
        )
        assert gone.status_code == 403


def test_the_pinned_address_comes_from_the_one_checked_answer(monkeypatch) -> None:
    """A name that answers public the first time and internal the second must
    be sent to the first (checked) answer: resolution happens exactly once."""
    answers = iter([["93.184.216.34"], ["10.0.0.1"]])
    calls: list[str] = []

    def resolve(host: str) -> list[str]:
        calls.append(host)
        return next(answers)

    monkeypatch.setattr(webhook_url, "_resolve", resolve)
    reason, target = webhook_url.pinned_target("https://flip.example/x")
    assert reason is None
    assert target["url"] == "https://93.184.216.34/x"
    assert calls == ["flip.example"]
