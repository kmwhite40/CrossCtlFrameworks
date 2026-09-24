"""TOTP multi-factor authentication.

Spec: ``docs/superpowers/specs/2026-09-23-mfa-totp-design.md`` §10.

Two things about how this file is written, both deliberate:

* **No wall clock reaches an assertion.** Drift and replay are properties of a
  30-second window, so a test that calls ``time.time()`` passes for the wrong
  reason at second 29. Every check drives an explicit ``now``.
* **The algorithm is pinned against the RFCs, not against itself.** RFC 4226
  Appendix D and RFC 6238 Appendix B publish test vectors; a hand-rolled HOTP
  checked only against its own output would agree with itself while disagreeing
  with every authenticator app in the world.
"""

from __future__ import annotations

import base64
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf import mfa
from ccf.ai.cipher import AAD_MFA, build_cipher
from ccf.api.auth_deps import MFA_PENDING_COOKIE, SESSION_COOKIE
from ccf.api.limiter import limiter
from ccf.api.login_service import (
    LoginResult,
    mint_mfa_pending,
    read_mfa_pending,
)
from ccf.api.main import create_app
from ccf.auth import hash_password, read_session, sign_session
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.identity import mfa_service
from ccf.models import Organization, User
from ccf.models_identity import UserMfaCredential, UserMfaRecoveryCode

pytestmark = pytest.mark.usefixtures("fresh_engine")

SECRET_ENV = "test-mfa-master-key-not-a-real-one"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CCF_AUTH_ENABLED", "true")
    monkeypatch.setenv("CCF_AUTH_SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", SECRET_ENV)
    get_settings.cache_clear()
    # The login rate limiter (10/minute, keyed by client IP) is a process-wide
    # singleton independent of the per-test app, and every test here posts from
    # the same default address. Without a reset the module's cumulative count
    # trips a spurious 429 on a login that should have succeeded.
    limiter.reset()
    yield
    limiter.reset()
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _user(label: str, *, password: str = "correct-horse-battery", role: str = "admin",
                policy: str = "optional") -> tuple[int, int, str]:
    """An organization and an active user in it. Returns (org_id, user_id, email)."""
    async with session_scope() as s:
        org = Organization(name=f"MFA-{label}-{os.urandom(4).hex()}", mfa_policy=policy)
        s.add(org)
        await s.flush()
        email = f"{label}-{os.urandom(4).hex()}@mfa.test"
        user = User(
            organization_id=org.id,
            email=email,
            role=role,
            active=True,
            password_hash=hash_password(password),
        )
        s.add(user)
        await s.flush()
        return org.id, user.id, email


async def _enrol(org_id: int, user_id: int, *, active: bool = True) -> str:
    """Put a credential on the user directly and return the base32 secret."""
    secret = mfa.generate_secret()
    cipher = build_cipher(get_settings(), aad=AAD_MFA)
    async with session_scope() as s:
        s.add(
            UserMfaCredential(
                organization_id=org_id,
                user_id=user_id,
                secret_encrypted=cipher.encrypt(secret),
                activated_at=datetime.now(UTC) if active else None,
            )
        )
    return secret


# ── §10 the algorithm, against the RFCs ─────────────────────────────────────

_RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


def test_hotp_matches_rfc4226_appendix_d() -> None:
    """The published vectors. Checking a hand-rolled HOTP against itself would
    agree with itself and disagree with every authenticator app."""
    expected = [
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489",
    ]
    assert [mfa.hotp(_RFC_SECRET, c) for c in range(10)] == expected


@pytest.mark.parametrize(
    ("moment", "code"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_matches_rfc6238_appendix_b(moment: int, code: str) -> None:
    assert mfa.hotp(_RFC_SECRET, mfa.timestep(moment), digits=8) == code


# ── §10.4 / §10.5 replay and drift ──────────────────────────────────────────


def test_a_code_is_accepted_once_and_then_refused() -> None:
    """RFC 6238 §5.2. A code left in a proxy log or read over a shoulder is
    otherwise valid for the rest of its window."""
    secret = mfa.generate_secret()
    now = 1_700_000_000.0
    code = mfa.hotp(secret, mfa.timestep(now))

    step = mfa.verify(secret, code, now=now)
    assert step == mfa.timestep(now)
    assert mfa.verify(secret, code, now=now, last_used_step=step) is None


def test_spending_a_step_also_refuses_every_earlier_one() -> None:
    """Refusing only the exact step would leave the rest of the drift window
    replayable, which is the same defect with one more step of work."""
    secret = mfa.generate_secret()
    now = 1_700_000_000.0
    current = mfa.timestep(now)
    previous_code = mfa.hotp(secret, current - 1)
    assert mfa.verify(secret, previous_code, now=now, last_used_step=current) is None


def test_one_step_of_drift_is_accepted_and_two_is_not() -> None:
    secret = mfa.generate_secret()
    now = 1_700_000_000.0
    current = mfa.timestep(now)
    assert mfa.verify(secret, mfa.hotp(secret, current - 1), now=now) == current - 1
    assert mfa.verify(secret, mfa.hotp(secret, current + 1), now=now) == current + 1
    assert mfa.verify(secret, mfa.hotp(secret, current - 2), now=now) is None
    assert mfa.verify(secret, mfa.hotp(secret, current + 2), now=now) is None


def test_a_malformed_code_is_refused_without_touching_the_secret() -> None:
    secret = mfa.generate_secret()
    for bad in ("", "12345", "1234567", "abcdef", "12 34 56 ", "  "):
        assert mfa.verify(secret, bad, now=1_700_000_000.0) is None


# ── §10.1 a password alone is not enough, on BOTH surfaces ──────────────────


@pytest.mark.asyncio
async def test_the_api_login_issues_no_session_for_an_mfa_user() -> None:
    org_id, user_id, email = await _user("api-nosession")
    await _enrol(org_id, user_id)

    async with _client() as c:
        resp = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mfa_required"] is True
    # Not merely "the response was not a normal login": assert the cookie that
    # would authenticate the caller was never set.
    assert SESSION_COOKIE not in resp.cookies
    assert "role" not in body and "organization_id" not in body


@pytest.mark.asyncio
async def test_the_form_login_issues_no_session_for_an_mfa_user() -> None:
    org_id, user_id, email = await _user("form-nosession")
    await _enrol(org_id, user_id)

    async with _client() as c:
        resp = await c.post(
            "/login", data={"email": email, "password": "correct-horse-battery"}
        )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login/mfa"
    assert SESSION_COOKIE not in resp.cookies
    assert MFA_PENDING_COOKIE in resp.cookies


# ── §10.2 THE test: a pending token is not a session ─────────────────────────


@pytest.mark.asyncio
async def test_a_pending_token_presented_as_a_session_cookie_authenticates_nobody() -> None:
    """The failure this whole design is arranged around.

    ``sign_session``/``read_session`` carry no audience claim, so a pending
    token minted with the session secret would verify as a session and the
    second factor would be a redirect a caller could skip.
    """
    org_id, user_id, email = await _user("replay")
    await _enrol(org_id, user_id)

    async with _client() as c:
        login = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        pending = login.json()["mfa_token"]
        whoami = await c.get("/api/auth/me", cookies={SESSION_COOKIE: pending})

    assert whoami.status_code in (401, 403), whoami.text

    # And assert WHY: the inner value's HMAC does not verify under the session
    # secret at all. If this passed only because of an audience check, a future
    # reader could drop that check and this file would stay green.
    inner = pending.split(".", 1)[1]
    assert read_session(inner, get_settings().auth_session_secret) is None


@pytest.mark.asyncio
async def test_a_real_session_cookie_is_not_accepted_as_a_pending_token() -> None:
    """The mirror. Domain separation has to hold in both directions."""
    _org_id, user_id, _email = await _user("mirror")
    settings = get_settings()
    real = sign_session(user_id, settings.auth_session_secret, ttl_hours=8)
    assert read_mfa_pending(f"{int(time.time())}.{real}") is None


@pytest.mark.asyncio
async def test_a_pending_token_expires_in_minutes_not_hours() -> None:
    _org_id, user_id, _email = await _user("ttl")
    async with session_scope() as s:
        user = await s.get(User, user_id)
        assert user is not None
        now = 1_700_000_000.0
        token = mint_mfa_pending(user, now=now)
        assert read_mfa_pending(token, now=now + 60) is not None
        assert read_mfa_pending(token, now=now + 3600) is None


@pytest.mark.asyncio
async def test_revoking_sessions_kills_a_login_already_in_flight() -> None:
    """The pending token carries ``session_version``; bumping it must invalidate
    a half-finished login, not only issued sessions."""
    org_id, user_id, email = await _user("revoke")
    secret = await _enrol(org_id, user_id)

    async with _client() as c:
        login = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        pending = login.json()["mfa_token"]

        async with session_scope() as s:
            user = await s.get(User, user_id)
            assert user is not None
            user.session_version = (user.session_version or 0) + 1

        resp = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": pending, "code": mfa.hotp(secret, mfa.timestep(time.time()))},
        )
    assert resp.status_code == 401


# ── §10.3 no third login surface may forget MFA_REQUIRED ────────────────────


def test_every_caller_of_authenticate_handles_mfa_required() -> None:
    """By inspection, because the defect is structural.

    Concord has had the same class of bug three times: a second route into a
    subsystem that nobody remembered to guard. ``authenticate`` now has an
    outcome that must not be treated as success, and a third login surface that
    forgets it would issue sessions on a password alone.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "ccf"
    callers = [
        path
        for path in src.rglob("*.py")
        if re.search(r"\bawait authenticate\(", path.read_text(encoding="utf-8"))
    ]
    assert callers, "no caller of authenticate() found — has it been renamed?"
    for path in callers:
        text = path.read_text(encoding="utf-8")
        assert "MFA_REQUIRED" in text, f"{path.name} calls authenticate() but never mentions it"
        # And it must gate on OK rather than on the user being present: the
        # MFA_REQUIRED result carries a user too.
        assert "LoginResult.OK" in text, f"{path.name} does not test for LoginResult.OK"


# ── §10.6 the second factor shares the lockout budget ───────────────────────


@pytest.mark.asyncio
async def test_failed_codes_and_failed_passwords_share_one_lockout_budget() -> None:
    """Six digits is a million guesses. A separate budget per factor gives most
    of the second factor away."""
    settings = get_settings()
    threshold = settings.auth_lockout_threshold
    org_id, user_id, email = await _user("lockout")
    await _enrol(org_id, user_id)

    async with _client() as c:
        # Spend all but one of the budget on bad passwords.
        for _ in range(threshold - 1):
            bad = await c.post("/api/auth/login", json={"email": email, "password": "wrong"})
            assert bad.status_code == 401, bad.text

        login = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        assert login.json()["mfa_required"] is True
        pending = login.json()["mfa_token"]

        # Exactly ONE bad code. It can only lock the account if the correct
        # password left the counter alone -- which is the property under test.
        # Spending a whole second budget here would lock either way and prove
        # nothing, which is how this test first passed against a version that
        # reset the counter.
        resp = await c.post(
            "/api/auth/mfa/verify", json={"mfa_token": pending, "code": "000000"}
        )
    assert resp.status_code == 429, (
        f"one bad code after {threshold - 1} bad passwords did not lock the "
        f"account (got {resp.status_code}) — the counter was reset in between"
    )


# ── §10.7 an un-activated credential challenges nobody ──────────────────────


@pytest.mark.asyncio
async def test_an_enrolled_but_unactivated_credential_does_not_challenge() -> None:
    """A user who scanned a code and lost the tab must not be locked out by a
    secret they never proved they held."""
    org_id, user_id, email = await _user("pending-enrol")
    await _enrol(org_id, user_id, active=False)

    async with _client() as c:
        resp = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
    assert resp.status_code == 200
    assert "mfa_required" not in resp.json()
    assert resp.json()["email"] == email


# ── §10.8 recovery codes ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_recovery_code_works_once_and_then_does_not() -> None:
    org_id, user_id, email = await _user("recovery")
    secret = await _enrol(org_id, user_id, active=False)

    async with session_scope() as s:
        user = await s.get(User, user_id)
        assert user is not None
        codes = await mfa_service.activate(
            s, user, mfa.hotp(secret, mfa.timestep(1_700_000_000.0)), now=1_700_000_000.0
        )
    assert codes is not None and len(codes) == mfa.RECOVERY_CODE_COUNT

    async with _client() as c:
        first = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        used = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": first.json()["mfa_token"], "code": codes[0]},
        )
        assert used.status_code == 200, used.text
        assert used.json()["mfa_method"] == "recovery_code"

        second = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        again = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": second.json()["mfa_token"], "code": codes[0]},
        )
    assert again.status_code == 401, "a recovery code was accepted twice"

    async with session_scope() as s:
        row = (
            await s.execute(
                select(UserMfaRecoveryCode).where(
                    UserMfaRecoveryCode.user_id == user_id,
                    UserMfaRecoveryCode.code_hash == mfa.hash_recovery_code(codes[0]),
                )
            )
        ).scalar_one()
        # Marked used, not deleted: "did somebody get in without their
        # authenticator, and when" is a question a deleted row cannot answer.
        assert row.used_at is not None


# ── §10.9 policy requires enrolment without locking anyone out ──────────────


@pytest.mark.asyncio
async def test_policy_all_requires_enrolment_but_does_not_refuse_the_login() -> None:
    """An organization that could lock every one of its own users out by
    changing a dropdown would have no way back in."""
    _org_id, user_id, email = await _user("policy-all", policy="all")

    async with _client() as c:
        resp = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
    assert resp.status_code == 200, resp.text

    async with session_scope() as s:
        user = await s.get(User, user_id)
        assert user is not None
        assert await mfa_service.policy_requires_enrolment(s, user) is True


@pytest.mark.asyncio
async def test_policy_admins_scopes_to_admins() -> None:
    _o1, admin_id, _e1 = await _user("policy-admin", role="admin", policy="admins")
    _o2, viewer_id, _e2 = await _user("policy-viewer", role="viewer", policy="admins")
    async with session_scope() as s:
        admin = await s.get(User, admin_id)
        viewer = await s.get(User, viewer_id)
        assert admin is not None and viewer is not None
        assert await mfa_service.policy_requires_enrolment(s, admin) is True
        assert await mfa_service.policy_requires_enrolment(s, viewer) is False


# ── §10.10 the secret leaves once, and never appears anywhere else ──────────


@pytest.mark.asyncio
async def test_the_secret_is_returned_at_enrolment_and_never_again() -> None:
    _org_id, user_id, _email = await _user("secret-once")
    settings = get_settings()
    cookie = sign_session(user_id, settings.auth_session_secret, ttl_hours=8)

    async with _client() as c:
        begun = await c.post("/api/auth/mfa/enroll", cookies={SESSION_COOKIE: cookie})
        assert begun.status_code == 200, begun.text
        secret = begun.json()["secret"]

        status = await c.get("/api/auth/mfa", cookies={SESSION_COOKIE: cookie})
        assert status.status_code == 200
        assert secret not in status.text
        assert "secret" not in status.json()

        activated = await c.post(
            "/api/auth/mfa/activate",
            json={"code": mfa.hotp(secret, mfa.timestep(time.time()))},
            cookies={SESSION_COOKIE: cookie},
        )
        assert activated.status_code == 200, activated.text
        assert secret not in activated.text

    # Nor is it stored in the clear.
    async with session_scope() as s:
        cred = (
            await s.execute(
                select(UserMfaCredential).where(UserMfaCredential.user_id == user_id)
            )
        ).scalar_one()
        assert secret not in cred.secret_encrypted
        assert cred.activated_at is not None


@pytest.mark.asyncio
async def test_an_active_authenticator_is_never_silently_replaced() -> None:
    """Otherwise anyone reaching an authenticated session swaps the second
    factor out from under its owner."""
    org_id, user_id, _email = await _user("no-replace")
    await _enrol(org_id, user_id)
    settings = get_settings()
    cookie = sign_session(user_id, settings.auth_session_secret, ttl_hours=8)

    async with _client() as c:
        resp = await c.post("/api/auth/mfa/enroll", cookies={SESSION_COOKIE: cookie})
    assert resp.status_code == 409, resp.text


# ── §10.11 tenancy ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_one_organizations_policy_never_governs_anothers_user() -> None:
    """Pinned on an unscoped session: ``get_session`` binds the RLS tenant, so
    an HTTP-only check here could not tell an app-layer predicate from RLS."""
    strict_org, _strict_user, _e1 = await _user("tenant-strict", policy="all")
    _loose_org, loose_user, _e2 = await _user("tenant-loose", policy="optional")

    async with session_scope() as s:
        # First assert the other tenant's row IS visible without a predicate,
        # so the negative below cannot pass because nothing was there.
        other = await s.get(Organization, strict_org)
        assert other is not None and other.mfa_policy == "all"

        user = await s.get(User, loose_user)
        assert user is not None
        assert await mfa_service.policy_requires_enrolment(s, user) is False


@pytest.mark.asyncio
async def test_a_credential_carries_the_users_own_organization() -> None:
    org_id, user_id, _email = await _user("tenant-cred")
    await _enrol(org_id, user_id)
    async with session_scope() as s:
        cred = (
            await s.execute(
                select(UserMfaCredential).where(UserMfaCredential.user_id == user_id)
            )
        ).scalar_one()
        assert cred.organization_id == org_id


# ── the happy path, end to end on both surfaces ─────────────────────────────


@pytest.mark.asyncio
async def test_the_api_round_trip_signs_the_user_in() -> None:
    org_id, user_id, email = await _user("api-happy")
    secret = await _enrol(org_id, user_id)

    async with _client() as c:
        login = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        verified = await c.post(
            "/api/auth/mfa/verify",
            json={
                "mfa_token": login.json()["mfa_token"],
                "code": mfa.hotp(secret, mfa.timestep(time.time())),
            },
        )
    assert verified.status_code == 200, verified.text
    assert verified.json()["email"] == email
    assert verified.json()["mfa_method"] == "totp"
    assert SESSION_COOKIE in verified.cookies


@pytest.mark.asyncio
async def test_the_form_round_trip_signs_the_user_in() -> None:
    org_id, user_id, email = await _user("form-happy")
    secret = await _enrol(org_id, user_id)

    async with _client() as c:
        first = await c.post(
            "/login", data={"email": email, "password": "correct-horse-battery"}
        )
        pending = first.cookies[MFA_PENDING_COOKIE]
        done = await c.post(
            "/login/mfa",
            data={"code": mfa.hotp(secret, mfa.timestep(time.time()))},
            cookies={MFA_PENDING_COOKIE: pending},
        )
    assert done.status_code == 303
    assert done.headers["location"] == "/"
    assert SESSION_COOKIE in done.cookies


@pytest.mark.asyncio
async def test_the_code_page_is_unreachable_without_a_pending_cookie() -> None:
    async with _client() as c:
        resp = await c.get("/login/mfa")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_a_user_without_mfa_still_signs_in_with_a_password_alone() -> None:
    """A change that makes nothing work is not a feature."""
    _org_id, _user_id, email = await _user("no-mfa")
    async with _client() as c:
        resp = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
    assert resp.status_code == 200, resp.text
    assert "mfa_required" not in resp.json()
    assert SESSION_COOKIE in resp.cookies


def test_the_login_result_enum_still_distinguishes_all_four_outcomes() -> None:
    assert {r.value for r in LoginResult} == {"ok", "invalid", "locked", "mfa_required"}


@pytest.mark.asyncio
async def test_the_service_persists_the_spent_step_so_a_code_cannot_be_reused() -> None:
    """``mfa.verify`` can refuse a replay only if somebody stored the step.

    The pure-function replay tests above pass ``last_used_step`` in by hand, so
    they say nothing about whether the service writes it back. Removing that one
    assignment left every one of them green.
    """
    org_id, user_id, _email = await _user("persist-step")
    secret = await _enrol(org_id, user_id)
    now = 1_700_000_000.0
    code = mfa.hotp(secret, mfa.timestep(now))

    async with session_scope() as s:
        assert await mfa_service.verify_code(s, user_id, code, now=now) is True

    async with session_scope() as s:
        cred = (
            await s.execute(
                select(UserMfaCredential).where(UserMfaCredential.user_id == user_id)
            )
        ).scalar_one()
        assert cred.last_used_step == mfa.timestep(now), "the spent step was not stored"

    async with session_scope() as s:
        assert await mfa_service.verify_code(s, user_id, code, now=now) is False


@pytest.mark.asyncio
async def test_a_code_cannot_be_replayed_over_http() -> None:
    """End to end, because that is the path an attacker actually has."""
    org_id, user_id, email = await _user("replay-http")
    secret = await _enrol(org_id, user_id)
    code = mfa.hotp(secret, mfa.timestep(time.time()))

    async with _client() as c:
        first = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        ok = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": first.json()["mfa_token"], "code": code},
        )
        assert ok.status_code == 200, ok.text

        second = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        replayed = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": second.json()["mfa_token"], "code": code},
        )
    assert replayed.status_code == 401, "the same code was accepted twice"


# ── disabling the authenticator, which shipped untested on both surfaces ────


async def _activate(user_id: int, secret: str) -> list[str]:
    """Activate an enrolled credential and return its recovery codes."""
    async with session_scope() as s:
        user = await s.get(User, user_id)
        assert user is not None
        codes = await mfa_service.activate(
            s, user, mfa.hotp(secret, mfa.timestep(1_700_000_000.0)), now=1_700_000_000.0
        )
    assert codes is not None
    return codes


@pytest.mark.asyncio
async def test_disabling_the_authenticator_revokes_its_recovery_codes() -> None:
    """A recovery code outlived the authenticator it was minted for.

    `mfa_disable` deleted `UserMfaCredential` and left `UserMfaRecoveryCode`
    untouched -- the codes are keyed on the user, not the credential, and there
    is no cascade between them. `consume_recovery_code` checked neither. So a
    code that leaked before somebody rotated their second factor still signed
    them in afterwards, and the status endpoint counted the dead codes in
    `recovery_codes_remaining`.

    Rotating a second factor has to rotate the credentials that bypass it.
    """
    org_id, user_id, email = await _user("revoke-on-disable", policy="optional")
    secret = await _enrol(org_id, user_id, active=False)
    assert await _activate(user_id, secret), "the fixture must issue codes"
    settings = get_settings()
    cookie = sign_session(user_id, settings.auth_session_secret, ttl_hours=8)

    async with _client() as c:
        removed = await c.delete("/api/auth/mfa", cookies={SESSION_COOKIE: cookie})
        assert removed.status_code == 204, removed.text

        # No authenticator now, so a password alone signs in -- and the old
        # recovery code must not be an alternative route to a session.
        status = await c.get("/api/auth/mfa", cookies={SESSION_COOKIE: cookie})
        assert status.json()["recovery_codes_remaining"] == 0, status.text

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(UserMfaRecoveryCode).where(UserMfaRecoveryCode.user_id == user_id)
            )
        ).scalars().all()
        assert rows, "the codes must still exist -- revoked is not deleted"
        assert all(r.revoked_at is not None for r in rows), (
            "a recovery code survived the authenticator it belonged to"
        )
        assert all(r.used_at is None for r in rows), (
            "revoking a code must not record it as having been used to sign in"
        )
    assert email  # named for the reader


@pytest.mark.asyncio
async def test_a_code_from_a_retired_authenticator_cannot_sign_anyone_in() -> None:
    """The end-to-end version, which is the one an attacker has.

    Enrol, activate, disable, re-enrol with a fresh secret and a disjoint set
    of codes -- then present one of the FIRST set.
    """
    org_id, user_id, email = await _user("retired-code", policy="optional")
    first_secret = await _enrol(org_id, user_id, active=False)
    old_codes = await _activate(user_id, first_secret)
    settings = get_settings()
    cookie = sign_session(user_id, settings.auth_session_secret, ttl_hours=8)

    async with _client() as c:
        assert (
            await c.delete("/api/auth/mfa", cookies={SESSION_COOKIE: cookie})
        ).status_code == 204

    second_secret = await _enrol(org_id, user_id, active=False)
    new_codes = await _activate(user_id, second_secret)
    assert not set(old_codes) & set(new_codes), "the two sets must be disjoint"

    async with _client() as c:
        login = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        assert login.json()["mfa_required"] is True
        replayed = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": login.json()["mfa_token"], "code": old_codes[0]},
        )
    assert replayed.status_code == 401, (
        "a recovery code from a retired authenticator was accepted"
    )

    # And the count a user is shown reflects only the live set.
    async with _client() as c:
        status = await c.get("/api/auth/mfa", cookies={SESSION_COOKIE: cookie})
    assert status.json()["recovery_codes_remaining"] == len(new_codes)


@pytest.mark.asyncio
async def test_a_new_code_from_the_current_authenticator_still_works() -> None:
    """A fix that revokes everything is not a fix."""
    org_id, user_id, email = await _user("live-code", policy="optional")
    secret = await _enrol(org_id, user_id, active=False)
    codes = await _activate(user_id, secret)

    async with _client() as c:
        login = await c.post(
            "/api/auth/login", json={"email": email, "password": "correct-horse-battery"}
        )
        used = await c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": login.json()["mfa_token"], "code": codes[0]},
        )
    assert used.status_code == 200, used.text
    assert used.json()["mfa_method"] == "recovery_code"


@pytest.mark.asyncio
async def test_a_live_code_with_no_authenticator_is_still_refused() -> None:
    """The second rung, exercised on the state it exists for.

    Revoking on disable is the primary fix, and it makes this state
    unreachable through the application -- which is exactly why removing this
    guard leaves every other test green. So the state is constructed directly:
    a live, unrevoked code belonging to a user with no credential, as a partial
    migration, a direct database edit or a future write path could leave it.

    Without this, the guard would be a survivor nobody could kill, and the next
    reader would be entitled to delete it as dead code.
    """
    org_id, user_id, _email = await _user("orphan-code", policy="optional")
    secret = await _enrol(org_id, user_id, active=False)
    codes = await _activate(user_id, secret)

    # Delete the credential WITHOUT revoking, which the routes no longer do.
    async with session_scope() as s:
        cred = (
            await s.execute(
                select(UserMfaCredential).where(UserMfaCredential.user_id == user_id)
            )
        ).scalar_one()
        await s.delete(cred)

    async with session_scope() as s:
        live = (
            await s.execute(
                select(UserMfaRecoveryCode).where(
                    UserMfaRecoveryCode.user_id == user_id,
                    UserMfaRecoveryCode.used_at.is_(None),
                    UserMfaRecoveryCode.revoked_at.is_(None),
                )
            )
        ).scalars().all()
        assert live, "the fixture must leave a live code, or this proves nothing"

        assert await mfa_service.consume_recovery_code(s, user_id, codes[0]) is False, (
            "a recovery code was spent for an account with no authenticator"
        )
