# Platform Config & Authentication Hardening — Design

- **Date:** 2026-07-27
- **Status:** Approved (brainstorming → spec)
- **Related:** `docs/superpowers/assessments/2026-07-27-holistic-capability-map.md` (Keystone #4, fast wins #1/#2/#5),
  the standing "insecure-by-default" hard blocker; `src/ccf/config.py`, `src/ccf/api/routes/auth.py`, `src/ccf/auth.py`

## Problem

The platform cannot yet meet the controls it assesses. Concrete gaps (from the 2026-07-27 audit):
- **Insecure-by-default (the standing blocker, IA-01/AC-4):** `config.py:22` `env` defaults to `"dev"`,
  and `enforce_secure_config` no-ops for dev/local/test. So an operator who deploys **without setting
  `CCF_ENV`** gets `env="dev"` → auth disabled + default session secret + wildcard CORS, silently — every
  request an unscoped global admin with RLS off. Wildcard CORS is only ever a *warning*, never blocking.
  Latent bug: `auth.py:37` gates the cookie `secure` flag on `env == "prod"`, a value the codebase never
  uses (it uses `production`), so session cookies are never marked secure.
- **No account lockout (AC-7):** `auth.py:50` verifies the password with no failed-attempt counter,
  delay, or lockout — trivially brute-forceable.
- **No password policy (IA-5):** `auth.py hash_password` accepts any string; no caller validates length.
- **No login rate limiting**, though `slowapi` is wired (`main.py:87`, default 120/min) — login has no
  specific limit.
- **No security response headers (SC-8/SI-10):** no HSTS/nosniff/frame-options/CSP.
- **No SAST (RA-5/SA-11):** CI runs ruff/mypy/pytest/pip-audit/Trivy but no static analysis of
  first-party code.

## Goal

A cohesive "platform meets its own IA/AC/SC/RA controls" slice: fail closed by default, lock out
brute-force, enforce a password policy, rate-limit login, ship security headers, and gate first-party
code with SAST — without breaking local dev or the test suite.

### Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Secure-by-default | **Hard fail-closed.** Unset `CCF_ENV`/`production` with insecure config refuses startup; wildcard CORS in non-dev is a hard error. Tests pinned to `env=test`; dev stack to `env=dev`. |
| Auth policy | **NIST 800-63B aligned.** Lockout 5 attempts / 15 min (configurable); password min length 12, no forced composition/rotation. |
| Extra scope | Login rate limiting (slowapi), security-headers middleware, SAST (bandit) in CI. |

### Non-goals (deferred)
MFA/TOTP/WebAuthn, PIV/CAC, SSO/OIDC hardening (nonce/PKCE), breached-password screening, KMS/FIPS,
SIEM export — larger separate slices (see the capability map's Keystone #4).

## 1. Secure-by-default inversion (`config.py`, `api/main.py`, `api/routes/auth.py`, conftest, compose)

- Add a canonical helper `def is_dev_env(settings) -> bool: return (settings.env or "").lower() in _DEV_ENVS`.
- `config.py`: change `env` default `"dev"` → `"production"`.
- `enforce_secure_config`: unchanged skip for `is_dev_env`; **move wildcard CORS from `warnings` to
  `problems`** (so non-dev `api_cors_origins == ["*"]` refuses startup). Keep auth-disabled + default-secret
  as problems.
- `auth.py:37`: replace `secure=settings.env == "prod"` with `secure=not is_dev_env(settings)` (fixes the
  latent never-secure-cookie bug).
- **Test/dev safety (must not break the 654-test suite or local dev):**
  - `tests/conftest.py`: `os.environ.setdefault("CCF_ENV", "test")` at the top, BEFORE any settings load
    (alongside the existing `CCF_DATABASE_URL` setdefaults).
  - `docker-compose.yml`: set `CCF_ENV=dev` on the `api` service env (dev stack stays frictionless);
    document that production must set `CCF_ENV=production` + `CCF_AUTH_ENABLED=true` +
    `CCF_AUTH_SESSION_SECRET` + `CCF_API_CORS_ORIGINS`.
  - `Makefile` `serve`: export `CCF_ENV=dev`.
- Existing `tests/test_secure_config.py` constructs `Settings` with explicit env — verify it still passes;
  extend it to assert wildcard CORS in non-dev now raises.

## 2. Account lockout (AC-7) — `models.py`, migration `0053`, `api/routes/auth.py`, `config.py`

- `User` += `failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")`,
  `locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))`. Migration `0053`
  (`down_revision=0052`). No RLS change (users table policy unchanged).
- `config.py`: `auth_lockout_threshold: int = Field(default=5)`, `auth_lockout_minutes: int = Field(default=15)`.
- Login route logic (`auth.py login`):
  1. Fetch the active user by email.
  2. If `user` and `user.locked_until` and `locked_until > now(UTC)` → `HTTPException(429, "account temporarily locked")`.
  3. If password fails: when `user` is not None, `failed_login_attempts += 1`; if `>= threshold`, set
     `locked_until = now + lockout_minutes` and reset the counter; `await session.commit()`; then `401`.
     (When `user is None`, no row to track — generic `401`, no enumeration signal.)
  4. On success: if `failed_login_attempts` or `locked_until` set, reset both to 0/None; `commit`; proceed.
- Use `datetime.now(UTC)`; tests set `locked_until`/attempts directly and drive the loop.

## 3. Password policy (IA-5) — `auth.py`, `cli.py`, `config.py`

- `config.py`: `auth_password_min_length: int = Field(default=12)`.
- `auth.py`: `def validate_password_policy(password: str, *, min_length: int) -> None` — raise
  `ValueError` if `len(password) < min_length`. (No composition/rotation — 800-63B.)
- Wire into every password-set path: `cli.py:430` (`user-create`) — validate before `hash_password`,
  surfacing a clear CLI error. (No password-change HTTP endpoint exists today; when one is added it must
  call this.) A thin helper `hash_password_checked(pw, min_length)` may wrap validate + hash for reuse.

## 4. Login rate limiting — `api/routes/auth.py`, `api/main.py`

- The app already has `limiter = Limiter(key_func=get_remote_address)` on `app.state.limiter` with the
  slowapi exception handler. Add a per-IP limit to the login route: decorate `login` with
  `@limiter.limit(settings-driven string, e.g. "10/minute")` (slowapi requires the endpoint to take
  `request: Request`; add it). Config `auth_login_rate_limit: str = Field(default="10/minute")`.
- Exceeding the limit returns slowapi's `429` via the existing handler. Test asserts the Nth rapid login
  attempt returns `429`.

## 5. Security headers middleware (SC-8/SI-10) — `api/security_headers.py`, `api/main.py`

- A **pure-ASGI** middleware `SecurityHeadersMiddleware` (NOT `BaseHTTPMiddleware` — avoids the known
  re-entry bug) that wraps `send` to append on the response start:
  `Strict-Transport-Security: max-age=31536000; includeSubDomains` (only when not dev / over TLS),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  and a baseline `Content-Security-Policy` (`default-src 'self'; ...`) tuned to allow the app's own
  static assets + inline needs (the templates use HTMX/Alpine/lucide/mermaid from `/static`; verify the
  CSP permits them — start permissive enough not to break the UI, e.g. allow `'self'` + `'unsafe-inline'`
  for styles/scripts as the current app relies on inline; tighten later).
- Register in `main.py` `app.add_middleware(SecurityHeadersMiddleware)`.
- Test: a normal response carries the headers; the CSP is present.

## 6. SAST in CI (RA-5/SA-11) — `.github/workflows/ci.yml`, `pyproject.toml`

- Add `bandit` to `[project.optional-dependencies].dev`.
- Add a CI step in the `quality` job (after mypy): `bandit -r src -ll -x tests` (medium+ severity/
  confidence; exclude tests). Fix or `# nosec` (with justification) any findings so the step passes.
- Locally run `bandit -r src -ll` and resolve findings before committing.

## Testing (TDD; harness `session_scope()`/`fresh_engine`, no `db_session` fixture)

- **Secure config:** `enforce_secure_config` — non-dev + insecure → raises (incl. wildcard CORS);
  `is_dev_env` correctness; the full suite still builds the app (conftest `env=test`).
- **Lockout:** N failed attempts → account locked (429 on the next attempt); a locked account with a
  future `locked_until` → 429; successful login resets the counter; lockout auto-expires (set
  `locked_until` in the past → login succeeds).
- **Password policy:** `validate_password_policy` raises under min length; `user-create` rejects a short
  password.
- **Rate limit:** rapid repeated login attempts trip `429`.
- **Security headers:** a response carries nosniff/frame-options/referrer/CSP.
- **CI/SAST:** `bandit -r src -ll` clean (verified locally).

## Rollout / behavior change (release note)

**Breaking (intended):** after this, a deployment with `CCF_ENV` unset (or `production`) and auth
disabled / default secret / wildcard CORS **will refuse to start**. Operators must set `CCF_ENV=production`
+ `CCF_AUTH_ENABLED=true` + a real `CCF_AUTH_SESSION_SECRET` + explicit `CCF_API_CORS_ORIGINS`. Local dev
and CI are unaffected (compose/Makefile/conftest set dev/test). Migration `0053` adds two nullable/default
columns to `users` (rebuild `api`+`migrator` images).

## Success criteria
1. Unset/`production` env + insecure config refuses startup; dev/test unaffected; full suite green.
2. Session cookie is `secure` in any non-dev env (latent bug fixed).
3. Account lockout after threshold; auto-expiry; reset on success (tested).
4. Password policy enforced on set (tested).
5. Login rate-limited (429, tested); security headers present (tested).
6. `bandit -r src -ll` runs in CI and is clean.
7. ruff + mypy-strict clean; alembic single head `0053`.
