# Platform Config & Authentication Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the platform meet its own IA/AC/SC/RA controls — fail closed by default, account lockout, password policy, login rate limiting, security headers, and SAST in CI — without breaking local dev or the 654-test suite.

**Architecture:** Config-layer inversion (`env` default → fail-closed; wildcard CORS a hard error; canonical `is_dev_env`), a `User` lockout state + login-route logic, a password-policy validator, a slowapi login limit, a pure-ASGI security-headers middleware, and a bandit CI step.

**Tech Stack:** Python 3.12, FastAPI, async SQLAlchemy/asyncpg, Alembic, slowapi, bandit, pytest.

**Spec:** `docs/superpowers/specs/2026-07-27-platform-hardening-design.md` (authoritative).

## Global Constraints

- **Must not break the suite or local dev:** `tests/conftest.py` sets `CCF_ENV=test` and `docker-compose.yml`/`Makefile` set `CCF_ENV=dev`. Verify the FULL suite stays green after the env-default flip.
- **Fail-closed semantics:** `enforce_secure_config` refuses startup (RuntimeError) in non-dev when auth is disabled OR the session secret is default OR CORS is wildcard.
- **Canonical env check:** add `is_dev_env(settings)` and use it in `enforce_secure_config` AND the cookie `secure` flag (never string-compare `env == "prod"`).
- **NIST 800-63B:** lockout 5/15min (config), password min length 12, no composition/rotation.
- **Pure-ASGI middleware** for security headers (not BaseHTTPMiddleware).
- **Test harness:** `PYTHONPATH=src`, `CCF_DATABASE_URL[_SYNC]=...localhost:5433/ccf_test`; NO `db_session` fixture — use `session_scope()` + `fresh_engine`; DB tests copy `_migrate` from `test_ato.py`. Style: ruff + mypy-strict clean, line-length 100, no function-level imports. **Stage only your own files** (never `git add -A`). Commit on branch `feat/platform-hardening`.

---

### Task 1: Secure-by-default inversion + CORS fail-closed + cookie fix

**Files:** Modify `src/ccf/config.py`, `src/ccf/api/main.py` (CORS/log path only if needed), `src/ccf/api/routes/auth.py` (cookie flag), `tests/conftest.py`, `docker-compose.yml`, `Makefile`; Test: `tests/test_secure_config.py` (extend existing).

- [ ] **Step 1: conftest env pin (do FIRST so the suite survives the flip).** In `tests/conftest.py`, near the existing `os.environ.setdefault("CCF_DATABASE_URL", ...)`, add `os.environ.setdefault("CCF_ENV", "test")`. Run the full suite once to confirm still green BEFORE changing the default.
- [ ] **Step 2: config changes.** In `src/ccf/config.py`:
  - Change `env: str = Field(default="dev", ...)` → `default="production"`.
  - Add after `_DEV_ENVS`:
    ```python
    def is_dev_env(settings: "Settings") -> bool:
        return (settings.env or "").lower() in _DEV_ENVS
    ```
  - In `enforce_secure_config`, replace the `env in _DEV_ENVS` guard with `if is_dev_env(settings): return []`, and MOVE the wildcard-CORS check from `warnings` into `problems`:
    ```python
    if settings.api_cors_origins == ["*"]:
        problems.append("CORS is wildcard '*' (set CCF_API_CORS_ORIGINS to explicit origins)")
    ```
    (Keep returning `warnings` for anything non-fatal; the function still raises when `problems`.)
- [ ] **Step 3: cookie fix.** In `src/ccf/api/routes/auth.py` `_set_session_cookie`, `import` `is_dev_env` and set `secure=not is_dev_env(get_settings())` (replacing `settings.env == "prod"`).
- [ ] **Step 4: dev ergonomics.** `docker-compose.yml`: add `CCF_ENV: dev` to the `api` service environment (find the `*ccf_env` anchor or the api `environment:` block). `Makefile` `serve` target: prefix `CCF_ENV=dev`. (These keep the local stack starting without extra config.)
- [ ] **Step 5: tests.** Extend `tests/test_secure_config.py`: constructing `Settings(env="production", auth_enabled=False)` → `enforce_secure_config` raises; `Settings(env="production", auth_enabled=True, auth_session_secret="x", api_cors_origins=["*"])` → raises for wildcard CORS; `Settings(env="test", ...insecure...)` → returns `[]`; `is_dev_env` true for dev/local/test, false for production/"". Read the existing test file first to match its construction style.
- [ ] **Step 6:** Run `tests/test_secure_config.py` + the FULL suite (must stay green). ruff/mypy clean. **Commit:** `feat(config): fail closed by default + wildcard CORS hard error + secure-cookie fix`.

---

### Task 2: Account lockout (AC-7)

**Files:** Modify `src/ccf/models.py` (User), `src/ccf/config.py`, `src/ccf/api/routes/auth.py`; Create `migrations/versions/0053_user_lockout.py`; Test: `tests/test_login_lockout.py`.

- [ ] **Step 1: model.** Add to `User`: `failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")` and `locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))`.
- [ ] **Step 2: config.** `auth_lockout_threshold: int = Field(default=5)`, `auth_lockout_minutes: int = Field(default=15)`.
- [ ] **Step 3: migration `0053_user_lockout.py`** (`down_revision="0052_system_boundary_inventory"`):
  ```python
  def upgrade():
      op.add_column("users", sa.Column("failed_login_attempts", sa.Integer, server_default="0", nullable=False), schema="ccf")
      op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True)), schema="ccf")
  def downgrade():
      op.drop_column("users", "locked_until", schema="ccf")
      op.drop_column("users", "failed_login_attempts", schema="ccf")
  ```
  Run `alembic upgrade head`; confirm single head `0053_user_lockout`.
- [ ] **Step 4: failing tests** `tests/test_login_lockout.py` (auth ENABLED — mirror `test_audit_rbac.py` harness; create a user with a known password via `hash_password`). Cover: (a) a locked user (`locked_until` in the future, set directly) → POST `/api/auth/login` returns 429; (b) `threshold` wrong-password attempts → the account becomes locked (attempt N+1 → 429), and `failed_login_attempts`/`locked_until` are set in the DB; (c) a correct login resets `failed_login_attempts` to 0 and clears `locked_until`; (d) an expired lock (`locked_until` in the past) → correct login succeeds.
- [ ] **Step 5: implement login** (`src/ccf/api/routes/auth.py login`), using `from datetime import UTC, datetime, timedelta` and `get_settings()`:
  ```python
  now = datetime.now(UTC)
  if user is not None and user.locked_until is not None and user.locked_until > now:
      raise HTTPException(429, "account temporarily locked")
  if user is None or not verify_password(body.password, user.password_hash):
      if user is not None:
          s = get_settings()
          user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
          if user.failed_login_attempts >= s.auth_lockout_threshold:
              user.locked_until = now + timedelta(minutes=s.auth_lockout_minutes)
              user.failed_login_attempts = 0
          await session.commit()
      raise HTTPException(401, "invalid credentials")
  if user.failed_login_attempts or user.locked_until:
      user.failed_login_attempts = 0
      user.locked_until = None
      await session.commit()
  _set_session_cookie(response, user.id)
  ...
  ```
- [ ] **Step 6:** Run `tests/test_login_lockout.py` + `tests/test_auth.py` (regression). ruff/mypy clean. **Commit:** `feat(auth): account lockout after failed logins (AC-7) + migration 0053`.

---

### Task 3: Password policy (IA-5)

**Files:** Modify `src/ccf/auth.py`, `src/ccf/config.py`, `src/ccf/cli.py`; Test: `tests/test_password_policy.py`.

- [ ] **Step 1: config.** `auth_password_min_length: int = Field(default=12)`.
- [ ] **Step 2: failing tests** — `validate_password_policy("short", min_length=12)` raises `ValueError`; a 12+-char password passes; assert the CLI `user-create` path rejects a short password (call the underlying function or the Typer command with a short password and assert a nonzero exit / raised error — read `cli.py` ~line 420-435 for how `user-create` is structured and test at the appropriate layer).
- [ ] **Step 3: implement** in `src/ccf/auth.py`:
  ```python
  def validate_password_policy(password: str, *, min_length: int) -> None:
      if len(password) < min_length:
          raise ValueError(f"password must be at least {min_length} characters")
  ```
  In `src/ccf/cli.py` `user-create` (~line 430, before `hash_password(password)`): call `validate_password_policy(password, min_length=get_settings().auth_password_min_length)` and surface a clean CLI error (e.g. `typer.echo(...); raise typer.Exit(1)`) on `ValueError`.
- [ ] **Step 4:** Run tests. ruff/mypy clean. **Commit:** `feat(auth): password minimum-length policy (IA-5)`.

---

### Task 4: Login rate limiting (slowapi)

**Files:** Modify `src/ccf/api/routes/auth.py`, `src/ccf/config.py`; Test: `tests/test_login_rate_limit.py`.

- [ ] **Step 1: config.** `auth_login_rate_limit: str = Field(default="10/minute")`.
- [ ] **Step 2: implement.** slowapi is already wired (`main.py:87` `limiter`, `app.state.limiter`, handler registered). Import the shared `limiter` (from `..main` would cause a cycle — instead import from where it's defined or expose it; SIMPLEST: define the limiter in a small module `src/ccf/api/limiter.py` and import it in both `main.py` and `auth.py`, OR access via `request.app.state.limiter`). Prefer: decorate `login` with `@limiter.limit("10/minute")` — slowapi's decorator REQUIRES the endpoint signature to include `request: Request`; add `request: Request` as the first param of `login`. Use the config value if the decorator supports a callable/string (a literal string is fine for v1; wire the config value if straightforward, else hardcode "10/minute" and read config in a follow-up — but prefer config).
  - If importing `limiter` cleanly is awkward, refactor: create `src/ccf/api/limiter.py` with `limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])`, import it in `main.py` (replacing the inline definition) and in `auth.py`. This avoids the circular import and is the clean structure.
- [ ] **Step 3: failing test** `tests/test_login_rate_limit.py` — POST `/api/auth/login` more than the limit times rapidly from the same client and assert a `429` appears. (slowapi keys on remote address; the test client's address is stable. Ensure the limiter is active — it may need `env` such that limiting is on; confirm slowapi isn't disabled in test config. If the limiter is globally disabled in tests, the test should enable it or assert the decorator is applied.) Read how any existing test exercises slowapi, if any.
- [ ] **Step 4:** Run test + `tests/test_auth.py` regression. ruff/mypy clean. **Commit:** `feat(auth): per-IP login rate limit`.

---

### Task 5: Security-headers middleware (SC-8/SI-10)

**Files:** Create `src/ccf/api/security_headers.py`; Modify `src/ccf/api/main.py`; Test: `tests/test_security_headers.py`.

- [ ] **Step 1: implement pure-ASGI middleware** `src/ccf/api/security_headers.py`:
  ```python
  from collections.abc import Awaitable, Callable
  from starlette.types import ASGIApp, Message, Receive, Scope, Send

  _HEADERS = {
      b"x-content-type-options": b"nosniff",
      b"x-frame-options": b"DENY",
      b"referrer-policy": b"no-referrer",
      b"content-security-policy": (
          b"default-src 'self'; img-src 'self' data:; "
          b"style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
          b"connect-src 'self'; frame-ancestors 'none'"
      ),
  }

  class SecurityHeadersMiddleware:
      def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
          self.app = app
          self.hsts = hsts

      async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
          if scope["type"] != "http":
              await self.app(scope, receive, send)
              return
          async def send_wrapper(message: Message) -> None:
              if message["type"] == "http.response.start":
                  headers = message.setdefault("headers", [])
                  existing = {k.lower() for k, _ in headers}
                  for k, v in _HEADERS.items():
                      if k not in existing:
                          headers.append((k, v))
                  if self.hsts and b"strict-transport-security" not in existing:
                      headers.append((b"strict-transport-security",
                                      b"max-age=31536000; includeSubDomains"))
              await send(message)
          await self.app(scope, receive, send_wrapper)
  ```
  IMPORTANT: verify the CSP does not break the app UI (HTMX/Alpine/lucide/mermaid + inline styles). The CSP above allows `'self'` + `'unsafe-inline'` for scripts/styles (the app relies on inline). If a test or manual check shows breakage, loosen minimally and note it.
- [ ] **Step 2: register** in `src/ccf/api/main.py`: `app.add_middleware(SecurityHeadersMiddleware, hsts=not is_dev_env(settings))` (import `is_dev_env`). Place it so it runs on all responses.
- [ ] **Step 3: failing test** `tests/test_security_headers.py` — GET a simple endpoint (e.g. `/healthz`) and assert the response carries `x-content-type-options: nosniff`, `x-frame-options: DENY`, `referrer-policy`, and a `content-security-policy`. (HSTS only asserted when not dev — in tests env=test so hsts off; assert HSTS absent OR construct the app with hsts on for that assertion.)
- [ ] **Step 4:** Run test + a broad UI regression (`tests/test_ui_grc_pages.py`, `tests/test_health.py`). ruff/mypy clean. **Commit:** `feat(api): security-headers middleware (SC-8/SI-10)`.

---

### Task 6: SAST (bandit) in CI

**Files:** Modify `pyproject.toml`, `.github/workflows/ci.yml`; optionally `bandit` config.

- [ ] **Step 1:** Add `bandit>=1.7,<2` to `[project.optional-dependencies].dev` in `pyproject.toml`.
- [ ] **Step 2: run locally** `pip install -e ".[dev]"` then `bandit -r src -ll -x tests` (or `-x src/ccf/reader` if needed). Review findings: fix real issues; for accepted ones add `# nosec BXXX - <reason>`. Common expected hits: `assert` usage (B101, in non-test code if any), `subprocess`/`hashlib` for non-security — justify or fix. Get the command to exit 0.
- [ ] **Step 3: CI step** — in `.github/workflows/ci.yml` `quality` job, after the `mypy src` step, add:
  ```yaml
      - run: bandit -r src -ll -x tests
  ```
- [ ] **Step 4: commit** `ci(sast): add bandit static analysis (RA-5/SA-11)`.

---

## Final verification (after all tasks)
- [ ] `PYTHONPATH=src ruff check .` + `mypy src` clean; `bandit -r src -ll -x tests` clean.
- [ ] Full suite green (`pytest -q`; baseline 654 + new).
- [ ] `alembic heads` → single `0053`; rebuild `docker compose build api migrator`; `docker compose up -d db migrator api` with `CCF_ENV=dev` starts cleanly; confirm `/healthz` carries security headers.
- [ ] Sanity: `CCF_ENV=production` + defaults → app refuses to start (manual: `CCF_ENV=production python -c "from ccf.api.main import create_app; create_app()"` raises).

## Self-Review
**Spec coverage:** secure-by-default inversion + CORS + cookie fix ✔(T1); lockout ✔(T2); password policy ✔(T3); rate limit ✔(T4); security headers ✔(T5); SAST ✔(T6). **Placeholders:** none — code given for the non-obvious pieces. **Type consistency:** `is_dev_env` defined T1 and reused T5; `validate_password_policy` T3; `auth_lockout_threshold/minutes` T2, `auth_password_min_length` T3, `auth_login_rate_limit` T4 all added to `config.py`. **Ordering risk:** T1 Step 1 (conftest env pin) MUST precede the default flip or the suite breaks — called out explicitly.
