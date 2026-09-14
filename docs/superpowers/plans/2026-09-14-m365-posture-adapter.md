# Microsoft 365 Posture Adapter (P3a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make P2a's posture spine real for one provider — three Microsoft Graph checks that name which users and policies are non-compliant.

**Architecture:** Check definitions and their pure evaluation functions live together in `posture/providers/m365.py` (content plus logic, destined for `packs/` in P2b); transport stays in `connectors/msgraph.py`, which gains a paginating fetch and a `scan()` that dispatches to the evaluators. Every evaluator is pure and unit-tested against recorded Graph shapes.

**Tech Stack:** Python 3.12, httpx (already a core dependency — no new ones), pytest + pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-09-14-m365-posture-adapter-design.md`
**Depends on:** `docs/superpowers/specs/2026-09-14-posture-validation-spine-design.md` (P2a)

## Global Constraints

- **This cannot be verified against a real tenant.** No M365 credentials exist here. Every *evaluation* function must be pure and tested against recorded Graph response shapes; the network call is a thin marked seam. Never describe a check as observed working against live M365.
- **A permission failure must NEVER read as a clean fleet.** P2a's rollup maps zero findings to `not_applicable`. A 401/403 must instead produce **exactly one** `ResourceFinding` with verdict `manual_review_required`, `resource_id` = the tenant, and `observed` naming the status and the required permission. This is the most important behaviour in the slice.
- **Follow `@odata.nextLink`.** A finding on page four must not be invisible. Page cap `_MAX_PAGES = 50`.
- **`scan()` must never raise**, per `ConfigConnector.scan`'s contract, and must return `[]` when not configured — matching `capture()`.
- **Per-check isolation.** One check's failure must not discard the others, matching `capture()`'s per-sub-capture `try` and the scheduler's per-tenant SAVEPOINT.
- **Do not modify `capture()`.** Its ODP behaviour is established and tested. Its own pagination gap is noted in the spec and deliberately left alone.
- **No new dependencies.** Graph over `httpx`. The repo's stance is that provider SDKs are not added — `boto3` is not in `pyproject.toml` at all.
- **No credential-handling change.** `resolve_credential` stays the only path, per-organization, no global fallback.
- **No new verdict vocabulary.** `manual_review_required` already exists in `VALIDATION_STATUSES` and is already ranked.
- **`control_ids` are canonical** (`IA-2`), never zero-padded (`IA-02`).
- **Staleness uses `signInActivity.lastSignInDateTime`** — the interactive timestamp. `lastNonInteractiveSignInDateTime` moves on background token refresh, so an abandoned account looks active indefinitely under it.
- **Test database is on port 5434.** `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test`. Never run two pytest sessions at once.
- `ruff check src tests` and `mypy src` must be clean.

---

### Task 1: The two enablers — pagination and required permissions

Both are small, both are needed by every check, and neither makes sense to test through a check.

**Files:**
- Modify: `src/ccf/posture/checks.py` (add `required_permissions`)
- Modify: `src/ccf/connectors/msgraph.py` (add `_get_all`)
- Test: `tests/test_m365_fetch.py`

**Interfaces:**
- Produces:
  - `PostureCheck.required_permissions: tuple[str, ...] = ()`
  - `MsGraphConnector._MAX_PAGES: int = 50`
  - `async MsGraphConnector._get_all(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> list[dict[str, Any]]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_m365_fetch.py
"""Graph pagination, and the permission field every check carries."""

from __future__ import annotations

import httpx
import pytest

from ccf.connectors.msgraph import MsGraphConnector
from ccf.posture.checks import PostureCheck


def test_posture_check_carries_required_permissions() -> None:
    c = PostureCheck(
        key="k",
        title="t",
        provider="msgraph",
        resource_type="entra_user",
        expected="e",
        control_ids=("IA-2",),
        required_permissions=("AuditLog.Read.All",),
    )
    assert c.required_permissions == ("AuditLog.Read.All",)


def test_required_permissions_defaults_to_empty() -> None:
    """Additive on a frozen dataclass: existing constructions keep working."""
    c = PostureCheck(
        key="k",
        title="t",
        provider="msgraph",
        resource_type="entra_user",
        expected="e",
        control_ids=("IA-2",),
    )
    assert c.required_permissions == ()


async def test_get_all_follows_next_link() -> None:
    """A finding on page two must not be invisible."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "skiptoken" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "b"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "a"}],
                "@odata.nextLink": "https://graph.microsoft.us/v1.0/users?$skiptoken=X",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert [r["id"] for r in rows] == ["a", "b"]
    assert len(calls) == 2


async def test_get_all_single_page_makes_one_request() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"value": [{"id": "only"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert len(rows) == 1
    assert len(calls) == 1


async def test_get_all_stops_at_the_page_cap() -> None:
    """A self-referential nextLink must not spin forever."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "value": [{"id": len(calls)}],
                "@odata.nextLink": "https://graph.microsoft.us/v1.0/users?$skiptoken=loop",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await MsGraphConnector()._get_all(
            client, "https://graph.microsoft.us/v1.0/users", {}
        )
    assert len(calls) == MsGraphConnector._MAX_PAGES
    assert len(rows) == MsGraphConnector._MAX_PAGES


async def test_get_all_raises_on_error_status() -> None:
    """scan() relies on this raising so it can map 403 to manual review."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "Insufficient privileges"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )


async def test_get_all_tolerates_a_missing_value_array() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert (
            await MsGraphConnector()._get_all(
                client, "https://graph.microsoft.us/v1.0/users", {}
            )
            == []
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_m365_fetch.py -v`
Expected: FAIL — `TypeError: PostureCheck.__init__() got an unexpected keyword argument 'required_permissions'`

- [ ] **Step 3: Add `required_permissions` to `PostureCheck`**

In `src/ccf/posture/checks.py`, inside `PostureCheck`, after `capability_key`:

```python
    #: Provider permissions this check needs, e.g. ("AuditLog.Read.All",).
    #: Carried so a manual_review_required verdict can name the missing
    #: permission instead of leaving an operator to infer it from a 403.
    required_permissions: tuple[str, ...] = ()
```

- [ ] **Step 4: Add `_get_all` to `MsGraphConnector`**

In `src/ccf/connectors/msgraph.py`, add the constant to the class body beside
`key`/`label`, and the method after `_token`:

```python
    #: Hard cap on pages followed, so a pathological or self-referential
    #: ``@odata.nextLink`` cannot spin forever.
    _MAX_PAGES: ClassVar[int] = 50

    async def _get_all(
        self, client: httpx.AsyncClient, url: str, headers: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Every page of a Graph collection, following ``@odata.nextLink``.

        Posture scanning needs this where :meth:`capture` does not: capture
        reads Conditional Access policies, of which there are few, but a fleet
        check that stopped at page one would report ``pass`` while three
        non-compliant users sat on page four. Raises on a non-2xx status so
        :meth:`scan` can tell "could not look" from "nothing to see".
        """
        rows: list[dict[str, Any]] = []
        next_url: str | None = url
        for _ in range(self._MAX_PAGES):
            if not next_url:
                break
            resp = await client.get(next_url, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            rows.extend(payload.get("value") or [])
            nxt = payload.get("@odata.nextLink")
            next_url = nxt if isinstance(nxt, str) else None
        return rows
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_m365_fetch.py tests/test_posture_contract.py tests/test_connectors.py -v`
Expected: all pass — the new fetch tests plus P2a's contract tests and the
existing connector suite, proving the additive field broke nothing.

- [ ] **Step 6: Lint and commit**

```bash
ruff check src/ccf/posture/checks.py src/ccf/connectors/msgraph.py tests/test_m365_fetch.py
mypy src/ccf/posture/checks.py src/ccf/connectors/msgraph.py
git add src/ccf/posture/checks.py src/ccf/connectors/msgraph.py tests/test_m365_fetch.py
git commit -m "feat(m365): follow Graph pagination and carry required permissions"
```

---

### Task 2: The three checks and their pure evaluators

Definitions and evaluation live together — a check and how to judge it are one
thing, and keeping them paired is what makes P2b's move into `packs/` a
relocation of content with named evaluators rather than a redesign.

**Files:**
- Create: `src/ccf/posture/providers/__init__.py`
- Create: `src/ccf/posture/providers/m365.py`
- Modify: `src/ccf/posture/checks.py` (register the provider's checks)
- Test: `tests/test_m365_checks.py`

**Interfaces:**
- Consumes: `PostureCheck`, `ResourceFinding` (P2a); `required_permissions` (Task 1)
- Produces:
  - `MFA_REGISTERED`, `LEGACY_AUTH_BLOCKED`, `STALE_ACCOUNTS` — `PostureCheck` constants
  - `CHECKS: tuple[PostureCheck, ...]`
  - `EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]]` keyed by check key
  - `evaluate_mfa_registered(rows) -> list[ResourceFinding]`
  - `evaluate_legacy_auth_blocked(rows, *, tenant_id) -> list[ResourceFinding]`
  - `evaluate_stale_accounts(rows, *, now) -> list[ResourceFinding]`
  - `STALE_ACCOUNT_DAYS: int = 90`
  - `ENDPOINTS: dict[str, str]` keyed by check key

- [ ] **Step 1: Write the failing test**

```python
# tests/test_m365_checks.py
"""The three M365 checks, evaluated against recorded Graph shapes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccf.posture.checks import CheckOutcome, checks_for
from ccf.posture.providers.m365 import (
    LEGACY_AUTH_BLOCKED,
    MFA_REGISTERED,
    STALE_ACCOUNT_DAYS,
    STALE_ACCOUNTS,
    evaluate_legacy_auth_blocked,
    evaluate_mfa_registered,
    evaluate_stale_accounts,
)

NOW = datetime(2026, 9, 14, tzinfo=UTC)


def _iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


# ── MFA registration: a per-user fleet ───────────────────────────────────────


def test_mfa_mixed_fleet_names_the_failures() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "a@x.gov", "isMfaRegistered": True,
         "userType": "member", "isAdmin": False},
        {"id": "u2", "userPrincipalName": "b@x.gov", "isMfaRegistered": False,
         "userType": "member", "isAdmin": False},
        {"id": "u3", "userPrincipalName": "c@x.gov", "isMfaRegistered": True,
         "userType": "guest", "isAdmin": False},
    ]
    findings = evaluate_mfa_registered(rows)
    assert len(findings) == 3
    failing = [f for f in findings if f.verdict == "fail"]
    assert [f.resource_id for f in failing] == ["b@x.gov"]
    assert CheckOutcome.from_findings(MFA_REGISTERED, tuple(findings)).verdict == "fail"


def test_mfa_all_registered_passes() -> None:
    rows = [
        {"id": "u1", "userPrincipalName": "a@x.gov", "isMfaRegistered": True},
        {"id": "u2", "userPrincipalName": "b@x.gov", "isMfaRegistered": True},
    ]
    findings = evaluate_mfa_registered(rows)
    assert CheckOutcome.from_findings(MFA_REGISTERED, tuple(findings)).verdict == "pass"


def test_mfa_empty_fleet_is_not_applicable() -> None:
    assert evaluate_mfa_registered([]) == []
    assert CheckOutcome.from_findings(MFA_REGISTERED, ()).verdict == "not_applicable"


def test_mfa_records_what_was_counted() -> None:
    """userRegistrationDetails has no accountEnabled, so detail must show the
    user type that was included."""
    rows = [
        {"id": "u1", "userPrincipalName": "g@x.gov", "isMfaRegistered": False,
         "userType": "guest", "isAdmin": True}
    ]
    (f,) = evaluate_mfa_registered(rows)
    assert f.detail["userType"] == "guest"
    assert f.detail["isAdmin"] is True


def test_mfa_falls_back_to_id_when_upn_missing() -> None:
    (f,) = evaluate_mfa_registered([{"id": "u9", "isMfaRegistered": False}])
    assert f.resource_id == "u9"


# ── Legacy auth: a tenant singleton ──────────────────────────────────────────


def _blocking_policy(state: str = "enabled") -> dict:
    return {
        "id": "p1",
        "displayName": "Block legacy auth",
        "state": state,
        "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
        "grantControls": {"builtInControls": ["block"]},
    }


def test_legacy_auth_enabled_blocking_policy_passes() -> None:
    (f,) = evaluate_legacy_auth_blocked([_blocking_policy()], tenant_id="t-1")
    assert f.verdict == "pass"
    assert f.resource_id == "t-1"
    assert f.resource_type == "m365_tenant"


def test_legacy_auth_disabled_policy_does_not_pass() -> None:
    (f,) = evaluate_legacy_auth_blocked([_blocking_policy("disabled")], tenant_id="t-1")
    assert f.verdict == "fail"


def test_legacy_auth_report_only_policy_does_not_pass() -> None:
    """Report-only enforces nothing."""
    (f,) = evaluate_legacy_auth_blocked(
        [_blocking_policy("enabledForReportingButNotEnforced")], tenant_id="t-1"
    )
    assert f.verdict == "fail"


def test_legacy_auth_policy_without_block_does_not_pass() -> None:
    pol = _blocking_policy()
    pol["grantControls"] = {"builtInControls": ["mfa"]}
    (f,) = evaluate_legacy_auth_blocked([pol], tenant_id="t-1")
    assert f.verdict == "fail"


def test_legacy_auth_policy_not_targeting_legacy_clients_does_not_pass() -> None:
    pol = _blocking_policy()
    pol["conditions"] = {"clientAppTypes": ["browser"]}
    (f,) = evaluate_legacy_auth_blocked([pol], tenant_id="t-1")
    assert f.verdict == "fail"


def test_legacy_auth_no_policies_fails_with_one_finding() -> None:
    findings = evaluate_legacy_auth_blocked([], tenant_id="t-1")
    assert len(findings) == 1  # the tenant is always the resource
    assert findings[0].verdict == "fail"
    assert (
        CheckOutcome.from_findings(LEGACY_AUTH_BLOCKED, tuple(findings)).verdict == "fail"
    )


# ── Stale accounts: per-user with exclusions ─────────────────────────────────


def test_stale_account_fails_past_the_threshold() -> None:
    rows = [
        {
            "id": "u1",
            "userPrincipalName": "old@x.gov",
            "accountEnabled": True,
            "signInActivity": {"lastSignInDateTime": _iso(STALE_ACCOUNT_DAYS + 10)},
        }
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "fail"


def test_recent_account_passes() -> None:
    rows = [
        {
            "id": "u1",
            "userPrincipalName": "new@x.gov",
            "accountEnabled": True,
            "signInActivity": {"lastSignInDateTime": _iso(3)},
        }
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "pass"


def test_disabled_account_is_not_applicable() -> None:
    """A disabled account is not a stale-access risk."""
    rows = [
        {
            "id": "u1",
            "userPrincipalName": "off@x.gov",
            "accountEnabled": False,
            "signInActivity": {"lastSignInDateTime": _iso(400)},
        }
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "not_applicable"


def test_missing_sign_in_activity_is_not_applicable() -> None:
    """Graph omits signInActivity without the right licence; absence is not
    evidence of staleness."""
    rows = [{"id": "u1", "userPrincipalName": "x@x.gov", "accountEnabled": True}]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "not_applicable"


def test_uses_interactive_sign_in_not_the_background_one() -> None:
    """lastNonInteractiveSignInDateTime moves on token refresh, so an
    abandoned account would look active under it."""
    rows = [
        {
            "id": "u1",
            "userPrincipalName": "abandoned@x.gov",
            "accountEnabled": True,
            "signInActivity": {
                "lastSignInDateTime": _iso(400),
                "lastNonInteractiveSignInDateTime": _iso(1),
            },
        }
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "fail"


def test_disabled_accounts_are_excluded_from_the_verdict() -> None:
    """End-to-end proof of P2a's exclusion rule: one disabled account among
    two passing ones must leave the check passing, while still being counted
    as examined."""
    rows = [
        {"id": "a", "userPrincipalName": "a@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": _iso(1)}},
        {"id": "b", "userPrincipalName": "b@x.gov", "accountEnabled": True,
         "signInActivity": {"lastSignInDateTime": _iso(2)}},
        {"id": "c", "userPrincipalName": "c@x.gov", "accountEnabled": False,
         "signInActivity": {"lastSignInDateTime": _iso(999)}},
    ]
    findings = evaluate_stale_accounts(rows, now=NOW)
    outcome = CheckOutcome.from_findings(STALE_ACCOUNTS, tuple(findings))
    assert outcome.verdict == "pass"
    assert outcome.evaluated == 3  # counted as examined
    assert outcome.failing == 0


def test_malformed_timestamp_is_not_applicable_not_a_crash() -> None:
    rows = [
        {
            "id": "u1",
            "userPrincipalName": "bad@x.gov",
            "accountEnabled": True,
            "signInActivity": {"lastSignInDateTime": "not-a-date"},
        }
    ]
    (f,) = evaluate_stale_accounts(rows, now=NOW)
    assert f.verdict == "not_applicable"


# ── Registration ─────────────────────────────────────────────────────────────


def test_all_three_checks_are_registered_under_msgraph() -> None:
    keys = {c.key for c in checks_for("msgraph")}
    assert keys == {
        "m365.identity.mfa_registered",
        "m365.policy.legacy_auth_blocked",
        "m365.identity.stale_accounts",
    }


def test_every_check_declares_controls_and_permissions() -> None:
    for c in checks_for("msgraph"):
        assert c.control_ids, c.key
        assert c.required_permissions, c.key
        assert c.provider == "msgraph"


def test_control_ids_are_canonical_not_zero_padded() -> None:
    for c in checks_for("msgraph"):
        for cid in c.control_ids:
            assert "-0" not in cid, f"{c.key} uses a zero-padded id: {cid}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_m365_checks.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ccf.posture.providers'`

- [ ] **Step 3: Create the providers package**

`src/ccf/posture/providers/__init__.py`:

```python
"""Per-provider posture check definitions and their evaluation logic.

A check and how to judge it are one thing, so they live together here rather
than the definition sitting apart from the function that reads it. Transport
stays in the connector: these modules never make a network call, which is what
makes every evaluator a pure unit test against a recorded provider shape.

P2b relocates the definitions into ``packs/``; the evaluators stay as named
functions the pack references by key, so that move is a relocation rather than
a redesign.
"""

from __future__ import annotations
```

- [ ] **Step 4: Write `src/ccf/posture/providers/m365.py`**

```python
"""Microsoft 365 / Entra posture checks.

Three checks spanning three resource shapes -- a per-user fleet, a tenant-level
singleton, and a per-user check with exclusions -- so the posture spine is
exercised across all of them rather than three variations of one.

Every evaluator here is pure: it takes the rows a Graph collection returned and
returns findings. No network, no clock, no database -- ``now`` is passed in --
so each is unit-testable against a recorded Graph shape, which matters because
no live tenant is reachable from the build environment.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from ..checks import PostureCheck, ResourceFinding

#: Inactivity threshold for the stale-account check. Wants to be an
#: organization-defined parameter -- the ODP machinery already exists for
#: exactly this -- but binding it is its own change, and a constant with a
#: recorded intent is honest where inventing configuration now is premature.
STALE_ACCOUNT_DAYS = 90

#: Graph client app types that mean legacy (pre-modern-auth) authentication.
_LEGACY_CLIENT_APP_TYPES = frozenset({"exchangeActiveSync", "other"})


MFA_REGISTERED = PostureCheck(
    key="m365.identity.mfa_registered",
    title="Every user has an MFA method registered",
    provider="msgraph",
    resource_type="entra_user",
    expected="every user has a multi-factor authentication method registered",
    control_ids=("IA-2", "IA-2(1)"),
    required_permissions=("AuditLog.Read.All",),
)

LEGACY_AUTH_BLOCKED = PostureCheck(
    key="m365.policy.legacy_auth_blocked",
    title="Legacy authentication is blocked",
    provider="msgraph",
    resource_type="m365_tenant",
    expected="an enabled Conditional Access policy blocks legacy authentication clients",
    control_ids=("IA-2", "AC-17"),
    required_permissions=("Policy.Read.All",),
)

STALE_ACCOUNTS = PostureCheck(
    key="m365.identity.stale_accounts",
    title="No enabled account is inactive past the threshold",
    provider="msgraph",
    resource_type="entra_user",
    expected=(
        f"no enabled account has been inactive longer than {STALE_ACCOUNT_DAYS} days"
    ),
    control_ids=("AC-2", "AC-2(3)"),
    required_permissions=("AuditLog.Read.All", "User.Read.All"),
)

CHECKS: tuple[PostureCheck, ...] = (MFA_REGISTERED, LEGACY_AUTH_BLOCKED, STALE_ACCOUNTS)

#: Graph collection each check reads, relative to the Graph base URL.
ENDPOINTS: dict[str, str] = {
    MFA_REGISTERED.key: "/v1.0/reports/authenticationMethods/userRegistrationDetails",
    LEGACY_AUTH_BLOCKED.key: "/v1.0/identity/conditionalAccess/policies",
    STALE_ACCOUNTS.key: (
        "/v1.0/users?$select=id,userPrincipalName,accountEnabled,signInActivity"
    ),
}


def _user_ref(row: dict[str, Any]) -> str:
    """UPN where Graph gave one, else the object id -- never empty."""
    upn = row.get("userPrincipalName")
    if isinstance(upn, str) and upn:
        return upn
    return str(row.get("id") or "unknown")


def evaluate_mfa_registered(rows: list[dict[str, Any]]) -> list[ResourceFinding]:
    """One finding per user: is an MFA method registered?

    Known limitation: ``userRegistrationDetails`` does not expose
    ``accountEnabled``, so every user Graph returns is assessed, disabled
    accounts included. ``userType`` and ``isAdmin`` are recorded in ``detail``
    so an operator can see what was counted. Joining ``/users`` to exclude
    disabled accounts is not something Graph supports cheaply, and inventing
    that join would trade a stated limitation for a hidden one.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        registered = bool(row.get("isMfaRegistered"))
        findings.append(
            ResourceFinding(
                resource_id=_user_ref(row),
                resource_type="entra_user",
                verdict="pass" if registered else "fail",
                observed=(
                    "MFA method registered" if registered else "no MFA method registered"
                ),
                detail={
                    "userType": row.get("userType"),
                    "isAdmin": row.get("isAdmin"),
                },
            )
        )
    return findings


def _blocks_legacy_auth(policy: dict[str, Any]) -> bool:
    """True when an *enforced* policy blocks legacy clients.

    ``state`` must be exactly ``enabled``: ``disabled`` enforces nothing, and
    ``enabledForReportingButNotEnforced`` reports without blocking, so neither
    may satisfy the check. The existing ``_map_mfa`` and
    ``_map_conditional_access`` mappers apply the same test.
    """
    if (policy.get("state") or "") != "enabled":
        return False
    app_types = set((policy.get("conditions") or {}).get("clientAppTypes") or [])
    if not (app_types & _LEGACY_CLIENT_APP_TYPES):
        return False
    controls = (policy.get("grantControls") or {}).get("builtInControls") or []
    return "block" in controls


def evaluate_legacy_auth_blocked(
    rows: list[dict[str, Any]], *, tenant_id: str
) -> list[ResourceFinding]:
    """Exactly one finding: the tenant is the resource.

    A tenant-level boolean still produces a ``ResourceFinding`` so one result
    model covers every shape, and so "which resource failed" has an answer
    here too.
    """
    blocking = next((p for p in rows if _blocks_legacy_auth(p)), None)
    if blocking is not None:
        return [
            ResourceFinding(
                resource_id=tenant_id,
                resource_type="m365_tenant",
                verdict="pass",
                observed=(
                    "blocked by Conditional Access policy "
                    f"{blocking.get('displayName') or blocking.get('id')!r}"
                ),
                detail={"policy_id": blocking.get("id")},
            )
        ]
    return [
        ResourceFinding(
            resource_id=tenant_id,
            resource_type="m365_tenant",
            verdict="fail",
            observed="no enabled Conditional Access policy blocks legacy authentication",
            detail={"policies_examined": len(rows)},
        )
    ]


def _parse_graph_datetime(value: Any) -> datetime | None:
    """Graph timestamps are ISO-8601 with a ``Z``; anything else is unusable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def evaluate_stale_accounts(
    rows: list[dict[str, Any]], *, now: datetime
) -> list[ResourceFinding]:
    """One finding per user: has an enabled account gone inactive?

    ``now`` is a parameter so the evaluator stays pure and the threshold is
    testable without freezing the clock.

    Two cases are ``not_applicable`` rather than ``pass`` or ``fail``. A
    disabled account is not a stale-access risk. And Graph omits
    ``signInActivity`` without the right licence -- absence of a timestamp is
    not evidence of staleness, and calling it ``pass`` would assert something
    never observed.

    Uses ``lastSignInDateTime``, the *interactive* timestamp:
    ``lastNonInteractiveSignInDateTime`` moves on background token refresh, so
    an abandoned account looks active indefinitely under it.
    """
    findings: list[ResourceFinding] = []
    for row in rows:
        ref = _user_ref(row)
        if not row.get("accountEnabled", False):
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="entra_user",
                    verdict="not_applicable",
                    observed="account disabled",
                )
            )
            continue
        activity = row.get("signInActivity") or {}
        last = _parse_graph_datetime(activity.get("lastSignInDateTime"))
        if last is None:
            findings.append(
                ResourceFinding(
                    resource_id=ref,
                    resource_type="entra_user",
                    verdict="not_applicable",
                    observed="no interactive sign-in activity reported",
                )
            )
            continue
        days = (now - last).days
        findings.append(
            ResourceFinding(
                resource_id=ref,
                resource_type="entra_user",
                verdict="fail" if days > STALE_ACCOUNT_DAYS else "pass",
                observed=f"last interactive sign-in {days} day(s) ago",
                detail={"last_sign_in": activity.get("lastSignInDateTime")},
            )
        )
    return findings


#: Check key -> its evaluator. ``scan`` dispatches through this rather than a
#: chain of conditionals, so adding a check is a registry entry.
EVALUATORS: dict[str, Callable[..., list[ResourceFinding]]] = {
    MFA_REGISTERED.key: evaluate_mfa_registered,
    LEGACY_AUTH_BLOCKED.key: evaluate_legacy_auth_blocked,
    STALE_ACCOUNTS.key: evaluate_stale_accounts,
}
```

- [ ] **Step 5: Register the checks**

In `src/ccf/posture/checks.py`, replace the empty `msgraph` entry. The import
goes at the **bottom** of the module, after `CHECK_REGISTRY` is defined, because
`providers.m365` imports `PostureCheck` and `ResourceFinding` from this module:

```python
CHECK_REGISTRY: dict[str, tuple[PostureCheck, ...]] = {
    "msgraph": (),
    "aws_govcloud": (),
}


def checks_for(provider: str) -> tuple[PostureCheck, ...]:
    """Checks registered for one provider; empty for an unknown provider."""
    return CHECK_REGISTRY.get(provider, ())


# Imported last: providers.m365 depends on PostureCheck/ResourceFinding above,
# so registering from here rather than at the top avoids a circular import.
from .providers import m365 as _m365  # noqa: E402

CHECK_REGISTRY["msgraph"] = _m365.CHECKS
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_m365_checks.py tests/test_posture_contract.py -v`
Expected: all pass — the 22 check tests plus P2a's contract tests, which now
see three real checks and must still hold (unique keys, real provider keys,
every check declaring controls).

- [ ] **Step 7: Lint and commit**

```bash
ruff check src/ccf/posture tests/test_m365_checks.py
mypy src/ccf/posture
git add src/ccf/posture tests/test_m365_checks.py
git commit -m "feat(m365): three posture checks spanning three resource shapes"
```

---

### Task 3: `scan()` — dispatch, isolation, and the failure-mode split

**Files:**
- Modify: `src/ccf/connectors/msgraph.py`
- Test: `tests/test_m365_scan.py`

**Interfaces:**
- Consumes: `_get_all` (Task 1); `CHECKS`, `ENDPOINTS`, `EVALUATORS`, check constants (Task 2); `CheckOutcome` (P2a)
- Produces: `MsGraphConnector.scan() -> list[CheckOutcome]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_m365_scan.py
"""scan() orchestration: dispatch, isolation, and 403-is-not-empty."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from ccf.connectors.msgraph import MsGraphConnector
from ccf.posture.providers.m365 import LEGACY_AUTH_BLOCKED, MFA_REGISTERED, STALE_ACCOUNTS

CRED = {"tenant_id": "t-1", "client_id": "c-1", "client_secret": "s-1"}


# Patched onto the class, so these fakes receive `self` first -- calling
# self._get_all(client, url, headers) becomes fake(self, client, url, headers).
async def _token_ok(self: Any, client: Any) -> str:
    return "token"


async def test_unconfigured_scans_nothing() -> None:
    assert await MsGraphConnector(credential=None).scan() == []


async def test_scan_returns_one_outcome_per_check(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_get_all(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        if "userRegistrationDetails" in url:
            return [{"id": "u1", "userPrincipalName": "a@x.gov", "isMfaRegistered": True}]
        if "conditionalAccess" in url:
            return []
        return []

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", fake_get_all)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    keys = {o.check_key for o in outcomes}
    assert keys == {MFA_REGISTERED.key, LEGACY_AUTH_BLOCKED.key, STALE_ACCOUNTS.key}
    mfa = next(o for o in outcomes if o.check_key == MFA_REGISTERED.key)
    assert mfa.verdict == "pass"
    legacy = next(o for o in outcomes if o.check_key == LEGACY_AUTH_BLOCKED.key)
    assert legacy.verdict == "fail"  # no policy blocks legacy auth


async def test_forbidden_is_manual_review_not_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE most important test here. A missing app permission must never read
    as a clean fleet -- zero findings would roll up to not_applicable and hide
    a broken check behind a benign-looking verdict."""

    async def forbidden(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        request = httpx.Request("GET", url)
        raise httpx.HTTPStatusError(
            "Forbidden", request=request, response=httpx.Response(403, request=request)
        )

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", forbidden)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    assert outcomes, "a forbidden scan must still report outcomes"
    for o in outcomes:
        assert o.verdict == "manual_review_required", o.check_key
        assert o.verdict != "not_applicable"
        assert o.findings, "the reason must be visible as a finding"
        assert "403" in o.findings[0].observed

    mfa = next(o for o in outcomes if o.check_key == MFA_REGISTERED.key)
    assert "AuditLog.Read.All" in mfa.findings[0].observed


async def test_one_check_failing_does_not_lose_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def selective(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        if "userRegistrationDetails" in url:
            raise RuntimeError("graph exploded")
        return []

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", selective)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    assert len(outcomes) == 3
    mfa = next(o for o in outcomes if o.check_key == MFA_REGISTERED.key)
    assert mfa.verdict == "manual_review_required"
    legacy = next(o for o in outcomes if o.check_key == LEGACY_AUTH_BLOCKED.key)
    assert legacy.verdict == "fail"  # unaffected by its neighbour


async def test_scan_never_raises_when_the_token_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_token(*a: Any, **k: Any) -> None:
        raise httpx.ConnectError("dns")

    monkeypatch.setattr(MsGraphConnector, "_token", no_token)
    assert await MsGraphConnector(credential=CRED).scan() == []


async def test_scan_returns_empty_when_token_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def none_token(*a: Any, **k: Any) -> None:
        return None

    monkeypatch.setattr(MsGraphConnector, "_token", none_token)
    assert await MsGraphConnector(credential=CRED).scan() == []


async def test_stale_check_receives_a_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """evaluate_stale_accounts needs `now`; scan must supply it."""

    async def one_old_user(
        self: Any, client: Any, url: str, headers: Any
    ) -> list[dict[str, Any]]:
        if url.endswith("conditionalAccess/policies"):
            return []
        if "userRegistrationDetails" in url:
            return []
        return [
            {
                "id": "u1",
                "userPrincipalName": "old@x.gov",
                "accountEnabled": True,
                "signInActivity": {"lastSignInDateTime": "2020-01-01T00:00:00Z"},
            }
        ]

    monkeypatch.setattr(MsGraphConnector, "_token", _token_ok)
    monkeypatch.setattr(MsGraphConnector, "_get_all", one_old_user)

    outcomes = await MsGraphConnector(credential=CRED).scan()
    stale = next(o for o in outcomes if o.check_key == STALE_ACCOUNTS.key)
    assert stale.verdict == "fail"
    assert stale.failing == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_m365_scan.py -v`
Expected: FAIL — `scan()` returns `[]` from the base class, so the
one-outcome-per-check assertions fail.

- [ ] **Step 3: Implement `scan()`**

Add to `src/ccf/connectors/msgraph.py` after `capture()`:

```python
    async def scan(self) -> list[CheckOutcome]:
        """Assess this tenant against the registered M365 posture checks.

        Never raises: an unconfigured org, a failed token, or a provider error
        all produce results (or none) rather than an exception, because
        ``ConfigConnector.scan``'s contract says so and ``scan_for_system``
        does not expect one.
        """
        if not self.is_configured():
            return []
        s = get_settings()
        tenant_id = str((self.credential or {}).get("tenant_id") or "unknown")
        outcomes: list[CheckOutcome] = []
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                token = await self._token(client)
                if not token:
                    return []
                headers = {"Authorization": f"Bearer {token}"}
                now = datetime.now(UTC)
                for check in m365.CHECKS:
                    # Per-check isolation: one permission gap must not discard
                    # the checks that did run, matching capture()'s
                    # per-sub-capture try and the scheduler's per-tenant
                    # savepoint.
                    try:
                        rows = await self._get_all(
                            client, f"{s.graph_base_url}{m365.ENDPOINTS[check.key]}", headers
                        )
                    except Exception as e:
                        outcomes.append(self._unrunnable(check, e))
                        continue
                    outcomes.append(self._evaluate(check, rows, tenant_id=tenant_id, now=now))
        except Exception as e:  # token/transport failure -- nothing to report
            log.warning("connector.msgraph.scan_failed", error=str(e)[:200])
            return []
        return outcomes

    def _evaluate(
        self,
        check: PostureCheck,
        rows: list[dict[str, Any]],
        *,
        tenant_id: str,
        now: datetime,
    ) -> CheckOutcome:
        """Dispatch one check's rows to its evaluator.

        The evaluators take different keyword arguments -- the tenant check
        needs the tenant id, the staleness check needs a clock -- so each is
        called with what it declares rather than forcing a uniform signature
        that most checks would ignore.
        """
        evaluator = m365.EVALUATORS[check.key]
        if check.key == m365.LEGACY_AUTH_BLOCKED.key:
            findings = evaluator(rows, tenant_id=tenant_id)
        elif check.key == m365.STALE_ACCOUNTS.key:
            findings = evaluator(rows, now=now)
        else:
            findings = evaluator(rows)
        return CheckOutcome.from_findings(check, tuple(findings))

    def _unrunnable(self, check: PostureCheck, error: Exception) -> CheckOutcome:
        """A check that could not run -- never a clean fleet.

        P2a's rollup maps zero findings to ``not_applicable``, so returning
        nothing here would hide a missing app permission behind a
        benign-looking verdict. Instead one finding carries
        ``manual_review_required`` and names the status and the permission the
        check needs, which puts the reason in the resource list where an
        operator looks.
        """
        status = ""
        if isinstance(error, httpx.HTTPStatusError):
            status = f"{error.response.status_code} "
        needed = ", ".join(check.required_permissions) or "unknown permissions"
        log.warning(
            "connector.msgraph.check_unrunnable",
            check=check.key,
            error=str(error)[:200],
        )
        return CheckOutcome.from_findings(
            check,
            (
                ResourceFinding(
                    resource_id=(self.credential or {}).get("tenant_id") or "unknown",
                    resource_type=check.resource_type,
                    verdict="manual_review_required",
                    observed=f"{status}could not read Graph; requires {needed}",
                    detail={"error": str(error)[:300]},
                ),
            ),
        )
```

Add the imports at the top of `msgraph.py`:

```python
from datetime import UTC, datetime

from ..posture.checks import CheckOutcome, PostureCheck, ResourceFinding
from ..posture.providers import m365
```

**Circular-import check.** `posture.checks` imports `providers.m365` at its
*bottom*, and `providers.m365` imports only from `posture.checks`. Neither
imports `connectors`, so importing both from `msgraph.py` is acyclic. Run
`python -c "import ccf.connectors.msgraph"` to confirm before moving on.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_m365_scan.py tests/test_m365_checks.py tests/test_m365_fetch.py tests/test_connectors.py tests/test_posture_contract.py -v`
Expected: all pass.

- [ ] **Step 5: Lint and commit**

```bash
ruff check src/ccf/connectors/msgraph.py tests/test_m365_scan.py
mypy src/ccf/connectors/msgraph.py
git add src/ccf/connectors/msgraph.py tests/test_m365_scan.py
git commit -m "feat(m365): scan() with per-check isolation and 403-is-not-empty"
```

---

### Task 4: Full verification and mutation testing

**Files:**
- Test: no new files; runs the whole suite

- [ ] **Step 1: Confirm the registry is no longer empty end to end**

```bash
export CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5434/ccf_test
export CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5434/ccf_test
python -c "
from ccf.posture.checks import checks_for
for c in checks_for('msgraph'):
    print(f'{c.key:40} {c.control_ids}  perms={c.required_permissions}')
"
```
Expected: the three checks, each with canonical control ids and permissions.

- [ ] **Step 2: Run the full suite**

```bash
pytest -q -p no:randomly
ruff check src tests
mypy src
alembic heads   # exactly one
```

Expected: the only failure is the known pre-existing
`test_analytics_residual_and_overdue.py::test_dashboard_overview_sla_excludes_no_due_date_from_on_track`
(it fails on `main` at line 272 — confirm it is still the *only* failure);
lint and types clean; one head. P3a adds no migration.

- [ ] **Step 3: Mutation-test the new guards**

Delete each, confirm a test fails, restore:

1. the `_unrunnable` call in `scan`'s `except` (replace with `continue` — the
   403 test must fail, because the check would then silently vanish)
2. the `state != "enabled"` test in `_blocks_legacy_auth` (the disabled-policy
   and report-only tests must fail)
3. the `app_types & _LEGACY_CLIENT_APP_TYPES` condition
4. the `"block" in controls` condition
5. the `accountEnabled` exclusion in `evaluate_stale_accounts`
6. the `last is None` guard for missing `signInActivity`
7. the `nxt if isinstance(nxt, str) else None` pagination continuation (the
   two-page test must fail)
8. the `_MAX_PAGES` loop bound (the self-referential-nextLink test must fail)
9. the per-check `try` in `scan` (the one-check-fails test must fail)

- [ ] **Step 4: Verify each mutation result**

Any guard reported as ESCAPED is a test gap, not a pass. Strengthen the test
until the mutation is caught, then re-run that mutation to confirm.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(m365): mutation-test the posture adapter guards"
```
