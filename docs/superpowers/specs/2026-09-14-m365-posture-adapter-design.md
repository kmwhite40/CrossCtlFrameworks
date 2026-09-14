# P3a — Microsoft 365 / Graph Posture Adapter (design)

**Date:** 2026-09-14
**Status:** Design approved in brainstorming; awaiting spec review
**Depends on:** `docs/superpowers/specs/2026-09-14-posture-validation-spine-design.md` (P2a)
**Inventory (authoritative on what exists):** `docs/architecture/forge-capability-inventory.md` §2.3
**Sub-project:** P3a — the first of four provider slices

## 0. What "done" means here, and what it does not

**This work cannot be verified against a real tenant.** There are no
credentials for a GCC High, DoD, or commercial M365 tenant in this
environment. "Done" therefore means:

- the adapter is implemented;
- every **evaluation** function is pure and unit-tested against recorded
  Microsoft Graph response shapes;
- the network call is a thin, clearly-marked seam;
- failure modes (unconfigured, forbidden, empty) are tested explicitly.

Confirming that a check reads a *particular* tenant correctly requires that
tenant's app registration and is the operator's step. Nothing in this spec
should be read as asserting a check has been observed working against live
M365.

This mirrors how `msgraph.py` is already tested: its existing tests exercise
`_map_mfa` and `_map_conditional_access` against payload dicts, never the HTTP
call.

## 1. Problem

P2a shipped the posture spine with `CHECK_REGISTRY` **empty**. The contract,
the per-resource result model, the rollup, the orchestration, and the
precedence helper all work, and nothing scans. This slice makes it real for one
provider.

M365 is the right first provider because `msgraph.py` already has working
client-credentials OAuth against the Government endpoints, `httpx` calls, and
unit-tested pure mappers. Adding `scan()` there validates the P2a contract with
the least new machinery, and GCC High / DoD are endpoint variants of an auth
flow that already works (`graph_base_url` defaults to `https://graph.microsoft.us`,
`graph_login_url` to `https://login.microsoftonline.us`).

## 2. Goals and non-goals

**Goals.**

1. Implement `scan()` on `MsGraphConnector`.
2. Register three checks spanning three resource shapes (§4).
3. Follow Graph pagination, so a finding on page four is not invisible.
4. Distinguish "nothing in scope" from "could not run" (§3.2).
5. Carry required Graph permissions on the check definition.

**Non-goals.**

- **No new provider.** Azure Government, GCP, and the AWS expansion are
  separate slices.
- **No change to `capture()`.** Its ODP role is unchanged, and its own
  pagination gap is noted but deliberately left alone (§3.1).
- **No new dependency.** Graph is called over `httpx`, already a core
  dependency. The repo's established stance is that provider SDKs are not
  added — `boto3` is not in `pyproject.toml` at all.
- **No credential-handling change.** `resolve_credential` stays the only path,
  per-organization, with no global fallback.
- **No new verdict vocabulary.** `manual_review_required` already exists and is
  already ranked; this slice only has to *use* it.
- **No ODP wiring for thresholds** (§4.3).

## 3. Components

### 3.1 Pagination — `_get_all`

```python
async def _get_all(
    self, client: httpx.AsyncClient, url: str, headers: dict[str, str]
) -> list[dict[str, Any]]
```

Follows `@odata.nextLink` and concatenates every page's `value` array, with a
hard page cap (`_MAX_PAGES = 50`) so a pathological or looping `nextLink`
cannot spin forever.

**Why this is required, not a nicety.** `capture()` reads `resp.json()` once
and never follows `nextLink`. For Conditional Access policies that is nearly
harmless — there are few. For a fleet scan it is a correctness hole: three
non-compliant users on page four would be invisible and the check would report
`pass`, which is the wrong direction for a compliance product to be wrong in.

`capture()` is deliberately **not** changed here. Its ODP behaviour is
established and tested, and rewriting it is not this slice's job; the helper
exists if that is taken up later.

### 3.2 Two failure modes that must never be confused

P2a's rollup maps zero findings to `not_applicable`. If Graph returns **403**
because the app registration lacks `AuditLog.Read.All`, the naive path produces
zero findings and therefore `not_applicable` — a silently broken check that
reads as benign. That is the worst available failure mode for this product.

The adapter distinguishes them explicitly:

| Situation | Verdict | Meaning |
|---|---|---|
| Fetched, no resources in scope | `not_applicable` | Genuinely nothing to assess |
| **401 / 403** | **`manual_review_required`** | The check could not run |
| Other transport or parse error | `manual_review_required` | Same: not a pass, not a clean fleet |
| Fetched and assessed | `pass` / `warn` / `fail` | A real result |

`manual_review_required` is already in `VALIDATION_STATUSES` and already ranks
between `warn` and `fail` in the shared `VERDICT_RANK`, so nothing about the
vocabulary changes.

A check that could not run emits **exactly one** `ResourceFinding` whose
verdict is `manual_review_required`, whose `resource_id` is the tenant, and
whose `observed` names the status and the permission expected (for example
`"403 Forbidden; requires AuditLog.Read.All"`). It then goes through
`CheckOutcome.from_findings` like every other outcome, which rolls a single
`manual_review_required` finding up to `manual_review_required` — so there is
one code path, not two.

Emitting a finding rather than an empty outcome is deliberate: it puts the
reason in the resource list, which is where an operator looks, and it keeps
`scan_for_system`'s summary detail from claiming "no resources in scope" when
the truth is "could not look".

### 3.3 `PostureCheck.required_permissions`

```python
required_permissions: tuple[str, ...] = ()
```

Additive on P2a's frozen dataclass: default empty, no migration, no change for
existing callers. It is what lets a `manual_review_required` verdict say
*which* application permission is missing instead of leaving an operator to
guess from a 403.

### 3.4 `scan()`

```python
async def scan(self) -> list[CheckOutcome]
```

1. Return `[]` when not configured — matching `capture()`, and meaning an
   unconfigured org produces no results rather than a spurious failing one.
2. Acquire a token once and reuse it across checks.
3. For each registered check, fetch and evaluate inside its own `try` — one
   check's permission gap must not discard the others, the same isolation
   `capture()` applies per sub-capture and the scheduler applies per tenant.
4. Never raise. `ConfigConnector.scan`'s contract says so, and
   `scan_for_system` is not written to expect exceptions.

## 4. The checks

Three, chosen so each exercises a different resource shape rather than three
variations of one.

### 4.1 `m365.identity.mfa_registered` — per-user fleet

- **Endpoint:** `/v1.0/reports/authenticationMethods/userRegistrationDetails`
- **Permission:** `AuditLog.Read.All`
- **Resource:** `entra_user`, one finding per user
- **Verdict:** `pass` when `isMfaRegistered` is true, else `fail`
- **Controls:** `IA-2`, `IA-2(1)`
- **Expected:** "every user has a multi-factor authentication method registered"

**Recorded limitation.** `userRegistrationDetails` does not expose
`accountEnabled`, so this assesses every user Graph returns, including disabled
ones. Each finding records `userType` and `isAdmin` in `detail` so an operator
can see what was counted. Joining against `/users` to exclude disabled accounts
is not something Graph supports cheaply, and inventing that join would trade a
stated limitation for a hidden one.

### 4.2 `m365.policy.legacy_auth_blocked` — tenant singleton

- **Endpoint:** `/v1.0/identity/conditionalAccess/policies`
- **Permission:** `Policy.Read.All`
- **Resource:** `m365_tenant`, exactly one finding, `resource_id` = tenant id
- **Verdict:** `pass` when an **enabled** policy blocks legacy clients, else
  `fail`
- **Controls:** `IA-2`, `AC-17`
- **Expected:** "an enabled Conditional Access policy blocks legacy
  authentication clients"

A policy qualifies when `state == "enabled"`, its
`conditions.clientAppTypes` include `exchangeActiveSync` or `other`, and its
`grantControls.builtInControls` include `block`. Disabled and report-only
policies do not qualify — `state` is checked exactly as the existing
`_map_mfa` and `_map_conditional_access` mappers already do.

A tenant-level boolean still produces a `ResourceFinding` so one result model
covers every shape: the tenant *is* the resource.

### 4.3 `m365.identity.stale_accounts` — per-user with exclusions

- **Endpoint:** `/v1.0/users?$select=id,userPrincipalName,accountEnabled,signInActivity`
- **Permissions:** `AuditLog.Read.All`, `User.Read.All`
- **Resource:** `entra_user`, one finding per user
- **Verdict:**
  - `not_applicable` when `accountEnabled` is false — a disabled account is not
    a stale-access risk
  - `not_applicable` when `signInActivity` is absent — Graph omits it without
    the right licence, and absence is not evidence of staleness
  - `fail` when `signInActivity.lastSignInDateTime` is older than the
    threshold. The **interactive** timestamp is used deliberately:
    `lastNonInteractiveSignInDateTime` is moved by background token refresh, so
    an abandoned account can look active indefinitely under it
  - `pass` otherwise
- **Controls:** `AC-2`, `AC-2(3)`
- **Expected:** "no enabled account has been inactive longer than the
  inactivity threshold"

**Why this check is here beyond its own value:** it is the only one emitting
**per-resource `not_applicable`**, so it proves P2a's exclusion rule end to
end — a disabled account must neither fail the check nor dilute its verdict.

**Threshold.** `STALE_ACCOUNT_DAYS = 90`, a named module constant. It wants to
be an organization-defined parameter, and the ODP machinery already exists for
exactly this, but wiring it is a separate decision; a constant with a recorded
intent is honest, where inventing configuration now would be premature.

## 5. Testing strategy

All on the pure seams, since no tenant is reachable.

- **Evaluators** — each against a recorded Graph response shape: a mixed fleet
  (some registered, some not); an all-compliant fleet; an empty fleet; a
  disabled user; a user with no `signInActivity`; an enabled blocking policy; a
  disabled blocking policy (must **not** pass); a report-only policy (must not
  pass); no policies at all.
- **Pagination** — `_get_all` follows `@odata.nextLink` across two pages and
  concatenates both `value` arrays; a response with no `nextLink` makes exactly
  one request; the page cap stops a self-referential `nextLink`.
- **Forbidden is not empty** — a 403 yields `manual_review_required`, **never**
  `not_applicable` and never `pass`, and the finding names the missing
  permission. This is the most important test in the slice.
- **Unconfigured** — `scan()` returns `[]` with no HTTP attempted.
- **Isolation** — one check raising leaves the others' outcomes intact.
- **Never raises** — a transport error surfaces as
  `manual_review_required`, not an exception.
- **Exclusion end to end** — a fleet of one disabled and two passing users
  rolls up to `pass`, with `evaluated == 3`: the disabled account is counted as
  examined but excluded from the verdict.
- **Registry** — the three checks are registered under `msgraph`, each carries
  `control_ids` and `required_permissions`, and P2a's existing registry tests
  (provider keys are real connector keys; keys are unique) still pass.

Every guard is mutation-tested: delete it, confirm a test fails, restore.

## 6. Risks

| Risk | Mitigation |
|---|---|
| A permission gap reads as a clean fleet | §3.2's explicit split, with the 403 test as the slice's most important (§5) |
| A finding beyond page one is invisible | `_get_all` follows `nextLink`, with a page cap and a two-page test |
| Recorded payload shapes drift from real Graph | Shapes come from documented Graph responses and are isolated in fixtures; when a real tenant contradicts one, the fixture is the single place to correct |
| Disabled users counted as MFA failures | Stated in code and in §4.1 rather than hidden; `detail` records what was counted |
| One check's failure loses the whole scan | Per-check `try`, matching `capture()`'s per-sub-capture isolation |
| Scanning a large tenant is slow inside a request | The token is acquired once; the POST endpoint scans one connector for one system, and the scheduler remains the bulk route |

## 7. Open items

1. **Stale-account threshold as an ODP.** `STALE_ACCOUNT_DAYS = 90` is a
   constant with recorded intent. Settled for this slice; binding it to the ODP
   machinery is its own change.
2. **Excluding disabled users from the MFA check.** Requires a join Graph does
   not cheaply support. Settled: state the limitation, record `userType` and
   `isAdmin` in `detail`, and revisit only if an operator reports it matters.
