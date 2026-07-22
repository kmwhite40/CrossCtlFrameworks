# Technical Validation Matrix — reference

Companion to the `information-assurance-engineer` skill. Use as a lookup when
turning a control claim into a code-anchored verdict.

## Control domain → where it lives → how to validate

| Control domain | Where it lives in Concord | Validation procedure | Failure state to test |
|---|---|---|---|
| AuthN / sessions | `src/ccf/auth.py` (PBKDF2/HMAC, signed sessions, tokens) | Confirm hashing params, token expiry, session signing key source | Auth off by default (`auth_enabled=False`) — is prod gated on? |
| AuthZ / RBAC | `api/auth_deps.py` `require_role`, `Principal`, `get_principal` | Trace a write endpoint to its `require_role`; confirm SoD on approvals | SYSTEM/global principal bypass — is it reachable by a tenant user? |
| Tenant isolation | Postgres RLS, `set_session_tenant`, `org_systems_subq`, `tests/test_rls.py` | Run RLS tests; confirm every tenant table has a policy + is set per request (note: `test_rls.py` proves only a subset of tables — a passing test proves a path, not the whole control; check coverage) | Missing `set_session_tenant` on a code path → cross-tenant read; `auth_enabled=False` default collapses to an unscoped principal |
| Audit integrity | `src/ccf/api/audit.py` (SHA-256 hash-chain), `ccf.audit_log` | Verify mutations write a chained entry; recompute chain | Silent row edits that bypass `audit_log` |
| Encryption at rest | connector captures (`encryption_at_rest`), provider config | Confirm the assertion is captured, not narrated | Claim with no capture / no provider evidence |
| Secrets | `config.py` (`CCF_`-prefixed), provider credentials | Confirm no secret in logs, prompts, exports, exception traces | Global vs. org-scoped key; key echoed after entry |
| Evidence integrity | `src/ccf/evidence/` (versioning, review, WORM), `evidence_*` tables | Confirm version + review + retention; check freshness | Expired/failed/contradicted evidence marked "validated" |
| AI outputs | `ai_actions/` (citation-first, `ai_require_human_approval`) | Confirm citations resolve to real records; approval gate enforced | AI statement auto-approved, or cites nonexistent asset |
| Cloud capture | `connectors/` (`msgraph.py`, `aws.py`), `capture_snapshots` | Confirm capture is read-only, degrades to manual w/o creds | Assumed capability with no credential / no snapshot |
| Scheduler / jobs | `governance/scheduler.py` (advisory-lock, `run_cycle`) | Confirm org context retained per job; single-flight | Background job loses tenant scope |

## The "implemented-but-not-connected" test

A mechanism can exist and be dead. For each claimed control, find the **call
site**, not just the definition. A `require_role` that no route references, an
evidence-validation function nothing invokes, a connector never scheduled — all
classify as *implemented-but-not-connected*, severity by blast radius.

## Provider-managed misassignment test

If AWS GovCloud / Azure Gov / M365 actually performs the control (KMS-managed
encryption, platform audit retention, MDM baseline), a customer "implemented /
system-specific" claim is a **finding** — reclassify as inherited/hybrid and route
to `fedramp-authorization-expert`. Match origination to who does the work (see
`ssp-authoring`).

## Severity anchors

- **Critical** — cross-tenant exposure, auth bypass, plaintext/leaked secret.
- **High** — ineffective control on a Moderate/High system, unvalidated AI
  statement presented as approved, missing RLS on a tenant table.
- **Medium** — implemented-but-not-connected with limited blast radius, stale
  evidence on an active control.
- **Low / Informational** — duplication, deprecated-but-inert, cosmetic.

Each finding carries a **regression test** requirement: name the test that would
fail today and pass after remediation (add to `tests/`).
