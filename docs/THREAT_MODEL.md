# Concord — Threat Model (living document)

## Assets

1. **Control catalog** (`ccf.controls`, `ccf.framework_mappings`) — public
   in spirit, private in practice because the workbook may contain
   customer-specific annotations.
2. **Operational program** (`ccf.systems`, `control_implementations`,
   `evidence`, `poams`, `risks`) — high sensitivity; a leak exposes a
   customer's security posture and findings.
3. **Audit trail** (`ccf_audit.*`, `audit_log`) — must be append-only;
   losing or tampering with it breaks the compliance value of the product.
4. **Provenance** (`workbook_versions`, SCD-2 history) — signed
   attestations are a future asset.

## Actors & trust

| Actor | Trust | Access |
|-------|-------|--------|
| Operator (admin) | Full | All reads + all writes. |
| Assessor | High | Reads + writing findings / closing POA&Ms. |
| Control owner | Medium | Reads + writing implementations + evidence for owned controls. |
| Viewer | Low | Reads only. |
| Unauthenticated external | **None** | Must not see any operational data. |

**Current state:** local authentication + RBAC are implemented and gate the
service when `CCF_AUTH_ENABLED=1` (signed session cookie / API token, role
checks, app-level org scoping). They default to **off** for the dev preview,
so an unconfigured instance still trusts any caller on the host network —
enable auth and bind to a trusted network before any shared/public deployment.
OIDC/IdP federation and DB-enforced RLS remain on the roadmap.

## STRIDE

- **Spoofing** — `auth_gate_middleware` resolves a `Principal` from an
  HMAC-signed session cookie or `secrets` API token; passwords are
  PBKDF2-HMAC-SHA256. Gap: auth is opt-in (`CCF_AUTH_ENABLED`) and OIDC/IdP
  federation is not yet wired.
- **Tampering** — Alembic-managed schema; `audit_log` is a SHA-256 hash chain
  (`prev_hash` → `row_hash`) verifiable via `/api/audit/verify`, so silent
  edits are detectable. Grants not yet split; the `ccf` role can still `DELETE`
  rows. Planned mitigation: `ccf_app` loses `UPDATE, DELETE` on `ccf_audit.*`
  + append-only triggers.
- **Repudiation** — `audit_middleware` records every successful mutation
  attributed to the authenticated `Principal` (else `X-Actor` /
  `CCF_AUDIT_DEFAULT_ACTOR`). With auth disabled, actions fall back to the
  default actor and are effectively anonymous.
- **Information disclosure** — queries are **org-scoped at the application
  layer** (`Principal.organization_id`), but there is no DB-enforced RLS yet,
  so a bug or a raw SQL path could cross tenants. Planned: row-level policies
  keyed on `current_setting('ccf.tenant_id')::int` injected per request.
- **Denial of service** — `slowapi` limits to 120/min per IP. Ingestion
  is not rate-limited but runs only via CLI / Docker; expose only on an
  admin network.
- **Elevation of privilege** — `require_role` enforces RBAC on privileged
  routes when auth is enabled. With auth disabled there are no role checks, so
  deploy with network-level isolation until auth is turned on.

## Supply chain

- CycloneDX SBOM produced in CI and uploaded as an artifact.
- `pip-audit` (advisory) and `Trivy` HIGH/CRITICAL (blocking) run in CI.
- Image signing with `cosign` + Sigstore verification on deploy — planned.
- Lockfile (`uv.lock` / `pip-compile`) — not yet committed.

## Data at rest / in transit

- In transit: `sslmode=verify-full` is supported via DSN; not enforced
  by default for dev.
- At rest: cloud-provider TDE (not applicable to local Postgres).
- Secrets: compose uses cleartext `ccf:ccf`; production must inject
  credentials via Docker secrets / Vault / cloud secret manager.

## Known accepted risks (dev preview)

1. Single shared DB role.
2. Auth + RBAC are implemented but **off by default** (`CCF_AUTH_ENABLED=0`);
   an unconfigured instance is unauthenticated.
3. Tenant isolation is app-level only — no DB-enforced RLS.
4. `localhost:8088` (app, with landing at `/`) and the optional
   `localhost:3000` (standalone Next.js landing) bind to `0.0.0.0` inside the
   container; bind to `127.0.0.1` on the host for multi-user workstations.
