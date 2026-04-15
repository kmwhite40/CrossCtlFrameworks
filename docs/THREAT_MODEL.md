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

**Current gap:** OIDC + RBAC are not yet wired; the service currently
trusts any caller on the host network. Public deployment is **not**
supported until Phase-3.

## STRIDE

- **Spoofing** — no auth today. Planned: OIDC with `fastapi-users` or an
  in-house `Principal` dep enforcing a signed JWT.
- **Tampering** — Alembic-managed schema; audit schema designed for
  append-only. Grants not yet split; `ccf` role can currently `DELETE` any
  row. Planned mitigation: `ccf_app` loses `UPDATE, DELETE` on `ccf_audit.*`.
- **Repudiation** — `audit_log` designed; middleware hook pending. Until
  it's live, actions on the system are effectively anonymous.
- **Information disclosure** — no tenant RLS; two orgs in one DB can
  query each other's rows via the API. Planned: row-level policies keyed
  on `current_setting('ccf.tenant_id')::int` injected per request.
- **Denial of service** — `slowapi` limits to 120/min per IP. Ingestion
  is not rate-limited but runs only via CLI / Docker; expose only on an
  admin network.
- **Elevation of privilege** — no role checks on `/systems/*` POSTs today.
  Only deploy with network-level isolation until Phase-3 lands.

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
2. No authentication.
3. No RLS / tenant isolation.
4. `localhost:3000` (landing) & `localhost:8088` (app) bound to `0.0.0.0`
   inside the container; bind to `127.0.0.1` on the host for multi-user
   workstations.
