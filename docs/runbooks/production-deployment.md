# Production deployment

The checklist that has to pass before Concord serves a real authorization
package. Every item here was a real finding, not a precaution.

`docker-compose.yml` in this repository is a **development stack**. It carries
dev-only secrets on purpose and must not be deployed.

## 1. Configuration the application refuses to start without

`ccf.config.enforce_secure_config` raises on start in a non-development
environment unless all of these hold:

| Variable | Requirement |
|---|---|
| `CCF_ENV` | not `dev` / `test` |
| `CCF_AUTH_ENABLED` | `true`. With auth off every caller is the system principal with no organization, and org-scoped pages refuse. |
| `CCF_AUTH_SESSION_SECRET` | not `dev-insecure-change-me`. A strong random value, 32+ bytes. |
| `CCF_API_CORS_ORIGINS` | explicit origins, never `*` |

## 2. Configuration it warns about but starts without

These do not block startup — neither lets a request act as someone it is not,
which is the bar for refusing — but both are logged at `warning` as
`config.insecure_default` on every start. Read the first lines of the log
after a deploy.

| Variable | Why it matters |
|---|---|
| `CCF_AI_CREDENTIAL_MASTER_KEY` | Wraps every stored connector, AI provider and MFA secret. **Without it the cipher fails closed and no credential can be saved at all** — which presents as "the connector page will not accept my key". With the wrong one, existing credentials are unreadable. Back it up separately from the database. |
| `CCF_AI_CREDENTIAL_KEY_PROVIDER` | Defaults to `local`, which keeps key material in the environment. Production should be `aws_kms` so the platform never holds it. |
| `CCF_CSRF_TRUSTED_ORIGINS` | Only if a separately-hosted front end posts to this API. Leave empty otherwise. |

## 2a. Configuration that decides whether the platform does anything on its own

Nothing below blocks startup, nothing warns, and every one defaults to **off**.
A deployment that follows every other section of this runbook and skips this one
comes up healthy, serves every page, and then sits still: no connector
collection, no ConMon scan, no control-test auto-runs, no assurance-graph
rebuild. Continuous monitoring that only runs when somebody clicks is not
continuous, and the platform will not tell you — an operator's first sign is a
posture page that never changes.

| Variable | Default | What stays switched off without it |
|---|---|---|
| `CCF_SCHEDULER_ENABLED` | `false` | **Every recurring job.** The in-app scheduler runs connector collection, pack sync, the ConMon scan, connector-backed control-test auto-runs, capability derivation and the assurance-graph rebuild — per organization, once per cycle. Set `true`, or drive `ccf scheduler --once` from an external cron. |
| `CCF_SCHEDULER_INTERVAL_HOURS` | `24.0` | The cycle cadence. It also sets the staleness threshold the `assurance_graph_freshness` reliability check warns past, so shortening the interval tightens that check automatically. |
| `CCF_AWS_CAPTURE_ENABLED` | `false` | AWS configuration capture. Leave off unless an AWS connector is bound. |
| `CCF_PREP_ENABLED` | `false` | The evidence-prep pipeline and its worker. |
| `CCF_AI_ENABLED` | `false` | AI drafting. Off is a defensible production posture; on requires a configured provider and leaves AI-drafted content visibly badged. |

Verify it took, rather than assuming — see section 6.

### Defaults that weaken an assurance claim rather than a feature

These are off by default too, and each one changes what the platform can honestly
say about its own output. They are listed apart from the table above because
switching them on is a compliance decision, not an operational one.

| Variable | Default | What the default costs you |
|---|---|---|
| `CCF_EVIDENCE_OBJECT_LOCK_ENABLED` | `false` | Evidence is written without WORM/object-lock. Only storage-enforceable on `evidence_backend='s3'` (Object Lock, COMPLIANCE mode); on `local` the platform logs `evidence.worm_not_storage_enforced` rather than making a false immutability claim — which is the right behaviour, and also means local evidence is mutable. An assessor asking "can this evidence have been altered after collection" gets "yes" while this is off. Pair with `CCF_EVIDENCE_OBJECT_LOCK_RETENTION_DAYS` (default 365) when no per-organization retention policy applies. |
| `CCF_AI_ALLOW_UNCITED_DRAFTS` | `false` | Leave it off. On, AI may produce draft content with no citation behind it, in a document an authorizing official reads. The default is the safe one; it is named here so nobody turns it on without meaning to. |
| `CCF_FEDRAMP20X_OSCAL_VALIDATE` | `false` | FedRAMP 20x OSCAL output is not schema-validated on export. A package that fails validation at the reviewer's end is discovered by the reviewer. |
| `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA` | `false` | Validation falls back to a bundled schema rather than requiring the official one. |
| `CCF_READONLY` | `false` | Not a gap — a mode. Set it for a demonstration or a frozen archive instance so nothing can be written through the UI or API.

## 3. TLS and the reverse proxy

- Session cookies and PIV/CAC both assume TLS termination in front of the app.
- `ccf.identity.piv` reads the client identity a terminator established, and
  accepts it **only** from a peer address named in its trusted CIDR list. An
  empty list is closed, not open.
- Do not rewrite `Host`. `CsrfOriginMiddleware` compares the browser's
  `Origin` against the served `Host`; a proxy that replaces `Host` with an
  upstream name makes every state-changing request fail with
  `cross-origin request rejected`. If the public name legitimately differs,
  add it to `CCF_CSRF_TRUSTED_ORIGINS` rather than relaxing the check.
- Keep `Referrer-Policy` at `same-origin`. `no-referrer` makes browsers send
  `Origin: null` on every non-GET request, which the CSRF check correctly
  refuses — two defensible headers that together break every form in the
  product.

## 4. Accounts

- **No seeded or demo accounts.** Verify before opening access:

  ```sql
  SELECT id, email, role, organization_id, active FROM ccf.users ORDER BY id;
  ```

  Any account whose password was set outside your provisioning process must be
  removed, not just disabled.
- Confirm MFA policy for the deployment (`ccf.identity.mfa_service`); TOTP
  enrolment is enforced by `auth_gate_middleware` once a policy requires it.

## 5. Migrations

`api` and `migrator` are separate compose services built from the same
Dockerfile. **Building one does not build the other**, and a stale migrator
reports success while leaving the database on the previous revision.

```bash
docker compose build api migrator
docker compose up -d api
docker compose up migrator
psql -c "select version_num from ccf.alembic_version;"   # confirm the head
```

## 6. What to verify after the first deploy

| Check | Expected |
|---|---|
| `GET /healthz` | 200 |
| Any form submission | not `cross-origin request rejected` |
| `select count(*) from ccf.users` | only accounts you provisioned |
| A connector's **Test** button | the provider's own error, or connected |
| `/api/posture/summary` `systems_total` | equals live systems in that org |
| `GET /api/reliability` → `assurance_graph_freshness` | `pass`, within a day or two of deploy. A persistent `warn` that the graph is *N*d old means no scheduler is running — see section 2a. |
| The API log on start | `scheduler.started` with the interval, if `CCF_SCHEDULER_ENABLED=true`. Its absence is the only signal that nothing recurring will happen. |

## 7. Known limits to state before anyone relies on this

- **Posture check coverage is 25 checks touching 33 of the 288 controls in a
  FedRAMP Moderate baseline** — roughly 11%. By provider:

  | Provider | Checks | Controls evidenced |
  |---|---|---|
  | `msgraph` (Entra / Intune) | 14 | AC-2, AC-2(3), AC-3, AC-6, AC-6(1), AC-11, AC-11(1), AC-12, AC-17, AC-19(5), AU-2, AU-3, AU-6, AU-12, CM-2, CM-6, IA-2, IA-2(1), IA-2(2), SC-28, SC-28(1), SI-2, SI-4 |
  | `aws_govcloud` | 4 | AU-2, AU-12, IA-2, IA-2(1), IA-5, IA-5(1) |
  | `azure_arm` | 5 | AU-4, AU-11, CM-2, CM-6, RA-5, SC-8, SC-8(1), SC-23, SC-28, SC-28(1), SI-3, SI-4 |
  | `puppetdb` | 2 | CM-2, CM-6, CM-8 |
  | `gcp` | 0 | none — the connector captures configuration but registers no posture checks, so scanning a system whose only connector is GCP runs nothing at all |

  Concord reports what it assessed and names what it did not: a scan response
  carries `checks_expected`, `checks_run` and a reason for every skipped check,
  and `GET /api/systems/{id}/framework-posture` reports the baseline as the
  denominator rather than the checks that happened to run.

  **State this number to anyone relying on the output.** Keep this table current
  — it said "9 checks across 7 controls" for several releases after the real
  figure had more than doubled, which is the kind of stale claim this platform
  exists to catch elsewhere. It is generated by:

  ```
  python -c "from ccf.posture.checks import checks_for; from ccf.connectors import connector_keys; print({k: len(checks_for(k)) for k in connector_keys()})"
  ```

- **800-171 coverage is 17 of the 110 requirements.** The 800-53 → 800-171
  crosswalk shipped in the catalog reaches only 80 of the 110 at all, so 30
  requirements cannot be evidenced by any scan regardless of check coverage.
  `framework-posture` reports those as `unreachable`.
- **The Microsoft Graph app registration needs
  `DeviceManagementConfiguration.Read.All`** on top of the permissions the
  earlier checks required. Without it the two device-compliance-policy checks
  (AC-11 session lock, SC-28 storage encryption) report
  `manual_review_required` naming that permission — never a false pass or fail,
  but no evidence either.
- **eMASS integration is unverified against a live instance** — written from
  the published specification and exercised only against a fake.
- **FedRAMP-assigned ODP values are not in the data.** Parameters carry their
  label, guidance and choices from the catalog; FedRAMP's own assigned values
  are not available to import.
