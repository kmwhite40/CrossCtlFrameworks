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

## 7. Known limits to state before anyone relies on this

- **Posture check coverage is 9 checks across 7 controls** (IA-2, IA-5, AC-2,
  AC-17, CM-2, CM-6, CM-8). A FedRAMP Moderate baseline is far larger. Concord
  reports what it assessed; it does not assess a baseline.
- **eMASS integration is unverified against a live instance** — written from
  the published specification and exercised only against a fake.
- **FedRAMP-assigned ODP values are not in the data.** Parameters carry their
  label, guidance and choices from the catalog; FedRAMP's own assigned values
  are not available to import.
