# External collaboration portal

Customers, assessors, and vendors need to see *some* of an authorization
package — the shared packages, evidence, and a comment thread — without an
internal Concord account and without any risk of seeing another tenant's data.
The portal delivers exactly that: **scoped, expiring, token-authenticated,
fully-audited** external access.

## Model

| Table | Purpose |
|---|---|
| `external_principals` | An external collaborator (customer / assessor / vendor) — never an internal user |
| `external_access_grants` | A bearer **token** with an expiry, a revoke flag, and an explicit scope |
| `external_package_shares` / `external_evidence_shares` | The artifacts explicitly shared into a grant |
| `external_comments` | Discussion on a shared package / evidence / finding |
| `external_questionnaire_requests` | A questionnaire sent to an external principal |
| `external_portal_audit_events` | Immutable record of every portal access |

Every tenant-owned table has row-level security. The org-scoped tables key on
`organization_id = ccf.current_tenant()`; the two share join-tables (which have no
`organization_id`) isolate transitively via a subquery against their parent
grant's org, so a share can never be read across tenants.

## Authorization boundary

External requests arrive **unauthenticated** — the portal paths are public
(`auth_deps._PUBLIC_PREFIXES`), so the session gate lets them through and the
`ccf.portal` service is the real boundary:

1. **Resolve** — a token resolves only if it exists, isn't revoked, and hasn't
   expired. Anything else → `401` and a `denied`/no access.
2. **Clamp** — once resolved, the session's RLS tenant is bound to the grant's
   own org before any tenant data is read (`set_session_tenant`).
3. **Allow-list** — reads return only the artifacts explicitly shared into the
   grant. RLS + explicit scope is defence in depth.
4. **Audit** — every view, comment, issuance, and revocation writes an immutable
   `external_portal_audit_events` row.

## Surfaces

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/admin/portal/grants` | admin | Issue a scoped, expiring grant |
| GET | `/api/admin/portal/grants?organization_id=` | admin | List a tenant's grants |
| POST | `/api/admin/portal/grants/{id}/revoke` | admin | Revoke a grant |
| GET | `/api/portal/session` | token | Shared packages, evidence, and comments |
| POST | `/api/portal/comments` | token | Post a comment |
| GET | `/portal?token=` | token | Read-mostly HTML view of the above |

## Reliability

Three checks defend the invariants continuously:

- **`external_access_scope_integrity`** — *fails* if any share references an
  artifact outside its grant's tenant (a cross-tenant leak).
- **`external_grant_expiration`** — *warns* on expired grants left un-revoked.
- **`external_portal_audit_completeness`** — *warns* if any grant has no audit
  trail (e.g. a direct insert bypassing the service).
