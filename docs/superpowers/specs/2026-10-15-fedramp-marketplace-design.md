# FedRAMP Marketplace as a reference for dependency status

**Status:** design, implementing
**Extends:** `etl/sources.py` (registration + fetcher), `fedramp20x` dependencies
**Adds:** `fedramp20x/marketplace.py`, `ccf.marketplace_products`, migration `0095`

## 1. The gap

A 20x system records each underlying cloud service it depends on
(`FedRAMPDependency`) with an operator-entered `fedramp_status`
(`authorized|in_process|not_authorized|unknown`), `impact_level` and
`authorization_level`. Readiness's `dependency_readiness` and the
`dependency_authorized` validation rule read those entries. Nothing checks
them: a dependency recorded "authorized" that FedRAMP lists as merely
"FedRAMP Ready" scores as authorized.

FedRAMP publishes the Marketplace daily, machine-readable and public domain:
`github.com/FedRAMP/marketplace-fedramp-gov-data` — `data.json` (662
products, stable FedRAMP IDs such as `F1607067912`, status, impact level,
authorization type and date, assessor, leveraged systems) with a draft-07
`data.schema.json`. The schema titles it "Legacy FedRAMP Marketplace Data";
it is nonetheless the complete daily set (the README: uploaded 2–3 AM ET
daily), while the CR26-shaped `fedramp-frc-cso-pkg.json` is updated "as
needed". Concord reads `data.json` and says so.

Found while looking for FedRAMP's Rev. 5 parameter baselines, which are no
longer published anywhere reachable (`GSA/fedramp-automation` returns 404;
the FedRAMP org has no successor) — that gap stays open.

## 2. Decisions

1. **Reference, never override.** `ccf.marketplace_products` is global
   reference data refreshed from FedRAMP. An operator *links* a dependency to
   a product (`FedRAMPDependency.marketplace_id`). Concord shows the
   Marketplace record beside the recorded values and names every
   disagreement; it never rewrites `fedramp_status`, because the operator's
   record may legitimately differ (an agency ATO not yet on the Marketplace)
   and silently replacing it would destroy that.
2. **One fetcher.** Refresh uses `etl.sources.fetch_conditional` (ETag +
   sha256) and `resolve_commit_sha` for provenance, and the source is
   registered in `DEFAULT_SOURCES` (`fedramp_marketplace_data`) so its row's
   `enabled` flag is the operator's off switch. The scheduler runs the refresh
   as a savepointed global step beside `poll_sources`; an air-gapped
   deployment logs a global-step failure and carries on.
3. **Validated, then upserted, then delisted.** The body is parsed and
   validated against the vendored, sha-pinned `data.schema.json` before any
   row changes. Products absent from a successful refresh get `delisted_at`
   (never deleted: a dependency may still link to one, and "FedRAMP no longer
   lists this" is exactly the finding to show).
4. **Findings, by vocabulary mapping stated once.**
   - status: `FedRAMP Authorized` → authorized; `FedRAMP In Process`,
     `Agency In Process` → in_process; `FedRAMP Ready` → not authorized
     (Ready is a readiness assessment, not an authorization).
   - impact: `Low`, `20x Low`, `LI-SaaS` → low; `Moderate`, `20x Moderate`
     → moderate; `High` → high.
   - authorization type: `JAB` → jab, `Agency` → agency; `Program` (the
     2026 program certification) has no recorded counterpart and is reported,
     not compared.
   A finding is raised when a recorded value is set and disagrees, when the
   linked product is delisted, or when the link points at no known product.
   `unknown` recorded status is not a disagreement.
5. **Reported, not scored.** Readiness reports `marketplace_disagreements`
   beside the score; `dependency_readiness` keeps reading the recorded status,
   so linking a product never silently moves a score.

## 3. Not in scope

- Auto-matching dependencies to products by name (wrong matches would be a
  worse claim than none); the API offers search, a person links.
- `fedramp-status-changelog.json` history, agency/assessor tables.
