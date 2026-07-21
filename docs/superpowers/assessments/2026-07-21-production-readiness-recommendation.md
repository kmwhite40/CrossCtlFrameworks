# Concord (ccf) — Production-Readiness Recommendation

**Date:** 2026-07-21 · **Author:** CISO-lens synthesis across the IA/ISSM/FedRAMP panel
**Basis:** the 73-finding consolidated register + six remediation slices on branch
`feat/catalog-currency-ssp-odp-connectors` (37 commits, unmerged; full suite 433 passing
+ 1 known-flaky; ruff + mypy clean; Alembic head `0041`).
**Scope of "production":** Concord as an internal compliance-ops + CMMC/800-171
SSP-authoring platform. Concord is **not itself a FedRAMP-authorized system**, and (as of
Slice 5) no longer claims to be.

## Decision: **CONDITIONAL GO**

The hard security **blockers are resolved** and tenant isolation is now proven, not
asserted. Remaining items are **conditions** — integrity, governance, and evidence-quality
gaps that must be cleared or explicitly risk-accepted by the Authorizing Official before
Concord serves real CUI across multiple tenants at scale. No unmitigated Critical stands.

## Blockers resolved this program (evidence-backed)

| Was a blocker | Status |
|---|---|
| Insecure-by-default: every request an unscoped global admin, RLS off (IA-01/CISO-03/IA-11) | **Fixed** — fail-closed startup guard; refuses non-dev boot with auth off / default secret |
| Audit trail world-readable & cross-tenant (IA-02) | **Fixed** — API *and* `/audit` UI role-gated |
| Bearer tokens stored plaintext; login/grants re-leaked them (IA-09) | **Fixed** — hashed at rest, plaintext columns dropped, leaks removed |
| "FedRAMP" SSP was actually CMMC/800-171 — false compliance claim (FR-01) | **Fixed** — relabeled to the truth; false claim removed |
| SSP readiness never checked evidence — all-draft scored 100% ready (FR-02) | **Fixed** — gated on real evidence join |
| Authorize lifecycle unreachable — `ato_status` set-never (ISSM-01) | **Fixed** — authorize write path, gated on open critical POA&Ms |
| Tenant isolation proven for only ~2 of ~108 tables (IA-03) | **Fixed** — coverage test over all 108 policy-bound tables + behavioral checks |
| RLS gaps on `poam_milestones`, `organizations` (IA-04/DATA-01) | **Fixed** — policies added |
| `/readyz` ignored reliability; insecure config passed the gate (CISO-04) | **Fixed** — blocking checks incl. migration drift + auth posture |
| CI supply-chain scan non-blocking; vulnerable crypto pin (CISO-08) | **Fixed** — pip-audit blocking; cryptography bumped to clear advisories |
| Leadership metrics hid residual/overdue risk; dashboards disagreed (CISO-01/05/06/11) | **Fixed** — honest buckets, reconciled populations, org-scoped queries |

## Conditions required before production (owner · AO-acceptance?)

Each must be **cleared** or **explicitly risk-accepted by the AO** (a `risks` row with owner
+ expiration — see `poam-risk-management`).

1. **External-portal referential integrity (DATA-02)** — portal share rows reference
   packages/evidence by plain integer, no FK; the highest-exposure surface can serve
   references to deleted/foreign artifacts. *Owner: Backend. AO-accept if deferred.*
2. **Per-org connector credentials (IA-05)** — one global cloud credential mis-attributes
   captured evidence across tenants, so an org's SSP can cite another tenant's configuration.
   *Owner: Backend/Platform. Material for SSP evidence integrity.*
3. **Evidence integrity enforcement (IA-07/08)** — stored SHA-256 is never re-checked on
   read, and WORM is inert on the default local backend; "evidence is immutable/authentic"
   is currently unenforced. *Owner: Backend. AO-accept or fix before evidence is relied on.*
4. **Audit-log per-tenant isolation (DATA-06)** — `audit_log` has no `organization_id`;
   the trail is admin-gated but not row-isolated per tenant, and can't be exported per
   tenant with integrity. *Owner: Backend. Condition for multi-tenant audit.*
5. **Approval-gating & separation of duties (ISSM-06/08/09)** — risk acceptance, POA&M
   closure, and SSP export require no approval precondition, and SoD collapses when auth is
   off. *Owner: Program/Backend. Condition for an auditable authorization program.*
6. **AI provenance in the UI (CISO-02/UX-01)** — before any AI-drafted content reaches an
   SSP export or external package, the UI must visibly distinguish AI-generated/draft from
   human-approved. The AI mutation path is already human-gated and citation-first, and SSP
   is deterministic-first, so this is a condition, not a blocker — but it must land before
   AI authorship is enabled for delivered artifacts. *Owner: Frontend/App.*
7. **Destructive-delete safety (DATA-04)** — `ON DELETE CASCADE` from systems/organizations
   erases the authorization record (POA&Ms, assessments, evidence) with no soft-delete.
   *Owner: Backend. Operational-safety condition.*
8. **Dependency hygiene** — the now-blocking `pip-audit` will surface transitive advisories
   a dependency refresh resolves; keep the gate green. *Owner: Platform.*

## Acceptable-and-track (not conditions)

Portal magic-link token-in-URL hardening; the remaining DATA FK/dedupe items
(DATA-03/07/09/11/12); scheduler audit coverage (ISSM-11); finding-vocabulary unification
(ISSM-13/DATA-05); CISO-09/10 decision-support polish; FR-03..13 residual SSP-statement
quality; FR-14 FedRAMP-2026 label currency (enforcement 2027-01-01). The known-flaky
audit-chain test should be investigated for a genuine concurrency issue in chain-verify
(it passes in isolation, but the intermittence warrants a root-cause pass) — **operational
note, not a gate.**

## Program-maturity note

Concord moved from "stores an authorization program" to "operates one" this program:
the finding→POA&M→risk→ATO spine is now wired (assessment/ConMon/control-test failures
generate provenanced, milestone-bearing POA&Ms; ATO is reachable and gated), tenant
isolation is proven, secrets are hashed, and leadership metrics are honest. The residual
gap is **governance rigor** (approvals/SoD) and **evidence assurance** (integrity/WORM,
per-org attribution) — the difference between a working platform and an audit-ready one.

## Bottom line

**Conditional Go.** Ship for internal compliance-ops and CMMC/800-171 SSP authoring once
conditions 1–8 are cleared or AO-accepted. Do **not** enable AI-authored content in
delivered artifacts until condition 6 lands. Do **not** represent Concord as FedRAMP-
authorized (it isn't) — a real 800-53r5 FedRAMP pipeline is a separate future program.
