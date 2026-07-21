# Concord (ccf) — Consolidated Findings Register

**Date:** 2026-07-21
**Method:** Six parallel read-only review workstreams, each driven by a role-lens skill
(`information-assurance-engineer`, `information-systems-security-manager`,
`chief-information-security-officer`, `fedramp-authorization-expert`) plus a
data-integrity and a UX lens. All findings emitted in one shared record format;
consolidated and triaged here. This is the Phase-25 register for the assessment slice.
**Scope:** Concord platform at HEAD of `feat/catalog-currency-ssp-odp-connectors`.
**Total findings:** 73 (IA 11 · ISSM 13 · FedRAMP 13 · CISO 11 · UX 13 · DATA 12).

## Consolidated production-readiness posture

**NO-GO for production serving federal data, and REJECT for FedRAMP-package use, as
currently configured.** Two independent hard blockers:

- **Insecure-by-default (IA-01 / CISO-03 / IA-11):** the shipped default
  (`auth_enabled=False`, wildcard CORS, `auth_session_secret="dev-insecure-change-me"`)
  turns every request into an **unscoped global admin with RLS disabled**, and the one
  safety check passes whenever `CCF_ENV` is unset (stays `"dev"`). Nothing fails closed.
- **Wrong control catalog (FR-01):** the "FedRAMP" SSP pipeline is hardwired to the
  **CMMC L2 / NIST SP 800-171 Rev. 2** 110-practice set while presenting itself as
  "FedRAMP Appendix A" — a category error before any content-quality question.

Conditional-go path exists once these plus the AI-provenance-visibility (CISO-02),
audit-read exposure (IA-02), and finding→POA&M→ATO wiring (ISSM-01/02/03) items are
resolved. The isolation *architecture* is well-built; the exposure is open defaults,
coverage/proof lagging design, and lifecycle stages wired as islands.

## Cross-cutting themes (where multiple lenses converged)

1. **Secure defaults / fail-open** — IA-01, IA-11, CISO-03, CISO-04. Insecure defaults
   pass the gate unless an env var is remembered; `/readyz` ignores the reliability suite.
2. **The finding→POA&M→risk→ATO spine is broken at every automated junction** —
   ISSM-01 (ATO status set-never), ISSM-02/03/04/13 (findings don't reach POA&Ms),
   ISSM-05/06 (risks have no provenance/gate), CISO-01 (accepted risk drops from metrics).
3. **AI-generated content has no user-visible provenance** — CISO-02, UX-01, FR-11,
   IA-10. AI text enters authoritative fields/SSP with no badge and no review UI.
4. **SSP content is CMMC-shaped and draft-grade, not FedRAMP** — FR-01..FR-13:
   wrong catalog, evidence never gates completeness, statements restate the control,
   origination copied from the M365 placemat onto AWS/Azure, no FIPS refs, OSCAL diverges.
5. **Tenant isolation: strong design, thin proof + edge holes** — IA-03 (2/68 tables
   tested), IA-04/DATA-01 (poam_milestones, organizations unpolicied), DATA-03/06
   (framework_controls, audit_log org-less), IA-02 (audit read ungated/cross-tenant).
6. **Referential integrity gaps in newer layers** — DATA-02/07/11 (integer "pointers"
   with no FK in portal/packages/evidence), DATA-04 (hard-cascade deletes wipe the
   authorization record), DATA-08/10 (missing unique constraints allow duplicates).
7. **UX silent-failure + risk-signal blindness** — UX-04/13 (creates bounce with no
   message), UX-06/07 (ATO/critical not color-coded), UX-03/08 (POA&M/evidence
   dead-end in read-only/API-only surfaces).

---

## Findings by domain

Format: **ID** · Sev/Conf · component — summary → recommendation. Disposition:
`FIX-NOW` (this slice), `DEFER→N` (target roadmap slice: 3=AI foundation,
4=SSP hardening, 5=cloud breadth, 6=prod-readiness), `DEFER→sec` (dedicated security slice).

### IA — technical security (information-assurance-engineer)

- **IA-01** · Critical/Confirmed · config.py:94, auth_deps.py:83 — default `auth_enabled=False` ⇒ every request an unscoped global admin, RLS off; nothing fails closed. → fail closed when `env!="dev"`. **DEFER→6** (blocker).
- **IA-02** · High/Confirmed · routes/audit.py:34-86 — audit-read API has no `require_role` and queries `audit_log` globally (no org_id, no RLS); any tenant reads all tenants' trail. → role-gate + org-scope. **FIX-NOW (role-gate)** + DEFER→sec (org column/RLS).
- **IA-03** · High/Confirmed · tests/test_rls.py — RLS proven for only 2 of ~68 policy-bound tables. → parametrized per-table isolation test. **DEFER→sec**.
- **IA-04** · Medium/Confirmed · poam_milestones, organizations — tenant tables with no RLS policy. → add policies. **DEFER→sec** (migration; see DATA-01).
- **IA-05** · Medium/Confirmed · connectors/*, collection.py — one global credential set; captures mis-attributed to each org. → per-org connector creds. **DEFER→3** (ties to org-scoped AI/creds).
- **IA-06** · Medium/Confirmed · scheduler.py:38 — background jobs run tenant=None (RLS bypass); snapshots written org_id=None. → per-org loop with `set_session_tenant`. **DEFER→sec**.
- **IA-07** · Medium/Confirmed · evidence/service.py:136 — stored SHA-256 never re-checked on read. → verify digest on read. **DEFER→4**.
- **IA-08** · Medium/HighlyLikely · evidence/storage.py:80 — WORM inert on default LocalStorage; S3 lock lacks retain-until date. → enforce object-lock backend + retain-until. **DEFER→4**.
- **IA-09** · Medium/Confirmed · models.py:296, portal/service.py:39 — API + portal tokens stored plaintext. → store hashed, show once. **DEFER→sec**.
- **IA-10** · Low/Confirmed · ai_actions/service.py — `ai_require_human_approval` & `ai_store_prompts` flags are inert. → honor flags. **DEFER→3**.
- **IA-11** · Low/Confirmed · config.py:95, main.py:114 — default session secret + wildcard CORS. → refuse default secret in prod; explicit CORS allow-list. **DEFER→6** (part of blocker).

### ISSM — program/workflow integrity (information-systems-security-manager)

- **ISSM-01** · Critical/Confirmed · routes/systems.py — no write path for `ato_status`; Authorize stage unreachable in-app. → authorize endpoint gated on approved assessment + AO + no open crit POA&M. **DEFER→6**.
- **ISSM-02** · High/Confirmed · routes/assessments.py:190 — finding→POA&M is manual, no source/owner/due/link; fragile title-match idempotency. → auto-open linked POA&Ms on OTS finding. **DEFER→4**.
- **ISSM-03** · High/Confirmed · governance/conmon.py, control_tests.py — ConMon/test failures create only Tasks, never POA&Ms/risks. → open idempotent POA&M on failure. **DEFER→4**.
- **ISSM-04** · High/Confirmed · models_grc.py:153 — audit findings have no poam/risk/system/org FK; closure is free-text. → add linkage + promote-to-POA&M + evidence closure. **DEFER→4**.
- **ISSM-05** · Medium/Confirmed · models.py:653 — risks have no FK to originating finding. → add origin link + accept-finding→risk. **DEFER→4**.
- **ISSM-06** · High/Confirmed · routes/risks.py:233 — risk acceptance has no approval gate/owner/expiry/SoD. → block `accepted` without AO approval + owner + expiry. **DEFER→4**.
- **ISSM-07** · Medium/Confirmed · governance/approvals.py:131 — approval decisions only reflect onto SSP, not poam/risk/assessment. → reflect on all entity types. **DEFER→4**.
- **ISSM-08** · Medium/HighlyLikely · approvals.py — no lifecycle transition requires an approval; SoD collapses when auth off. → make approval a precondition on authorizing transitions. **DEFER→4**.
- **ISSM-09** · Medium/Confirmed · routes/poams.py:320 — POA&M close has no validation/evidence gate. → require milestones/evidence+approval to close. **DEFER→4**.
- **ISSM-10** · Medium/Confirmed · assessments.py:213 — auto POA&Ms carry no milestones. → seed default milestone; require ≥1 to export. **DEFER→4**.
- **ISSM-11** · Medium/Confirmed · api/audit.py, scheduler.py — scheduler mutations bypass the audit hash-chain. → automated jobs call `record_event`. **DEFER→sec**.
- **ISSM-12** · Medium/Confirmed · ssp/completeness.py — SSP can be approved/exported with controls missing responsible party (completeness is advisory). → gate approve/export on completeness. **DEFER→4**.
- **ISSM-13** · Medium/Confirmed · models.py:505 — 3 disjoint finding vocabularies; the generic AssessmentResult path has no POA&M handoff. → unify enum + add handoff. **DEFER→4** (see DATA-05).

### FedRAMP — SSP/package quality (fedramp-authorization-expert)

- **FR-01** · Critical/Confirmed · ssp/generator.py, oscal.py — "FedRAMP" SSP is actually CMMC/800-171r2; wrong control set. → gate FedRAMP projects onto 800-53r5 baseline+profile, or remove FedRAMP/800-53 options. **DEFER→4/5** (major).
- **FR-02** · Critical/Confirmed · ssp/completeness.py — readiness never checks evidence; all-`[DRAFT]` SSP scores 100% ready. → gate on evidence + reject DRAFT/unfilled ODP narratives. **DEFER→4**.
- **FR-03** · High/Confirmed · ssp/statements.py — auto statements restate the control; answer ~3/12. → inject role/frequency/evidence/policy in all styles. **DEFER→4**.
- **FR-04** · High/Confirmed · ssp/seed.py — origination derived from M365 placemat for every platform. → per-platform origination source. **DEFER→5**.
- **FR-05** · High/Confirmed · ssp/platforms.py — provider-performed controls claimable as system-specific; PE inherited misattributed to org. → enforce origination vs derived responsibility. **DEFER→5**.
- **FR-06** · High/Confirmed · ssp/platforms.py — Azure Gov statements generated with no connector to evidence them. → flag manual-evidence-required until connector exists. **DEFER→5**.
- **FR-07** · High/Confirmed · ssp/platforms.py — "GCC High" hardcoded regardless of tenant tier. → carry tier from connector/profile. **DEFER→5**.
- **FR-08** · High/Confirmed · ssp/platforms.py — SC crypto statements name no FIPS 140-2/3 module or key custody. → add FIPS refs + key location. **DEFER→4**.
- **FR-09** · High/Confirmed · routes/oscal.py:202 — OSCAL SSP drops boundary/roles/categorization, omits system-implementation. → source from same metadata as docx. **DEFER→4**.
- **FR-10** · Medium/Confirmed · routes/oscal.py — SSP export=800-171r2 but component-def=800-53r5 (contradictory baselines). → one baseline per system. **DEFER→4**.
- **FR-11** · Medium/Confirmed · ssp/statements.py:88 — inherited statements auto-accepted, assert evidence with no CRM link. → require leveraged-authorization link; mark needs_review. **DEFER→4**.
- **FR-12** · Medium/HighlyLikely · governance/automation.py:109 — non-M365 inheritance is domain-level guessing. → per-control CRM mapping. **DEFER→5**.
- **FR-13** · Low/Confirmed · constants.py:101 — responsible role is a generic per-domain string. → populate from roles metadata. **DEFER→4**.

### CISO — aggregation + production readiness (chief-information-security-officer)

- **CISO-01** · High/Confirmed · analytics/posture.py — risk-accepted/completed POA&Ms vanish from all metrics/MTTR. → add residual/accepted bucket. **DEFER→6**.
- **CISO-02** · High/HighlyLikely · ai_actions/service.py, templates — AI content indistinguishable from human-approved; no review UI. → AI-provenance badge + review queue UI. **DEFER→3**.
- **CISO-03** · High/Confirmed · config.py, reliability/checks.py:228 — insecure defaults pass the gate unless `CCF_ENV` set. → fail closed regardless of env. **DEFER→6** (blocker; = IA-01/11).
- **CISO-04** · Medium/Confirmed · routes/health.py:20 — `/readyz` runs only `SELECT 1`, ignores reliability suite. → aggregate blocking checks → 503 on FAIL. **DEFER→6**.
- **CISO-05** · Medium/Confirmed · analytics/overview.py — risk heatmap vs risk-status use different populations; blocks ignore org scope (rely on RLS only). → reconcile populations; thread org_id. **DEFER→6**.
- **CISO-06** · Medium/HighlyLikely · analytics/posture.py:143 — overdue keys only on `due_on`; null-due counted "on track". → fall back to scheduled_completion + "no due date" bucket. **DEFER→6**.
- **CISO-07** · Medium/Confirmed · api/audit.py:35 — `_REDACT` misses `api_key`/`anthropic_api_key`/`aws_secret_access_key`. → add key/credential/private. **FIX-NOW**.
- **CISO-08** · Medium/Confirmed · .github/workflows/ci.yml:69 — `pip-audit … || true` non-blocking; no prod release gate. → drop `|| true`; add env approval + branch protection. **DEFER→6**.
- **CISO-09** · Low/Confirmed · analytics/posture.py:195 — `avg_sprs` masks a failing system. → show min/worst. **DEFER→6**.
- **CISO-10** · Low/Confirmed · reporting/export.py — leadership export lacks risk posture + AI provenance. → add reconciled summary + provenance column. **DEFER→6**.
- **CISO-11** · Low/Possible · analytics/overview.py:34 — findings-by-severity is POA&M-only; latent divergence. → catch-all bucket; sum==total. **DEFER→6**.

### DATA — schema/data integrity

- **DATA-01** · High/Confirmed · poam_milestones — no RLS policy (only tenant child table uncovered). → parent-scoped policy. **DEFER→sec** (= IA-04).
- **DATA-02** · High/Confirmed · external_package_shares/evidence_shares — package_id/evidence_object_id have no FK. → add FK ON DELETE CASCADE. **DEFER→sec**.
- **DATA-03** · High/Confirmed · framework_controls — no org_id, no RLS; global unique key; cross-tenant overwrite/leak on upload. → add org_id + scoped unique + RLS. **DEFER→sec**.
- **DATA-04** · High/Confirmed · systems/organizations cascade — hard `ON DELETE CASCADE` wipes the entire authorization record; no soft-delete. → soft-delete + RESTRICT + archive gate. **DEFER→sec**.
- **DATA-05** · Medium/Confirmed · finding/status/impl columns — fragmented vocabularies (Enum vs free String vs JSONB). → canonical shared enums. **DEFER→4** (= ISSM-13).
- **DATA-06** · Medium/Confirmed · audit_log — no org_id, no RLS; single interleaved global chain. → add org_id + RLS. **DEFER→sec** (= IA-02 backend).
- **DATA-07** · Medium/Confirmed · evidence/packages/portal `*_id` — plain integers, no FK (dangling-pointer risk). → convert to FKs. **DEFER→sec**.
- **DATA-08** · Medium/Confirmed · vendors/policies/fedramp_dependencies/pack_mappings/people — missing unique constraints → duplicates. → add unique constraints. **DEFER→sec**.
- **DATA-09** · Medium/HighlyLikely · evidence vs evidence_objects — two disconnected evidence stores, no FK bridge. → bridge models. **DEFER→4**.
- **DATA-10** · Low/Confirmed · pack_mappings — no unique(pack_id,control_id,framework); duplicate mappings. → add constraint. **DEFER→sec**.
- **DATA-11** · Low/Confirmed · external grant refs — Integer PK vs BigInteger grant_id width mismatch. → normalize + FK. **DEFER→sec**.
- **DATA-12** · Low/Confirmed · poams control/risk/vendor_id — ON DELETE SET NULL silently orphans traceability. → RESTRICT control_id or emit event. **DEFER→sec**.

### UX — navigation/usability

- **UX-01** · High/Confirmed · _ssp_entry.html — generated narratives indistinguishable from human-approved; no provenance in UI or .docx. → per-entry review-state chip + export watermark. **DEFER→3/4**.
- **UX-02** · High/Confirmed · ssp_detail.html — missing/incomplete SSP info hidden; .docx always enabled. → per-entry completeness chip + readiness bar + gated export. **DEFER→4**.
- **UX-03** · High/Confirmed · poams.html, risks.html — read-only registers; no detail/edit/milestone/accept in UI. → POA&M detail with milestone CRUD + remediate/accept. **DEFER→4**.
- **UX-04** · High/Confirmed · ui.py POST handlers — create/validation failures redirect silently; record just absent. → flash/error banner pattern. **DEFER→6**.
- **UX-05** · High/Confirmed · system_detail.html vs _scoring_score.html — "Inherited" green on one page, blue on another; no customer-responsibility category. → consistent color+label. **DEFER→4** — *on verification the `cls` var in the system_detail KPI block is unused (dead), so the green/blue inconsistency does not actually render; the real work is adding a customer-responsibility category. Not a small fix.*
- **UX-06** · Medium/HighlyLikely · systems.html:91, system_detail.html:28 — ATO status neutral chip; expired/none looks authorized. → map ato_status→ok/warn/err. **FIX-NOW**.
- **UX-07** · Medium/HighlyLikely · governance.html:39 — critical severity renders orange (warn), never red. → chip--err for critical. **FIX-NOW**.
- **UX-08** · Medium/HighlyLikely · evidence.html, system_detail.html:76 — evidence attach is API-only / "coming soon". → UI upload/version/detail. **DEFER→4**.
- **UX-09** · Medium/Confirmed · scoring.html:121 — control link hard-coded to `/controls` list, not the control. → deep-link `/controls/{id}`. **DEFER→4** — *verified against live data: scoring `nist_id` is 800-171 format (`3.1.1`), `controls.identifier` is 800-53A (`AC-01`), zero matches across all 110; a naive deep-link would 404 every row. Needs a scoring→800-53 identifier mapping first.*
- **UX-10** · Medium/HighlyLikely · governance.html:99 — mermaid loaded from CDN; silent failure in air-gapped/CSP deploys. → vendor locally + fallback. **DEFER→6**.
- **UX-11** · Low/Confirmed · ssp.html/systems.html/dashboard.html — terminology drift (customer/org/tenant; findings vs POA&Ms). → standardize. **FIX-NOW (labels)**.
- **UX-12** · Low/Confirmed · ssp.html:34 — SSP `draft` and `in_review` render identical orange chip. → distinct chip for in_review. **FIX-NOW**.
- **UX-13** · Low/HighlyLikely · ui.py detail routes — bare `HTTPException(404)` outside app chrome. → templated 404/403 handler. **DEFER→6**.

---

## This-slice fix set (FIX-NOW)

Small, safe, self-contained, verifiable defects landed in the assessment slice:

| Finding | Fix | Verification | Status |
|---|---|---|---|
| CISO-07 | Add `key`/`credential`/`private` to `_REDACT` (api/audit.py) | `tests/test_audit_redaction.py` (3 tests, real ccf_test DB) | ✅ landed + tested |
| UX-07 | Critical → `chip--err`, high → `chip--warn` (governance.html tasks + alerts) | Jinja parse OK | ✅ landed |
| UX-06 | ATO status → `chip--ok`(authorized)/`chip--err`(expired) (systems.html, system_detail.html) | Jinja parse OK | ✅ landed |
| UX-12 | SSP `in_review` → `chip--info` (ssp.html) | Jinja parse OK | ✅ landed |
| UX-11 | Dashboard stat relabel "Open findings" → "Open POA&Ms" (matches `/poams` link) | Jinja parse OK | ✅ landed |
| UX-05 | ~~inherited chip color~~ | — | ⤳ reclassified DEFER→4 (dead `cls` var; nothing renders) |
| UX-09 | ~~deep-link control~~ | live-data check | ⤳ reclassified DEFER→4 (id schemes don't match; would 404) |

**Verification note:** checking the actual code/data before editing reclassified UX-05
and UX-09 out of the fix set — UX-09's naive deep-link would have 404'd all 110 rows,
UX-05's target variable is dead. This is why the fixes are verified against real
data/templates, not applied on the finding's face value.

Everything else is structural (schema migrations, new endpoints, lifecycle wiring, the
SSP catalog correction) and is deliberately deferred to its target slice — consistent
with "do not immediately rewrite major sections." Each deferred item carries a concrete
recommendation and acceptance criterion above.

A pre-existing design-polish item was surfaced (not from these edits): dashboard.html
L284/L292/L322 (border-accent-on-rounded, layout-property animations) — logged for a
future design pass, out of scope here.

---

## Slice 4 resolutions (2026-07-21, subagent-driven, branch `feat/catalog-currency-ssp-odp-connectors`)

Executed via 7 TDD tasks + a whole-branch review + a fix wave. **RESOLVED:**

- **FR-02** — completeness now gates on real evidence (SSPControlEntry → system →
  ControlImplementation → Evidence join, wired in the completeness route) and rejects
  DRAFT/ODP-placeholder narratives. Proven by a production-path integration test.
- **FR-08** — SC-family (SC-8/13/28) statements now name FIPS 140-2/140-3 validated
  modules + key custody, with a marked cert placeholder.
- **FR-09 / FR-10** — OSCAL SSP export sources categorization/boundary/roles from the
  same `metadata_json` as the docx, emits system-implementation, and both OSCAL
  artifacts cite one consistent baseline.
- **ISSM-01** — ATO authorize write path (`POST /api/systems/{id}/authorize`),
  admin-gated, refuses (409) when an open critical/high POA&M exists, audit-covered.
- **ISSM-02 / ISSM-10** — assessment findings auto-generate provenanced
  (source='assessment', control, due date, stable `source_ref` back-reference),
  milestone-bearing, idempotent POA&Ms (migration `0038_poam_source_ref`).
- **ISSM-03** — ConMon overdue controls + failed control tests now open idempotent
  POA&Ms (source='conmon'/'control_test') alongside the existing Tasks/Notifications.
- **Slice 3b** — org-admin AI settings surface (routes + minimal UI) over the vault +
  gateway: add/test/rotate/revoke, masked, admin-gated, org-scoped; token never returned.

**Whole-branch review findings (all fixed, commit `a107a74`):** the evidence gate was
initially inert in production (keyed on dict fields the entry builder never emitted) —
now wired to real records + covered by an integration test; `[Selection` token match;
OSCAL impact `base` token validity; `control_tests` dedupe `system_id` filter.

**New this slice (register addendum):** FR-14 — FedRAMP 2026 (CR26) terminology
currency (see `2026-07-21-fedramp-2026-terminology-review.md`): no MUST-CHANGE;
label-only SHOULD-CHANGE items on `fedramp20x/` surfaces deferred (enforcement 2027-01-01).

Verification: full suite 347→(post-fix)-green except 1 known-flaky async test that passes
in isolation; ruff + mypy clean across `src`/`tests`.

**Still open after Slice 4:** FR-01 + FR-03/04/05/06/07/11/12/13 (→ Slice 5, below),
the ISSM approval-gating / risk-provenance items (ISSM-04..09, -11..13),
CISO-01..06/08 (aggregation + prod-readiness → Slice 6), and the DATA schema/security
items (→ dedicated security slice).

---

## Slice 5 resolutions (2026-07-21, subagent-driven, same branch)

4 TDD tasks + a test-isolation fix + a whole-branch review + a fix wave. **RESOLVED:**

- **FR-01** — DECISION: relabel (not build 800-53). The generator now truthfully names
  **CMMC L2 / NIST 800-171 Rev.2**; the "FedRAMP SSP Appendix A" cover claim and the
  FedRAMP/800-53 framework picker options (verified unread no-ops) are removed. Building
  a real 800-53r5 FedRAMP pipeline is a separate future program.
- **FR-04/05/12** — control origination is now derived **per-platform** from a single
  shared `PLATFORM_DOMAIN_RESPONSIBILITY` table, independent of M365 coverage; a
  provider-performed control can never render system-specific; non-M365 controls lacking
  per-control coverage carry a `MANUAL_RESPONSIBILITY_FLAG`.
- **FR-06/07** — no-connector platforms (Azure/GCP) are flagged manual-evidence-required
  and **excluded from readiness "covered"** (not just labeled), and their inherited
  status is downgraded from "Implemented"; the environment label emits "GCC High" only
  for a confirmed `m365_gcc_high` tier, never by default.
- **FR-03/11/13** — `compose()` injects responsible role + frequency + evidence pointer
  in **all** styles and this is now wired into the production `generate_statements` path
  (named System Owner reaches the rendered narrative — proven by a production-path test);
  inherited statements are `needs_review` and carry a customer-responsibility line unless
  a **real** `crm_ref` (sourced from `Vendor.authorization`/`Policy`, never fabricated)
  is linked; responsible role uses named roles when metadata provides them and a generic
  fallback is honestly flagged (does not silently satisfy the completeness gate).

**Whole-branch review findings (all fixed):** production `compose()` call omitted the new
params so narratives falsely read "No Named Party on File" (commit `3bc91bb`); no-connector
status consistency; `crm_ref` sourced from real records. **Test hygiene:** a new test
leaked global `ScoringControl` rows → fixed (`bc75b62`); full suite now deterministic
(393 passed + 1 known-flaky async test that passes in isolation).

**Still open → later slices:** ISSM-04..09/11..13 (approval-gating, risk provenance,
finding-vocabulary unification), CISO-01..06/08 (aggregation + prod-readiness → Slice 6),
DATA-01..12 (schema/security → dedicated security slice), FR-14 (FedRAMP-2026 label-only),
and the FedRAMP 800-53r5 pipeline (FR-01 future program). Manual SSP-editor PATCH of
`control_origination` is not yet validated against derived responsibility (noted follow-up).
