# Concord (ccf) — Improvement Opportunities Backlog

- **Date:** 2026-07-27
- **Basis:** Read-only recon over current `main` + the merged assessment program, excluding items already resolved in the [2026-07-21 consolidated findings register](2026-07-21-consolidated-findings-register.md).
- **Excluded (already delivered):** control-read accuracy — the **OSCAL 800-53r5 catalog reconciliation engine** was designed, planned, and built on branch `feat/oscal-catalog-reconciliation` (advisory reconciliation + raw→canonical crosswalk). Items #4 and #6 below are scoped to *consume* that engine's catalog, not duplicate it.

Ranked by leverage (impact ÷ effort). Effort S/M/L, impact High/Med.

| # | Opportunity | Lens | Effort | Impact |
|---|---|---|---|---|
| 1 | Secure-by-default inversion + CORS fail-closed | Config blocker | S | High |
| 2 | Kill per-system N+1 in posture dashboard | Performance | S–M | Med |
| 3 | Wire ai_actions path to the real org gateway | AI maturity | M | High |
| 4 | OSCAL assessment-results (SAR) + package bundle | Feature | M | Med–High |
| 5 | Azure Gov / GCP config connectors | Connector breadth | L | High |
| 6 | Real 800-53r5 FedRAMP SSP pipeline (on reconciliation catalog) | FR-01 / feature | L | High |
| 7 | BaseHTTPMiddleware → pure ASGI (metrics/auth unguarded) | Reliability | M | Med |
| 8 | AI review-queue UI | AI maturity | M | Med |
| 9 | Continuous-monitoring drift detection + on-by-default | ConMon | M | Med |
| 10 | Residual SSP statement quality (FR-03..13) | Feature/quality | M | Med |
| 11 | Guard 27MB workbook sync load from /readyz | Performance | S | Low–Med |

## Details

### 1. Invert secure-by-default; make wildcard CORS fail closed — `src/ccf/config.py`
The auth/secret half of the blocker is fixed (`enforce_secure_config`), but the whole mechanism is gated on `env not in {dev,local,test}` and `env` **defaults to `"dev"`**. Deploy to production without setting `CCF_ENV` and you silently get the full insecure posture (auth off, default session secret, wildcard CORS) — every request an unscoped global admin with RLS off. Wildcard CORS is only ever a *warning* and is applied verbatim in `api/main.py`. **Fix:** (a) require explicit `CCF_ENV=dev` to relax rather than treating unset as dev; (b) promote wildcard CORS in non-dev from warning to a hard config problem. Highest-leverage single change.

### 2. Collapse the per-system N+1 in the posture dashboard — `src/ccf/analytics/posture.py`
`dashboard_cards`/`org_summary` loads all systems then loops, issuing ~5 round-trips per system (open-POA&M count, POA&M-by-severity, two evidence counts, `sprs_summary`'s own grouped query). Cost is O(systems × 5) on every dashboard load — the leadership landing analytics. **Fix:** rewrite as a handful of `GROUP BY system_id` aggregates joined in memory.

### 3. Route the typed AI-action path through the real org gateway — `ai_actions/provider.py`, `ai_actions/service.py`
`ai/gateway.py` is a genuine org-scoped choke point (per-org encrypted creds, model allowlist, usage logging) and `governance/ai.py` calls it. But the typed, auditable, human-approval, registry-gated action path never reaches it: `ai_actions/provider.py` `generate()` ignores its `provider` arg and always returns `_stub()`. So even with a fully configured org gateway, POA&M remediation drafts and control-test suggestions are canned text. **Fix:** wire `provider.generate` → `gateway.generate_structured` when `provider != "stub"` — unlocks the whole ai_actions feature with guardrails already built.

### 4. Emit OSCAL Assessment-Results (SAR) + authorization-package bundle — `api/routes/oscal.py`
`oscal/validation.py` already models `assessment-results`, but routes only export SSP, component-definition, and POA&M. A FedRAMP package is SSP + SAP/SAR + POA&M together; today the SAR side has no OSCAL export and there's no single "download the package" artifact. OSCAL completeness is what federal customers evaluate. Can consume the reconciliation catalog for control identity.

### 5. Add Azure Government and GCP config connectors — `src/ccf/connectors/`
Only `msgraph.py` (M365) and `aws.py` (GovCloud) ship. Azure/GCP systems are honestly flagged manual-evidence-required (Slice 5), but that's a placeholder — an Azure Gov system can't auto-evidence a single control, and Azure Gov is dominant in federal. The `ConfigConnector` ABC + per-org encrypted credentials already exist, so this is additive.

### 6. Build the real 800-53r5 FedRAMP SSP pipeline on the reconciliation catalog — `src/ccf/ssp/`
FR-01 was resolved by *relabeling* the generator to its true content (CMMC L2 / 800-171r2); the product still has no FedRAMP 800-53r5 SSP capability. The new reconciliation engine vendors the pinned 800-53r5 catalog + baselines + crosswalk — exactly the substrate a real pipeline needs. The distinct work is the *generation* layer: baseline selection, ODP handling, 800-53r5 statement composition → SSP/OSCAL. Largest single product-value gap; scope it to consume the engine's catalog.

### 7. Convert middleware from BaseHTTPMiddleware to pure ASGI — `api/audit.py`, `api/metrics.py`, `api/auth_deps.py`
Slice 9 fixed the Starlette double-invocation bug but only for audit (per-handler idempotency guard). `metrics_middleware` and `auth_gate_middleware` use the same `app.middleware("http")` form with **no** re-entry guard — under the same exception/re-entry condition metrics can double-count and the auth gate can re-run, on the exact error paths where correctness matters. **Fix:** a single pure-ASGI middleware base.

### 8. Ship an AI review-queue UI — `api/routes/ai_actions.py`
CISO-02 landed the AI/draft provenance badge and the JSON plumbing (`review_queue`, `guardrail_violations`) exists, but there's no reviewer-facing surface to see pending AI runs with citations and approve/reject in-app. With #3, this turns "AI drafts exist" into "AI drafts safely operationalized." `ai_require_human_approval` is the core safety control; without a UI, approvals happen via raw API calls (nobody will) or get rubber-stamped.

### 9. Make continuous monitoring real: drift detection + on-by-default — `governance/scheduler.py`, `config.py`
The per-tenant scheduler is solid (per-org savepoint isolation), and ConMon failures open idempotent POA&Ms. But `scheduler_enabled=False` by default, 24h interval, and collection compares captured parameters without an explicit **drift/delta** signal or change alert. **Fix:** drift detection (config changed vs last snapshot → alert + POA&M) is what keeps an ATO alive and is currently latent.

### 10. Close residual SSP implementation-statement quality (FR-03..13) — `src/ccf/ssp/statements.py`
Slice 5 improved `compose()` (role/frequency/evidence injection, inherited→needs_review, real crm_ref), but the register leaves FR-03..13 open and a manual PATCH of `control_origination` isn't validated against derived platform responsibility. Statements remain largely templated rather than system-specific — the top authorization-package rejection reason.

### 11. Guard the synchronous 27MB workbook load from /readyz — `etl/pipeline.py`
`ingest_workbook` loads the workbook with synchronous `openpyxl.load_workbook` inside an `async def`. CLI-only today, but the OSCAL reconciliation engine adds a tail-call in `ingest_workbook` and a `/readyz` consumer. If any probe path triggers ingest, a 27MB synchronous parse blocks the event loop and can trip readiness timeouts. **Fix:** wrap in `asyncio.to_thread` (pattern already used in `connectors/aws.py`, `etl/sources.py`, `api/routes/ssp.py`) and keep parsing off any probe path.

## Recommended first moves
- **#1** — one-file config change; removes the last fail-open path (the standing hard blocker). Highest safety leverage.
- **#3** — connects two already-built systems (org gateway ↔ ai_actions) to unlock the entire AI feature under existing guardrails.
