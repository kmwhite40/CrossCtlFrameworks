# Concord assessment + AI/SSP program — role skills, org-scoped AI, SSP hardening, security & governance

Delivers a full operational-security / compliance / authorization / SSP-generation program
on top of the Concord (`ccf`) platform, executed as 11 reviewed slices. Every slice was built
test-first, code-reviewed on a fresh agent, and left with a green, deterministic suite.

**Status:** full suite **539 passed, 0 failures**; `ruff` + `mypy` clean (185 source files);
Alembic head `0050` (migrations `0037→0050`, all verified up/down/up). Production-readiness
recommendation: **GO** for the scoped use (internal compliance-ops + CMMC/800-171 SSP authoring),
AI-authored content enabled with visible provenance. Concord is not, and does not claim to be,
FedRAMP-authorized (a real 800-53r5 pipeline is a separate future program).

## What's in it

**1. Four reusable role-lens skills** — `information-assurance-engineer`,
`information-systems-security-manager`, `chief-information-security-officer`,
`fedramp-authorization-expert` (matching the GRC house style; verified via subagent activation
tests). They form the review panel used throughout.

**2. Whole-platform assessment** — a 73-finding consolidated register + a static integrity
validator (`docs/superpowers/assessments/`).

**3. Org-scoped AI foundation** — envelope-encrypted per-org credential vault
(`src/ccf/ai/cipher.py`, KMS-pluggable), a provider-neutral gateway with **Anthropic + OpenAI**
adapters, and an admin settings surface. Secrets stored hashed; never returned or logged.

**4. AI-assisted SSP generation** — evidence-gated completeness, FIPS-referenced crypto
statements, per-platform control origination, honest cloud-environment fidelity
(AWS/GovCloud, Azure/Gov, M365 GCC/GCC High/DoD, GCP), OSCAL consistency, and per-entry
**AI/draft provenance badges** with human-approval gating.

**5. Security & tenant isolation** — fail-closed insecure-default guard; audit-read role-gating
and per-tenant audit-log isolation; RLS coverage across ~108 tables (proven, not asserted);
bearer tokens hashed at rest; per-org connector credentials; evidence integrity verified on read
+ honest WORM; soft-delete so deletes don't wipe authorization records.

**6. Operational program wiring** — the finding→POA&M→risk→ATO spine is connected: assessment/
ConMon/control-test failures generate provenanced, milestone-bearing POA&Ms; ATO has a real
authorize path gated on open criticals; approval-gating + separation-of-duties on closure/
acceptance; approval state surfaced on records; honest leadership metrics (residual risk, worst
SPRS, dashboard/export reconciliation).

**7. Reliability & CI** — root-caused and fixed a real Starlette `BaseHTTPMiddleware`
double-invocation audit bug (the long-standing "flaky" test is now deterministically green);
blocking `pip-audit` with a clean dependency tree.

## Reviewing this PR

Start with the consolidated register and the production-readiness recommendation:
- `docs/superpowers/assessments/2026-07-21-consolidated-findings-register.md`
- `docs/superpowers/assessments/2026-07-21-production-readiness-recommendation.md`

Per-slice plans are under `docs/superpowers/plans/`. Migrations `0037`–`0050` add: org AI
credentials; RLS on `poam_milestones`/`organizations`/`framework_controls`/`audit_log`; unique
natural keys; hashed tokens; POA&M provenance; soft-delete; portal + evidence foreign keys.

## Not included (tracked follow-ups, none blocking the scoped GO)

Finding-vocabulary unification (ISSM-13/DATA-05), residual SSP-statement quality (FR-03..13),
portal magic-link token-in-URL hardening, wiring the SSP connector routes fully to per-org creds,
and the two future programs (a real FedRAMP **800-53r5** pipeline, FedRAMP-2026 label currency).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
