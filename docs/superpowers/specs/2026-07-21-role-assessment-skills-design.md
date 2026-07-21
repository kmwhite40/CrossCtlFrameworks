# Role-Assessment Skills — Design

**Date:** 2026-07-21
**Status:** Approved (Approach A)
**Slice:** First slice of the larger Concord assessment/build program — the four reusable role skills.

## Context

Concord (`ccf`) is a mature internal compliance-controls platform (FastAPI + async
SQLAlchemy/asyncpg, HTMX/Alpine UI, Typer CLI, Postgres with RLS). It already
implements most of the domain the broader spec assumes must be built: SSP
generation (`src/ccf/ssp/`), a typed citation-first AI action layer
(`src/ccf/ai_actions/`), AI-agent governance (`src/ccf/ai_governance/`), evidence
WORM (`src/ccf/evidence/`), an assurance graph, authorization packages, and
read-only cloud connectors (M365/Graph + AWS GovCloud).

Three sibling GRC skills already exist and define the house style:
`grc-authorization`, `poam-risk-management`, `ssp-authoring`.

This slice adds four **role-lens** skills that will drive the subsequent
platform-assessment slice:

- `information-assurance-engineer` (IA) — technical control effectiveness
- `information-systems-security-manager` (ISSM) — program/workflow integrity
- `chief-information-security-officer` (CISO) — enterprise risk & go/no-go
- `fedramp-authorization-expert` — SSP/package quality & OSCAL readiness

## Approach (A — thin role-lens skills that delegate)

Each skill is a **persona + review methodology + coordination protocol**, not a
re-teaching of domain mechanics. Domain how-to is delegated by cross-reference to
the existing task skills (`grc-authorization`, `poam-risk-management`,
`ssp-authoring`). Rejected alternatives: self-contained skills (heavy duplication,
style drift) and a single combined skill (spec requires four independently
invocable skills).

## File layout

```
.claude/skills/
  information-assurance-engineer/        SKILL.md + references/technical-validation.md
  information-systems-security-manager/  SKILL.md + references/workflow-and-raci.md
  chief-information-security-officer/     SKILL.md + references/risk-aggregation-and-go-live.md
  fedramp-authorization-expert/           SKILL.md + references/ssp-quality-and-cloud-caveats.md
```

No `agents/openai.yaml` — no such convention exists in the repo; matching the GRC
house style was chosen over the spec's literal structure.

## Shared shape (matches the three siblings)

- Frontmatter: `name` + `description` only. `description` = capability summary +
  "Use when…" trigger. Frontmatter ≤ 1024 chars.
- Body < 500 words: `# GRC — <Role>` H1 → grounding intro citing real `ccf.*`
  tables / `src/ccf/...` files → `## When to activate` → `## Review methodology`
  → `## Finding classification` → `## Required evidence` → `## Escalation` →
  `## Coordinating with the other role skills` → `## Guardrails`.
- Sibling cross-refs by bare backticked name; no `@`-links.

## Coordination protocol (the review panel)

Fixed handoff order encoded in every skill's coordination section:

**IA (technical truth) → ISSM (program/workflow integrity) → FedRAMP (package/SSP
quality) → CISO (enterprise risk & go/no-go).**

All four emit findings in one shared **finding-record format** (trimmed Phase-25
register): `id, title, domain[IA|ISSM|CISO|FedRAMP], severity, confidence,
component, expected, actual, evidence, ssp_impact, recommendation`.

The full consolidated register + a validator script are **deferred to the
assessment slice** (where they are actually exercised). This slice ships the
format definition only.

## Per-skill scope

- **IA** — verifies *implemented-and-effective* vs. the 13 states (implemented /
  partial / ineffective / not-connected / no-evidence / AI-unvalidated /
  inherited-undocumented / provider-misassigned / …). Anchors on real seams: RLS
  (`tests/test_rls.py`), audit hash-chain (`api/audit.py`), `require_role`,
  evidence WORM, connector captures. Reference: control→evidence→validation matrix.
- **ISSM** — walks the authorization lifecycle against real tables, flags orphans,
  broken handoffs, missing approvals, untraceable records. Reference: lifecycle
  map + RACI + shared finding-record format.
- **CISO** — risk aggregation, dashboard-vs-source consistency
  (`ccf.analytics.overview`), AI-generated-vs-approved visibility, owns the
  go-live gate. Reference: risk aggregation + production-readiness gate criteria.
- **FedRAMP** — the "12 questions" SSP-statement rubric, boilerplate/unsupported/
  cross-environment-copy detection, inheritance & shared-responsibility validation,
  OSCAL readiness, cloud service-availability caveats. Reference: SSP quality
  rubric + cloud caveats.

## Validation

Per `writing-skills`: a subagent activation test — give a fresh agent one skill +
a small real slice of the codebase and confirm it activates, classifies findings
in the shared format, and hands off to the right sibling. Fix wording on
under-trigger.

## Out of scope (later slices)

Assessment execution + consolidated register + validator; org-scoped AI credential
vault + real provider adapters; SSP-engine hardening; Azure/GCP connectors +
service-availability catalog; production-readiness go/no-go.
