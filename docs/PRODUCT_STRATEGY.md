# Concord — Product Strategy & Competitive Upgrade Plan

> Strategy of record. Benchmarked against 14 GRC/compliance vendors (Vanta, Drata,
> Secureframe, Sprinto, Hyperproof, OneTrust, AuditBoard/Optro, ServiceNow IRM,
> Archer, RegScale, Paramify, Telos Xacta, Ignyte, FutureFeed) plus the
> services-led segment (Steel Patriot/ZenGRC, CyberSheath). Gap findings are
> grounded in the codebase; see file references inline.

## 1. Where Concord stands today

Concord is a **strong FedRAMP/CMMC authoring engine**, not a prototype. Shipped and
fully built: live CMMC L2 SPRS scoring, SSP / SAR / report (xlsx·docx·csv·json)
generation, OSCAL 1.1 export (component-definition + SSP), a 26-framework /
~121k-mapping crosswalk with Postgres full-text search, POA&M + risk registers,
evidence tracking, opt-in auth/RBAC, app-layer multi-tenancy, and a tamper-evident
hash-chained audit log. On **document generation and cross-framework mapping** it is
competitive with Xacta, RegScale, and Paramify.

The gap is **not authoring — it is everything around it**: continuous monitoring,
automated evidence, AI, and the enterprise trust/integration layer. The entire
commercial field has converged on those four, and Concord has none yet.

## 2. Strategic position

> **Own the niche: the self-hostable, OSCAL-native, SPRS-transparent compliance
> engine for CUI/DIB and federal.** Compete with RegScale / Paramify / Xacta /
> FutureFeed — *not* the SOC-2 automation crowd (Vanta/Drata/Secureframe/Sprinto).

Do not try to out-Vanta Vanta on SaaS breadth. Win on the things SaaS-only vendors
structurally cannot offer a CUI/ITAR/air-gapped buyer.

### Market timing (two forcing functions)

- **FedRAMP 20x / RFC-0024 (OSCAL mandate).** FedRAMP 20x (launched Mar 2025) and
  RFC-0024 push **machine-readable OSCAL packages** (SSP + SAP + SAR + POA&M) and
  continuous **Key Security Indicator (KSI)** validation — moving toward mandatory for
  FedRAMP providers around **Sept 2026**. Concord already exports OSCAL
  component-definition + SSP, which puts it in the credible minority — but the window
  to reach RegScale/Paramify parity (full package + KSI) is now.
- **Continuous controls monitoring (CCM) is the industry's weakest link.** Forrester's
  Q2 2026 GRC Wave found CCM was the *single weakest current-offering criterion* across
  all evaluated vendors — most "CCM" today is just audit-evidence gathering, not live
  control-performance monitoring. The category leaders are still racing here, which
  means a focused, self-hostable CCM story is an open lane rather than a closed gap.

## 3. Differentiators to protect

| Differentiator | Why it matters | Who else has it |
|---|---|---|
| **Self-hosted / air-gap capable** (Docker + Postgres; read-only Reader build) | CUI/ITAR/classified DIB shops cannot use Vanta/Drata/Secureframe/Sprinto/OneTrust/AuditBoard/ServiceNow/Hyperproof (all SaaS-only) | Only RegScale + Xacta |
| **Transparent, deterministic live SPRS** (−203→110, recompute on change) | Most enterprise GRC don't compute SPRS at all | FutureFeed, Xacta |
| **Cross-framework crosswalk depth** (26 frameworks, ~121k mappings, FTS) | "Map once, comply many" is the #1 marketed GRC value | Hyperproof, OneTrust |
| **OSCAL export already shipping** (component-def + SSP) | The gov-native moat; RegScale's entire pitch | RegScale, Paramify, ServiceNow CAM |
| **No per-seat SaaS tax** | Competitors are quote-based $10K–$100K+/yr | — |

## 4. Table-stakes gaps vs. the industry

Every benchmarked product competitor has these; Concord does not yet:

1. **Continuous monitoring + automated evidence connectors** (AWS/Azure/M365/GitHub) —
   *the* defining feature of modern GRC. Concord evidence is manual, URI-only, with
   **no background worker at all**.
2. **AI layer** — agentic AI for evidence validation, questionnaire auto-answer,
   control mapping, remediation shipped across the field in 2025–26 (Vanta AI Agent,
   Drata agentic suite, Archer Evolv 50+ operators, Hyperproof 4 agents, OneTrust
   Athena, RegML, Xacta.ai).
3. **SSO / OIDC / SAML + MFA** — table stakes; Concord has local passwords only, auth
   **off by default**.
4. **Trust Center** (customer-facing posture portal) — Vanta/Drata/Secureframe/
   Sprinto/Paramify all ship one.
5. **Security questionnaire automation** — standard in the compliance-automation segment.
6. **Auditor / 3PAO portal** — Drata Audit Hub, Secureframe Auditor Console, Sprinto
   auditor dashboard.
7. **Integrations marketplace** (competitors: 112–400+). Concord: 0.
8. **Workflow / approvals / assignments / notifications** — no review states, no email,
   no reminders.

Segment-specific gaps that also matter (enterprise GRC breadth, lower priority for the
CUI/DIB wedge):

9. **Full OSCAL package** — Concord exports component-definition + SSP only; RegScale/
   Paramify/Xacta generate **SAP + SAR + POA&M** in OSCAL too (RFC-0024 territory).
10. **Policy management + attestation campaigns** — standard enterprise GRC module; absent.
11. **Third-party / vendor risk management (TPRM)** — a flagship module everywhere; absent.
12. **Quantitative risk (FAIR / dollar-based)** — Concord's register is qualitative;
    ServiceNow (native FAIR/Monte Carlo) and Archer (Archer Insight) set the upmarket bar.
13. **Auditor / 3PAO portal** — matters acutely because CMMC L2 *requires* a C3PAO
    assessment; a collaborative assessor workspace is a natural extension of the existing
    assessment workflow.

## 5. Prioritized roadmap

### P0 — Enterprise hardening (credibility blockers; do first)

- **DB-enforced tenant isolation (Postgres RLS).** Today isolation is app-layer only
  (`src/ccf/api/routes/systems.py` Python `.where()`); one missed clause leaks tenants.
  Add RLS keyed on `current_setting('ccf.tenant_id')` set per request.
- **SSO/OIDC + MFA (TOTP)**, password reset, session/token **revocation**, scoped +
  expiring API tokens (`src/ccf/api/auth_deps.py` tokens are equality-checked and never
  expire).
- **Production secrets + CORS.** `auth_session_secret` defaults to
  `"dev-insecure-change-me"` (`src/ccf/config.py`), compose ships `ccf:ccf`, CORS
  defaults to `*`. Integrate a secret manager; lock CORS.
- **Default `auth_enabled` ON** for non-dev images.
- **Append-only audit at the DB layer** — the hash chain is verifiable but the app role
  can still `DELETE` (`docs/THREAT_MODEL.md`). Split Postgres grants + add triggers.

### P1 — Close the defining gap: continuous monitoring

- **Background worker** (`arq` or APScheduler — lightweight, fits the stack) for
  scheduled jobs.
- **Cloud evidence connectors** — start M365 + AWS Config + Azure Policy + GitHub. The
  platforms are already modeled for SSP narratives in `src/ccf/ssp/platforms.py`; make
  them live: pull config → map to controls → attach as `Evidence`.
- **Control freshness** — `evidence.expires_on` and `control_implementations.next_assessment_due`
  exist but nothing acts on them. Add freshness scoring, a "% controls with current
  evidence" metric, and expiry alerts.
- **Real evidence file storage** (S3/Azure Blob/local) — today evidence is URI-only.

### P1 — Workflow, notifications, integrations

- Approval states (draft → review → approved → published) for SSP entries, assessment
  findings, evidence (build on existing `reviewed`/`reviewer` fields).
- **Email/Slack notifications + reminders** (assignments, due dates).
- **Outbound webhooks**, bulk CSV/XLSX import, uniform pagination.
- **Complete the OSCAL package + import.** Extend export from component-definition + SSP
  to the **full set (SAP, SAR, POA&M)** and add OSCAL **import** for round-trip /
  eMASS-adjacent workflows. This is the RFC-0024 play and reaches RegScale/Paramify
  parity — high strategic value given the ~Sept 2026 window.
- **KSI / continuous-authorization story** — surface Key Security Indicators tied to the
  evidence connectors, so the CCM work above doubles as FedRAMP 20x relevance.

### P2 — Differentiate & delight

- **AI layer** — start with the two highest-ROI, lowest-risk agents: evidence-gap
  detection and control-narrative/SSP drafting, on the latest Claude models.
  *Self-hosted + AI is itself a moat:* gov buyers who cannot send CUI to a SaaS AI can
  run inference inside their own boundary.
- **Trust Center** (read-only posture portal) — repurpose the Reader read-only mode +
  posture analytics.
- **Security questionnaire automation** grounded in the control catalog + evidence.
- **Trend / time-series dashboards** (SPRS over time, POA&M velocity, evidence aging) —
  capture metric snapshots; everything is point-in-time today.
- **Signed/dated audit export packages** (chain-of-custody manifest) — extends the
  hash chain.

### Ongoing — ops maturity

OpenTelemetry tracing + correlation IDs, enforced coverage + SAST (Semgrep/Bandit) +
Dependabot, blocking Trivy (currently `|| true`), migration up/down tests, HA Postgres,
tuned connection pool, accessibility (WCAG AA) + responsive/light-mode.

## 6. Recommended sequence

| Quarter | Theme | Outcome |
|---|---|---|
| Q1 | P0 hardening (RLS, SSO/MFA, secrets, audit grants) | "Strong internal tool" → "deployable enterprise product" |
| Q2 | Background worker + 3–4 evidence connectors + control freshness | Closes the defining competitive gap; unlocks the "live compliance" story |
| Q3 | Workflow/approvals/notifications/webhooks + OSCAL import | Operational maturity + gov round-trip |
| Q4 | AI evidence/SSP agents + Trust Center | Differentiation on the self-host/air-gap edge |

## 7. Highest impact-to-effort starting points

1. **Postgres RLS tenant isolation** (P0 security) — recommended first.
2. **OIDC/SSO + MFA login.**
3. **OSCAL import** (round-trips existing export; gov differentiator).
4. **Background worker + first evidence connector** (M365 or AWS).
