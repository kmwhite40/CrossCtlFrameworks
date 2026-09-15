# Forge Capability Inventory — Architecture Discovery (Phase 1)

**Date:** 2026-09-14
**Repository:** `CrossCtlFrameworks` — the `ccf` package, product name **Concord**
**Purpose:** Phase 1 gate. Classify every requested capability as
**EXISTS / EXTEND / WIRE / NEW** against what the repository actually contains,
so nothing already built gets rebuilt.
**Audience:** platform owner + the engineers implementing the programme

## 0. Method and one structural correction

Every classification below was read out of source, not inferred. Where a prior
document of mine disagrees, this file wins and the correction is stated inline.

**Naming.** The target architecture names Forge / Concord / Fabric / Carbon /
Anchor / Forge AI as modules, with Concord as "regulatory intelligence and
mappings." **This repository is Concord**, and it already contains most of what
that diagram assigns to Carbon, Fabric, and Anchor. Splitting the tree along
those lines would itself be the duplication the brief prohibits, so the five
names are treated as **logical layers over the existing package**:

| Logical layer | Physical location today |
|---|---|
| Concord (regulatory intelligence) | `ccf/catalog`, `ccf/etl`, `ccf/oscal`, `ccf/packs` |
| Fabric (evidence) | `ccf/evidence`, `ccf/connectors`, `ccf/ingest`, `ccf/prep` |
| Carbon (assessment & assurance) | `ccf/assessment`, `ccf/governance`, `ccf/fedramp20x`, `ccf/scoring`, `ccf/analytics`, `ccf/assurance` |
| Anchor (identity & boundary) | `ccf/auth.py`, `ccf/identity`, `ccf/boundary` |
| Forge AI | `ccf/ai`, `ccf/ai_actions`, `ccf/ai_governance` |

No directories are created for these. The architecture is logical.

## 1. Platform inventory

~42k LOC of Python across 28 packages, 57 API route modules, 63 Jinja
templates, 66 Alembic migrations, 1527 passing tests.

### Services and engines

| Area | Location | Notes |
|---|---|---|
| Cross-framework catalog + mappings | `etl/frameworks.py`, `catalog/` | ~25 frameworks classified; `framework_mappings` crosswalks control→control |
| OSCAL catalog loader (sha256-pinned) | `catalog/oscal.py` | 800-53r5 + L/M/H baselines + CSF 2.0 |
| Catalog revisions (fetch/diff/adopt) | `catalog/revisions.py`, `catalog/diff.py`, `catalog/impact.py` | **Added 2026-09-14** (P0'), migration 0066 |
| Catalog currency poller | `etl/sources.py` | ETag + sha256 drift detection, `CatalogCheck` log |
| Catalog reconciliation (advisory) | `catalog/reconcile.py` | Identity, baseline, drift, dangling endpoints |
| OSCAL schema validation | `oscal/validation.py`, `oscal/schemas/` | Official NIST v1.1.2 schemas |
| Authorization package export | `packages/` | SSP+SAR+POA&M+component-definition, provenance, diff, replay |
| SSP authoring & generation | `ssp/` (2,170 LOC) | CMMC L2/800-171 docx, 800-53r5 docx, ODP parsing, completeness |
| Assessment engine | `assessment/engine/` | Objectives → retrieval → LLM verdict → dissent → human accept → SAR → POA&M |
| Evidence prep & retrieval | `prep/`, `evidence/` | Parsers, chunking, confidence scoring, reproducible digests |
| FedRAMP 20x | `fedramp20x/` (1,561 LOC) | KSI catalog, deterministic rule validation, readiness, dependencies, package |
| Continuous control monitoring | `governance/conmon.py`, `governance/control_tests.py` | `ControlTest`/`ControlTestResult`, scheduler-driven |
| Scan ingestion → POA&M | `ingest/scanners.py` | Nessus/Tenable, AWS Inspector, CSV/Qualys; idempotent reconciliation |
| Inheritance / shared responsibility | `governance/automation.py` | Profile-driven: applicable + inherited (platform **and** vendor) controls, SPRS, coverage, auto-POA&M |
| Risk register | `models.py:862`, `governance/risk.py` | System-scoped, likelihood/impact, `source_ref` traceable |
| TPRM | `governance/tprm.py`, `models_tprm.py` | Weighted CAIQ-lite questionnaire scoring, vendor register |
| AI governance | `ai_governance/` | Agent inventory, risk scoring, approval, monitoring, kill-switch |
| AI action layer | `ai_actions/` | Typed, citation-first, human-approved; full provenance |
| Assurance graph | `assurance/` | Authorization digital twin + impact analysis |
| Compliance packs runtime | `packs/` | Validated JSON manifests, per-tenant install, coverage, tests |
| Deterministic query layer | `queries/` | Typed, parameterized, reproducible; **no AI** |
| Analytics | `analytics/` | Org rollups, systems scorecard, POA&M aging, evidence freshness |
| Reporting | `reporting/` | xlsx + docx report builder |
| Self-assurance | `self_assurance/` | Concord continuously assessing itself |
| Reliability self-check | `reliability/` | DB, migrations, core services, 20x layer |
| External portal | `portal/` | Scoped, expiring, token-auth, audited access |

### Cross-cutting platform services

| Service | Location | State |
|---|---|---|
| Event bus + webhooks + notifications | `governance/bus.py` | Append-only `Event`, webhook fan-out, de-duplicated `Notification` |
| Outbound delivery | `governance/delivery.py` | Slack/Teams webhook, severity-gated, never raises |
| Alert digest | `governance/digest.py` | Portfolio sweep: ATO expiry, catalog drift, POA&M load, reviews due |
| Scheduler | `governance/scheduler.py` | In-app asyncio loop: drift poll, ConMon, digest, connector collection |
| Notification hub API | `api/routes/notifications.py` | Unified inbox across modules |
| Authentication | `auth.py` | Session cookie + bearer token; `session_version` revocation |
| Enterprise identity | `identity/`, `api/routes/identity.py` | **OIDC SSO + SCIM v2 provisioning** |
| RBAC / SoD | `auth.py`, `api/auth_deps.py` | `require_role(...)`, separation-of-duties on writes |
| Row-level security | migrations 0010/0020/0044/0064 | RLS on every tenant-owned table; `GLOBAL_TABLES` allowlist test |
| Audit hash-chain | `api/audit.py`, `models.py:1160` | `prev_hash`/`row_hash`; `record_event` is the only safe writer |
| Approvals | `governance/approvals.py` | Approval workflow |
| Tasks | `Task` model, `api/routes/tasks.py` | Internal remediation tasks |
| UI | 63 Jinja templates + `api/static` | Top-nav shell; shared partials `_charts`, `_controls_table`, `_scoring_score`, `_ssp_entry` |
| Workers | `docker-compose.yml` | `migrator`, `etl`, `poller`, `prep-worker`, `assessment-worker` |

### Integrations — actual state

| Provider | State | Evidence |
|---|---|---|
| Microsoft Graph / M365 / Entra | **Partial adapter** | `connectors/msgraph.py` — 6 ODP params, MFA + Conditional Access reads |
| AWS GovCloud | **Partial adapter** | `connectors/aws.py` — 6 ODP params, 2 real reads (EBS default encryption, CW log retention) |
| Azure / Azure Gov | **Vocabulary only** | `ConnectorConfig.connector_type` enumerates it; no adapter |
| GCP | **Vocabulary only** | Same |
| GitHub / Jira / ServiceNow | **Vocabulary only** | Same; no adapter |
| Slack / Teams | **EXISTS (outbound)** | `governance/delivery.py` webhook |
| Qualys / Nessus / Tenable / Inspector | **EXISTS (file ingest)** | `ingest/scanners.py` parsers |
| Okta | **Name only** | A string in `governance/automation.py`; no integration |
| Defender / Sentinel / Intune / Purview | **Name only** | Mentioned in connector `PARAMETER_MAP` prose; no reads |
| GitLab / CrowdStrike / Kubernetes | **Absent** | No occurrences |
| MCP | **Absent** | Zero occurrences anywhere |

**The key integration finding:** `ConnectorConfig.connector_type`
(`models_grc.py:203`) already enumerates
`azure|azure_gov|m365|m365_gcc_high|aws|aws_govcloud|gcp|github|jira|servicenow`.
The configuration surface, credential storage (`connectors/credentials.py`,
per-org, no global fallback), status tracking, and UI all anticipate these
providers. **Only the adapters are missing.** This is EXTEND, not NEW.

## 2. Capability classification

### 2.1 Common control graph — **EXTEND**

**Exists:** `framework_mappings` (control→control crosswalk, ~25 frameworks),
`Control`/`Framework`/`ControlFamily`, `catalog/canonical.py` +
`catalog/reconcile.py` for id normalization, `assurance/` graph with impact
analysis, `boundary/` components, `KSI.nist_refs`.

**Gap:** the crosswalk runs control→control. There is **no
capability→control edge**, and no component→control edge at all — so one
technical control cannot yet be declared once and reused across frameworks.
`Risk` (`models.py:862`) exists but is terminal: no edge downward.

**Action:** implement the Capability object and its edges — this is programme
item **P1**, whose design is already approved in outline. Store the **canonical
control id as a string** (as `SSPControlEntry.control_id` does), not an FK,
because the workbook-derived `controls` table and the OSCAL catalog genuinely
differ — that is why `reconcile.py` exists. Cross-framework reach resolves
through `canonicalize()` → `controls.identifier` → `framework_mappings` at
query time. **Concord's crosswalk stays the authoritative mapping source; no
second mapping table.**

**Verified traversal:** canonical `AC-2` → CMMC `AC.L2-3.1.2`, FedRAMP `AC-2`,
ISO `A.5.16`. Note `controls.identifier` is zero-padded (`AC-01`); the
canonical form is `AC-1`, so canonicalization is mandatory on this path.

New APIs requested map onto: `/api/controls/{id}/relationships`,
`/api/frameworks/{id}/coverage` (extends existing `api/routes/coverage.py`),
`/api/evidence/{id}/supported-controls`, `/api/controls/{id}/evidence`,
`/api/controls/{id}/findings`.

### 2.2 Evidence fabric — **EXTEND**

**Exists:** `Evidence` model, `evidence/` confidence scoring with reproducible
digests, `models_evidence.py` + `models_evidence_conf.py`, `prep/` parsers and
chunking, an evidence repository with pluggable backend (local / S3 with
optional Object Lock WORM), and **evidence freshness already computed**
(`analytics.evidence_freshness`, served at `/api/posture/evidence-freshness`).

**Gaps against the requested evidence object:** `Evidence.implementation_id`
parents evidence to a *(system, control)* `ControlImplementation`, so evidence
cannot attach to a capability or be shared across controls without duplication.
Absent fields: provider, connector, tenant/account, resource + resource type,
collection method, source timestamp (distinct from collected-at), refresh
interval, explicit freshness **state**. Freshness is computed ad hoc rather
than stored as `LIVE | CURRENT | AGING | STALE | EXPIRED` with per-type
thresholds.

**Action:** add the provenance/resource columns; add nullable `capability_id`
(the approved coexist posture — every existing `implementation_id` row keeps
working); promote freshness to a stored, configurable state. Append-only is
**partly** true already: the evidence repository is versioned and
content-addressed, but `CaptureSnapshot` (connector captures) has
`UniqueConstraint(organization_id, connector, odp_key)` and keeps **only the
latest value** — that one must become append-only or drift is unprovable.

### 2.3 Connector abstraction — **EXTEND**

**Exists:** `connectors/base.py` defines `ConfigConnector` — a
provider-neutral ABC with a registry (`get_connector`, `list_connectors`),
per-org credential resolution that explicitly refuses a global/env fallback,
and a `PARAMETER_MAP` so the UI can show what a connector *would* pull before
credentials exist. Compliance logic is **already decoupled** from provider
SDKs: boto3 is imported behind an availability check, Graph via `httpx`.

**Gap:** the contract's output is `CapturedParameter(odp_key, value, …)` — an
*ODP value*, not normalized evidence and not a posture verdict. Two adapters
exist (12 parameters total).

**Action:** do **not** create a new connector interface. Extend the existing
one with a second method returning normalized evidence/posture objects
alongside the existing `capture()`, then add adapters for the providers the
config vocabulary already names. Keep `credentials.py` as the only credential
path.

### 2.4 Autonomous control testing — **EXTEND**

**Exists:** `ControlTest`/`ControlTestResult` with `method='connector'`,
scheduler-driven auto-run, alert + remediation task on failure
(`governance/control_tests.py`); `fedramp20x/validation.py` — a **deterministic**
rule engine with a pure, unit-testable core and the verdict vocabulary
`pass | warn | fail | not_tested | manual_review_required | not_applicable`;
and the LLM assessment engine for objectives no check can reach, with a dissent
challenger that degrades rather than averages.

**So the deterministic/AI split the brief asks for already exists**, in the
right proportion, with the right vocabulary.

**Gap:** deterministic tests read `CaptureSnapshot` (last value, one scalar per
ODP key), so there is no resource-level evaluation ("47 evaluated, 3 failing"),
no expected-vs-observed, no time series. Rules are a thin JSON dialect rather
than portable validation-as-code.

**Action:** extend `ControlTestResult` for resource-level, append-only results;
express rules as versioned validation-as-code shipped through `packs/`; adopt
the explicit principle that **a deterministic result outranks a model verdict
whenever a check exists**.

### 2.5 Regulatory change intelligence — **EXTEND**

**Exists, and more than expected:** `etl/sources.py` polls registered
authorities with ETag + sha256, parses OSCAL, diffs per-control prose, logs
every poll to `CatalogCheck`, raises digest alerts on drift, and deliberately
does **not** auto-ingest. As of 2026-09-14 the P0' work adds retained
commit-pinned revisions, a full diff (controls, prose, parameters, baseline
membership), an impact report against this deployment's own systems and
authored content, and human-gated adoption.

**Gap:** sources cover NIST only. FedRAMP (`GSA/fedramp-automation`), CMMC,
800-171 r2, and the DISA CCI list are not registered. There is no
requirement-text-level change feed for non-OSCAL sources (CR26 rules, RFCs).

**Action:** register the remaining authorities through the existing
`DEFAULT_SOURCES` + `CatalogSource` registry using the `fmt`/`kind` dispatch
already present. No new subsystem.

### 2.6 Findings & remediation workflow — **EXTEND**

**Exists:** SAR findings from the assessment engine, `POAM` + `PoamMilestone`,
`Task`, `Risk` promotion from findings with `source_ref` idempotency,
`governance/approvals.py`, alerting via the bus, and
`governance/conmon.py`/`control_tests.py` auto-opening alerts and tasks on
failure.

**Closure loop — EXISTS (corrected 2026-09-14).** An earlier assessment of mine
listed "auto-opened Tasks and POA&Ms never close on a later pass" as an open
defect. It has since been fixed, exactly as resolve-or-propose:
`control_tests.py:270` `_resolve_on_recovery` handles the fail/warn → pass
transition, resolving the remediation Task (an internal work item with a free
status vocabulary) while deliberately **not** auto-closing the POA&M — closing
one asserts in an authorization package that a weakness is remediated, and a
single passing test is one observation. The POA&M instead gains a dated,
result-id-stamped note plus a notification so a human closes it through the
ISSM-08/09 gate. Deliberately asymmetric with `scanners.py:397`'s
scan-absence auto-close, and the reasoning is in the docstring. Covered by
`tests/test_control_test_recovery.py` and `tests/test_conmon_recovery.py`
(fail→pass, POA&M surfaced-not-closed, pass→pass no-op, human edits surviving
recovery, failure isolation).

**Action:** EXTEND — close the loop, add retest/closure, and relate findings to
capabilities and evidence.

### 2.7 POA&M automation — **EXTEND**

**Exists:** `ingest/scanners.py` reconciles scan findings into POA&Ms
deterministically and idempotently (re-ingest is a no-op, improvement
auto-closes, regression reopens); `automation.py` generates POA&M placeholders
for profile-derived gaps; aging analytics.

**Gap:** SLAs come from a flat `SEVERITY_SLA_DAYS` map keyed on normalized
severity. No exploitability / internet-reachability / data-impact factors, no
EPSS, no CISA KEV, no asset-owner attribution. No VDR/VER (LEV/IRV/PAIN)
anywhere. Under CR26 the FedRAMP lane replaces POA&Ms with **Accepted
Weaknesses** — a second deliverable profile, not a migration (Rev5 runs to at
least 2028-12-31, and CMMC/DoD are unaffected).

### 2.8 MCP gateway — **NEW**

**Zero MCP presence.** But the foundation is unusually good: `queries/` is a
registry of typed, parameterized, tenant-scoped, reproducible queries with no
AI — precisely the shape a tool surface wants — and RLS + RBAC/SoD + the audit
hash-chain supply the safety envelope.

**Action:** NEW server, but **generated from `queries/registry.py`** plus
selected read endpoints rather than hand-written tools. Writes route through
the existing `ai_actions` / approvals gate; every tool call audited. Do not
build a parallel read API.

### 2.9 AI GRC agents — **EXISTS / WIRE**

**Exists:** `ai/` gateway with providers, `ai_actions/` (typed, citation-first,
human-approved, full provenance: model, prompt version, input/output SHA-256,
cited units), `ai_governance/` (non-human actor inventory, risk scoring,
approval, monitoring, incidents, kill-switch), `governance/ai.py`,
`api/routes/ai_agents.py` + `ai_settings.py`, and the assessment engine's
dissent path. AI-drafted SSP narrative always carries `DRAFT_PREFIX` until a
human clears it.

**Action:** mostly **WIRE** — expose these agents through the MCP gateway
(2.8) and give them the capability graph (2.1) to reason over. The governance
and provenance rails already exist and must be reused, not re-invented.

### 2.10 Shared responsibility & inheritance — **EXTEND**

**Exists, and this was missed in earlier analysis:** `governance/automation.py`
derives, from a `SystemProfile`, which controls are *applicable*, which are
*inherited from the cloud platform*, and which are *inherited from each linked
vendor* — plus SPRS score, coverage rollup, and POA&M placeholders for gaps.
Pure function of profile + vendor register, idempotent, snapshot is the single
source SSP and coverage read. `FedRAMPDependency` tracks authorized
dependencies for 20x.

**Gap — corrected 2026-09-14.** Inheritance *is* expressed in SSP narrative:
`ssp/statements.compose` handles inherited/shared/customer responsibility,
names the provider, carries a CRM reference, and refuses to claim retained
evidence without one (FR-11). `governance/automation.py:545` supplies that
reference from `vendor.authorization`. What is genuinely missing is CRM
*document* generation — the reference is a string, not a produced matrix — and
narrative authored once on a capability rather than re-derived per control.

**Action:** EXTEND into the document layer (programme item P4). The derivation
engine itself is done.

### 2.11 Third-party risk management — **EXISTS**

`governance/tprm.py` (weighted CAIQ-lite scoring, pure function, gap flagging),
`models_tprm.py`, vendor register, `api/routes/vendors.py` +
`questionnaires.py`, vendor review alerts in the digest, and vendor-inherited
controls in `automation.py`.

**Action:** **EXISTS.** Only wiring: relate vendors to capabilities and
inherited responsibilities once 2.1 lands. Build nothing new.

### 2.12 AI governance — **EXISTS**

See 2.9. `ai_governance/` covers inventory, risk scoring, approval workflow,
monitoring events, incidents, and kill-switch, each audited. **Build nothing
new.**

### 2.13 Trust Center — **EXTEND**

**Exists:** `portal/` — scoped, expiring, token-authenticated, fully-audited
external access for customers, assessors, and vendors with no internal
account.

**Gap:** no *public* trust page publishing current control state, KSI results,
and evidence freshness without a token.

**Action:** EXTEND `portal/` with a public, read-only, cached projection.
Reuse the portal token model and audit path; do not build a second external
access mechanism.

### 2.14 Analytics / API access layer — **EXISTS / EXTEND**

`analytics/` (org summary, systems scorecard, POA&M aging, evidence freshness),
`api/routes/posture.py` (**note: this is *compliance* posture — internal
rollups. The name is taken; security posture needs its own namespace**),
`queries/` deterministic exportable queries with CSV export, `reporting/` xlsx
+ docx, 57 route modules with OpenAPI at `/docs`, `api/routes/diff.py` and
`events.py`.

**Action:** EXTEND with capability-graph and posture endpoints. The access
layer itself exists.

### 2.15 Continuous assurance scoring — **EXTEND**

**Exists:** `scoring/` (CMMC SPRS engine — pure functions, live per-system),
`fedramp20x/readiness.py`, `ssp/completeness.py`, `analytics/` rollups,
`evidence/` confidence scoring, `assessment/engine/calibration.py`.

**Gap:** no single composite assurance score across validation coverage,
evidence freshness, vulnerability performance, configuration integrity,
identity assurance, change governance, and logging coverage — and, more
importantly, no **validation-source split** (automated / semi-automated /
manual). That split is what makes "drive manual validation toward zero"
measurable and is the number that separates this from a questionnaire tool.

**Action:** EXTEND by composing the existing scorers. Write no new scorer.

### 2.16 Evidence freshness — **EXTEND**

Computed today (`analytics.evidence_freshness`) but not a stored, configurable
state. See 2.2.

### 2.17 FedRAMP 20x / KSI validation — **EXISTS / EXTEND**

**Exists:** `fedramp20x/` — KSI catalog seeded from
`data/fedramp_20x_ksi_catalog.json` (idempotent upsert on `identifier`),
deterministic rule validation with append-only history and per-system KSI
state, readiness scoring, authorized-dependency tracking, assessor review, and
a machine-readable package foundation. KSIs stay traceable to 800-53 through
`nist_refs`.

**Source-hierarchy constraint (must be preserved):** there is **no official
FedRAMP 20x OSCAL package**. The OSCAL Foundation's Phase One KSI catalog is
community-maintained and **must not** become the system of record. FedRAMP
provides the requirements; NIST provides OSCAL (`usnistgov/OSCAL`, distinct
from `usnistgov/oscal-content`); Concord generates its own OSCAL. The existing
code already takes this posture and its docstring disclaims official OSCAL
output — preserve it.

**Gap:** CR26 (in force 2026-07-04, **enforced 2027-01-01**) renames
authorization→Certification, replaces Impact Levels with Certification Classes
A–D, replaces the SSP with CPO + SDR in JSON, and **eliminates POA&Ms in favour
of Accepted Weaknesses**. Registered as **FR-14** in the 2026-07-21
terminology review and deferred there as "non-breaking, pre-2027-01-01"; that
deferral should now be lifted. The Class↔impact mapping remains **unvalidated
at source** and no schema change may depend on it until it is.

### 2.18 VDR — **NEW (on existing rails)**

No VDR/VER, LEV/IRV/PAIN anywhere. Scan ingestion, POA&M reconciliation,
severity SLAs, and aging analytics all exist to build on. Needs EPSS/KEV/CVSS
enrichment, asset-owner attribution, risk-factor SLAs, and the VDR surface.

### 2.19 Significant change notification — **NEW**

Nothing detects environment change, classifies boundary impact, or produces an
SCN. Building blocks exist: `boundary/` (authorization boundary + inventory),
`assurance/` (impact analysis over the authorization graph), `governance/bus.py`
(events), `governance/scheduler.py`. Missing: change ingestion (config/event
streams, IaC apply, deployment pipelines), a classifier
(boundary-impacting? security-impacting? SCN required?), and an SCN object with
review/approve/generate workflow. Valuable beyond FedRAMP — the same engine
answers "what did this change break in my authorization" for CMMC and RMF.

## 3. Summary

| Capability | Status |
|---|---|
| Common control graph | **EXTEND** |
| Evidence fabric | **EXTEND** |
| Connector abstraction | **EXTEND** |
| Autonomous control testing | **EXTEND** |
| Regulatory change intelligence | **EXTEND** |
| Findings & remediation workflow | **EXTEND** |
| POA&M automation | **EXTEND** |
| MCP gateway | **NEW** (generated from `queries/`) |
| AI GRC agents | **EXISTS / WIRE** |
| Shared responsibility & inheritance | **EXTEND** (engine exists; document layer missing) |
| Third-party risk management | **EXISTS** |
| AI governance | **EXISTS** |
| Trust Center | **EXTEND** (`portal/`) |
| Analytics / API access layer | **EXISTS / EXTEND** |
| Continuous assurance scoring | **EXTEND** (compose existing scorers) |
| Evidence freshness | **EXTEND** (exists as computation, not state) |
| FedRAMP 20x / KSI validation | **EXISTS / EXTEND** (CR26 delta) |
| VDR | **NEW** (on existing rails) |
| Significant change notification | **NEW** |

**Nothing in the requested set is wholly absent except MCP, VDR, and SCN.**
Two of those three build directly on existing rails. Everything else extends
or wires what is already here — which is why Phase 1 mattered: earlier analysis
of mine wrongly called the catalog fetcher, OIDC SSO, and SCIM missing, and all
three exist.

## 4. Corrections to prior documents

`docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md`
contains three errors this inventory supersedes:

1. **"No fetcher; refresh is manual."** False — `etl/sources.py` polls with
   ETag + sha256 and diffs OSCAL prose. Corrected in that document's G3.
2. **"No SSO/SCIM."** False — `identity/` and `api/routes/identity.py`
   implement OIDC SSO and SCIM v2.
3. **"A KSI is a Capability."** Imprecise. FedRAMP designed KSIs as
   capability-*shaped requirements*; they sit on the **requirement** side with
   controls. A Capability *satisfies* KSIs. The payoff is that KSIs map to
   capabilities roughly 1:1 where controls fragment one capability across many.

## 5. Phase 1 gate

Discovery is complete for the capabilities listed in the brief. Implementation
of any capability classified NEW or EXTEND should proceed only through its own
design and plan, in the sequence already agreed: **P0' (done) → P1 capability
graph → P2 validation/posture → P4 document layer**, with connectors and
STIG/SCAP parallel, then Trust Center + scoring, MCP, and the CR26/SCN work.

Phases 6 and beyond of the brief were truncated in transmission and are not
covered here.

---

# 6. Continuous Configuration & Enforcement (CC&E) — Phase 1 discovery

Added 2026-09-14, answering the Principal Cloud Architect directive's Phase 1
(repository discovery + capability matrix) for the Puppet-*inspired* continuous
configuration capability. It is a section of this document rather than a second
inventory, because a parallel capability matrix is precisely the duplication the
directive's own rule forbids — sections 1–5 above already classify 19
capabilities, several of which CC&E is asking about under different names.

**Scope discipline, stated once.** The directive says Puppet-inspired, not
Puppet. Concord is not becoming a configuration-management agent: no node
catalog compiler, no agent/daemon on managed hosts, no resource DSL, no MCollective
equivalent. What is architecturally borrowed is the *loop* — declare desired
state, observe actual state, compute drift, converge, record what happened —
applied to **cloud control-plane configuration assessed against a compliance
baseline**, which is a different problem than converging a Linux host.

## 6.1 What already exists (and must not be rebuilt)

| CC&E ask | Status | Where it already lives |
|---|---|---|
| Continuous execution loop | **EXISTING** | `governance/scheduler.py` — an asyncio cycle running catalog drift poll, ConMon scan, digest, and connector collection; GLOBAL vs PER-TENANT jobs with the tenant clamped per iteration so RLS backstops app-layer scoping |
| Provider abstraction | **EXISTING** | `connectors/base.py:ConfigConnector` — `capture()` / `verify()` / `scan()`, per-org credentials, `PARAMETER_MAP` advertising intended coverage |
| Policy-as-code packaging | **EXISTING (format only — see correction below)** | `packs/` — JSON manifests, validate/install/coverage/`run_tests`, written only under the installing tenant |
| Check registry (the rules themselves) | **EXISTING** | `posture/checks.py:CHECK_REGISTRY` + `posture/providers/m365.py` — declarative checks with `required_permissions`, per-resource findings |
| Assessment result spine | **EXISTING** | `ControlTestResult` via `governance/control_tests.py:record_result` — append-only time series, and the **only** writer (alerting, POA&M, recovery, events all hang off it) |
| Findings → remediation workflow | **EXISTING** | `governance/reactions.py` + POA&M auto-close; §2.6, §2.7 above |
| Config-drift baseline (parameter level) | **EXISTING** | `CaptureSnapshot` (`models.py:1555`) — "the config-drift baseline" for ODP values |
| Evidence binding + replay drift | **EXISTING** | `evidence/`, `evidence/confidence.py`, `models_packages.py` (`reproducible\|drifted\|missing`) |
| Audit trail | **EXISTING** | `ccf.api.audit.record_event` — SHA-256 `prev_hash`/`row_hash` chain; a hand-built row silently breaks tamper-evidence |
| RBAC | **EXISTING** | `api/auth_deps.py:require_role` |
| Telemetry export | **EXISTING** | `api/metrics.py` (Prometheus) |
| OSCAL integration | **EXISTING** | `catalog/`, `oscal/`, `ssp/` — and P0′ adds live revisions with baseline diff/adopt |
| Change-impact analysis | **EXISTING, different subject** | `catalog/impact.py:build_adoption_impact` (catalog revision → affected mappings), `governance/automation.control_impact` (control → score delta) |
| Compliance graph | **EXISTING** | P1 capability ontology + `framework_mappings` crosswalk; `capability/service.framework_reach` traverses it |

## 6.2 Capability matrix — the CC&E-specific asks

| # | Capability | Verdict | Reasoning |
|---|---|---|---|
| 1 | **Desired-state declaration** | **NEEDS EXTENSION** | Expectation today is encoded *in check code* (`evaluate_mfa_registered`), not declared per organization as versioned data. CC&E needs a first-class, org-owned, diffable target state. The extension point is `packs/` (already a validated manifest format) plus `posture/checks.py` parameterization — not a new format. |
| 2 | **Drift detection at resource level** | **NEEDS EXTENSION** | Three drift notions exist (catalog source, evidence replay, captured parameter). Missing: *this resource's observed configuration versus its declared desired state, over time*. `ResourceFinding` already carries expected-vs-observed per resource; what is missing is retention and comparison across scans (the pending P2c snapshots/retention work). |
| 3 | **Closed-loop remediation — decide** | **EXISTING / WIRE** | `ai_actions/` already implements typed actions, citation requirements, human approval, and a declared `allowed_mutation` applied only after approval. CC&E's decision loop should be an action type here. |
| 4 | **Closed-loop remediation — enforce** | **MISSING, and gated** | Every connector is **read-only**. Writing into a customer's GCC High / Azure Gov tenant is a different risk class than anything Concord does today, and it is the one CC&E capability that can cause an outage in a system under authorization. See §6.4 — this must not be built as a side effect of the loop. |
| 5 | **Configuration timeline** | **NEEDS EXTENSION** | `ControlTestResult` is already append-only and time-series (this is why P2 shrank from five pieces to three), and `AuditLog` is hash-chained. Extend retention/query, do not add a second history table. |
| 6 | **Change-impact analysis for config changes** | **NEEDS EXTENSION** | `catalog/impact.py` answers this shape of question for catalog revisions. The same pattern — enumerate affected endpoints, refuse when impact is unresolvable — applied to a proposed configuration change. Reuse `check_mapping_endpoints`, `roll_up`, and `capability/service` rather than a new traversal. |
| 7 | **Patch orchestration** | **MISSING** | No patch/update orchestration anywhere (every `patch` hit is HTTP PATCH or a parser). Genuinely new, and it depends on #4's write path, so it inherits that gate. |
| 8 | **Exception / waiver management** | **NEEDS EXTENSION** | `KSIException` (`models.py:1775`) already models a documented deviation with rationale, status, linked risk, and `expires_on` — but **only for a KSI**. CC&E needs the same object against a check, a control, or a resource. Generalize that table; do not create a parallel waiver. A waiver must also suppress **one** thing — the finding — without suppressing the evidence that the drift occurred. |
| 9 | **PuppetDB / CMDB connector** | **MISSING (optional)** | A read-only inventory source implementing `ConfigConnector`. Cheap once #1–#2 exist; no reason to build first. Explicitly optional in the directive. |
| 10 | **GitOps flow** | **MISSING** | Packs load from disk or a path, not from a git-backed desired-state repo with PR review. Depends entirely on #1 — there is nothing to put in git until desired state is declarative data. |
| 11 | **Telemetry for drift/convergence** | **NEEDS EXTENSION** | `api/metrics.py` exports app metrics; per-check drift and convergence counters are additions to it. |
| 12 | **AI assistant extension** | **EXISTING / WIRE** | `ai_actions/` + the planned MCP gateway (§2.8). Nothing new. |

**Count: 2 EXISTING/WIRE, 6 NEEDS EXTENSION, 4 MISSING** — of which one (#4) is
gated and two (#7, #10) depend on a gated or unbuilt prerequisite.

## 6.2a Correction — the declaration format has no reader

Found while designing #1: **`PackRule` is written by `packs/service.install_pack`,
deleted on upgrade, and never read by anything.** Three bundled packs declare
`rules` entries that no code evaluates. Searching `src/ccf` for `PackRule` or
`pack_rules` returns only the install path.

So §6.1's "policy-as-code packaging — EXISTING" is true of the *packaging*
(validated, versioned, tenant-scoped, audit-logged, atomically replaced on
upgrade) and false of the *runtime*. Symmetrically, `posture/checks.py` has a
working runtime whose rules are hardcoded Python, so declaring a new expectation
needs a code release and every tenant gets the same thresholds.

This makes #1 smaller and better-shaped than first classified: not "design a
desired-state subsystem" but **bridge a validated declaration format to a
working evaluation runtime**. Spec:
`docs/superpowers/specs/2026-09-14-declared-posture-checks-design.md`. It is
also exactly programme item P2b, and `posture/checks.py`'s own docstring already
anticipated it — *"the registry is deliberately the same shape as
`etl.sources.DEFAULT_SOURCES` so P2b's move into `packs/` relocates content
rather than redesigning it."* Building CC&E #1 as a new subsystem would have
forked P2b.

## 6.2b Status — #1 is built (2026-09-14)

Capability #1 (desired-state declaration) is **implemented and verified**, which
also completes programme item P2b. `PackRule` has a reader.

A tenant declares a posture check in a pack manifest in one of two forms: **Form
A** parameterizes a platform evaluator (the platform keeps logic that needs a
clock or real arithmetic; the tenant supplies the threshold), and **Form B**
supplies a closed, fail-closed predicate for the genuinely declarative shapes.
Validation refuses anything unevaluable at install, so a pack that installs can
be scanned. Each pack version's manifest is now retained, so a desired-state
change is diffable — which is what #6 (change impact) and the
configuration-timeline ask needed for *desired* state.

Spec `docs/superpowers/specs/2026-09-14-declared-posture-checks-design.md`,
plan `docs/superpowers/plans/2026-09-14-declared-posture-checks.md` (results
section carries the mutation-testing outcome and one deferred finding).

Revised matrix rows: **#1 EXISTING**; **#6 partially satisfied** for desired
state (observed-state change impact still open); **#11** unchanged.

## 6.2c Status and correction — #8 is built, and my classification was wrong (2026-09-15)

Capability #8 (exception/waiver management) is **implemented and verified**.

§6.2 classified it "NEEDS EXTENSION — generalize `KSIException`". That was
wrong, and the reason matters. `fedramp20x/readiness.py` counts `KSIException`
rows with `status == "open"` into `Readiness.open_exceptions`, a **detractor**
surfaced in the readiness payload and the authorization package. It suppresses
nothing — it is a *disclosure*. What #8 needed was the opposite effect: stop
the operational consequence of an accepted finding. Conflating the two would
fail in both directions, so `Waiver` is a distinct mechanism and `KSIException`
is untouched.

The whole design is one invariant: **a waiver changes what happens next, never
what was observed.** A fail stays `fail`, every per-resource verdict and
observation stays, `last_status` stays, `effective_verdict` still reports
`fail`. Exactly one thing is suppressed — the `_alert_on_failure` call — and
only when *every* failing resource is covered. The result records `waived` and
each accepted resource records its `waiver_id`, so a waiver leaves a **stronger**
record than an unwaived failure.

Spec `docs/superpowers/specs/2026-09-15-waivers-design.md`, plan
`docs/superpowers/plans/2026-09-15-waivers.md` (results carry the mutation
outcome and two findings deliberately not fixed).

Revised matrix row: **#8 EXISTING**. This also answers the P2b finding that two
checks can now cover one control and disagree — a waiver is how one of them is
accepted, though *which* verdict wins for a control remains open (see the P2b
plan's results).

## 6.2d Status — #2 is built, and it found a shipped bug (2026-09-15)

Capability #2 (drift detection at resource level) is **implemented and
verified**, which also completes programme item P2c.

Designing it surfaced a defect in shipped, operator-facing code:
`GET /api/posture/failing-resources` documented itself as returning resources
*currently* failing but returned every resource that had ever failed, with the
stale `observed` text from the scan that found it broken. The cause is the gap
#2 exists to close — `0068` made the resource table append-only history, which
was right, but nothing since gave the platform a notion of *latest*, and read
as current state an append-only table answers a different question. Fixed with
one shared definition (`posture/latest.py`) that every current-state read
joins.

Drift itself has five kinds, two of which existed nowhere before: **appeared**
separates a resource entering scope already failing from one that regressed,
and **disappeared** catches a resource that was deleted, left scope, *or whose
collection silently truncated* — which until now read as an improvement.
Retention keeps every `ControlTestResult` forever and windows only the
per-resource detail, exempting the latest result at any age and any row a
waiver covered.

Spec `docs/superpowers/specs/2026-09-15-resource-drift-design.md`, plan
`docs/superpowers/plans/2026-09-15-resource-drift.md`.

Revised matrix rows: **#2 EXISTING**; **#5 (configuration timeline) satisfied
for observed state** by `resource_timeline`, alongside P2b's `packs/diff.py`
for desired state.

## 6.2e Status — #6 and #11 are built (2026-09-15)

Both **implemented and verified**.

**#6 change impact** (`packs/impact.py`, `GET /api/packs/{key}/impact`) answers
what adopting a desired-state change would affect here, in the shape
`catalog/impact.py` established for catalog revisions. Two of its four findings
are consequences nobody would think to look for: a removed rule leaves a
generated `ControlTest` to retire — reported with its *current* status, since
retiring a failing check is a different decision from retiring a passing one —
and it leaves any waiver keyed on that check **orphaned**, a formal acceptance
of a finding that can no longer be produced.

**#11 telemetry** adds five posture metrics. One constraint shaped every label:
bound the cardinality. No resource or check label anywhere — a fleet of 10,000
users would otherwise put 10,000 series into Prometheus from one check — and
the rule is enforced by a structural test over `POSTURE_METRICS` rather than by
reviewer memory. Drift is counted during a scan, never in the drift endpoint,
because a counter incremented by a read double-counts dashboard refreshes.

Spec `docs/superpowers/specs/2026-09-15-config-change-impact-and-telemetry-design.md`,
plan `docs/superpowers/plans/2026-09-15-config-impact-and-telemetry.md`.

Revised matrix rows: **#6 EXISTING**, **#11 EXISTING**.

**Remaining CC&E work:** #10 GitOps (needs desired state in git, now that it is
data), #4 enforcement behind the §6.4 gate, then #7 patch orchestration and
#9 PuppetDB — both optional and downstream of #4.

## 6.2f Status — #10 is built (2026-09-15)

**Implemented and verified.** A tenant registers a repository that declares its
desired state; the platform polls it on the scheduler's per-tenant cycle,
reports what adopting the change would do (#6), and installs only when told.

**No git client was added, and that is the design.** Three of GitOps' four
properties already had machinery: P2b made desired state data, `etl/sources.py`
polls with conditional fetch plus a content sha, and `resolve_commit_sha`
already resolves a raw URL to the commit that last touched it. A manifest is a
file, so a raw URL plus that commit sha is the whole of git's contribution —
where shelling out to `git` would mean SSH credentials, a working tree and a
clone cache inside a product that runs in GCC High. The *functions* are reused;
the table is not, because `catalog_sources` is global reference data and a
tenant's repository is its own.

**Detection is automatic; adoption is not.** `auto_install` defaults to False,
mirroring `CatalogSource.auto_ingest` and for a stronger reason: a pack rule
executes against a customer tenant, so a platform that silently changed what it
asserts because someone merged a PR would have an SSP that no longer describes
a reviewed decision. This is deliberately not pure GitOps convergence.

`divergence` answers the question GitOps exists for, and `diverged` is the state
nobody asks for: a manifest installed through the API while a source is
configured — how a deployment quietly stops matching its own repository.

Spec `docs/superpowers/specs/2026-09-15-gitops-pack-sources-design.md`, plan
`docs/superpowers/plans/2026-09-15-gitops-pack-sources.md`.

Revised matrix row: **#10 EXISTING**.

**Remaining CC&E work is all downstream of the §6.4 enforcement gate:** #4
enforcement (its own spec — write-scoped opt-in credentials, plan-then-apply,
blast-radius limits, reversal data), then #7 patch orchestration and #9
PuppetDB, both optional and dependent on #4. Everything buildable read-only is
now built.

## 6.3 DUPLICATIVE — asks that must be refused as specified

Recording these explicitly, because each is a plausible-sounding new subsystem
that would fork something load-bearing:

- **A CC&E-specific findings table.** `record_result` is the only writer of
  `ControlTestResult`, and alerting, POA&M creation, recovery-resolution and
  event emission all hang off it. A second finding path would produce drift
  that never becomes a POA&M and recoveries that never close one.
- **A CC&E scheduler.** `governance/scheduler.py` already has the tenant-clamping
  and global-versus-per-tenant distinction that took real care to get right.
- **A CC&E evidence store, audit log, RBAC layer, or connector base class.**
  All four exist; a second audit log in particular breaks the hash chain's
  meaning.
- **A second desired-state/policy format alongside `packs/`.** One manifest
  format, extended.
- **An LLM that decides compliance verdicts.** Deterministic-check-wins is
  already the platform's rule; CC&E does not get an exception to it.

## 6.4 The one architectural gate: enforcement is not just another connector method

Read and write are not symmetric here. A read-path bug produces a wrong
verdict, which review catches. A write-path bug reconfigures a production
federal system — potentially one mid-authorization, where an unplanned
configuration change is itself a reportable significant change (the SCN
problem §2.19 exists to model).

So enforcement must not arrive as `ConfigConnector.enforce()`. It needs, at
minimum: separate write-scoped credentials that an org opts into per provider;
plan-then-apply with the plan persisted and diffable before anything executes;
human approval reusing `ai_actions`' approval path rather than a new one;
blast-radius limits (a change touching N resources refuses rather than
proceeds); full reversal data captured before mutation; and every applied
change recorded through `record_event` **and** as a candidate significant
change. That is a sub-project with its own spec, not a task inside the drift
loop.

## 6.5 Recommended sequencing

1. **#1 desired state** (extends `packs/`) — nothing else is coherent without it.
2. **#2 resource drift over time** — merges with the already-planned P2c
   snapshots/retention rather than competing with it.
3. **#8 generalized waivers** — needed before drift reporting is usable, or
   every accepted risk reads as an open finding forever.
4. **#6 change impact** + **#11 telemetry** — cheap, on existing rails.
5. **#10 GitOps** — only once #1 is data.
6. **#4 enforcement** — its own spec, its own gate, after everything above has
   been operating read-only long enough to trust the drift signal.
7. **#7 patch orchestration** and **#9 PuppetDB** — last; both are optional and
   downstream.

This ordering deliberately puts the capability the directive emphasizes most
(closed-loop enforcement) late, because acting on a drift signal that has never
been validated read-only is how a compliance tool causes an incident.
