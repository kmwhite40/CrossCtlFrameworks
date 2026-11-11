# GRC program build-out — design

2026-10-20. Builds every navigation entry the redesign left `partial` or
`planned` (`ccf/api/navigation.py`) into a working capability, on the schema
added by migration `0099_grc_program` (`ccf/models_program.py`, plus
`Risk.likelihood_score/impact_score` and `System.business_unit_id`).

Seven workstreams run in parallel, each on its own branch and its own test
database. **No workstream changes the schema.** If one needs a column it does
not have, it stops and reports; the integrator owns migrations.

## Rules every workstream follows

These are the defects this codebase has shipped before. Each is a requirement.

1. **Tenant scope is explicit in every query.** Use `_principal_org(request)`
   (`api/routes/ui.py`) in pages and `principal.org_id` in API routes. Tables
   without `organization_id` scope through a **live** system:
   `posture.org_system_subq(org)` (excludes soft-deleted systems). Every new
   table has its own `organization_id`; filter on it.
2. **Writes are role-gated and audited.** Every POST/PUT/PATCH/DELETE uses
   `Depends(require_role(...))` (`api/auth_deps.py`): `admin` for
   configuration and decisions, `admin`/`control_owner`/`assessor` for
   records people maintain, as each workstream says. Viewers are already
   refused by middleware; do not add anything to `_VIEWER_WRITE_ALLOWLIST`.
   Call `record_event(...)` (`api/audit.py`) for each write, as the existing
   routes do. A write never trusts an id from the body for ownership: look
   the record up, check its `organization_id` equals the caller's, else 404.
3. **Separation of duties where the spec says so**: the person who proposed
   or prepared a record cannot approve or finalise it (compare
   `principal.email`/`user_id`, refuse with 403 and a message saying why).
4. **A ratio over nothing is `None`**, rendered `—`, never 0% or 100%. A
   label must not claim more than its computation: name the denominator in
   the text or the tooltip, and test that the parts sum when they should.
5. **Never fabricate.** No sample data, no seeded demo rows, no computed
   value standing in for a recorded one. An empty state says what is missing
   and how to add the first record.
6. **Pages extend `base.html`** and pass `"active": "<key>"` where `<key>` is
   the navigation key listed for the page below. Use the existing classes:
   `card`, `panel`, `panel__head`, `table-wrap`, `chip chip--ok|warn|err|info|ghost|brand`,
   `kpi-grid kpi-grid--4`, `kpi`, `feed`, `empty-state`, `btn btn--primary|secondary|ghost|sm`,
   `input`, `select`, `field-group`, `label`, `filters`. Charts use the
   macros in `templates/_viz.html`. No inline colours: tokens only
   (`tests/test_ui_shell.py` fails undefined CSS variables and classes).
   Forms post with a normal `<form method="post">` (CSRF is Origin-based
   middleware; nothing to add) and redirect with 303 on success.
7. **No schema changes, no edits outside your files list.** Shared files are
   integrated by the integrator: `navigation.py`, `governance/scheduler.py`,
   `api/main.py`, `models*.py`, `migrations/`. If you need a scheduler step,
   expose an `async def ...(session, org_id, today)` function and name it in
   your report.

## Testing every workstream delivers

- One test module per workstream: `tests/test_<workstream>.py`.
- **Isolation on an RLS-bypass session**: copy the `_unscoped_session`
  override and two-org scene pattern from
  `tests/test_command_center_and_modules.py`. Assert the other org's records
  never appear **and** the caller's own do.
- **Role gates**: a viewer and a role outside the gate get 403 on each write;
  the permitted role succeeds.
- **SoD**: the preparer/proposer cannot finalise/approve.
- **Mutation check**: after the tests pass, delete each org predicate and
  each role/SoD guard you wrote, one at a time, and confirm a test fails;
  restore it. Report any that survive and the test you added.
- Run tests only through your own `t.sh` (it targets your own database).
  Never run the full suite. Pass an explicit timeout (e.g. 900000 ms) to any
  pytest call. Do not use the browser tools (one browser is shared).
- Before reporting: `ruff check` and `ruff format` on the files you touched,
  run `tests/test_ui_shell.py` and your own test module, commit on your
  branch with a message ending `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Workstreams

### A — history: posture history, compliance trends, risk forecasting
Files: `analytics/posture_history.py`, `api/routes/ui_history.py`,
`templates/trends.html`, `templates/forecast.html`; may edit
`analytics/command_center.py` and `templates/command_center.html` only to add
a "Posture over time" tab to the existing Trends panel; `cli.py` to add a
`posture-snapshot` command (append at the end of the file).
- `capture_snapshot(session, org_id, *, today, source)` upserts the day's
  `PostureSnapshot` from `command_center(...)`: controls passing/judged,
  findings open by severity, risks by band, remediation resolved/remediable,
  overdue, per-framework addressed/total, SPRS average (`org_summary`),
  evidence, monitoring. Same day = replace (one row per org per day).
- `/trends` (key `trends`): each metric as a series over recorded days, with
  the date range and number of snapshots; fewer than two snapshots says so.
  `POST /trends/capture` (admin) records today's snapshot now.
- `/forecast` (key `forecast`): least-squares linear projection of open
  POA&Ms, failing controls and open risks from snapshots. Requires at least
  4 snapshots spanning 14+ days, else says why it will not project. Never
  projects beyond 90 days; shows the slope, the fit (R²) and the projected
  date the backlog reaches zero only if the slope is negative. Labelled as a
  projection from recorded history, not a prediction.
- Expose `capture_all(session, today)` for the scheduler.

### B — risk: five-point scale, appetite, KRIs
Files: `governance/risk.py`, `governance/kri.py`, `api/routes/risks.py`,
`api/routes/ui_riskprog.py`, `templates/risks.html`, `templates/risk_heatmap.html`,
`templates/risk_appetite.html`, `templates/kri.html`, `templates/_viz.html`
(the `riskgrid` macro only); in `api/routes/ui.py` only the `risks_page`
function; in `api/routes/ui_modules.py` only `risk_heatmap`; in
`analytics/command_center.py` only `risk_matrix` and `RISK_LEVELS`.
- Five-point scale: `likelihood_score`/`impact_score` 1-5 are the source of
  truth; the three-level enums stay in step (1-2 low, 3 moderate, 4-5 high;
  low→1, moderate→3, high→5 when only a level is given). `compute_scores`
  uses the scores. API create/update accept either form and validate 1-5.
  The risk form uses 1-5 selects with labels (Rare, Unlikely, Possible,
  Likely, Almost certain / Negligible, Minor, Moderate, Major, Severe).
- Heat map 5×5 on the command center and `/risks/heatmap`, drill-down by
  `?l=&i=` (keep accepting the old `likelihood=`/`impact=` level params).
  Zone = `band(l*i)`.
- `/risk-appetite` (key `kri` is the KRI page; appetite lives on it or at
  `/risk-appetite` with key `risk_appetite`): statements per category with a
  default (NULL category), admin-only writes, and **breaches**: open risks
  whose residual score exceeds their category's (or the default) appetite.
- `/kri` (key `kri`): KRIs with latest reading, status against warn/critical
  thresholds respecting `direction`, readings history (sparkline). Create/edit
  (admin, control_owner), record a manual reading, "compute now" for KRIs with
  a `metric_key`. `governance/kri.py` holds the registry of computed metrics:
  open critical+high POA&Ms, overdue POA&Ms, failing controls (count),
  controls-passing ratio, expired evidence, risks above appetite. Expose
  `record_computed_readings(session, org_id)` for the scheduler.

### C — govern: organization structure and governance bodies
Files: `governance/org_structure.py`, `api/routes/ui_govern.py`, templates
`org_units.html`, `teams.html`, `committees.html`, `committee_detail.html`,
`objectives.html`, `objective_detail.html`, `org_settings.html`.
- `/org-units` (key `org_units`): business-unit tree, CRUD (admin), assign
  live systems to a unit (sets `System.business_unit_id`; system must be in
  the caller's org), counts of systems per unit. No cycles in `parent_id`.
- `/teams` (key `teams`): teams, members (users of the same org only), lead.
- `/committees` (key `committees`) and `/committees/{id}`: charter, cadence,
  chair, members, meetings with minutes, attendees (members of the org) and
  decisions (text, owner, due date); decisions with a due date and no
  closure appear as open actions. Admin writes members/charter; chair or
  admin records meetings.
- `/objectives` (key `objectives`) and `/objectives/{id}`: objectives with
  owner, target, status, measure; links to risks, controls (catalog
  identifier), systems, policies and KRIs, each link validated to exist in the
  caller's org (controls are global). Status changes recorded as events.
- `/settings/organization` (key `org_settings`): rename the organization
  (admin only, own org only).

### D — auditprog: audit and assurance, evidence operations
Files: `governance/audit_program.py`, `api/routes/ui_auditprog.py`, templates
`workpapers.html`, `audit_findings.html`, `evidence_requests.html`,
`evidence_packages.html`, `assessment_schedule.html`, `compensating_controls.html`,
`audit_readiness.html`; may edit `templates/audit_detail.html` to add a
Workpapers section; in `api/routes/ui_modules.py` only `exceptions_page`
(to include approved compensating controls as exceptions in force).
- Workpapers (key `workpapers`, `/audit/workpapers` and per engagement):
  create (admin/assessor), submit for review, finalise by a reviewer who is
  not the preparer; a final workpaper is read-only. Conclusion required to
  finalise.
- `/audit/findings` (key `audit_findings`): findings across engagements with
  severity/status filters and links to their POA&M.
- `/evidence/requests` (key `evidence_req`): PBC requests across engagements,
  overdue first, owner, status.
- `/evidence/packages` (key `evidence_pkg`): authorization packages
  (`models_packages`) for the org, contents and status; read-only.
- `/assessments/schedule` (key `scheduled`): implementations by
  `next_assessment_due` (overdue, next 30/90 days) and control tests by
  frequency and last run, on live systems.
- `/compensating-controls` (key `compensating`): propose (admin/control_owner/
  assessor), approve/reject (admin, not the proposer), retire; expiry shown;
  approved ones also listed on `/exceptions`.
- `/audit/readiness` (key `audit_ready`): per open engagement, PBC accepted ÷
  requested, workpapers final ÷ total, open findings by severity; `—` over
  nothing.

### E — tprmprog: third parties, obligations, projects
Files: `governance/third_party.py`, `governance/obligations.py`,
`api/routes/ui_tprmprog.py`, templates `contracts.html`, `contract_detail.html`,
`due_diligence.html`, `vendor_findings.html`, `obligations.html`,
`projects.html`, `project_detail.html`; in `api/routes/ui_modules.py` only
`vendors_page` and `templates/vendors.html`.
- `/contracts` (key `contracts`), `/contracts/{id}`: contracts per vendor with
  dates, value, owner, status; obligations with category, due date, status,
  linked control; renewals within 90 days and missed obligations surfaced.
- `/due-diligence` (key `due_diligence`): per-vendor checklist; "apply the
  standard checklist" creates the standard items for a vendor (SOC 2 report,
  pen test summary, insurance certificate, BCP/DR plan, privacy policy,
  sub-processor list, security questionnaire) as `requested` -- these are
  requests, not data; review (accept/reject) by admin/assessor.
- `/vendor-findings` (key `vendor_findings`): findings per vendor with
  severity, status, due date; create from a questionnaire gap.
- Vendor risk score on `/vendors` (key `vendor_scores` page section): a
  composite with its formula shown: criticality weight, latest questionnaire
  score, open findings by severity, overdue due diligence. `—` when a vendor
  has none of the inputs.
- `/obligations` (key `regulatory` stays on the regulatory-change page; this
  page key `obligations`): compliance obligations register with source,
  citation, owner, due date, status, mapped controls (validated against the
  catalog).
- `/projects` (key `projects`), `/projects/{id}`: projects with status and
  dates; links to POA&Ms, tasks, risks, systems in the caller's org; progress =
  linked POA&Ms closed ÷ linked POA&Ms (`—` over none).

### F — platform: administration and governed AI
Files: `api/routes/ui_platform.py`, `governance/rbac_matrix.py`, templates
`api_tokens.html`, `rbac.html`, `ai_analysis.html`, `teams_roles.html` (if
needed).
- `/settings/api-tokens` (key `apitokens`): a signed-in non-viewer can
  rotate their own API token (shown once, stored hashed as `user-create`
  does) or revoke it; an admin sees which users in their org hold a token and
  can revoke any of them. Every action is an event.
- `/admin/rbac` (key `rbac`): the permission matrix **derived from the
  routes**: walk the app's routes, read each route's `require_role(...)` /
  `require_platform_admin()` dependency, and show path, method and roles. Not
  a hand-written table. Plus IdP group-to-role mappings
  (`models_identity.GroupRoleMapping`) listed and editable by admin through
  the existing identity service.
- `/ai/analysis` (key `ai_analysis`): the governed AI actions
  (`ccf/ai_actions`, `/api/ai-actions`): definitions available, start a run
  for a record the caller can see, list runs with their review state; output
  shown as a draft with its citations and never applied to a record from
  this page. If no provider is configured, say so and link
  `/admin/ai-settings`.

### G — intel: threat intelligence, analytics, cross-system control views
Files: `intel/kev.py`, `analytics/studio.py`, `api/routes/ui_intel.py`,
templates `intel.html`, `analytics_studio.html`, `implementations.html`,
`inheritance.html`, `remediation_plans.html`, `issues.html`; `cli.py` to add a
`kev-sync` command (append at the end).
- KEV: `sync_kev(session, payload)` upserts `KevEntry` rows from CISA's JSON
  feed format; `fetch_kev()` downloads
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (timeouts, size cap, error surfaced, never a silent empty). Tests use a
  fixture payload, never the network.
- `/intel` (key `operations` page stays; this page key `intel`): the org's
  scan findings and POA&Ms whose CVE ids appear in KEV, with due dates and
  ransomware use; catalog version and last sync time; admin "sync now". Find
  where scan findings store CVE ids before building; if they do not, match
  CVE ids in POA&M titles/weakness text and say that is the method.
- `/analytics` (key `queries` stays for assurance queries; this page key
  `analytics`): a safe studio -- choose a register (POA&Ms, risks, control
  test results, evidence objects, vendors, tasks) and one or two group-by
  dimensions from a fixed allowlist per register; counts in a table and a
  column chart. No free-form SQL, no user-supplied column names reach SQL.
- `/implementations` (key `ctrl_impl`): control implementations across live
  systems with status, responsibility, owner; filters.
- `/inheritance` (key `ctrl_inherit`): inherited and hybrid implementations
  by system and provider (FedRAMP dependencies where linked).
- `/remediation` (key `remediation`): remediation plans
  (`models_enforcement`) for the org, with status; read-only here.
- `/issues` (key `issues`): one list of open issues across POA&Ms, audit
  findings, vendor findings and failing control tests, by severity and age.

## Additions (same day): no entry may stay `partial`

A navigation entry is done only when its label is true without a qualifier.
Migration `0100_risk_program` adds what the risk items need.

### B — risk, extended (merge `feature/concord-enterprise-redesign` first)
Schema now available: `Risk.organization_id` (a DB trigger keeps it equal to
the system's org when `system_id` is set; set it to the caller's org for a
system-less risk), `Risk.register` (`enterprise`|`cyber`),
`RiskAssessment`, `RiskTreatmentPlan`, `RiskTreatmentAction`
(`models_program.py`). Scope every risk query as
`Risk.organization_id == org` **or** `Risk.system_id IN org_system_subq(org)`,
and never return a risk on a soft-deleted system.
- `/risks?register=enterprise|cyber` (keys `risks` and `risks_cyber`): two
  registers over one table; create a system-less enterprise risk.
- `/risks/{id}` (key `risk_assess` for the assessments tab): risk detail with
  assessment history; record an assessment (admin/control_owner/assessor):
  qualitative 1-5 and/or quantitative SLE and ARO (ALE = SLE x ARO, computed,
  never entered); the latest assessment updates the risk's scores. A
  quantitative register view lists ALE per risk with its total (`—` when no
  risk has one).
- Treatment plans (key `risk_treat`): per risk, strategy, owner, due date,
  target residual, actions with owners and due dates, optional POA&M link
  (POA&M must be on a live system of the caller's org); plan progress = done
  actions ÷ actions (`—` over none).

### D — auditprog, extended
`/evidence/packages`: if `ccf/packages` exposes create/add/seal operations,
make them role-gated actions on the page (same gates as the API), so the
page is a workflow, not a listing.

### G — intel, extended
`/remediation`: if `models_enforcement` has service functions for plan state
transitions, expose them as role-gated actions (same gates as the API) so
Remediation Workflows is a working workflow.

### H — assure: control assurance and evidence operations (new)
Files: `analytics/assurance_views.py`, `api/routes/ui_assure.py`, templates
`control_effectiveness.html`, `evidence_map.html`, `evidence_expiration.html`,
`integrations.html`.
- `/controls/effectiveness` (key `ctrl_eff`): per control, the latest
  automated test outcome across live systems, the latest final audit
  workpaper conclusion if any, approved compensating controls, and a rating
  stated with its rule: `effective` (latest tests pass and no ineffective
  conclusion), `ineffective` (a failing test without an approved acceptance,
  or an ineffective final conclusion), `not determined` (otherwise). Counts
  per rating; filters by system and family.
- `/evidence/mapping` (key `evidence_map`): controls × evidence: for each
  control with evidence, the evidence objects (repository) and legacy evidence
  tied to it, status and expiry; controls in a system's baseline with no
  evidence listed as gaps; filter by system.
- `/evidence/expiration` (key `evidence_exp`): expired and expiring (30/60/90
  days) evidence objects with owner; "request renewal" creates a Task assigned
  to the evidence owner (admin/control_owner), deduplicated per object.
- `/integrations` (key `integrations`): one hub over connectors (status, last
  sync), webhooks (list, create, disable through the existing events/webhook
  service, admin only), IdP/SSO configuration status, and issue-tracker links
  (counts per provider); each section links to its detail page.
