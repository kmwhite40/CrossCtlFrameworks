# VDR engine: evaluations and class timeframes (FedRAMP 20x VDR/VER)

Date: 2026-11-05. Status: building. Base: `feat/aws-collector-truth` (top of
the #37–#43 stack), migration `0107`.

## 1. Why

FedRAMP's 20x Vulnerability Detection and Response rules take effect
**2026-12-07** (obtain and maintain; grace period ends 2027-03-07; "Mandated
by CISA BOD 26-04"). Every timeframe in them runs from an **evaluation**: a
PAIN N-rating (VER-EVA-EPA), internet reachability (VER-EVA-EIR) and likely
exploitability (VER-EVA-ELX).

Concord has no evaluation. It already renders the VDT/AVI/history
deliverables from POA&Ms (`ccf.cr26.ver`, spec 2026-09-18), and that spec's
§3.4 correctly **omits** `currentRating`, `isInternetReachable`,
`isLikelyExploitable`, `evaluationCompletedAt`, `painReductionEvents` and
`finalDisposition` because no source exists — and says: *"Do not add a
mapping for any of these without a new source."* This is that source.

Without it, no 20x deadline can be computed: remediation SLAs today are
severity-based (`patching.sla.FEDRAMP_TIMEFRAMES`, and a second, different
table in `ingest.scanners.SEVERITY_SLA_DAYS`).

## 2. Goals

1. Record evaluations of a vulnerability, append-only, as the source the
   2026-09-18 spec asked for.
2. Compute, per open flaw, the deadlines the rules set for the system's
   certification class: evaluation (VER-TFR-EVU), mitigation (VDR-TFR-PVR),
   KEV remediation (VDR-TFR-KEV), acceptance (VER-TFR-MAV).
3. Measure detection cadence per scanner against the class (VDR-TFR-PSD).
4. Feed the evaluation into the existing VDT/AVI rendering.
5. One page per system that shows all of it with the rule each number comes from.

## 3. Non-goals

- A second vulnerability table. The POA&M stays the vulnerability record
  (`providerTrackingId` is already the POA&M id). Evaluations attach to it.
- EPSS. No FedRAMP rule uses it.
- VDR-TFR-MVX: on fedramp.gov today, absent from the pinned dataset
  (2026.10.13.01). Re-vendoring the rules is a separate change.
- Automatic evaluation. A model or heuristic guessing PAIN is exactly the
  claim this platform refuses to make. People evaluate; the engine computes.

## 4. Anti-goals (would be a failure even if it "works")

- A default class. A system with no `certification_class` gets **no** class
  timeframes and is told so; picking one is a claim (see the platform-default
  defect).
- A timeframe typed into Python. Every number is read from the pinned
  `fedramp-consolidated-rules.json`; tests pin the read values to the
  fedramp.gov text so a re-vendor that changes them fails loudly.
- An unevaluated flaw reading as on time. It is `awaiting_evaluation` until
  EVU passes, then `evaluation_overdue`.
- Re-saving an identical evaluation restarting the clock.
- Extending a POA&M due date. Tier-0 made extension an approval; this engine
  may only **tighten** `due_on`.

## 5. Data

`ccf.vulnerability_evaluations`, append-only (no UPDATE/DELETE route):

| column | |
|---|---|
| id | bigint pk |
| organization_id | int fk, nullable (0103 pattern; RLS direct predicate) |
| poam_id | int fk poams, cascade |
| pain_rating | smallint 0–5, CHECK |
| internet_reachable | bool not null |
| likely_exploitable | bool not null |
| false_positive | bool not null default false |
| rationale | text not null, non-blank (VER-EVA-EFA factors) |
| evaluated_by | varchar(255) (principal email, like `poam_extensions`) |
| evaluated_at | timestamptz not null default now() |

`false_positive` with `pain_rating > 0` is refused: a false positive is not
present (FRD-FPV), so it has no impact to rate.

## 6. Engine (`ccf.vdr.timeframes`, pure)

Inputs: flaw (POA&M), its evaluations, class, KEV due dates, `now`.

- **Detection** = `identified_on` at 00:00Z — the same convention
  `cr26.ver._detected_at` declares, so the page and the deliverable agree.
- **EVU**: detected + `VER-TFR-EVU[class]`. Unevaluated past it → overdue.
- **Clock start (my call)**: the earliest evaluation in the trailing run of
  evaluations with the same `(pain, irv, lev)`. A re-save does not restart
  it; a changed rating or reachability does — the rule is "from evaluation …
  factoring for the current N-rating".
- **PVR column**: `nlev` when not likely exploitable, else `irv_lev` /
  `nirv_lev`. N0/N1 have no row → `no_timeframe` (VDR-TFR-RMN, routine
  operations), never "within".
- **KEV**: earliest CISA `dueDate` among CVE ids the POA&M names (the same
  `intel.kev.cve_ids` text match the KEV page uses, and says so). Applies
  even when fully mitigated; only closure satisfies it.
- **MAV**: first evaluation + 192 days. Open and not `risk_accepted` past it
  → `accept_required`.
- Output: every deadline, which ones are breached, and one plain-language
  explanation per breach naming the rule ID.

Class unset: EVU/PVR/PSD are `None` with reason `class_not_set`; KEV and MAV
still apply (class-independent).

## 7. Writes

**Relaxing needs a second person** (added after the automated security review
of the first commit, which found one principal could clear an overdue verdict
in the filed VDT by recording a lower rating or a false positive). An
evaluation that relaxes a deadline — a lower rating or a less exposed column
than the one in effect, any false positive (it lifts the KEV deadline), or a
first rating of N0/N1 (no timeframe at all; FedRAMP's default for an unknown
effect is debilitating, FRD-DCE) — is stored with `requires_confirmation` and
ignored by the engine and the deliverables until someone other than its
author confirms it (`POST /api/poams/{id}/evaluations/{eid}/confirm`). Only
the latest evaluation can be confirmed; a later one supersedes it. Tightening
takes effect at once. With auth off there is no second person, so nothing is
held — the same rule as the closure and extension gates.

`POST /api/poams/{id}/evaluations` — scope-checked like every POA&M route;
viewers refused by the existing gate. Records an audit event via
`record_event`. If the computed mitigation or KEV deadline is earlier than
`due_on`, sets `due_on` to it and says so; never later.

## 8. Reads

- `GET /api/poams/{id}/evaluations` — history.
- `GET /api/systems/{id}/vdr` — class, rules version, per-flaw status,
  counts, cadence per scanner.
- `/systems/{id}/vdr` page.

## 9. Deliverables

`cr26.ver.render_vulnerability` gains the fields §3.4 omitted, **only when an
evaluation exists**: `currentRating` (1–5; N0 is outside the schema's enum,
so omitted), `isInternetReachable`, `isLikelyExploitable`,
`evaluationCompletedAt` (first evaluation — the MAV clock), and
`painReductionEvents` (each later evaluation whose rating dropped, rating ≥1).
`overdueStatus` uses the engine whenever the class is set — evaluated or
not, because the schema defines overdue by VER-TFR-EVU and VER-TFR-MAV —
and carries the `explanation` the schema requires when `isOverdue` is true.
With no class it stays the existing severity SLA (which still emits
`isOverdue: true` without an explanation; a pre-existing schema gap, not
changed here). `finalDisposition = "False Positive"`
for a closed POA&M whose latest evaluation says so; other dispositions stay
omitted (closure still cannot distinguish remediated from mitigated).

## 10. Known seams, not fixed here

- `ingest.scanners.SEVERITY_SLA_DAYS` (critical 15) and
  `patching.sla.FEDRAMP_TIMEFRAMES` (critical 30) disagree.
- KEV matching is a text match on POA&M title/weakness, because scan findings
  are stored as POA&Ms (stated on the KEV page already).
