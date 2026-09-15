# Flaw remediation: SLA measurement and patch campaigns (CC&E #7)

**Status:** design, awaiting implementation plan
**Extends:** `ingest/scanners.py`, POA&M, `enforcement/`
**Depends on:** #4 enforcement (for the execution seam)

## 1. What already exists, and the gap it leaves

Concord already knows a great deal about flaws:

- `ingest/scanners.py` normalizes Nessus / Tenable / Qualys / Inspector / CSV
  exports into `ScanFinding` — severity, the **asset** it was seen on, the
  vendor's `solution` text, and CVE refs.
- `reconcile_findings` turns those into POA&Ms deterministically and
  idempotently: re-ingesting the same scan changes nothing, an improved scan
  auto-closes fixed findings, a regressed scan reopens them.
- The POA&M carries `severity`, `identified_on`, `due_on`, `closed_on`,
  `original_due_on` and `source='scan'`.

So the *data* for flaw remediation is complete. Two things are missing.

**First, nothing measures remediation against a declared timeframe.** SI-2
requires the organization to remediate system flaws "within
[organization-defined time period]". That parameter exists in Concord only as
free text in an SSP template (`{{flaw_remediation_timeframe}}` in
`ssp/templates_seed.py`) — a sentence in a document, with nothing comparing it
to what actually happened. A POA&M's `due_on` is per-row and editable; it is
not a policy, and a deviation to it is invisible as a *policy* breach.

**Second, patching is not organized.** Forty assets needing the same fix are
forty independent POA&Ms with no notion of doing them in a deliberate order,
inside a window, with a record of which batch went when. That record is the
artefact an assessor asks for under SI-2 and RA-5, and it does not exist.

## 2. The measurement is the valuable half, and it is exact

A per-organization **remediation policy** maps severity to days. Defaults are
the FedRAMP timeframes — critical 30, high 30, moderate 90, low 180 — because
inventing different numbers for a federal product would be worse than adopting
the ones assessors already expect.

Against that, for scan-sourced POA&Ms:

| Bucket | Meaning |
|---|---|
| `within_sla` | open, and `today - identified_on <= allowed` |
| `breached` | open, and past the allowed window |
| `closed_on_time` | `closed_on - identified_on <= allowed` |
| `closed_late` | closed, but past it |
| `unknown` | **no `identified_on`** — latency is unmeasurable |

`unknown` is its own bucket and never folded into a passing one. A finding with
no identification date cannot be shown to have been remediated in time, and
counting it as on-time would overstate the exact number SI-2 is about. This is
the same discipline `poam_aging` already applies with `no_due_date`.

Latency is computed **pure** — POA&Ms, policy and `today` in, buckets out —
so it is testable without a clock and reusable by the dashboard, a report, and
a campaign's completion record.

## 3. Campaigns organize the work; they do not perform it

A `PatchCampaign` groups open scan-derived POA&Ms for one system into ordered
**waves**, each with a scheduled window.

- Waves are **ordered and small first**. A campaign's first wave is a canary:
  the point of sequencing is that the blast radius of a bad patch is bounded by
  the wave, which is the same reasoning as enforcement's resource limit.
- A wave records **completion**, with the POA&Ms it covered and the evidence
  reference. Completion is a recorded fact, not an inference from the next
  scan — although the next scan auto-closing those findings is exactly the
  corroboration an assessor wants, and the campaign links to it.
- **Overlapping windows on one system are refused.** Two campaigns patching
  the same assets in the same window is how a maintenance window becomes an
  outage.

### The execution seam, stated plainly

**Concord has no endpoint-management provider.** Applying a patch means talking
to Intune, WSUS, SSM, Puppet or similar, and no such connector exists here.

So a wave does not push patches. It either:

1. records that a wave was completed, with evidence — the honest path today,
   and the one that produces the SI-2 artefact; or
2. references an enforcement `RemediationPlan` (#4), when a deployment supplies
   a provider that handles the relevant check.

Option 2 is a **seam, not a stub**: nothing here fabricates a provider, and no
code path pretends a patch was applied. Writing an Intune provider is a
separate, deployment-specific integration on rails that already exist — the
same rails, the same plan-approve-apply gate, the same reversal requirement.

Calling this "patch orchestration" without that caveat would overstate it. What
this builds is the governance and measurement of patching, which is the part a
compliance platform is actually responsible for.

## 4. What this does NOT do

- **No patch execution.** §3.
- **No second remediation engine.** A wave that executes does so through
  enforcement's plan/approve/apply, not a parallel path.
- **No change to `reconcile_findings`.** Scanner ingestion, auto-close and
  reopen behaviour are untouched; campaigns read POA&Ms, they do not rewrite
  them.
- **No POA&M `due_on` rewriting.** The policy measures; it does not silently
  move a human's dates. A breach is reported, not corrected.
- **No scheduler automation.** Campaigns are created and advanced by people.

## 5. Testing strategy

- The SLA calculation is pure and table-driven: every bucket, both boundaries
  (`exactly at the limit` is within SLA, one day past is not), a missing
  `identified_on`, a closed POA&M with no `closed_on` (a data-quality signal,
  never on-time), and severity-specific windows.
- The policy defaults are asserted against the FedRAMP numbers, so a change to
  them is deliberate.
- Campaign refusals each get a test: overlapping window, a wave with no
  POA&Ms, completing a wave twice, completing out of order.
- Only scan-sourced POA&Ms are measured — an assessment-sourced POA&M is not a
  flaw, and including it would distort the SI-2 number.
- Tenant isolation on every query, with two rows where a filter is tested.
- Mutation testing on every guard, with the harness invariants from the
  mutation-testing memory.
