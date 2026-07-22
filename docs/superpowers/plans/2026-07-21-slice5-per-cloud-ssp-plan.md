# Slice 5 — Truthful Framing + Per-Cloud SSP Fixes — Implementation Plan

Executes FR-01 (relabel decision), FR-03/04/05/06/07/11/12/13 from the register.
Tasks run **sequentially** (they overlap files in the SSP-generation layer).
Decision on FR-01: **relabel to truthful CMMC/800-171 framing now; do NOT build an
800-53r5 catalog** (that is a separate future program).

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **TDD**, and where behavior is data-driven, tests must exercise the **real production
  path** (build real records / go through the real compose/generate functions) — not a
  synthetic dict shape the production code never emits (this was a real defect in the
  prior slice's review).
- **Do NOT** add or change the underlying control catalog, add an 800-53 catalog, or add
  cloud connectors/SDKs. This slice is code-level only.
- Reuse existing status/enum/origination vocabularies. `ruff` + `mypy` clean on changed
  files. Match surrounding style. Preserve existing passing tests (fix a stale
  assertion only when your change legitimately corrects the behavior it asserted; STOP
  and report a real regression).
- No new Alembic migration is expected in this slice.

## Task 1 — FR-01: Relabel the SSP generator to its true framework (CMMC L2 / NIST 800-171 Rev.2)

**Files:** `src/ccf/ssp/generator.py`, `src/ccf/governance/automation.py`,
`src/ccf/ssp/constants.py` (+ tests).

**Problem:** the pipeline is hardwired to the 110 CMMC L2 / 800-171 Rev.2 practices but
the cover markets it as "FedRAMP SSP Appendix A" and the questionnaire offers
"FedRAMP"/"NIST_800_53" as selectable frameworks — a false claim for a compliance tool.

**Requirements:**
1. Cover/title text (`generator.py` ~lines 136-149): state the SSP's true basis —
   CMMC Level 2 / NIST SP 800-171 Rev.2. Remove or correct language implying it is a
   FedRAMP SSP / "FedRAMP Appendix A control style". It may note the *format* resembles
   an Appendix-A layout, but must not claim FedRAMP/800-53 content.
2. Framework picker (`automation.py` where "NIST_800_53"/"FedRAMP" are offered, ~line 95):
   remove FedRAMP/800-53 as selectable SSP-target frameworks (the generator does not
   produce those catalogs), OR — if they must remain visible — make selecting them a
   clear, explicit no-op/"not yet supported" rather than silently emitting 800-171.
   Prefer removal.
3. Docstrings/comments in `constants.py`/`generator.py` that call this a FedRAMP SSP:
   correct to CMMC/800-171.
4. Do NOT change the actual control set, ODP logic, or origination behavior here — this
   is a truthful-labeling task only.

**Acceptance:** the generated document and the framework options accurately reflect
CMMC/800-171; no code path presents 800-171 output under a "FedRAMP"/"800-53" label.

**Tests:** assert the cover/metadata text names CMMC/800-171 (not "FedRAMP SSP"); assert
the framework options no longer offer FedRAMP/800-53 as a producing target (or return
the explicit not-supported signal).

## Task 2 — FR-04, FR-05, FR-12: Control origination must reflect who actually performs the control per platform

**Files:** `src/ccf/ssp/seed.py`, `src/ccf/ssp/constants.py`,
`src/ccf/governance/automation.py`, `src/ccf/ssp/platforms.py` (+ tests).

**Problem:** `build_entries`/`seed_project_entries` set origination from
`default_origination(rec.m365_coverage_status)` for **every** platform, so an AWS/Azure
SSP inherits the Microsoft-365 responsibility split (FR-04). Provider-performed controls
can be saved as system-specific and PE inherited controls are attributed to "the
organization" (FR-05). Non-M365 inheritance is coarse per-domain guessing (FR-12).

**Requirements:**
1. Derive origination from a **per-platform** source, not `m365_coverage_status`. Read
   how `automation.py` already computes per-platform responsibility (`_platform_state`/
   `_PLATFORM_DOMAIN`, the derivation) and use that platform's responsibility for the
   selected project platform, so an AWS project's origination is independent of Microsoft
   coverage.
2. Where a provider performs the control (inherited/provider-managed per the derivation),
   the origination must be inherited/hybrid — not "system-specific"/"organization
   implemented"; name the provider. Prevent a provider-performed control from being
   recorded as system-specific (validate origination against the derived responsibility,
   or at minimum stop defaulting it to system-specific).
3. For non-M365 platforms where only domain-level coverage exists, mark controls whose
   responsibility is not per-control-known as "requires manual responsibility
   assignment" (a clear flag) rather than silently defaulting all to customer/
   system-specific.

**Acceptance:** an AWS-platform project's origination column does not equal the M365
placemat's; a control the provider performs renders inherited (provider named), not
system-specific; non-M365 controls without per-control coverage are flagged for manual
assignment. Tests build the real per-platform entries and assert these.

## Task 3 — FR-06, FR-07: Cloud-environment fidelity (no assumed services; real tenant tier)

**Files:** `src/ccf/ssp/platforms.py`, `src/ccf/governance/automation.py` (+ tests).

**Problem:** Azure-Gov SSPs auto-compose statements asserting Azure services (PIM,
Defender, Key Vault…) although **no Azure connector exists** to evidence them (FR-06).
`GOV_ENVIRONMENTS["m365"]` hardcodes "Microsoft 365 Government (GCC High)" and injects it
into every M365 statement regardless of the actual tenant tier (FR-07).

**Requirements:**
1. Azure (and any platform with no capture connector — connectors today are M365/Graph +
   AWS GovCloud only) auto-composed statements must carry a clear
   "manual-evidence-required — no connector" flag and be **excluded from readiness
   "covered"** rather than presented as implemented/evidenced. Do not delete the Azure
   service catalog; gate its use.
2. The environment label must reflect the **actual** tenant tier carried on the
   project/profile, not a hardcoded "GCC High". If the tier is unknown, render a neutral,
   accurate label and do not assert "GCC High"; block "GCC High" language unless the tier
   is confirmed.

**Acceptance:** an Azure-Gov project's statements are flagged manual-evidence-required and
excluded from "covered"; an M365 project with an unspecified/commercial tier does not
render "GCC High". Tests drive the real generate/compose path.

## Task 4 — FR-03, FR-11, FR-13: Statement quality (role/frequency/evidence; inherited CRM linkage; named roles)

**Files:** `src/ccf/ssp/statements.py`, `src/ccf/ssp/constants.py`, `src/ccf/ssp/seed.py`
(+ tests).

**Problem:** `compose()` produces statements that restate the requirement and (except in
"detailed" style) omit responsible role, frequency, and evidence (FR-03). Inherited
statements are auto-accepted (`needs_review=False`) and assert a CRM/authorization
exists with no linkage, and omit the customer-responsibility half (FR-11). Responsible
role is a generic "{Domain} Lead / System Owner" string (FR-13).

**Requirements:**
1. `compose()` must inject a responsible role, a frequency/cadence, and an evidence
   pointer in **all** styles (not only "detailed"), and reference the governing
   policy/procedure where available — for customer/system-specific statements.
2. Inherited statements: mark `needs_review=True` (do not auto-accept) unless a leveraged
   authorization / CRM reference actually exists to link; emit an explicit
   customer-responsibility line for the residual/hybrid portion. Do not assert "evidence
   is retained" when nothing is linked.
3. Responsible role: prefer the project's real roles metadata (system_owner / ISSO) when
   present, falling back to the domain label only when no named role exists — and, if
   falling back, do not let that satisfy a "named responsible party" completeness gate
   silently.

**Acceptance:** a spot-check of composed statements (all styles) each name who/frequency/
evidence; inherited controls without a CRM link are `needs_review=True` and carry a
customer-responsibility line; responsible role uses named roles when metadata provides
them. Tests drive the real compose path across styles.
