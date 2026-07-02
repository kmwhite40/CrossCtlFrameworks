# Guide — Profile-driven compliance automation

Define a system once; the app derives applicable controls, inheritance, a live
SPRS score, coverage, and POA&M placeholders. The system profile is the source
of truth — everything downstream reads its derivation snapshot.

## The simplistic front door — the questionnaire

`GET /api/intake/questionnaire` returns the questions; the `/intake` UI renders
them. Answering once (UI) or one API call does the whole thing:

```bash
POST /api/intake/systems
{ "system_name": "GCC High Enclave", "environment_type": "cloud",
  "cloud_platform": "m365_gcc_high", "identity_model": "entra_id",
  "data_types": ["CUI"], "endpoint_scope": ["managed_windows"],
  "connectivity": "internet", "frameworks": ["CMMC_L2"] }
```

Returns the derivation: SPRS score, applicable count, by-responsibility /
by-state breakdown, gap count, and POA&M placeholders created.

## What derivation does (`ccf/governance/automation.py`)

1. **Applicability** — N/A rules over the profile (e.g. no mobile endpoints ⇒
   mobile-device practices Not Applicable; no wireless ⇒ wireless practices N/A).
2. **Inheritance** — layered, in priority order:
   - **Every vendor**: any control in a vendor's `linked_controls` (org-scoped or
     global shared services) is marked *inherited* from that vendor.
   - **Cloud platform**: M365 GCC High uses each practice's coverage status
     (Microsoft = inherited, Shared = partial, Customer = gap, N/A). Azure Gov /
     AWS GovCloud use per-domain defaults (PE inherited, SC/AU/CM/SI/MA shared).
   - Anything else ⇒ customer-responsible.
3. **SPRS** — writes the derived state into `scoring_statuses` (never clobbering
   a human assessment) so the live SPRS score reflects reality. `inherited` and
   `not_applicable` score as met; `partial` earns partial credit; gaps deduct.
4. **POA&M placeholders** — one open POA&M per customer/shared gap (idempotent).
5. **Event** — emits a `derived` event to the activity feed / webhooks.

Re-run anytime (idempotent): `POST /api/systems/{id}/derive`.
Read coverage: `GET /api/systems/{id}/coverage`.

## Adding a framework later (uploadable controls)

New frameworks don't need a code change or the NIST workbook:

```bash
POST /api/framework-controls/{CODE}          # JSON: {name, controls:[{identifier,title,...}]}
POST /api/framework-controls/{CODE}/csv      # multipart CSV (identifier,title,description,family,baseline)
GET  /api/framework-controls/{CODE}          # list
```

Upserts by `(framework_code, identifier)` and registers the framework if new.

## Notes & next phases

- Derivation is currently anchored on the CMMC L2 practice set (the SPRS
  engine's strength) with the crosswalk carrying other frameworks; extending
  applicability to drive `control_implementations` for 800-53 baselines directly
  is the next phase.
- Human edits win: an assessed `scoring_status` is not overwritten by re-derive.
- Approval workflow / separation-of-duties RBAC (draft→reviewed→approved on SSP
  and POA&M) is the recommended follow-on for full "enterprise" posture.
