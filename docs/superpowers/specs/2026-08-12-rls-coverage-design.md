# RLS Coverage for the Engine Tables — Design

**Date:** 2026-08-12
**Status:** Approved (design), pending implementation plan
**Slice:** hardening, ahead of the remaining ATO Bot capability delta
**Depends on:** slices 1–6, all on `feat/evidence-prep-spine`

## Context

110 of the 135 tables in the `ccf` schema carry a row-level security policy.
Eleven of the twenty-five that do not are tables slices 1–6 created:

```
prep_runs  prep_lines  prep_screens  prep_units  prep_classifications
prep_embeddings  prep_jobs  assessment_jobs  calibration_snapshots
assessment_control_proposals  assessment_objective_proposals
```

The remaining fourteen — `controls`, `frameworks`, `control_families`,
`framework_mappings`, `worksheets`, `worksheet_rows`, `ingestion_runs`,
`catalog_sources`, `catalog_checks`, `scoring_controls`, `statement_templates`,
`ksis`, `ai_action_definitions`, `alembic_version` — are global reference data
with no tenant dimension. They are correctly excluded and this slice does not
touch them.

So every table built in the last six slices holds tenant data with no database
backstop, while the tables they sit directly beside — `assessment_control_results`,
`poams`, `evidence` — have one.

### Why this is worth a slice rather than a follow-up

Not because a leak is known to exist. The application-level checks are present
and several are mutation-tested as attacks. It is because of what happened while
building those checks: three endpoints in slice 1 leaked cross-tenant by trusting
a body field, one laundered through a foreign-key id belonging to another
organization, and in slice 5 an app-level organization check turned out to be
passing its test only because RLS filtered the row first — the check itself was
never exercised.

That last one is the argument in miniature. On an RLS-backed table a forgotten
filter is contained by Postgres. On these eleven, nothing contains it. The
defence that caught the slice-5 mistake is exactly the defence these tables lack.

## Goals

1. Every one of the eleven tables carries a `tenant_isolation` policy matching
   the convention the other 110 already use.
2. The policy is demonstrably effective — not merely present.
3. No regression: the pipelines, workers and API keep working.

## Non-goals

- **No changes to the fourteen global tables.** They have no tenant column and
  no tenant meaning.
- **No removal of any application-level check.** This is defence in depth, not a
  replacement. Removing an app check because "the database handles it now" would
  trade a tested guard for an untested assumption.
- **No new tenancy model.** `current_tenant()` and the existing role plumbing
  are used exactly as they are.

## The policy

Every one of the eleven tables carries `organization_id` directly — verified
against `information_schema.columns`, all eleven. So none of them needs the
parent-join derivation that `poams` (`system_id → systems.organization_id`) and
`assessment_control_results` (`assessment_id → assessments → systems`) use. The
policy is the simplest form in the codebase:

```sql
ALTER TABLE ccf.<table> ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ccf.<table>
  USING (current_tenant() IS NULL OR organization_id = current_tenant());
```

Same policy name and same `current_tenant() IS NULL` escape as the existing 110,
so an operator reading `pg_policies` sees one uniform pattern rather than two.

## The part that is actually load-bearing

**The DDL is trivial. The verification is the slice.**

`current_tenant() IS NULL` means *unrestricted*. So the failure mode of getting
this wrong is not an outage — it is a policy that exists, reports as enabled, and
filters nothing, because the code path never set the tenant GUC. That failure is
invisible to a test that only asserts the policy exists, and invisible to an
operator reading `pg_policies`. It would leave the system exactly as exposed as
it is today while appearing to be fixed, which is worse than not doing the work.

Three things therefore have to be established for each table, and each needs its
own assertion:

1. **The policy exists, is enabled, and is forced** — `relrowsecurity` AND
   `relforcerowsecurity` both true, and a
   `tenant_isolation` row in `pg_policies`.
2. **It actually filters.** With the tenant GUC set to org A, a row belonging to
   org B is not visible. Asserted per table, against a session that has the GUC
   set — not the bootstrap session, which is unrestricted by design.
3. **The real code paths set the GUC.** The API sets it through
   `deps.get_session`. The **workers and the CLI are the open question** — the
   prep pipeline and the assessment worker claim jobs and write across all eleven
   of these tables, and if they run with the tenant unset then the policy is
   decorative on exactly the paths that touch the most rows. This must be
   established by reading the code and asserting on it, not assumed.

If a worker genuinely must run unscoped — a reaper sweeping across tenants, for
instance — that is legitimate, but it must be **named as a deliberate exception
with its reason**, the way `scanners.py`'s auto-close is documented as a
deliberate exception to the POA&M closure gate. An undocumented unscoped path is
indistinguishable from a bug.

## Ownership and `FORCE`

A table's owner bypasses its own RLS policies unless the table is set to `FORCE
ROW LEVEL SECURITY`. **Checked, not assumed:** all 135 tables in `ccf` are owned
by the role `ccf`, and all 110 RLS-backed tables carry
`relforcerowsecurity = true`. The application authenticates as `ccf` and then
`SET ROLE`s to `ccf_app`, so the owning role is in play on every connection.

`FORCE` is therefore **required**, not optional. Enabling RLS without it would
produce a policy that exists, reports as enabled, and is bypassed on exactly the
connections the application uses — the silent-no-op failure this design is most
concerned with, arrived at by a second route.

Each of the eleven gets:

```sql
ALTER TABLE ccf.<table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE ccf.<table> FORCE ROW LEVEL SECURITY;
```

and the per-table test asserts `relforcerowsecurity`, not merely
`relrowsecurity` — the two are separate columns and only the pair is meaningful
here.

(This is the kind of assumption worth checking rather than reasoning about. An
earlier suggestion of mine in this project — `ALTER ROLE ... SET search_path` —
was wrong for a closely related reason: role-level settings apply at
connection-time authentication, and this application authenticates as one role
and then becomes another.)

## Migration

Migration `0060`. It carries the `IF EXISTS (SELECT 1 FROM pg_roles WHERE
rolname = 'ccf_app')` guard that `0054` establishes as this repo's standard —
`0057` and `0058` omitted it, which stays on the debt list.

`downgrade()` drops the policies and disables RLS, and must round-trip
(`upgrade head && downgrade -1 && upgrade head`).

## Risk, and how it is contained

The realistic failure is a code path that reads or writes one of these tables
without the tenant GUC set and *depends* on seeing everything — a cross-tenant
sweep, a reaper, a metrics query. Under the `IS NULL` escape such a path keeps
working, so the risk is not breakage; it is that the path is unscoped and nobody
noticed. The test for point 3 above is what surfaces those, and each one found
gets either a GUC or a documented exception.

The suite is the safety net: **948 passed, 1 skipped** before this slice. Any
path that breaks under RLS will fail loudly there, and the eleven tables are
covered by roughly 200 tests across slices 1–6.

## Testing

- **Per table, all eleven:** RLS enabled, `tenant_isolation` present, and — the
  one that matters — org A's session cannot see org B's row. Parameterise over
  the eleven so a twelfth table added later without a policy is caught by the
  same test rather than needing a new one.
- **A registry test:** assert that the set of `ccf` tables with a tenant column
  and no RLS policy is empty, with the fourteen global tables named as an
  explicit allow-list. This is the test that stops the gap reopening — every
  future slice adding a tenant table fails it until a policy is written.
- **Worker and CLI paths:** assert the tenant is set where it should be, and that
  every unscoped path is on the documented-exception list.
- **No regression:** the full suite, run alone, unchanged at 948 passed.
- **Mutation discipline:** drop one policy and confirm the per-table test fails;
  drop the GUC on a worker path and confirm its test fails. This project has
  found roughly twenty defects by mutation and none by reading, including four
  tests that passed against deliberately broken code.

## Documentation

`docs/ARCHITECTURE.md` gains the coverage statement and the allow-list of global
tables with the reason each is exempt. `CHANGELOG.md` records the hardening.
Both must state plainly that RLS is defence in depth and that the
application-level checks remain the primary control — so no future reader deletes
one believing the other suffices.
