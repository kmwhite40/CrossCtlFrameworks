# Runbook — Ingestion failed

**Symptom:** `docker compose --profile etl run --rm etl` exits non-zero, or
`/ingestions` shows a run with `status = failed`.

## Triage

1. `docker compose logs --tail=200 etl` — read the last Python traceback.
2. Check `/ingestions` — find the run row and its `stats` JSON.
3. If `stats.error == "header_contract"`: go to the **header contract
   mismatch** runbook.
4. If `stats.error == "exception"`: read `stats.detail` for the message.

## Common causes

### Missing identifier rows (expected)

Rows without `identifier` are *not* failures; they land in
`ccf_audit.rejected_rows` (see `/quarantine`). The run still succeeds.

### Duplicate identifier

Source workbook has two rows with the same `identifier`. The ETL
automatically suffixes the later row with `#row<N>`. No action.

### Header contract violation

A previously-required header has been removed. Either:
- Update the source to restore the header, **or**
- Update `contracts/headers.v1_1.json` to drop the requirement (PR +
  review).

Then re-run the ETL.

### Postgres connection refused

```
asyncpg.exceptions.CannotConnectNowError
```

- Confirm `ccf-db` is up (`docker compose ps`).
- Confirm `CCF_DATABASE_URL` resolves inside the container.
- Check port collisions on the host (`lsof -i :5433`).

## Recovery

`ingest_workbook` writes `status='failed'` and persists
`stats.error` / `stats.detail`. The previous successful snapshot remains
intact because the run rolled back. A re-run with a good workbook will:

1. See the same `sha256` — dedupe to the existing `workbook_versions`
   row.
2. Create a new `ingestion_runs` record referencing the same version.
3. Re-run history snapshots and `framework_mappings` rebuild.

## Escalation

- `/quarantine` count trending up over successive runs ⇒ data-quality
  regression; open an issue with the three most recent `rejected_rows`
  payloads and the workbook `sha256`.
- Same run failing three times in a row with distinct errors ⇒ roll
  back the last Alembic migration and reopen.
