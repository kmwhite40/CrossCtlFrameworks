# Runbook — Header contract mismatch

**Symptom:** ETL raises `HeaderContractError: Workbook is missing required
headers: [...]`. The ingestion run is marked `failed` with
`stats.error == "header_contract"`.

## Why this fires

`src/ccf/etl/validate.py` asserts that every header listed in
`contracts/headers.v1_1.json` under `required_headers` is present in the
source workbook's `SP.800-53Ar5_assessment` tab. This is a fail-closed
check: removing a required header silently would corrupt downstream
crosswalks.

## Options

### 1. Restore the header in the workbook (preferred)

Usually the right answer when the source has accidentally renamed or
deleted a column.

### 2. Update the contract (deliberate source change)

If the source intentionally renamed a column (e.g., workbook revision
1.1 → 1.2):

1. Open `contracts/headers.v1_1.json` and either update the name or
   drop the requirement.
2. Bump the filename to `headers.v1_2.json` and update the loader
   path in `src/ccf/etl/validate.py::CONTRACT_PATH` — or add a version
   discriminator based on workbook revision.
3. Commit the contract change in a separate PR. Reviewers must confirm
   the column change is expected.

### 3. Accept drift temporarily

Not recommended. The contract is the drift alarm; disabling it defeats
the point. If absolutely required, run the CLI with a commented-out
`validate_headers` call in a branch — do **not** merge.

## Recovery

After fixing either the workbook or the contract:

```
docker compose --profile etl run --rm etl
```

Confirm:
- `/ingestions` shows a new run with `status = succeeded`.
- `/quarantine` count has not increased.
- Counts in the dashboard match expected values.

## Preventing recurrence

- Subscribe the workbook custodian to the contract file so any diff
  review is explicit.
- CI nightly job (planned) ingests the latest workbook into an ephemeral
  DB and reports drift before it reaches prod.
