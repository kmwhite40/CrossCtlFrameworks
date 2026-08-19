# Runbook — Corrupt text indexes (collation drift)

**Symptom:** a query returns *nothing* where the row plainly exists. No error,
no log line. Adding `LIKE '%…%'` to the same query finds it.

This is not a Concord bug. It is a Postgres btree index built under one
collation and read under another, and it has been observed on the deployed
database.

## Confirm it in one minute

Compare an index scan against a sequential scan of the same predicate:

```sql
SELECT count(*) FROM ccf.controls WHERE identifier = 'AC-02';
--> 0

SET enable_indexscan = off;
SET enable_bitmapscan = off;
SET enable_indexonlyscan = off;
SELECT count(*) FROM ccf.controls WHERE identifier = 'AC-02';
--> 1
```

Two different answers to one question means the index is wrong.

## Find every affected index

```sql
CREATE EXTENSION IF NOT EXISTS amcheck;

DO $$
DECLARE r record; bad int := 0; tot int := 0;
BEGIN
  FOR r IN
    SELECT c.oid::regclass AS idx
    FROM pg_class c
    JOIN pg_index i ON i.indexrelid = c.oid
    JOIN pg_am a ON a.oid = c.relam
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE a.amname = 'btree'
      AND n.nspname IN ('ccf', 'ccf_audit')
      AND i.indisvalid AND i.indisready
  LOOP
    tot := tot + 1;
    BEGIN
      PERFORM bt_index_check(r.idx::regclass, true);
    EXCEPTION WHEN OTHERS THEN
      bad := bad + 1;
      RAISE NOTICE 'CORRUPT: % -- %', r.idx, SQLERRM;
    END;
  END LOOP;
  RAISE NOTICE 'checked % btree indexes, % corrupt', tot, bad;
END $$;
```

`item order invariant violated` on a **text** column is the collation signature.
Indexes on integers and timestamps are not affected.

## Check the data before repairing

A corrupt UNIQUE index cannot enforce uniqueness, so duplicates may have entered
while it was blind. Look **before** reindexing — a `REINDEX` over duplicate keys
fails, and you want to know why rather than guess:

```sql
SET enable_indexscan = off;
SET enable_bitmapscan = off;
SET enable_indexonlyscan = off;

SELECT identifier FROM ccf.controls GROUP BY 1 HAVING count(*) > 1;
SELECT control_id, column_key FROM ccf.framework_mappings
  GROUP BY 1, 2 HAVING count(*) > 1;
```

## Repair

```sql
REINDEX INDEX CONCURRENTLY ccf.controls_identifier_key;
```

`CONCURRENTLY` takes no write lock, so this is safe on a running system. The
catalog tables are tens of megabytes and finish in seconds. Repeat for each
index the check named, then **run the check again** and confirm zero.

If `CONCURRENTLY` is interrupted it leaves an invalid index behind:

```sql
SELECT c.relname FROM pg_class c
JOIN pg_index i ON i.indexrelid = c.oid
WHERE NOT i.indisvalid;
```

Drop those and reindex again.

## Why Postgres did not warn

Postgres records the collation version a database was built against and warns
when it changes. On this database that column is empty:

```sql
SELECT datname, datcollversion, pg_database_collation_actual_version(oid)
FROM pg_database WHERE datname = 'ccf';
--> ccf | (null) | 2.36
```

It was created from a template that never recorded one, so there was no baseline
to compare against and no warning was possible. `ALTER DATABASE ccf REFRESH
COLLATION VERSION` is rejected with `invalid collation version change` for the
same reason: Postgres will not validate a change it has no starting point for.

Until that is resolved, **run the amcheck loop above as a scheduled job**, and
always after upgrading the Postgres image — a base-image bump that changes glibc
is exactly what causes this.

## What it can silently break

Any equality lookup on an indexed text column:

- a control fetched by `identifier` — the SSP, POA&M and assessment paths
- a system fetched by `(organization_id, name)`
- a catalog source fetched by `key`
- `ccf frameworks-reclassify`, which matches on `column_key` and will
  under-apply rather than fail

None of these raise. They return an empty result, and the caller treats it as
"no such row".
