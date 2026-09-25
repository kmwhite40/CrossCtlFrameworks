# Backup and restore

## What has to be backed up together

Two things, and they are only useful as a pair:

1. **The database.** Everything the platform records — systems, controls,
   evidence, POA&Ms, the audit chain, and the *ciphertext* of every stored
   credential.
2. **The credential master key** (or the KMS key, if
   `CCF_AI_CREDENTIAL_KEY_PROVIDER` is not `local`).

A database restored without its key comes back with every connector, AI
provider and MFA secret unreadable. The rest of the data is intact and each
credential has to be re-entered by hand. Store the key somewhere the database
backup is not — restoring both from one compromised store defeats the
encryption.

## Backup

```bash
pg_dump --format=custom --no-owner --file=ccf-$(date +%Y%m%dT%H%M%SZ).dump \
        "postgresql://<user>@<host>:<port>/<database>"
```

`--format=custom` so `pg_restore` can be selective. Record alongside the dump:

- the Alembic revision (`select version_num from ccf.alembic_version;`)
- which master key the ciphertext is wrapped with (its identifier, never the key)

Restoring a dump taken at a *later* revision than the application expects will
fail or behave unpredictably; the revision is part of the backup.

## Restore

1. Restore into an empty database:

   ```bash
   pg_restore --no-owner --dbname="postgresql://…" ccf-<timestamp>.dump
   ```

2. Confirm the revision matches what the dump recorded, then bring the
   application to head:

   ```bash
   docker compose build api migrator && docker compose up migrator
   ```

3. Set `CCF_AI_CREDENTIAL_MASTER_KEY` to the key that dump was wrapped with —
   not the current production key, unless they are the same.

4. Verify before reopening access:

   ```bash
   ccf keys-status      # nothing unreadable
   ```

   Then open one connector and press **Test**: a real provider round trip is
   the only proof the credentials survived. `status = configured` on its own
   proves only that a row exists.

## Row-level security

All tenant tables carry `FORCE ROW LEVEL SECURITY`. `pg_dump`/`pg_restore` run
as the owning role and are unaffected, but anything you run against a restored
database as `ccf_app` is tenant-scoped: an empty query result may mean the
session has no tenant set, not that the data is missing.

## What is not in the database

- The master key (above).
- Uploaded evidence files, if a deployment stores them outside the database.
  Check `CCF_EVIDENCE_*` settings for the deployment before assuming a dump is
  complete.
