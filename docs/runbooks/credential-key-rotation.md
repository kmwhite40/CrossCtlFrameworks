# Rotating the credential master key

Every stored connector credential, AI provider key and MFA secret is wrapped
with the key named by `CCF_AI_CREDENTIAL_MASTER_KEY` (or, with
`CCF_AI_CREDENTIAL_KEY_PROVIDER=aws_kms`, by KMS). Rotation moves the stored
ciphertext onto a new key.

**Editing the key in place destroys access to every stored secret.** The old
key is the only way to read what was written with it, and nothing in the
application can recover a credential whose key is gone — the holder must
re-enter it. Rotate with the procedure below instead.

## The rule

The new key goes in `CCF_AI_CREDENTIAL_MASTER_KEY`; the outgoing key moves to
`CCF_AI_CREDENTIAL_PREVIOUS_KEYS` and stays there until the sweep reports
nothing unreadable. Dropping a predecessor too early is what makes a
credential unrecoverable.

## Procedure

1. **Check what is currently wrapped and with which key.**

   ```bash
   ccf keys-status
   ```

2. **Add the new key, keeping the old one as a predecessor.**

   ```bash
   CCF_AI_CREDENTIAL_MASTER_KEY=<new>
   CCF_AI_CREDENTIAL_PREVIOUS_KEYS='["<old>"]'   # JSON list
   ```

   Restart the application so settings are re-read.

3. **Rewrap.** Idempotent — running it twice is a no-op.

   ```bash
   ccf keys-rewrap
   ```

4. **Confirm nothing is unreadable.** The report lists
   `(table, row id, the key id the row needs)` for anything it could not read.
   A non-empty list means a predecessor is missing: put it back before going
   further.

   ```bash
   ccf keys-status     # expect: nothing unreadable, everything on the current key
   ```

5. **Only then drop the predecessor** from `CCF_AI_CREDENTIAL_PREVIOUS_KEYS`
   and restart.

## What is covered

`ccf.ai.rotation.ENCRYPTED_COLUMNS` is the full list, and a test asserts it
against the models that actually carry an enveloped column, so a fourth one
added later cannot be silently left behind:

- `ai_provider_configs.encrypted_credential`
- `connector_configs.encrypted_credential`
- `user_mfa_credentials.secret_encrypted`

## If a row is reported unreadable

It was written with a key that is no longer configured. Either restore that key
as a predecessor and rewrap again, or — if the key is genuinely gone — delete
the row and have its owner re-enter the credential. There is no third option;
the ciphertext is not recoverable, which is the point of it.
