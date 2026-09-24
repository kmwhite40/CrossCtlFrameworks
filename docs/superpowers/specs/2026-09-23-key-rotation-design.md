# Key rotation — making the master secret changeable

**Status:** design 2026-09-23. Closes a defect named twice and fixed neither
time: rotating `ai_credential_master_key` today silently orphans every stored
credential.

---

## 1. Measured

`ai/cipher.py` envelope-encrypts with a per-secret AES-256-GCM data key, wrapped
by a key-encryption key. The structure is right. Two things about the local
provider are not:

```python
self._kek = hashlib.sha256(master_key.encode("utf-8")).digest()
```

1. **A bare SHA-256 is not a key-derivation function.** One unsalted hash pass
   over a value the constructor accepts at 16 characters. The docstring asks for
   "a strong, random" secret; the check permits a passphrase, and a passphrase
   run through one SHA-256 is brute-forceable at a rate limited only by the
   attacker's hardware.
2. **No key identity is recorded.** The stored blob is
   `[version][wrapped_len][wrapped][nonce][ciphertext]` and says nothing about
   which key wrapped it. So there is no migration path: change the master
   secret and every existing row fails to decrypt, with an AES-GCM tag failure
   that names nothing.

Three columns hold this ciphertext today:

| Store | Context |
|---|---|
| `ai_provider_configs.encrypted_credential` | `ccf-cred` |
| `connector_configs.encrypted_credential` | `ccf-cred` |
| `user_mfa_credentials.secret_encrypted` | `ccf-mfa` |

The third arrived yesterday, which is what makes this urgent rather than
tidy: an unrotatable key now also gates **authentication**, not only
integrations.

---

## 2. What rotation has to mean

An operator must be able to introduce a new master secret **without downtime
and without re-entering every credential**. That requires exactly two things
the current format cannot express:

- **More than one key usable at once** — the new one for writing, the old one
  for reading, until everything has moved.
- **Knowing which key a given ciphertext needs.**

So the envelope gains a key identifier, and the configuration gains a list of
decrypt-only predecessors.

### 2.1 The key id is derived, never configured

`HMAC-SHA256(key_material, "ccf-kek-id-v1")`, truncated to 8 bytes.

Deterministic, so nothing has to be kept in step with anything; and a
one-way function of the key, so a blob's header does not leak the secret that
wrapped it. **An operator who has the key can always identify its rows**, which
is what makes a stuck rotation diagnosable.

### 2.2 Version 2 of the blob

```
[2][key_id:8][wrapped_len:2][wrapped_dek][nonce][ciphertext]
```

**Version 1 is read forever and never written again.** Its rows carry no key
id, so decryption tries every configured key in turn. That is safe rather than
sloppy: AES-GCM authenticates, so a wrong key fails the tag rather than
returning plausible garbage.

Version 1 also keeps the **legacy `sha256` derivation**, because that is what
actually wrapped those rows. Re-deriving them with the new KDF would "fix" the
weakness by making the data unreadable.

### 2.3 New keys use a real KDF

PBKDF2-HMAC-SHA256, 600,000 rounds, with a fixed application salt.

- **PBKDF2 rather than HKDF** because the constructor accepts a 16-character
  value, so the input may be a passphrase, and stretching is the whole point.
  HKDF assumes the input is already high-entropy and this one is not
  guaranteed to be.
- **A fixed salt** because a KEK must be re-derivable from configuration alone;
  there is nowhere to persist a random salt that is not itself the thing being
  protected. This is weaker than a per-deployment random salt and is the
  accepted cost of a derivable key. The rounds carry the defence.
- **Derivation is cached**, keyed by the key id. `build_cipher` constructs a
  provider per call, and 600,000 rounds on every decrypt would turn a login
  into a denial-of-service surface.

---

## 3. Rewrapping is explicit, never automatic

A decrypt that succeeds under an old key **does not** silently re-encrypt under
the new one. Two reasons:

- A read path that writes is a read path that can fail, deadlock, or fire
  inside a transaction that then rolls back — leaving the operator believing a
  rotation completed.
- An operator needs to **know** when rotation is finished. Lazy rewrapping
  makes that unanswerable: the remaining rows are whichever nobody happened to
  read.

So there is a command that sweeps all three stores, reports what it moved, and
reports what it could not. Running it twice is a no-op.

### 3.1 What it cannot move is named, never skipped

A row whose key id is not among the configured keys cannot be rewrapped. It is
**reported with its key id and its table**, not counted as a failure and not
passed over in silence. An operator who dropped a predecessor too early needs
to know which key to put back, and a tag failure naming nothing cannot tell
them.

---

## 4. Fail closed, and say which key

`CredentialStorageError` today means "credential storage is unavailable".
Decryption failures gain the same treatment, carrying the key id when there is
one. The distinction that matters to an operator is between *"this deployment
has no key configured"* and *"this row needs key `a1b2c3…`, which is not
configured"*, and today both surface as the same exception.

---

## 5. Out of scope

- **A real KMS provider** (AWS KMS, Key Vault, Vault). The `KeyProvider`
  abstraction already exists for it and this change does not add one; it makes
  the *local* provider rotatable, which is what every current deployment runs.
- **Rotating data keys.** Each secret already has its own DEK; rewrapping
  changes the KEK that wraps them, which is the thing an operator can actually
  rotate.
- **Re-deriving version-1 rows with the new KDF** (§2.2). They are rewrapped to
  version 2, which is how they get the stronger derivation — in one step, under
  operator control, rather than invisibly.
- **Forcing the migration.** A deployment that never rotates keeps working
  unchanged, on version-1 rows, forever.

---

## 6. Testing requirements

1. **Round trip under one key**, for both contexts, with no regression to what
   is stored today.
2. **A version-1 blob written by the current code still decrypts** after the
   change. Construct it with the old format and the old derivation explicitly —
   not by calling the new encrypt — or the test proves nothing about existing
   data.
3. **Rotation end to end**: encrypt under key A, move A to the predecessor list
   and make B current, assert the value still decrypts, rewrap it, then assert
   it decrypts with A removed entirely.
4. **Before rewrapping, removing A breaks it** — the negative that makes test 3
   mean something. Assert the error names A's key id.
5. **The key id does not leak the key**: it is stable for a given key, differs
   between keys, and the key material does not appear in the blob.
6. **A wrong key fails the tag rather than returning garbage** — assert the
   exception, on a version-1 blob where every key is tried.
7. **Rewrapping is idempotent**: a second sweep moves nothing and reports zero.
8. **A row whose key is unknown is reported, not skipped** (§3.1), with its key
   id, and is still present and unmodified afterwards.
9. **Derivation is cached**: two ciphers built for the same key derive the KEK
   once. Assert by counting derivations, not by timing.
10. **The three stores are all swept.** Assert by enumerating the models the
    sweep touches, so a fourth encrypted column added later fails this test
    rather than being quietly left behind on an old key.

Mutation-verify: remove the key id from the blob, remove the predecessor
lookup, remove the legacy-derivation branch, and remove the cache — each must
fail a named test.
