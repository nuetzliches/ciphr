# The master key

**Status:** current as of 2026-08-18, phase 1. The mechanism is implemented and tested; the CLI that
will drive it (`ciphr init`, `ciphr rotate-master-key`) arrives in phase 3. Where a procedure has no
command yet, this document says so instead of inventing one.

This is the highest-consequence thing in the system. Lose it and every secret is unrecoverable —
there is no reset, no recovery code, and no support channel that can help. Leak it and the database is
plaintext. Everything below follows from those two sentences.

## What it is

A 32-byte key, supplied as 64 hexadecimal characters in an environment variable
(`CIPHR_MASTER_KEY` by default). It wraps the root key and nothing else, so it is never used to
encrypt a secret directly.

It is **not** a password. It is not stretched with Argon2 or PBKDF2, because it is not
human-chosen: it is full-entropy random data, and key derivation would add cost without adding
strength.

## Generating one

```sh
openssl rand -hex 32
```

Any source of 32 cryptographically random bytes will do; the requirement is that it is not derived
from anything guessable. Do not use a passphrase, a hash of a passphrase, a UUID, or the output of a
password generator with a character-set limit.

Bad practice worth naming, because it looks reasonable: generating the key on a workstation and
pasting it into a chat message or ticket "temporarily". Chat history is a backup you do not control.

## Where it lives

In the service environment file, mode `0600`, owned by the account that runs ciphr — the same place
other signing secrets already live. That is deliberate, and it is worth being clear about what it
buys and does not buy:

- **It buys unattended startup.** A restart at 03:00 does not wait for a human. That is the whole
  justification (ADR-5).
- **It buys no cryptographic strength.** Trust rests on file permissions and on whatever distributes
  that file. Root on the host reads it, and so does anything running as the service account.

If that trade is unacceptable for a given deployment, the answer is a different seal mechanism — split
keys or a hardware module — and the design keeps that path open without a data format change. It is
not something to compensate for with a more complicated environment file.

## Backups: the rule that matters most

**The master key must not be in the same backup as the database.**

- Database plus key in one backup means the backup *is* a complete, decryptable secret store. Every
  copy of it, on every medium, in every retention tier.
- Database without the key is inert. It is ciphertext, and that is exactly what a backup of a secret
  store should be.
- Key without a database is useless on its own, which is why it can be kept somewhere the database is
  not.

Concretely: back up the SQLite file with the ordinary file-backup job, and keep the master key in a
**break-glass** location instead — a human-oriented password manager, plus one offline copy (paper or
an encrypted removable medium) held somewhere physically separate. Two copies, because one copy of an
irreplaceable secret is a single point of failure with no fallback.

Then, and this is the part that gets skipped: **rehearse the restore**. A backup that has never been
restored is a hypothesis. Restoring a ciphr database means recovering the file *and* fetching the
break-glass key, and the second half is exactly the step that turns out to be undocumented or
inaccessible at the worst moment. Fold it into whatever backup audit cycle already exists.

## Rotating it

Rotation re-wraps the root key. It does not re-encrypt any secret, does not change any ciphertext,
and does not require downtime beyond a restart. That is by design: a rotation that was expensive would
never be performed.

The sequence, as implemented in `ciphr-store`:

1. Read the seal record from the store.
2. Unseal the root key with the **old** master key.
3. Wrap the same root key — same identifier — with the **new** master key.
4. Replace the seal record.
5. Put the new key in the environment file and restart.

Two invariants are enforced rather than trusted: replacing the seal record with one for a *different*
root key is refused (it would make every secret unreadable, with no error until the first read), and
so is initializing a store that already has a seal record.

**No CLI command does this yet.** In phase 1 the operation exists as a library call, exercised by
`crates/ciphr-store/tests/master_key_rotation.rs`. `ciphr rotate-master-key` arrives with the CLI in
phase 3. Until then, rotation on a live deployment is not a supported procedure — which is fine,
because there is no live deployment yet.

When it is: keep the old key until the new one is confirmed working. The window between step 4 and a
successful restart is the one where having discarded the old key too early would be unrecoverable.

## When it is compromised

Rotating the master key does **not** contain a compromise of the *secrets*. Whoever held the master
key and a copy of the database can decrypt everything in it, forever, offline. Rotation stops future
access with the old key; it does nothing about the copy already taken.

So the response is to rotate the secrets themselves — every one of them — and the master key is the
smaller half of that job. Which is where the rotation classes matter, because some of those secrets
cannot simply be replaced: see [rotating-secrets.md](rotating-secrets.md).

## What breaks, and how it will look

| Situation | What you will see | What to do |
|---|---|---|
| Variable not set | Startup fails naming the variable | Set it; do not "temporarily" generate a new one — a new key cannot read the existing database |
| Wrong key, valid format | Unsealing fails as an authentication failure, indistinguishable from a corrupted record | Check you are pointing at the intended environment file before concluding the database is damaged |
| Key not 64 hex characters | Startup fails with a length or encoding error, never echoing the value | Regenerate as above; watch for a trailing newline or quotes |
| Key lost entirely | The database is ciphertext and stays that way | Restore the break-glass copy. If there is none, the data is gone; recreate the secrets from their sources |
| Seal record partially written | Startup refuses with "the seal record is incomplete" | Restore the database from backup rather than repairing it by hand — guessing which half is authoritative can mean unsealing with the wrong record |

Note the second row: a wrong key and a damaged record look the same on purpose, because
distinguishing them would be a decryption oracle. It also means "the database must be corrupt" is a
conclusion to reach *after* checking which key is in the environment, not before.
