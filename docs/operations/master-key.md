# The master key

**Status:** current as of 2026-08-28. Every procedure here has a command that exists. *Getting the
key off the host* is the exception and says so in its own words: its second and third levels describe
mechanisms that are **not implemented**, and they are there because this document was the one place an
operator looks and the only one that did not mention them.

This is the highest-consequence thing in the system. Lose it and every secret is unrecoverable —
there is no reset, no recovery code, and no support channel that can help. Leak it and the database is
plaintext. Everything below follows from those two sentences.

## What it is

A 32-byte key, supplied as 64 hexadecimal characters — from a file (preferred) or from an environment
variable (`CIPHR_MASTER_KEY` by default). It wraps the root key and nothing else, so it is never used
to encrypt a secret directly.

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

Two sources, both a static key (ADR-5). **Prefer the file** where the deployment allows it:

```toml
# ciphr.toml — preferred
[seal]
type = "static_file"
path = "/run/secrets/ciphr-master-key"

# ciphr.toml — the older form, still supported
[seal]
type = "static_env"
env  = "CIPHR_MASTER_KEY"
```

```sh
ciphr --master-key-file /run/secrets/ciphr-master-key get infra/a/B
ciphr --master-key-env  CIPHR_MASTER_KEY            get infra/a/B
```

The two cannot be combined — configuration allows one, and the CLI refuses both flags together. There
is no precedence rule on purpose: a rule about which source wins is a rule that lets a deployment use
the key nobody thought was active.

Why the file is better: an environment value is baked into the container configuration when the
container is created, and that is readable through the runtime's inspect API — by everyone with access
to the runtime socket, a broader set of principals than root. It is also in `/proc/<pid>/environ`. This
is the same objection [section 13 of the plan](../../.claude/plans/PLAN.md) raises against passing
secrets to *other* services through the environment, and it applied to ciphr's own key until now.

Three things the file does **not** change:

- Root on the host reads it either way. Adversary A5 is unchanged.
- The key is in process memory either way.
- It is still one bootstrap secret per host.

And one thing that depends on the runtime: **whether the key is at rest on a disk.** Swarm secrets and
Kubernetes secret volumes are memory-backed, so the file never touches one. Plain Compose outside
Swarm bind-mounts a real file — still better, because a file carries permission bits and a container
configuration does not, but not "never at rest". Know which case your deployment is.

A key file that anyone on the host can read **or write** **stops the process**. Group bits are
accepted: root-owned and read by a service group is a legitimate arrangement. Windows has no
equivalent bit and no check runs there.

**World-writable was added 2026-08-21** (finding F6 of the review); before that a file at mode `0602`
started. It is worth having for a reason that is not symmetry: a local account that can *replace*
the key plants one it knows if it gets there before `init`, and afterwards manufactures an unseal
failure on the next restart. Group-writable stays accepted — that is the same judgement call as
group-readable, and it belongs to a deployment rather than to this check.

**Mode 0777 exactly usually means something else** (noted 2026-08-20). A file bind-mounted from a
filesystem that has no Unix permissions — a Windows or macOS host under a Linux container engine, or
a CIFS share — reports 0777 for every file it exposes, whatever the file is on that host. The check
fires correctly and the message would send you looking for a permission you never set, so at that
one mode it now says so itself.

The answer is a **named volume**, not a weaker check: put the key file in a volume the engine owns,
and the permission bits mean what they say again. This is the normal case for developing against a
container on Windows, and it costs an hour the first time nobody has written it down.

**The file is opened once and inspected through that descriptor**, so the file whose mode was approved
is the file whose content is read — a replacement between the two steps is not possible (F10 of the
2026-08-21 review). What that check cannot settle is who could write the file *before* it was opened:
whoever can create entries in the directory the key lives in can put their own key there at mode
`0600`. So the directory is part of the requirement, not only the file — a secrets mount or a
root-owned directory, never one the service account can write. Something that is not a regular file — a
directory, a named pipe — is refused for what it is rather than measured for its mode.

## What either source buys, and what it does not

The key sits in a file or a variable that the deployment supplies, mode `0600`, owned by the account
that runs ciphr — the same place other signing secrets already live. That is deliberate, and it is worth being clear about what it
buys and does not buy:

- **It buys unattended startup.** A restart at 03:00 does not wait for a human. That is the whole
  justification (ADR-5).
- **It buys no cryptographic strength.** Trust rests on file permissions and on whatever distributes
  that file. Root on the host reads it, and so does anything running as the service account.

If that trade is unacceptable for a given deployment, the answer is a different seal mechanism — split
keys or a hardware module — and the design keeps that path open without a data format change. It is
not something to compensate for with a more complicated environment file.

## Getting the key off the host

**Added 2026-08-28.** Several records in this repository say the path to a hardware module is cheap —
[ADR-5](../adr/0005-seal-static-key-from-environment.md) that moving to it *"is a migration of a
single row, not of every secret"*, [monitoring.md](monitoring.md) that a field exists so a client
need not change shape when such a seal arrives, and
[why-build-this.md](../why-build-this.md) that PKCS#11 outside the commercial edition is a thing
Vault Community does not give you. None of those is a document an operator opens, and this one — the
one they do open — said nothing. That is what this section fixes.

**Read the three levels below as three different claims, not three grades of the same one.** Only the
second and third move adversary A5, and confusing them is how a deployment ends up believing it has
protection it does not have.

### Level 1 — the key is supplied by something outside ciphr. Works today, no code.

Keep `type = "static_file"` and let a credential system own the file. ciphr reads a path; nothing in
it cares what put the file there.

```toml
[seal]
type = "static_file"
path = "/run/secrets/ciphr-master-key"
```

What can own that path, in rising order of what protects the key at rest:

- **Container-runtime secrets.** Compose under Swarm, or Podman secrets. Covered in *Where it lives*
  above: memory-backed under Swarm and Kubernetes, a real file under plain Compose.
- **A systemd credential.** `LoadCredentialEncrypted=` decrypts into the unit's private credentials
  directory at start; at rest the key is sealed to the TPM, or to a host key where there is no TPM.
  This is the strongest of the three on a single host that has no cloud, and it needs no daemon.
- **A secrets driver against a KMS.** The Kubernetes Secrets Store CSI driver, or an equivalent, so
  the at-rest copy lives in AWS KMS, Azure Key Vault, GCP KMS, or an existing vault, and the file
  appears in a `tmpfs` mount for this workload only.
- **An envelope-encrypted file in the repository.** `sops` or `age`, decrypted into the mount by the
  deploy step. Weaker than the three above — the decryption key has to be somewhere — but it removes
  the plaintext key from the artefact that is most often copied.

**What level 1 buys, stated so it can be checked:** the plaintext key is not in the image, not in the
container configuration, not in `/proc/<pid>/environ`, and not in a routine filesystem backup. The
at-rest copy is protected by another system's key hierarchy, and revoking access there revokes it
here.

**What level 1 does not buy, and the sentence not to lose:** *it does not move A5.* Root on the host
reads the mounted file, and reads the key out of process memory whether or not it can read the file.
Anything that hands ciphr a plaintext key hands it to whoever owns that process. A deployment that
adopts level 1 and reports that the master key is "in the KMS" has said something true about where
the key is stored and nothing about who can read it while the service runs.

### Level 2 — the key never becomes plaintext in this process. Not implemented.

A `Seal` implementation that asks a hardware module or a KMS to unwrap the root key, so that this
process holds the *root* key and never the master key: PKCS#11 against an HSM or a TPM, or a cloud
KMS `Decrypt` against the stored wrapped record.

**This is the level that moves A5**, and it is the only one that does. It is a code change,
[ADR-5](../adr/0005-seal-static-key-from-environment.md) promised it its own ADR, and no such ADR
exists yet. The abstraction is in place — `Seal` has three methods and the mechanism's identifier is
stored beside the wrapped root key, so a database says which mechanism sealed it — and the
migration remains one row.

Worth knowing before it sounds like a complete answer: the root key is still in this process's
memory after an unwrap, so root on the host still reaches the secrets of a *running* service. What
level 2 removes is the offline case — a stolen disk plus a stolen key file stops being enough,
because the unwrap needs the module.

### Level 3 — startup requires a human. Not implemented, and not planned.

Split-key unsealing, in the shape OpenBao uses. It was
[proposed and closed](https://github.com/nuetzliches/ciphr/issues/64): ADR-5 rejected it for v1
because every restart would then need a human, which defeats the purpose of the system for automated
deploys, and that reasoning has not weakened. The cost was also larger than it looks — the server
would grow a locked-but-listening state it has never had.

### What changes operationally under level 1

Three procedures elsewhere in this document assume the deployment owns the file directly. Under
level 1 they still work, with one adjustment each:

- **`ciphr init` needs the key too.** The mount has to exist before the store is initialized, not
  merely before the service starts. A credential system scoped to the service unit and not to the
  one-shot init step is the common way to get a first boot that fails with an unseal error.
- **Rotation is unchanged in ciphr and gains a step outside it.** *Rotating it* below writes the new
  key alongside the old and passes both. Under level 1 the new key is generated and stored in the
  external system first, then made available at a second path for the length of the rotation, and
  retired there after a restart with the new key has been confirmed. The invariants ciphr enforces
  are the same either way.
- **The break-glass copy is still mandatory, and this is the point most easily lost.** A KMS you
  cannot reach is a key you do not have — an expired account, a deleted key version, a region you
  cannot log into. *Backups* below requires an offline copy outside this system, and moving the
  primary copy into a KMS does not discharge that requirement. It makes it more important, because
  the failure mode is now somebody else's outage.

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

**Keep every key that any retained backup was sealed under, for as long as that backup is kept.** The
seal record lives inside the database, so a backup taken before a rotation carries the *older*
wrapping and the current key will not open it. That is a longer obligation than the one in
[Rotating it](#rotating-it) below, which is about the window around a single restart. What the rest of
a backup has to contain, and what a restore undoes, is in [backup.md](backup.md).

Two copies of the key, above, is advice for a store of replaceable values. For a store holding
anything classified `breaks-data`, `volume-bound` or `seed-only` it stops being advice: the rule here
protects against the key being *stolen* with the database, and does nothing about it being *lost*
without one. [backup.md](backup.md) reads the classification on that axis.

## Rotating it

Rotation re-wraps the root key. It does not re-encrypt any secret, does not change any ciphertext,
and does not require downtime beyond a restart. That is by design: a rotation that was expensive would
never be performed.

The sequence, as implemented in `ciphr-store`:

1. Read the seal record from the store.
2. Unseal the root key with the **old** master key.
3. Wrap the same root key — same identifier — with the **new** master key.
4. Replace the seal record.
5. Put the new key where the deployment reads it, and restart.

Two invariants are enforced rather than trusted: replacing the seal record with one for a *different*
root key is refused (it would make every secret unreadable, with no error until the first read), and
so is initializing a store that already has a seal record.

```sh
# with a file — write the new one alongside the old
printf %s "$(openssl rand -hex 32)" > /run/secrets/ciphr-master-key.new
chmod 0600 /run/secrets/ciphr-master-key.new
ciphr --master-key-file /run/secrets/ciphr-master-key       rotate-master-key --new-key-file /run/secrets/ciphr-master-key.new

# with a variable
export CIPHR_NEW_MASTER_KEY=$(openssl rand -hex 32)
ciphr rotate-master-key --new-key-env CIPHR_NEW_MASTER_KEY
```

The two sources can be mixed across a rotation — reading the old key from a variable and writing the
new one to a file is exactly how a deployment migrates from one to the other, and it needs no
re-encryption.

**Keep the old key until a restart with the new one has been confirmed.** The window between step 4
and a successful restart is the one where having discarded it too early would be unrecoverable.

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
| Key file world-readable or world-writable | Startup fails naming the file, its mode, and which of the two bits is set | `chmod 0600`, or `0640` if a service group needs it |
| Key file reports mode 0777 in a container | The same refusal, plus a sentence about bind mounts | It is almost certainly a bind mount from a host without Unix permissions; move the key into a named volume |
| Key file missing or unreadable | Startup fails naming the path and the I/O category, never the content | Check the mount actually landed; a secret that failed to mount looks exactly like this |
| Variable not set | Startup fails naming the variable | Set it; do not "temporarily" generate a new one — a new key cannot read the existing database |
| Wrong key, valid format | Unsealing fails as an authentication failure, indistinguishable from a corrupted record | Check you are pointing at the intended environment file before concluding the database is damaged |
| Current key against a database restored from before a rotation | Exactly the row above — the seal record in that file is the older one | Use the key that was current when the backup was taken. This is why the old keys are retained as long as the backups are ([backup.md](backup.md)) |
| Key not 64 hex characters | Startup fails with a length or encoding error, never echoing the value | Regenerate as above; watch for a trailing newline or quotes |
| Key lost entirely | The database is ciphertext and stays that way | Restore the break-glass copy. If there is none, the data is gone; recreate the secrets from their sources |
| Seal record partially written | Startup refuses with "the seal record is incomplete" | Restore the database from backup rather than repairing it by hand — guessing which half is authoritative can mean unsealing with the wrong record |

Note the second row: a wrong key and a damaged record look the same on purpose, because
distinguishing them would be a decryption oracle. It also means "the database must be corrupt" is a
conclusion to reach *after* checking which key is in the environment, not before.
