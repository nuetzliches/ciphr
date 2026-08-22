# Backups and restores

**Status:** current as of 2026-08-22. Every procedure below uses a command that exists. `ciphr
backup` **is released in `0.6.0`** — a deployment on `0.5.1` or earlier has the file-level procedure
below and nothing else.

The rule about the master key was written down first, in [master-key.md](master-key.md), because it
is the one whose violation is unrecoverable. This document is the rest of it: what a backup has to
contain to be a backup at all, how to take one that is not torn, and what a restore quietly undoes.
That last part is the reason this is a document and not a paragraph — a restore is not only a
recovery, it is a rollback of every decision made since the backup, and three of those decisions are
security decisions.

## The rule that comes before the procedure

**The master key must not be in the same backup as the database.** Database plus key in one archive
means that archive *is* a complete, decryptable secret store, on every medium and in every retention
tier. Database without the key is inert ciphertext, which is what a backup of a secret store should
be. The full argument, and where the key belongs instead, is in [master-key.md](master-key.md); it
is not repeated here.

Everything below assumes that rule holds. If it does not, the procedures are beside the point.

## What the backup is worth is a property of what is in it

There is no single answer to "how important is the ciphr database", and a document that asserted one
would be wrong for most deployments. The criticality of the store is the criticality of **the least
replaceable value in it**, and that is a question the store can already answer — the rotation
classification exists and every version carries one ([rotating-secrets.md](rotating-secrets.md)).

Read on the axis of *loss* rather than of *rotation*, the six classes separate into the replaceable
and the not:

| Class | If the store is lost and there is no backup |
|---|---|
| `rotatable` | **Recoverable.** Write a new value, redeploy the consumers. An availability problem with a known cost |
| `invalidates-sessions` | **Recoverable**, at the price the class names: sessions and derived tokens go |
| `seed-only` | **Not recoverable by writing a new value.** The running system took the value at initialization and does not read it again, so a replacement does not reach it. The value is only knowable from this store |
| `volume-bound` | **Not recoverable from here.** It must match what a persistent volume was initialized with, so recovery means retrieving it from the system that holds it — if that system still does ([cli.md](cli.md)) |
| `breaks-data` | **Not recoverable at all.** The value encrypts data at rest elsewhere. Losing it does not mean "generate a new secret", it means the data encrypted under it is unreadable |
| `unclassified` | **Unknown, and therefore assumed worst.** The default, and the state of everything written before the classification existed — migration 005 set it on every such row |

The consequence is the sentence worth carrying out of this document: **a store holding fifty
rotatable CI tokens is an availability question; the same store with one `breaks-data` value in it
is a data-loss question for a different system**, and the ciphr backup becomes a precondition for
recoverability *there*. Nothing about ciphr changed between those two stores. The first `put` of
such a value is what moved it, and no alarm fires when that happens.

Three things follow, and they are the practical content of this section.

**Backup frequency is a function of the classes, not a number in a policy.** A nightly job is a
reasonable floor for a store of rotatable values. Writing a value that cannot be regenerated —
`breaks-data`, `volume-bound`, `seed-only` — is an *event* after which a backup is due, because the
window until the next scheduled run is a window in which that value exists in exactly one place. The
same holds for the master key of a newly initialized store, for the same reason.

**"How critical is this backup" is an answerable query, and it is the same one a rotation review
asks.** Against a running service:

```
GET /v1/list/{prefix}?rotation=breaks-data
GET /v1/list/{prefix}?rotation=volume-bound
GET /v1/list/{prefix}?rotation=unclassified
```

or on the host, `ciphr list --rotation breaks-data` — read-only since 2026-08-22 (ADR-22), so it
runs with the service up or down. That link between the
two documents is worth making explicit: the classification was added to answer *may I rotate this*,
and it answers *what does losing this cost* on the same data. The two are different axes —
`seed-only` and `invalidates-sessions` sit differently on each — so read the table above rather than
reusing the `needs_care` grouping the CLI prints, which groups by rotation hazard.

**`unclassified` is the dangerous state here, not the neutral one.** For rotation it means "nobody
has looked"; for backups it means the store cannot say what its own backup is worth. Since it is the
default and was written across everything older by migration 005, a store that has never been
classified offers no answer to the question a restore is about to depend on. This is a second reason
to work that list down, and it is the reason that is felt during an incident rather than during a
rotation.

**And the master-key rule cuts both ways once such a value is in the store.** Keeping the key out of
the database's backup protects against *compromise*: the archive is inert without it. It does
nothing about *loss* — the key without the database is equally useless, and for a `breaks-data`
value both directions are sharp at once. The two copies of the key that
[master-key.md](master-key.md) recommends stop being a recommendation for a store like that.

## What has to be in the backup

**Ask the deployment rather than this table:**

```sh
ciphr state /etc/ciphr/ciphr.toml
```

Every path is derived from that configuration, so a store that was moved, a second audit device or a
key that changed from a variable to a file all produce an answer about *those* files. It reports what
each piece is for, whether it is there, and what a backup should do with it — and it exits non-zero if
something the configuration requires is absent, which makes it usable before an upgrade rather than
only during one. It needs no store lock and no master key: it checks whether the key file exists and
never opens it.

Two things no configuration names, so the command says so instead of guessing: the anchor file, chosen
by whoever runs `audit anchor --out`, and the audit archive's rotated siblings. Both belong in the
backup.

**And the job that keeps the files can be told, rather than taught:**

```sh
ciphr state --json    /etc/ciphr/ciphr.toml   # every row, with the verdict as a value
ciphr state --exclude /etc/ciphr/ciphr.toml   # only the paths that must never be copied
```

The table this command prints is a report for a person; those two forms are the same inventory for the
thing that actually takes the backup. `--json` gives each row a `verdict` to branch on —
`include`, `include-with-store`, `never`, `separately`, `reissue` — instead of the sentence in the
right-hand column, and it names the two undeducible rows above under `not_derivable`. `--exclude`
gives a file-level backup tool the one thing it wants handed to it: the paths that must not be copied,
one per line. Both are in [cli.md](cli.md), and the reason they exist is that a deployment wired this
into a nightly job and found the report unparseable
([field-report-2026-08-22.md](../field-report-2026-08-22.md)).

**A missing required file is exit `3`, not `1`.** All three forms print their whole output first and
then report the pre-flight result, and `3` says exactly that: the listing is complete, and something
the configuration requires is not on this host. A backup container that deliberately cannot see the
TLS material or the master key — which is what the rule above asks for — gets `3` on every run, and a
job can branch on it instead of parsing text. `1` remains a command that failed.

The table below is the *why*. The database is not self-sufficient, three of these rows are things a
restored database needs in order to serve a single request, and each has been a surprise to
somebody.

| What | Where it lives by default | What a restore without it costs |
|---|---|---|
| **The database** | `/var/lib/ciphr/store.db`, plus `-wal` if present | Everything: ciphertext, wrapped data keys, the seal record, tokens, the audit chain, rotation classes, planted bait |
| **The master key** | Not here — break-glass, **separately** | The database stays ciphertext forever. There is no recovery path by construction |
| **The policy file** | `/etc/ciphr/policies.toml` | Every request is denied. Identities are defined in the policy file and deliberately have no table (migration 003, ADR-3), so a token whose identity is not in that file authenticates to nothing |
| **The server configuration** | `/etc/ciphr/ciphr.toml` | The service may refuse to start rather than start wrong — a `[[surface]]` stanza needs a date and a reason or startup fails, and an older binary rejects the field entirely. See [upgrade.md](upgrade.md) |
| **The anchor file** | Wherever the store's writer cannot reach it | The audit chain can only be checked against itself, which is exactly what an anchor exists to fix. It is never rewritten, so it costs nothing to keep |
| **The audit archive** | `/var/log/ciphr/audit.jsonl` and its rotations | `ciphr audit cut` looks for every record it would remove in `--archive` and refuses when one is missing. The trail before the last cut exists only there |
| **TLS material** | `/etc/ciphr/tls/` | Recoverable by reissuing rather than by restoring, which is the argument for treating it as configuration and not as data (ADR-8, ADR-17) |

And one file that must **not** be in it:

| What | Why not |
|---|---|
| `store.db.lock` | It is the exclusive store lock, and it records a process id and that process's start time. Restored onto a host, it names a holder that does not exist — and where liveness cannot be checked, an unverifiable lock is treated as **held**, on purpose (`crates/ciphr-store/src/lock.rs`). A file-level job that globs `store.db*` picks it up; exclude it, and `ciphr state --exclude` prints it — with the `-shm` beside it — one path per line so the job can be handed the list |

### The two `.toml` files, and what losing them costs

They are the rows most likely to be skipped, because neither holds a secret — and that is also the
first thing to say about them: **the master-key rule does not apply to configuration.** `[seal]` names
a variable or a file path, never a key; the TLS entries are paths. Nothing in either file becomes
dangerous by sitting next to the database backup, so the copy belongs there. The rule is about the
key, not about everything on the host.

Their primary home is version control, and that is a decision rather than a habit: ADR-3 keeps
policies in configuration precisely so that a policy change has an author, a diff and a history —
*"the commit history of the policy file is itself part of the audit trail"*. A deployment whose
`policies.toml` exists only on the host has already lost that, and the backup question is the second
problem rather than the first.

**Losing `policies.toml` does not destroy the secrets, and it does destroy the authorization.** The
database can tell you which identity *names* exist, because tokens reference them, and it cannot tell
you what any of them was allowed to read — there is deliberately no identities table (migration 003).
So a restore without that file is not a restore: every request is denied, deny-by-default working
exactly as designed, and the way out is to write the authorization model again, from memory, during an
incident. The audit trail is a poor substitute and a tempting one: it records what *was* accessed, so
rebuilding a policy from it grants what happened rather than what was intended, and the difference is
every permission nobody exercised in the window the trail covers.

**Losing the server configuration is smaller but sharper in two places.** The `[seal]` stanza is the
record of where the master key comes from — which variable, or which path — and an operator who has
lost it is exactly the operator who reaches for the one action [master-key.md](master-key.md) forbids:
*"do not 'temporarily' generate a new one"*. The `[[surface]]` stanzas are the part that cannot be
reconstructed at all: each one carries the date a deployment accepted a cost and the reason, and that
record exists nowhere else. A rebuilt file either re-accepts without the record or leaves the entry
off — and off is a `404` byte-identical to a typo'd path, so the difference is not visible from the
outside.

The audit devices are the reassuring case, and worth naming as the contrast: a configuration with no
`[[audit]]` device **refuses to start**, so losing the file entirely fails loudly. What fails quietly
is rebuilding it with one device where there were two, which halves the trail and reports nothing.

So, to the question directly: no, losing a `.toml` does not make the data unrecoverable the way
losing the master key does. It converts a restore into a re-derivation of the authorization model,
under time pressure, with the trail inviting the wrong inference. That is how a recovery becomes an
incident of its own, which is reason enough for two files that cost nothing to copy.

## Taking one

### `ciphr backup`, which is what to reach for

```sh
ciphr --database /var/lib/ciphr/store.db backup /path/to/backup/store-2026-08-21.db
```

One command, with the service running or stopped, and it is the recommended path for both. What it
does and why each part of it is there is in [cli.md](cli.md); the four properties that matter to a
backup job:

- **It needs neither the store lock nor the master key.** A scheduled job does not need a maintenance
  window, and does not need the highest-value secret in the deployment in its environment.
- **The output is one self-contained file**, with no `-wal` beside it, whatever the source uses. The
  most common way to get a bad backup of this store is simply not available through this command.
- **It refuses an existing destination** instead of truncating it. A mistyped path cannot destroy the
  previous backup.
- **It checks what it wrote** — `integrity_check` on the copy, and its schema version against the
  source's — so the exit code means "there is a readable database there" rather than "the statement
  returned".

It also opens the source **read-only**, which matters on the one occasion a backup is most important:
taking one with a newer binary cannot migrate the database first. `ciphr` and `ciphr-server` both
migrate on an ordinary open, so a pre-upgrade backup taken any other way with the new binary would
have already destroyed the rollback it exists for.

**"With the service running or stopped" carries one condition, and it is about the source's
*mount* rather than about the command.** The store is write-ahead-logged, and SQLite can only open
such a database if the `-shm` file is there or can be created. While the service runs it is there,
so a source mounted read-only works. A **clean stop checkpoints the log away and removes both
sidecars** — and since `0.6.0` made `docker stop` reach the graceful shutdown, that is the ordinary
state after a maintenance stop rather than a rarity — so on a read-only source the open then fails
with `database error: unable to open database file`, in exactly the window where somebody is most
likely to be taking a copy by hand: the service is down and there is time.

**So a containerized job mounts the store directory read-write and runs as the service's uid.** A
throwaway container of the same image is the right shape — it needs nothing from the service
container, so it still works when that one is unhealthy, stopped or gone — but read-only is not the
mount mode that makes it work. Running as the service's uid is the half that must not be got wrong:
the `-shm` created against a stopped store belongs to whoever created it, and a root-owned `-shm` in
the store directory leaves the service unable to open its own database on the next start. While the
service is up, no file is created at all. Both halves were measured by a deployment before they were
written down here ([field-report-2026-08-22.md](../field-report-2026-08-22.md)).

What it does *not* do is make the copy a backup. It is ciphertext; the master key belongs somewhere
else, and the rest of the list above has to exist too.

#### In a scheduled job

The example above names a dated destination, which is the right shape for a copy taken by hand
before an upgrade. An unattended job usually wants the opposite — one current file whose name does
not move, so that the file-backup tool behind it deduplicates instead of accumulating — and that
choice is forced by a documented refusal rather than by taste: **`ciphr backup` does not overwrite
an existing file.**

- **A fixed name** therefore needs the previous copy removed in the same script, immediately before
  the new one is taken. `rm -f` and then `backup`, in that order — and not a `--force` on the
  command, because the refusal is what protects a mistyped path.
- **A dated name** removes nothing and owns its own retention. Schedule, retention and where the
  copies go are deployment decisions and stay out of this document; which of the two shapes needs
  an `rm` does not, because that is this command's behaviour and nothing else says it.

Either way, **verify the copy inside the job**:

```sh
rm -f /var/backups/ciphr/store.db
ciphr --database /var/lib/ciphr/store.db backup /var/backups/ciphr/store.db
ciphr --database /var/backups/ciphr/store.db audit verify
```

The two checks answer different questions, which is why both are worth the seconds. `ciphr backup`
proves the file is a readable database — `integrity_check` on the copy and its schema version
against the source's. `audit verify` on the copy proves it is *this store's* trail, unbroken from
its start, which is the claim a restore actually depends on. Neither needs the master key or the
store lock, so both belong in an unattended job, and a job that fails loudly on either is a job
that cannot report a torn copy as a success.

### Without the binary: a file-level copy

For a host where `ciphr` is not available — a rescue system, or a deployment on `0.5.1` or earlier.
Everything in this section is the older procedure, and it is more fragile in exactly the ways the
command removes.

```sh
# 1. stop the service, and anything else that writes — a CLI command is a writer too
# 2. copy the database and its sidecar
cp /var/lib/ciphr/store.db      /path/to/backup/
cp /var/lib/ciphr/store.db-wal  /path/to/backup/   # if it is there
# 3. copy the configuration, the policy file, and the anchor file
# 4. start the service
```

**Copy the `-wal` if it exists, and do not copy the `-shm`.** The write-ahead log is part of the
database: a committed transaction lives there until a checkpoint moves it, so a `store.db` taken
without its `-wal` opens cleanly and is silently missing the most recent writes — the worst shape a
backup failure can take. The `-shm` file is a shared-memory index that SQLite recreates, and
carrying a stale one gains nothing.

**Whether a `-wal` is there depends on how the service stopped.** A cleanly closed database has
none: the last connection to close checkpoints and removes it. A process that was killed leaves one
behind, with committed data in it. It is not corruption — `synchronous = FULL` and WAL are set on
every connection (`crates/ciphr-store/src/sqlite.rs`) precisely so that an abrupt stop costs no
committed write — but it is data, and copying `store.db` alone throws it away.

**Up to and including `0.5.1`, the ordinary stop was the abrupt one.** The graceful shutdown awaited
`tokio::signal::ctrl_c`, which on Unix is SIGINT and nothing else, while a container stop sends
SIGTERM — so the process was terminated and the database was not closed. That is fixed in `0.6.0`, the same
release that adds `ciphr backup`, and it does not change what to do here: check for the
`-wal` rather than reasoning about which kind of stop happened. A killed container still leaves one,
and that is not a case any release removes.

**Do not `cp` a database that is running.** Nothing prevents it and it usually appears to work,
which is the problem: `cp` reads a moving file with no transaction, so the result can be a snapshot
of two different moments. Stop the service, or use `ciphr backup`, which does not have this failure
mode at all.

### The same thing without `ciphr`: `VACUUM INTO`

`ciphr backup` is a wrapper around one SQLite statement, and the statement is worth knowing because
it is what a rescue procedure has when the binary is not there:

```sh
sqlite3 /var/lib/ciphr/store.db "VACUUM INTO '/path/to/backup/store.db'"
```

It is read-only with respect to the source (SQLite 3.27 and later), it takes no ciphr store lock —
that lock refuses a second *writer*, and a reader is not one — and it produces the same
single-file, no-`-wal` output. What it does not do is check the result or refuse to migrate; the
command does both.

**`sqlite3` is not in the runtime image.** It installs `ca-certificates`, `curl` and `gosu` and
nothing else, so this cannot be run with `docker exec` — it runs from outside, against the volume.
`ciphr backup` exists in part because that was the only hot path a deployment had.

### What is not a backup

`ciphr dump --format portable` decrypts by design, carries no bait, and has no counterpart that
imports. It is an **exit** to another system, not a restore path. A store rebuilt from it has no
honeypots in it, and re-planting is a deployment step.

## Restoring

```sh
# 1. stop everything that writes to the target database
# 2. put the files back — the database, its -wal, the policy file, the configuration
#    NOT store.db.lock
# 3. make sure the master key in the environment is the one this backup was sealed under
#    (see "A master-key rotation", below — it is not always the current one)
# 4. verify the chain before serving anything. Neither the lock nor the master key is needed:
ciphr audit verify --anchor /path/to/anchors.jsonl
# 5. deal with what the restore undid (next section) before the service is reachable
# 6. start the service
```

**Step 4 belongs before step 6, not after.** `verify` needs neither the store lock nor the master
key, which is exactly what makes it usable on a restored file with the service still down. What it
can tell you:

- **`AnchorUnreachable`** means the restored database is *older than the evidence* — an anchor was
  taken after the backup. That is the expected result of a restore and not a tampering finding. The
  distinction, and what to do next, is in [audit-trail.md](audit-trail.md).
- **A chain that disagrees with an anchor at a sequence they share** is a different matter, and one
  worth stopping for.

## Four things a restore undoes

A restore rolls the store back. Three of the four below are security decisions that come back
undone, and none of them announces itself.

**A crypto-shred.** `destroy` deletes the version's wrapped data key, and [cli.md](cli.md) is right
that the value cannot be recovered from any backup taken *after* the shred. The inverse is the part
that needs saying: a backup taken **before** it still has that column, so restoring across a
`destroy` brings the secret back readable and ends the shred it was meant to be. Re-run `destroy`
after the restore, from the audit trail — which is the operational reason the archive is in the
backup list.

**A token revocation.** `revoked_at` is a column in the database (migration 003). A restore from
before a revocation makes that token valid again, and the holder of it is whoever the revocation was
about. Re-revoke — `ciphr token revoke-all` for the identity if the individual ids are not to hand —
**before** the service is reachable, not after.

**A master-key rotation.** The seal record is four rows in `meta`, inside the database. An older
backup therefore carries the older wrapping and needs the **old** master key; the current one will
not open it. A wrong key and a damaged record look identical on purpose — distinguishing them would
be a decryption oracle — so this failure presents as *"the database may be corrupt"*, which is the
wrong conclusion.

The consequence for retention: **keep every master key any retained backup was sealed under, for as
long as that backup is kept.** [master-key.md](master-key.md) says to keep the old key until a
restart with the new one is confirmed; that is the rotation window, and it is the shorter of the two
rules. This one runs the length of the backup retention.

**Everything else that is state.** Secrets and versions written since the backup are gone. Soft
deletes come back undeleted, or go back to deleted. Rotation classes revert, including
classifications somebody did deliberately. Bait planted since is absent, and a tripped honeypot
latch is un-tripped — so a restore taken to recover *from* an incident can erase the record that the
tripwire fired. The audit trail is the only place that still knows, which is the third argument for
keeping the archive and the anchor outside the database.

## Rehearsing it

[master-key.md](master-key.md) says a backup that has never been restored is a hypothesis.
Concretely, a rehearsal is worth doing when it exercises the two halves that actually fail: fetching
the break-glass master key, and confirming that the restored file is the database it claims to be.
`ciphr audit verify` on a copy answers the second without a running service and without the key.

One detail that turns a rehearsal into a puzzle if it is not known: **verifying a *file-level* copy
needs a writable directory**, not merely a readable file. A `ciphr backup` copy is not
write-ahead-logged and reads fine from a read-only mount; a copy of the live database is, and does
not. SQLite reads a write-ahead-logged database
through its `-shm` file and may have to create it, so a read-only mount fails to open even though
nothing would be written to the database. `Store::open_read_only` returns that error rather than
quietly falling back to a read-write connection, and the reasoning is at the function
(`crates/ciphr-store/src/sqlite.rs`). Copy the file somewhere writable first.

## What breaks, and how it will look

| Situation | What you will see | What to do |
|---|---|---|
| `store.db` copied without its `-wal` | The database opens fine and the most recent writes are absent | Take the copy with `ciphr backup`, or copy both files after a stop. There is no error to catch this one |
| A live database copied with `cp` | Anything from a clean open to a corruption error, depending on what was in flight | Do not; `ciphr backup` runs against a live service and is the reason not to |
| `store.db.lock` restored with the database | A command or a startup fails as locked, naming a process id that is not the holder | Delete the lock file. Exclude it from the backup job — it is state about a process, not about the store |
| Master key from the wrong era | Unsealing fails as an authentication failure, indistinguishable from a corrupted record | Check which key this backup was sealed under before concluding the file is damaged |
| Backup restored under an older binary | Startup refuses with `SchemaTooNew` | Expected and correct. Restore a backup taken *before* the upgrade — that is why the backup is taken first ([upgrade.md](upgrade.md)) |
| Policy file not restored | Every request is denied, and the service looks healthy | Restore `policies.toml`. Deny by default is working as intended; the identities are simply not there |
| Configuration not restored | The service refuses to start, naming an unknown field or a surface entry without a date and reason | Keep the configuration beside the database backup ([upgrade.md](upgrade.md)) |
| A *file-level* copy checked on a read-only mount | The open fails even for a read-only command | Copy it somewhere writable; WAL needs to create the `-shm` file. A `ciphr backup` copy is not write-ahead-logged and does not have this problem |
| `ciphr backup` against a read-only source, service stopped | The open fails: `unable to open database file` | A clean stop removed the `-shm` SQLite has to create to read a write-ahead-logged database. Mount the source read-write and run as the service's uid — nothing is written while the service is up |
| `ciphr backup` refuses: the destination exists | `database error: output file already exists` | Deliberate — it will not truncate a previous backup. Name the new file, or remove the old one knowingly |
| `audit verify --anchor` reports `AnchorUnreachable` | The restored chain is shorter than the newest anchor | Expected after a restore: older than the evidence, not tampered with ([audit-trail.md](audit-trail.md)) |

## What is not built, and what is not this repository's job

**Built, and worth knowing what it covers:** `crates/ciphr-server/tests/restore.rs` performs the
procedure on this page — removes the live database and its sidecars, moves a backup into its place —
and then serves a secret out of it over the real router. That makes four claims checked rather than
written down: the restored seal record opens with the same master key, a token issued before the
backup still authenticates, the policy evaluator still decides, and the audit chain resumes from the
restored head instead of colliding with it. Two of its tests also pin the *consequences* below, so a
restore that stopped rolling back a revocation would fail CI rather than surprising somebody.

**Not built, and not buildable here:** a rehearsal. No test covers this deployment's backups, on this
deployment's medium, with the break-glass key actually fetched from wherever it lives. That is a human
act on a schedule, and it is the half that fails in practice.

**Not this repository's job:** schedule, retention, where the copies go, whether they are encrypted
at rest, and how the offsite copy is made. Those are deployment decisions and they live where the
deployment is documented, for the same reason there are no hostnames in this file. What belongs here
is the list of what must be in a copy, the way to take one that is not torn, and what a restore does
to the store — and those do not vary between deployments.
