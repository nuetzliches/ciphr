# The `ciphr` command

**Status:** implemented and tested as of 2026-08-21. Every command below works, `backup` included —
it is implemented and tested but not yet in a release. Deployment
— containers, reverse proxy, certificates — is documented in `docs/operations/` and in the
deployment's own repository, not here.

The CLI works on the **local** store, with the master key from a file or from the environment. It does not go through
the HTTP API, and that is deliberate: initializing a store, issuing a token, shredding a version,
verifying the chain, and exporting for migration all need the master key and have no endpoint by
design (ADR-3). A CLI that spoke HTTP would need a privileged API to do its job — the API this
project does not have.

Remote access is `curl` (see `openapi.yaml`) or, from phase 7, the SDK.

## Three rules that shape every command

**A value is never an argument.** There is no `--value` flag, and adding one would be a regression.
An argument lands in shell history and in `/proc/<pid>/cmdline`, where every other process on the
host can read it while the command runs. Values come from standard input:

```sh
printf %s "$VALUE" | ciphr put infra/service-a/DB_PASSWORD
ciphr put infra/service-a/TLS_KEY < key.pem
```

There is no interactive prompt either. Disabling terminal echo would need another dependency, and
prompting *with* echo writes the secret into the scrollback of whoever typed it. Piping is the one
route that leaves no copy behind. A trailing newline is stripped once, so `printf %s` and
`echo` both do the right thing; supply two if the value genuinely ends in one.

**A secret is not written to a pipe unasked.** `get`, `export`, `dump`, and `token issue` refuse
when output is not a terminal, because that is how a secret reaches a log, a CI transcript, or a
shell history through `$(…)`. Pass `--force` when it is intended:

```sh
ciphr get infra/service-a/DB_PASSWORD                 # refuses, tells you why
ciphr get infra/service-a/DB_PASSWORD --force > /tmp/x # deliberate
```

`export --format actions-env` is exempt: writing into the runner's environment file *is* its
purpose.

**One process holds a store at a time, and the running server is that process.** Every command that
opens a session takes an exclusive lock on the store, and the server holds that lock for its whole
lifetime. So while the service is up, such a command does not run — it fails before it touches the
database, and the message says what to do:

```
the store is in use by process 4711; stop it, run this, start it again.
Two writers collide on the audit sequence and leave the first one refusing every request.
```

**"Opens a session" includes the commands that only read**, and the list below is the whole reason
this paragraph is worth reading twice. The CLI audits what it does, reads included, so `get`, `list`,
`rotation <path>` and `audit tail` each append to the trail and are writers by the time the lock is
taken. Two of them surprise people:

- `token issue` — **issuing a credential requires stopping the service.**
- `token list` — **so does asking whether a credential is still valid**, when it expires, or when it
  was last used. It changes nothing and, unlike the other reads, records nothing either; it takes the
  lock all the same, because it opens a session to reach the store.

Plan both as scheduled operations with a short outage, not as something done while someone waits on
the phone — and note what the second one means for an incident: the question "is this token still
valid" has no answer from a live service today. The credential's state is not on `/v1/health`, and
`/v1/identities` carries names, kinds and policies but no expiry, no revocation and no last use.

The exceptions are `backup`, `audit anchor`, `audit verify` and `audit cut`, which need neither the
lock nor the master key and are documented as such below — they exist to run against a live service.
For `backup` that is the whole point: a copy of the store that could only be taken during a
maintenance window is a copy that stops being taken.

The rule is not bureaucracy, and the alternative is worse than an outage. The audit chain's head
lives in the writing process's memory: a second writer moves the head, the first does not notice,
and its next record carries a sequence number that is already taken. Fail-closed then does what it
promises and refuses the request — **every** request, permanently, until the server is restarted.
That was measured once, with one `ciphr put` beside a running server. The lock does not add a
constraint; it makes an existing one visible before the damage instead of as a `503` afterwards.

## Global options

| Option | Default | What it is for |
|---|---|---|
| `--database`, `-d` | `ciphr.db` | The store. |
| `--master-key-env` | `CIPHR_MASTER_KEY` | Variable holding 64 hexadecimal characters. |
| `--master-key-file` | — | File holding the key instead. Preferred where the deployment allows it; cannot be combined with the variable. See [master-key.md](master-key.md). |
| `--policies` | `policies.toml` | Needed by `token issue`, which checks the identity exists. |
| `--audit-file` | — | Also append this session's audit entries to a JSON Lines file. |

## Starting a store

```sh
# preferred: the key in a file the deployment mounts
printf %s "$(openssl rand -hex 32)" > /run/secrets/ciphr-master-key
chmod 0600 /run/secrets/ciphr-master-key
ciphr --database /var/lib/ciphr/store.db --master-key-file /run/secrets/ciphr-master-key init

# or from the environment
export CIPHR_MASTER_KEY=$(openssl rand -hex 32)
ciphr --database /var/lib/ciphr/store.db init
```

`init` refuses on a store that already has a root key: initializing twice would orphan every secret
in it. The first audit entry of a store is its own creation, so the chain starts at something rather
than at nothing.

Read [master-key.md](master-key.md) before the first real secret goes in. The short version: keep a
break-glass copy outside the host, and never in the same backup as the database.

## Everyday commands

```sh
printf %s "$V" | ciphr put infra/service-a/DB_PASSWORD
printf %s "$V" | ciphr put infra/service-a/JWT_SECRET --rotation invalidates-sessions

ciphr get infra/service-a/DB_PASSWORD
ciphr get infra/service-a/DB_PASSWORD --version 2
ciphr list infra
ciphr list --rotation unclassified                     # what has nobody looked at yet
ciphr versions infra/service-a/DB_PASSWORD
ciphr rotation infra/service-a/DB_KEY                  # what does it say, and why
ciphr rotation infra/service-a/DB_KEY breaks-data      # prints what to do instead
```

A secret written without `--rotation` is `unclassified`, not `rotatable`: the default is the absence
of an answer rather than a claim that rotating it is safe. See
[rotating-secrets.md](rotating-secrets.md).

All three forms here need the service stopped, like every other session command. Since 2026-08-21
`PUT /v1/secrets/{path}` takes an optional `rotation` alongside the value, which is the way to
classify an import that runs against a live service — the case the CLI cannot serve.

**`sys/` is refused.** `put` and `delete` under that prefix fail, because `sys/audit`,
`sys/identities`, and `sys/policies` are the virtual paths administrative access is authorized
against — a real secret there would make one policy rule mean two things. Storage enforces this, so
the CLI cannot get around it; until 2026-08-21 only the HTTP API did, and `ciphr put sys/audit`
worked.

Every one of these is audited, including the metadata ones. Setting a class writes a `classify`
entry — its own action, because it produces no version and would otherwise be invisible among the
value writes. The trail says the same thing whether an
access came through the API or from the host — a channel that records less is a channel someone will
use for that reason.

## Deleting, and destroying

```sh
ciphr delete infra/service-a/OLD_TOKEN                 # reversible
ciphr undelete infra/service-a/OLD_TOKEN --version 3
ciphr destroy infra/service-a/OLD_TOKEN --version 3 --yes
```

`destroy` deletes the version's wrapped data key. The value cannot be recovered afterwards by
anyone — including from a backup taken after the shred, which is the point. `--yes` is required, and
there is no HTTP equivalent.

**A backup taken *before* the shred is the other half of that sentence**, and it is the half that
surprises people: it still holds the wrapped key, so restoring across a `destroy` brings the value
back readable and ends the shred. Re-run `destroy` after any such restore — see
[backup.md](backup.md), which lists the three other decisions a restore rolls back with it.

Before destroying a version of a `breaks-data` secret, read
[rotating-secrets.md](rotating-secrets.md): a restore from a backup that predates a rotation needs
the value that was current then.

## Exporting into a process

```sh
ciphr export --prefix infra/service-a --format dotenv --force > .env
ciphr export --path infra/a/ONE --path infra/b/TWO --format json --force
ciphr export --prefix ci/widget --format actions-env --github-env
```

The variable name is the **last path segment**: `infra/service-a/DB_PASSWORD` becomes
`DB_PASSWORD`. Each exported secret produces its own audit entry, exactly as the bulk endpoint does.

`dotenv` single-quotes values and escapes embedded quotes, which is the one form that needs no
reasoning about what the shell will do with `$`, backticks, or backslashes.

### The masking trap

**No forge masks a value fetched at runtime.** Only its own native secrets are masked. A bare
`curl | jq` puts secrets in the job log the moment anyone adds `set -x` — and that log is usually
readable by more people than the secret store is.

`--format actions-env` therefore emits `::add-mask::` for every value **before** anything else, then
writes the assignments. The order is the whole point: a mask registered after a value has been
printed masks nothing that already went out. Multi-line values get one mask per line, because
runners match literal strings, and are assigned with a heredoc whose delimiter includes the variable
name so a value containing `EOF` cannot end its own block.

With `--github-env` the assignments go to the file named by `$GITHUB_ENV` and only the masks reach
standard output.

**Measured on a Forgejo runner, and claimed only there.** On 2026-08-18 the directive was exercised
on a real runner — `forgejo-runner exec -i -self-hosted`, the same binary and execution mode a job
uses, rather than a simulation — with a set of values differing from one another in a single
character. It holds for everything the format exists for: the same step, across steps through
`$GITHUB_ENV`, multi-line values, a value inside a composed URL, a value in the stderr of a failing
command. The multi-line round trip was checked by comparing SHA-256 digests rather than by printing
anything.

**It does not hold under `set -x`, which is the case masking exists for.** A runner matches a mask as
a literal substring, and bash re-quotes an argument before xtrace prints it: a value containing a
single quote renders as `'part'\''part'` — bytes inserted in the middle — and one containing a tab
as `$'a\tb'`, where the tab becomes the two characters after the escape. Both reach the log in
clear text. Everything else survives: a space, `$`, a backtick, a double quote and a backslash all
render inside single quotes with the content untouched, and multi-line values survive because the
mask is emitted per line. Hex and base64 values can never contain either character; a generated
password from a full punctuation alphabet contains a single quote roughly every third time at usual
lengths. So the rule for a job that holds fetched values is `set -x` off, not "the mask will catch
it" (`docs/review-2026-08-18.md`, finding 9).

**act_runner is not claimed.** "Both are act derivatives" is precisely the assumption this project
refused to make about the Forgejo runner before measuring it, and it stays refused: measuring needs
a Gitea runner to measure on, and where there is none the only alternative to measuring is
assuming. The statement above is therefore about the runner that was measured and not about the
family it belongs to. Plan section 21 carries that as a scoped claim rather than as outstanding
work.

## Migrating an existing corpus in

```sh
ciphr import --from-dotenv ./.env --prefix infra/service-a --dry-run
ciphr import --from-dotenv ./.env --prefix infra/service-a --rotation rotatable

render-config | ciphr import --stdin --prefix infra/service-a --dry-run
```

`--dry-run` prints target paths and value *lengths*, never values: it is something people run to
check their work, often with someone else looking at the screen. A line the parser cannot read stops
the import rather than being skipped — a partially moved corpus surfaces as a broken deploy much
later. Comments, blank lines, `export` prefixes, and quoted values are handled; `$VAR` references
are **not** expanded, because storing the expansion would store something the file does not say.

`--stdin` reads the same format from standard input, with the same parser, for a corpus that has no
`.env` on disk and should not acquire one in order to be migrated. The two are mutually exclusive
and one of them is required.

`--rotation` sets one class for the whole import, and a real `.env` mixes classes. The safe order is
to import with the most dangerous class present and then downgrade per path with `ciphr rotation`,
never the reverse: a wrong `rotatable` reads as "safe to rotate" and invites the one action that
destroys data. Importing without `--rotation` leaves everything `unclassified`, which is also safe —
it warns rather than reassuring — and `ciphr list --rotation unclassified` then says what is left to
do.

Where the estate is migrated service by service against a **running** instance, the per-path class
travels with the value instead: `PUT /v1/secrets/{path}` takes an optional `rotation`, so the
downgrade loop does not have to wait for a window in which the service is down. That is the shape to
prefer for a live migration; this command remains the one for a corpus moved with the service
stopped.

### What no import can do, and what to do instead

**A forge does not give a secret back.** Once a value is stored as a CI secret it can be overwritten
and used, not read out. So there is no import path from a forge, and there never will be one: the
only sources an import can have are a rendered file on a host, a process that can produce the values,
or the operator's own hands.

That bounds the migration rather than the tool. For a value whose only copy lives in a forge, the
honest move is **not** to hunt for a way to extract it:

1. Generate a new value, or take it from the system that is authoritative for it — a database
   password lives in the database, an API key in the provider's console.
2. `ciphr put` it, with the right `--rotation`.
3. Point the consumer at ciphr, through `ciphr-run`, the SDK, or a rendered file.
4. Remove the forge secret once nothing reads it.

That is a rotation performed deliberately, which is better than a copy: the value that was pasted
into a forge years ago and has been in every job log's blast radius since is retired rather than
carried forward. The exception is a value that **cannot** be regenerated — `breaks-data` and
`volume-bound` classes — where the value must be recovered from the system that holds it, or from
the operator, and entered with `put`.

## Tokens

```sh
ciphr token issue deploy-runner --ttl 90d
ciphr token list --identity deploy-runner
ciphr token revoke A1b2C3d4
ciphr token revoke-all deploy-runner
```

The identity must exist in the policy file: identities are defined there (ADR-3), and issuing a
token for a name nobody granted anything produces a credential that authenticates and can do
nothing.

The token is printed **once**. What the database holds is
`HMAC-SHA256(pepper, secret)`, and the pepper is derived from the root key — so a stolen database
does not permit offline verification of guessed tokens, and no `ciphr token show` can exist.

A TTL needs a unit: `90d`, `12h`, `30m`, `3600s`. A bare number is refused rather than assumed to be
seconds, because "90" meaning seconds when days were intended is a token that expires mid-deploy.
Prefer shorter lifetimes for CI than for a host: those tokens are spread across more systems.

Issuing and revoking are audited (`issue-token`, `revoke-token`), naming the operator who ran the
command, the identity the credential is for, and the token's non-secret id — never the token. A
`revoke-all` writes one entry per token rather than one for the batch, because the question asked
afterwards is when *this* credential stopped working. What that buys, and what it does not, is in
[audit-trail.md](audit-trail.md).

`revoke-all` is what to reach for when an identity is compromised — one call, rather than listing
tokens and hoping the list was complete.

**All four need the service stopped, `list` included.** It is a read, it records nothing, and it
still opens a session and therefore takes the lock — see the rule at the top of this page. The
consequence is worth planning around rather than discovering: the state of a credential (expiry,
revocation, last use) is readable only with the service down, which is the opposite of when the
question gets asked. Nothing on the API answers it either — a refused request is `401` with no
reason, deliberately, so that probing learns nothing.

## Backing up

```sh
ciphr --database /var/lib/ciphr/store.db backup /path/to/backup/store-2026-08-21.db
```

**`VACUUM INTO`, not `cp`.** A file copy of a running database reads a file that is moving underneath
it, so the result can be a snapshot of two different moments — and nothing reports it. This runs in a
read transaction and writes one file that is committed state as of one instant.

**It needs neither the lock nor the master key**, which is why it is in the short list of commands
that run against a live service. Nothing in it decrypts, so a scheduled backup job does not need the
highest-value secret in the deployment in its environment.

Four things it does that a shell script would have to remember:

- **Refuses an existing destination** rather than truncating it, so a mistyped path cannot destroy the
  previous backup.
- **Writes no `-wal` beside the copy.** The output is a single self-contained file whatever the source
  uses, which removes the mistake a file-level copy invites — a `store.db` taken without its `-wal` is
  silently missing the newest writes.
- **Opens the copy read-only afterwards** and checks it: `integrity_check` must pass and the schema
  version must match the source. The report on stdout is the file, its size and that version.
- **Opens the source read-only**, so backing up with a *newer* binary cannot migrate the database
  first. That would destroy the rollback the backup was being taken for, which is the one thing an
  upgrade backup exists to preserve.

**It writes no audit entry.** Two reasons, and both are worth stating rather than leaving as an
omission: an entry would need the lock, which would cost the property that makes the command useful;
and whoever can run this can already read the database file, so `cp` was available to them regardless
— the command adds convenience, not access. `audit anchor` is treated the same way, for the related
reason that recording itself would move the head it just wrote down.

What the copy is, and what it is not: it is ciphertext, worthless without the master key, and
therefore **not** a backup on its own. What else has to exist for a restore to be possible, and what
a restore undoes, is in [backup.md](backup.md).

## The audit trail

```sh
ciphr audit tail -n 50
ciphr audit verify

# record the head somewhere the writer of this store cannot reach
ciphr audit anchor --out /mnt/evidence/ciphr-anchors.jsonl

# and check the chain against the newest anchor in that file
ciphr audit verify --anchor /mnt/evidence/ciphr-anchors.jsonl
```

`verify` recomputes every hash and checks that each record chains to its predecessor. What it proves
and what it does not is printed with the result and explained in
[audit-trail.md](audit-trail.md): a verified chain shows no entry was removed, edited, or reordered,
and it does **not** show that nobody rewrote the chain forward.

`anchor` is what closes that. It writes one JSON line — sequence number, hash, timestamp — to
standard output and appends it to `--out`, so a scheduled job can pipe the record on without
filtering prose out of it; everything a person reads goes to standard error. Both commands read
**without the store lock and without the master key**, so they work while the server is running, and
`anchor` deliberately records no audit entry of its own: it would move the head it just wrote down.
Where the file lives is the whole value of the exercise — on the same host as the database, an anchor
proves nothing.

### Bounding it

```sh
# keep the newest 50 000 entries queryable; the rest must already be in the archive
ciphr audit cut --keep 50000 \
  --anchor /mnt/evidence/ciphr-anchors.jsonl \
  --archive /var/lib/ciphr/audit.jsonl

# see what that would do, and do none of it
ciphr audit cut --keep 50000 --anchor … --archive … --dry-run
```

The `audit_log` table grows for as long as the store exists, and because auditing is fail-closed a
full volume stops the service serving secrets. `cut` is the bound. Both file arguments are required,
and each answers a different objection to removing audit records:

- **`--anchor`** is where the anchor at the cut goes. Removing the oldest records leaves a chain that
  no longer starts at sequence one, so what remains can only be verified from the point the cut ended
  at — and if that point lives only in the store, it is a claim by whoever can write the store.
  The command appends **two** lines: the anchor at the cut, and one over what survived.
- **`--archive`** is the file device's file, rotated siblings included. Every record the cut would
  remove has to be in there byte for byte, or the cut is refused. The queryable copy may be bounded;
  the evidence may not be thrown away. `--assume-archived` replaces that check with an assumption,
  for a deployment whose lines are shipped off the host as they are written or whose rotated files
  are compressed and therefore unreadable here — it says what it is trusting on every run.

`--keep` is a count, not an age. The bound it answers is how large the queryable table is;
age-based retention belongs on the archive, where the host's log tooling already does it.

Like `anchor` and `verify`, `cut` needs **neither the store lock nor the master key**, so it runs
against a live service — a retention job that needed downtime would not get scheduled, and then the
bound would not exist. It writes no audit entry of its own for the same reason `anchor` does not, and
its record in the store is the `audit_cut` row. A trail shorter than `--keep` is reported and exits
zero; every refusal happens before anything is removed.

The reason this is a command and not something the service does on a schedule: a cut has to be
anchored outside the store, and the service is the thing an anchor exists to be independent of. An
anchor the service wrote about its own trail is worth nothing against the service.

## Rotating the master key

```sh
ciphr rotate-master-key --new-key-file /run/secrets/ciphr-master-key.new
# or
export CIPHR_NEW_MASTER_KEY=$(openssl rand -hex 32)
ciphr rotate-master-key --new-key-env CIPHR_NEW_MASTER_KEY
```

The old and the new key may come from different kinds of source, which is how a deployment moves from
the environment to a file: read the old one from the variable, write the new one to the file, rotate.

One record changes and nothing is re-encrypted — that is what the root key exists for. Keep the old
key until a restart with the new one has been confirmed; the window between the rewrite and a
successful restart is the one where having discarded it too early would be unrecoverable.

## Leaving

```sh
ciphr dump --format portable --force > ciphr-export.json
```

Every value in that file is plaintext. Treat the file as the secret store itself: it is the one
artifact that is exactly as sensitive as the database plus the master key.

It exists on purpose. If this project ever struggles at the cryptographic or authorization layer,
moving to OpenBao is the correct decision, and a migration must not fail because of a proprietary
file format. Insurance bought after the fire is worthless, which is why this shipped in v1 rather
than being left for the day it is needed.
