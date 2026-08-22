# Upgrading

**Status:** current as of 2026-08-22, covering every released version up to `0.6.0` plus the
unreleased change below.

The changelog says what changed. This says what to *do* about it, and it exists because the two are
not the same document: a changelog entry sinks under the next release, while the person upgrading two
versions later needs the same four sentences that mattered the first time.

## The rules that hold for every upgrade

**Back up the database before starting the new image.** The server migrates the schema on start, and
migrations are one-way — there is no down-migration in this project and there will not be one. An
older binary refuses a database it does not understand, with `SchemaTooNew`, rather than working on
it and corrupting something.

**That refusal is the whole reason a rollback needs a plan.** Once the new server has started once,
going back to the previous image means restoring the database from the backup. A container rollback
alone leaves the old binary in front of a newer database, and it will not start.

**The anchor file belongs in the backup too**, and is never rewritten. After any restore, run
`ciphr audit verify --anchor <file>`. A database restored from a backup older than the newest anchor
reports `AnchorUnreachable`, which means "older than the evidence" and not "tampered with" — see
[audit-trail.md](audit-trail.md).

**A backup taken the wrong way is the one failure this document cannot warn you about later.** How to
take one that is not torn, what else has to be in it, and what a restore undoes are in
[backup.md](backup.md). Two short versions, because these are the steps nobody reads twice: use
`ciphr backup` rather than `cp`, and if the binary is not available, the `-wal` file is part of the
database and a `store.db` copied without it is silently missing the newest writes.

**Read the changelog entry for every version you are skipping**, not only the one you are landing
on. The breaking notes below are per version and they accumulate.

## The order of operations

1. Take the backup with the **old** binary: `ciphr backup /path/to/backup/store-<date>.db`, plus the
   configuration, the policy file, and the anchor file. See [backup.md](backup.md).
2. Stop the service.
3. Start the new image. It migrates on start; watch the log for the migration lines.
4. Run `ciphr audit verify` — with `--anchor` if a file is kept.
5. Only then update anything that consumes the API: the viewer, the SDK, `ciphr-run`.

**Step 1 says "the old binary" for a reason that only bites here.** `ciphr` and `ciphr-server` both
migrate the schema on an ordinary open, so a pre-upgrade backup taken with the *new* binary any other
way would have migrated the database first — destroying the rollback the backup exists for. `ciphr
backup` opens the source read-only and cannot do that, which is why it is safe either way; a `cp`
after the new binary has already been run once is not.

**This step used to read "back up, then stop", and copying a running database with `cp` is the one
backup mistake that produces no error.** `ciphr backup` runs against a live service, so the ordering
question is gone. Without it — a deployment on `0.5.1` or earlier — stop first, and copy the database
**and its `-wal` sibling if one is there**, never the `.lock` file. The `-shm` file was in this list
and is not part of the database: SQLite recreates it, and carrying a stale one gains nothing.

Step 5 is last on purpose, and from `0.3.0` it is load-bearing rather than tidy — see below.

From `0.4.0` there is a step 0: **check the file modes below before stopping anything.** A refusal
there happens at start, which is the worst moment to discover it.

From `0.5.0` step 0 has a second half: **run `ciphr-server --check-config <file>` against the new
binary and the configuration you mean to run it with.** That release adds two refusals about surface
entries, and it is also the one that makes four existing routes conditional on the configuration — so
the file that started the previous version can be a file this one declines, and a `404` on the viewer
is a quieter way to find out than a process that will not start.

**Read its surface report and not only its exit code.** The mistake this release makes possible is a
*forgotten* stanza, and that file is legal: the command exits zero on it, because off is a legitimate
deployment and most deployments should have `viewer_api` off. What it prints is the list of entries
the binary knows and the mark against the ones this file did not name, which is the only place that
question is answered — an entry that is off is absent from the router, so its `404` is byte-identical
to a typo'd path.

## Unreleased

### `0.6.0` is a partial release — take `0.6.1`

The wrapper image `…/run:0.6.0` does not exist, and neither do the `v0.6.0` release assets: that build
failed after the server image had already been published. Nothing is wrong with the server image —
`0.6.1` is the same code — but a host that mounts `ciphr-run` cannot obtain the `0.6.0` copy, and the
fetch sequence in [wrapper.md](wrapper.md) needs `0.6.1`.

**What to do:** pin `0.6.1` for both images. There is no schema move and no configuration difference
between them, so if the server is already on `0.6.0` this is an ordinary re-pin at the next
convenient moment rather than something to hurry.

**Not affected:** anything already mounted. A wrapper file on a host keeps working; this is about
where a *new* copy comes from.

## 0.6.0

### Use `ciphr backup` for the backup this document asks for

The pre-upgrade backup now has a command. `ciphr backup <destination>` needs neither the store lock
nor the master key, so it runs with the service up; it writes one file with no `-wal` beside it;
it refuses an existing destination rather than truncating it; and it checks the copy it wrote. The
order of operations above changed to use it, and it changed the ordering too — "back up, then stop"
was only ever safe because it was assumed to mean `cp` on a *stopped* service.

**What to do:** nothing, if the previous procedure was followed with the service stopped. If a
backup job ran `cp` against the live volume, replace it — that is the one backup mistake that
produces no error, and it has been producing possibly-torn copies for as long as it has been running.
Verifying an existing backup is `ciphr --database <copy> audit verify`, which needs no key.

**Not affected:** the restore side. A backup taken either way restores the same way, and
[backup.md](backup.md) has the procedure.

### `ciphr state` answers what has to be kept, and doubles as a pre-flight check

`ciphr state <config>` derives the file set a deployment has to back up from that deployment's own
configuration, rather than from the table in [backup.md](backup.md) that somebody has to remember to
edit. **A non-zero exit means a file the configuration requires is not there** — a store before
`init`, a policy file that did not mount, TLS material that is not where the configuration says. Each
of those is a service that will not start.

**What to do:** run it before the service is stopped, not after. That ordering is the whole value: a
missing file found while the old service is still serving is a correction, and the same file found on
the first start of the new one is an outage. It needs no key and takes no lock.

**Two absences it deliberately reports without failing:** the write-ahead log, which exists only
between checkpoints, and the audit archive, which the file device creates on its first record — so a
fresh deployment that has never started legitimately has none. Nothing here can tell that apart from
an archive somebody deleted, so it says so rather than failing on every new deployment.

**Not affected:** anything running. The command reads a configuration file and stats the paths it
names; it never opens the store and never reads the master key, and a test asserts the key's value
does not reach the output.

### A container stop now runs the graceful shutdown

`docker stop` sends SIGTERM. The graceful shutdown awaited `tokio::signal::ctrl_c`, which on Unix is
SIGINT and nothing else, so on an ordinary stop the process was terminated instead: a request that
had been audited and not yet answered was dropped, leaving a trail entry for an access the client
never received. Both signals are handled now.

**What to do:** nothing. No configuration changes and nothing is at risk in the database either way —
`synchronous = FULL` and WAL mean an abrupt stop costs no committed write. Two consequences worth
knowing: the audit trail stops recording accesses that did not happen, and a clean stop now
checkpoints the write-ahead log away, so a file-level backup after a *graceful* stop no longer finds
a `-wal` to copy. A killed container still leaves one, so [backup.md](backup.md) still says to check.

### Nothing to do about the rotation class in listings

`GET /v1/list/{prefix}` gained an `entries` array and an optional `?rotation=` filter. Purely
additive: `paths` is unchanged, every existing client keeps working, no schema moves, and no
configuration changes. Rolling back is safe.

Worth knowing rather than doing: *what has nobody classified yet?* is now answerable against a
running service — `GET /v1/list/{prefix}?rotation=unclassified` — where before it needed
`ciphr list --rotation unclassified` on the host with the service **stopped**, because the CLI took
the exclusive store lock. If a rotation review was scheduled around a maintenance window for that
reason, it no longer has to be. (The CLI listing answers live too now, for a different reason and
with one thing to do about it — the note below.)

### The CLI's metadata listings answer live now, and stop appearing in the trail

`ciphr list` (including `--rotation`), `ciphr versions`, `ciphr rotation <path>` without a class, and
`ciphr token list` open the store read-only: no exclusive lock, no master key, **and no audit entry**.
They answer while the service runs, which is the point — "is this token still valid" and "what has
nobody classified" are questions asked during an incident, and until now both required stopping the
secrets service to ask. The reasoning is [ADR-22](../adr/0022-the-trail-records-what-consumed-an-authority.md):
those columns are plaintext in the database file, so an entry only the polite reader writes measures
politeness rather than access.

**What to do — one thing, and only if the trail is monitored for them.** A host-side listing stops
producing an audit entry, so an alert or a report that counted them counts zero from this version on.
Adjust or retire it, and note why the count was never the measure it looked like: whoever can run
`ciphr list` can read the same rows with `sqlite3` on the same file and leave nothing behind.

**What did not change:** `get` and every mutation stay audited and session-bound — `get` spends the
master key, and that entry measures something nobody affected can route around. **The API's `list`
entries are untouched**, because an API caller cannot read the file; there the entry still records an
authorization. The audited, authenticated answer to "is this token valid" remains a proposed endpoint,
not this command.

**Also new, and worth knowing before an incident:** a refusal under the store lock on `get`, `put`,
`delete` and `export` now also names the equivalent live route (`GET /v1/secrets/{path}` and so on).
It names it and never calls it — a CLI that silently routed to the API when it found a lock file would
make one command mean two identities, decided by whether a file exists.

**Not affected:** rollback. An older binary takes the lock and writes the entries again. Nothing in
the store changes and the schema stays at 6.

### The `ciphr-run` release asset has a new name

The file attached to a release tag is now `ciphr-run-x86_64-unknown-linux-musl`, with its checksum
as `ciphr-run-x86_64-unknown-linux-musl.sha256`. It was `ciphr-run` and `ciphr-run.sha256`.

**What breaks:** any script that fetches the wrapper from a release tag by that name. It will fail
to find the asset, which is a loud failure rather than a quiet one — nothing downloads a wrong file.
Nothing that is already deployed changes: the binary is byte-identical, and a wrapper already sitting
on a host keeps working untouched.

**What to do:** update the asset name in the fetch step. There is no compatibility copy under the old
name, deliberately — one release publishing both names is the inconsistent pair this change exists to
avoid, and while this repository is private the consumer side is the same people making the change.

**Not affected:** the registry route. The file inside `<image>/run` is still `/ciphr-run`, so the
`docker create` / `docker cp` sequence in [wrapper.md](wrapper.md) is unchanged. An image says which
architecture it is in its own manifest; a file pulled from a tag says it only in its name, which is
the whole reason the two differ.

**Why now, with one architecture.** Renaming the asset costs a line today and costs every fetch
script the day a second architecture appears. Multi-arch itself is still deferred and this does not
change that — it only removes the part of that decision that gets more expensive by waiting.

## 0.5.1

**Nothing to do, and a rollback is safe.** Schema stays at 6, no interface moves, and the
`[[surface]]` stanzas `0.5.0` needs are the ones `0.5.1` needs — so going back to the
`0.5.0` image needs neither a database restore nor a configuration edit. The general rule
at the top of this document relaxes for this upgrade, as it did for `0.4.0`.

**One thing to re-read, if you decided about `bulk_export` on what `0.5.0` told you.** That
entry's cost sentence claimed that turning it off removes fetched prefixes, and therefore
makes a honeypot secret easier to place. It does not, and the `0.5.0` section below has the
correction in full. Short version: `POST /v1/export` reads the paths a caller *names*, and
`GET /v1/list/{prefix}` is not a surface entry, so a caller that lists a prefix and then
reads each path covers the same prefix either way. What turning the entry off actually costs
is `ciphr-run` entirely — both `--prefix` and `--path` fetch through that route — and one
request per path for an SDK consumer.

A deployment that turned `bulk_export` off *for that reason* has paid a real cost for a
property it did not get, and the fix is a decision rather than a command: either name the
entry again, or keep it off on the grounds that actually apply. Where bait sits is settled
by reading the fetching code, which is what [honeypots.md](honeypots.md) says.

**`--check-config` says more than it did.** It now prints the resolved surface: the entries
the configuration named, and the ones it did not with what each absence costs. Worth one run
after the upgrade even though nothing requires it — on a `0.5.0` file it answers the question
`0.5.0` could not, which is whether the file is the one you meant rather than merely a legal
one. `ciphr surface show <config>` does the same from the host.

**A consumer built on `ciphr-sdk` can drop its own `ciphr-core` dependency.** The types that
forced it — `SecretPath`, `Plaintext`, `SecretVersion`, `EnvVarName`, `Rotation`, `PathError`,
`EnvNameError` — are re-exported from `ciphr_sdk` now. Nothing breaks if it stays; the
`ciphr_core::` paths still work.

## 0.5.0

**This release has a breaking change, a one-way schema migration, and a new refusal to
start.** Read all three before scheduling it.

### Four routes stop existing unless you name them

`GET /v1/audit`, `/v1/identities`, `/v1/policies` and `POST /v1/export` are now surface
entries (ADR-20). Without a stanza for each, they answer `404` — the viewer stops working
and `ciphr-run` refuses with exit code `125` rather than starting a service without its
secrets. **Add this to the server configuration before deploying**, or accept the loss
deliberately:

```toml
[[surface]]
entry    = "viewer_api"
accepted = "2026-08-21"
reason   = "the audit viewer runs beside the service"

[[surface]]
entry    = "bulk_export"
accepted = "2026-08-21"
reason   = "ciphr-run fetches whole prefixes on service start"
```

All three fields are required. `ciphr surface show <config>` prints what each entry costs
next to your reason **and lists the entries the file did not name**, which is the check
worth running against the file you are about to deploy; `GET /v1/health` lists the entries
the running service has.

**Take the loss where you can — for `viewer_api`.** A deployment with no viewer was serving
those three routes to nobody, while putting the policy structure and the identity inventory
on the network for anyone holding any token. Turning that entry off costs such a deployment
nothing.

**`bulk_export` is a different decision, and an earlier version of this note argued it
badly.** It said that turning the entry off removes fetched prefixes, and therefore makes a
honeypot secret easier to place. It does not. `POST /v1/export` reads the paths a caller
*names* — there is no prefix in the request — so whether a prefix is covered is a property
of the fetching code, and `GET /v1/list/{prefix}` is not an entry: a caller that lists a
prefix and then reads each path covers the same prefix with the entry off. What turning it
off actually costs is `ciphr-run` entirely, because both `--prefix` and `--path` fetch
through this route, and one request per path for an SDK consumer. Decide it on that, and
place bait by reading the consumer — [honeypots.md](honeypots.md) says how.

### Schema 6 is a one-way door, and a rollback is two-part

Back up the database, its `-wal` and `-shm` siblings, and the anchor file first. A `0.4.0`
binary refuses a schema-6 database with `SchemaTooNew`, so a rollback needs the restore.
The migration is additive — two columns and a table for bait — and touches no existing row.

**A rollback also needs the `[[surface]]` stanzas taken back out**, and this is the half
that surprises. `Config` rejects unknown top-level keys, so the configuration `0.5.0`
requires is one `0.4.0` cannot parse — the older binary stops with a TOML error naming
`surface`, the stanza this note told you to add, in a moment you believe is about the
database:

```
ciphr-server: invalid configuration in …: TOML parse error at line 82, column 3
   |
82 | [[surface]]
   |   ^^^^^^^
unknown field `surface`, expected one of `server`, `storage`, `seal`, `policies`, `audit`
```

It fires before the store is touched, so nothing is half-rolled-back. Keep the previous
configuration file beside the database backup and the rollback is two restores rather than
an edit under pressure.

### The service can refuse to start on its own configuration

Two new refusals, both about surface entries and both deliberate:

- A `[[surface]]` stanza with no `accepted` date or no `reason`. A flag with no reason
  beside it reads as an accident six months later, and the safest-looking fix for an
  accident is the default.
- A stanza naming `honeypot_alert` in a binary built without that feature, or a binary
  built *with* it and no stanza. The second direction is the one that matters: without it a
  deployment could believe it had bait detection, have written down when and why, and have
  none — and nothing would ever say so, because bait that cannot fire looks exactly like
  bait nobody took.

`ciphr-server --check-config <file>` exercises both without starting the listener. Run it
before you stop anything.

**It also prints the resolved surface**, which is what makes the recommendation above worth
following for this release rather than only the next one. A *missing* runtime stanza is
legal, so this command cannot refuse the file that started `0.4.0` — but it now names every
entry the binary knows, marks the ones this file did not name as off, and prints what each
absence costs. That is the difference between "the configuration is usable" and "the
configuration is the one you meant":

```
configuration and policies are usable

surface: 0 of 3 entries on (ADR-20)
  off  viewer_api      runtime  not named by this configuration
       The viewer stops working. The CLI does not: …
  off  bulk_export     runtime  not named by this configuration
       `ciphr-run` cannot fetch at all: …
  off  honeypot_alert  build    not named by this configuration, and not in this binary
       No detection of bait. …
```

`ciphr surface show <config>` prints the same off list from the host, without needing the
store or the master key.

### A strict consumer of `GET /v1/audit` needs a look, again

Records gain a `detail` field — `null` on everything except `surface-active` and
`honeypot-triggered` — and there are four new `action` values: `surface-active`,
`honeypot-triggered`, `honeypot-marked`, `honeypot-cleared`. `deny_reason` gains
`latch-failed`. A consumer that rejects unknown fields or unknown actions needs updating;
the CLI, the SDK and the viewer all tolerate both by design.

`GET /v1/health` gains `surface` (always) and `tripped`/`open_tripwires` (only in a build
with `honeypot_alert`). **Absent rather than `false`** where the build lacks it: "this build
cannot detect bait" and "nothing has been taken" are different facts, and a monitor that
conflates them reports a working tripwire on a service that has none.

### Honeypots are off unless you build for them

The `alert` tier of ADR-15 is a **Cargo feature**, absent from the default binary, so the
default artefact of this release contains none of it. That is also what makes it safe to
release: the surface it adds is newer than the accepted external review, and
[../security-review.md](../security-review.md) marks the three claims that describe it as
uncovered. Turning it on is a decision about accepting unreviewed code on the
authentication path. [honeypots.md](honeypots.md) is the runbook, and it leads with the
condition this software cannot check: something has to poll `/v1/health` and page a human.

### Nothing to do about the rest

`PUT /v1/secrets/{path}` accepts an optional `rotation` so an import over the API does not
leave every path `unclassified`. `GET /v1/surface` is new. No interface moves.

## 0.4.0

**Check the mode of the master key file and every token file before you deploy.** This is the only
change in this release that can turn a working deployment into one that does not start. The refusal
for a credential file anyone can reach now covers world-**writable** as well as world-readable, so a
file at `0602`, `0666` or `0622` starts the process today and stops it after the upgrade. It applies
to two files:

```sh
stat -c '%a %n' /path/to/master.key /path/to/token   # want 0600, or 0640 / 0660 for a service group
```

Group bits are still accepted, read and write alike. The refusal names which of the two bits it
found, so a log line from a failed start says exactly what to fix. On a container whose key comes
from a bind mount off a Windows or macOS host, mode `0777` is reported for every file regardless —
that is the pre-existing false positive, the message says so, and the answer is a named volume
rather than a weaker check.

**No migration, and a rollback is safe.** Schema stays at 5. This is the first release here without
a one-way door, after schema 4 in `0.2.0` and schema 5 in `0.3.0`, so the general rule above relaxes
for this one upgrade only: going back to the `0.3.0` image needs no database restore. The new audit
records do not trouble an older binary either — nothing on the read path parses a record into a
strict struct, and verification hashes the stored bytes rather than re-serializing them.

**A strict consumer of `GET /v1/audit` needs a look.** Two additions: records carry a `subject`
field (who an action was *about*, set by the token operations and null everywhere else), and
`deny_reason` has two new values, `delete-failed` and `not-listed`. A consumer that rejects unknown
fields, or that treats every `deny_reason` as a denial, needs the update — a correcting entry is not
a denial, and `openapi.yaml` now says so where the enum is defined. The CLI and the viewer are in
this release.

**Expect a few more audit entries per failed request, not per request.** A `delete` that deletes
nothing, a version listing of a missing path, and an export that aborts now each write a second
entry recording that the authorized work did not happen. A failing export writes one correction per
path it had already recorded, bounded by the paths in that request. Steady-state volume does not
change; a client in a retry loop against a missing path writes twice what it used to.

**Nothing to do about the rest.** The token codec no longer leaves unwiped copies of a token secret
in freed heap memory, `ciphr put sys/…` is refused by storage rather than only over HTTP, and two
documentation claims were narrowed to what the code does. No interface moves.

## 0.3.0

**The viewer must not be deployed before the service.** `GET /v1/versions/{path}` returns an object
where it returned a bare array, and the viewer built for `0.3.0` reads the object. Pointed at a
`0.2.0` service it finds no `versions` field. The viewer image is therefore tagged and published
*after* the service is live, so the wrong order is hard rather than merely discouraged — but if both
images exist by the time you read this, the order still applies.

**Any other client of `/v1/versions/{path}` needs the same upgrade.** Anything that parsed the
response as an array breaks. `openapi.yaml` carries the new schema, and `ciphr-sdk` handles it from
`0.3.0` (`versions()` returns `History` rather than `Vec<VersionSummary>`).

**Schema 5 is the second one-way door**, after schema 4 in `0.2.0`. The general rule above applies:
back up first, and do not plan an image rollback after the first start.

**Every secret that was `rotatable` is now `unclassified`, and there is work to do.** The default
class used to be `rotatable` — a claim that rotating is safe, attached to every secret whose writer
never passed `--rotation`. Migration 005 resets those, and leaves every other class untouched,
because nobody types `breaks-data` by accident while `rotatable` might be either a decision or the
old default. **This includes values somebody classified `rotatable` deliberately**; nothing recorded
which was which.

So after upgrading:

```sh
ciphr list --rotation unclassified
```

and work the list with `ciphr rotation <path> <class>`. Until then those secrets warn rather than
reassure, which is the safe direction — nothing is broken by taking a week over it.
[rotating-secrets.md](rotating-secrets.md) has the question to ask per secret.

**Setting a class now writes a `classify` audit entry**, from `ciphr rotation`, `put --rotation` and
`import --rotation` alike. Expect the trail to grow by one entry per classification during the pass
above. A trail that is close to its retention bound may want `ciphr audit cut` scheduled before it,
not after.

**Audit entries now carry the address the request came from.** Nothing to do; the field was always in
the record and was always null.

## 0.2.0

**`ciphr export --format dotenv` and `--format actions-env` can refuse where they used to succeed.**
Two paths under one prefix sharing a last segment used to export as the same variable name and the
second won — a service received a valid secret that was the wrong one, with both reads recorded as
successful. It is now a refusal naming both paths, as is a path segment that cannot be a variable
name. Nothing is written when either fires. `--format json` is keyed by full path and is unaffected.
The fix is to rename the path or export as JSON.

**`import --from-dotenv` rejects a key with a leading digit** (`1FOO=x`), which it used to accept.

**Schema 4 is a one-way door.** `ciphr audit cut` refuses on a database that has not been migrated
yet, and refuses before writing anything — including to the anchor file. So: start the new server
first, then schedule the cut.

**`ciphr-run` arrived**, and with it a second image (`<image>/run:<version>`) carrying the static
wrapper. See [wrapper.md](wrapper.md) for how to get the file out and what its exit codes mean.

## 0.1.0

The first tagged version. Nothing to upgrade from.
