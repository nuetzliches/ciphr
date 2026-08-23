# Upgrading

**Status:** current as of 2026-08-23, covering every released version up to `0.10.0`.

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

**Since 0.8.0 that report needs neither a store nor a key, so this step is runnable in review.** The
command prints the configuration, the policy counts and the whole surface report first, and reports
store readiness as its own last section; only that last section needs a host. So the same binary that
will run the file can check the file in a pipeline, with nothing mounted but the two `.toml` files —
which is where a configuration edit is actually reviewed. On the host it also no longer takes the
store's writer lock, so it runs while the service is up, and it neither migrates the store nor writes
to the audit trail.

**Since 0.10.0 a pipeline can branch on the status alone**, which is what makes this step a gate
rather than a report somebody remembers to read:

| Exit | What it means | What to do |
|---|---|---|
| `0` | the files are usable and this host is ready | proceed |
| `1` | the files are not usable — a refused rule, a stanza this binary cannot honour, a parse error | fix the file; the reason is on stderr |
| `2` | usage error: no path, or a misspelled flag | fix the invocation |
| `3` | the files are usable, this host is not ready | on a review host, expected. On the target host, read the `store:` section |

A review host wants to fail on `1` and `2` and to accept `3`; the host itself wants `0` and nothing
else ([field-report-2026-08-23.md](../field-report-2026-08-23.md), finding 1, and
[field-report-2026-08-23-b.md](../field-report-2026-08-23-b.md), finding 1).

## 0.10.0

### `--check-config` has its own exit code for "the files are usable, this host is not"

**Check anything that branches on this command's status.** A host whose store is absent, sealed under
a different key, or missing an audit device was exit `1` and is now exit `3`. `1` now means one thing
only: the *files* are unusable — a policy rule the binary refuses, a surface stanza it cannot honour,
a configuration that does not parse. `2` is still the usage error, and `0` is unchanged.

**Why this release and not the last one.** `0.8.0` split the report so the file half holds without a
host, and `0.9.0` then made a policy edit mandatory and named review as the place to catch a file that
still has the old form — where there is no store by design. Both cases exited `1`, so the pipeline
this document recommends could not tell the finding it runs for from the host it runs on, and what was
left was parsing a dozen lines of prose. The precedent is this project's own: `ciphr state` got exit
`3` in `0.8.0` for the same shape, a complete answer whose negative half is about something other
than what the caller asked.

`ciphr state` and `--check-config` therefore agree: `3` means the command answered and this host is
missing something ([field-report-2026-08-23-b.md](../field-report-2026-08-23-b.md), finding 1).

### `--check-config` says when `token_revoke` is on and nobody can call it

**Nothing to do, and one new line to expect.** Where the `token_revoke` entry is on and no identity
in the policy file is authorized for `revoke` on `sys/tokens`, the report says so under the surface
list. The exit code does not change: an entry switched on before its identity exists is a legitimate
order of work, and the note exists so that it does not stay that way unnoticed. An entry that is on
and unreachable is the same class of quiet as a stanza that was forgotten, which is the mistake the
surface report exists to catch.

### An audit device that cannot be opened names the requirement, not only the OS error

**Nothing to do.** The message was `audit device: cannot open <path>: Read-only file system
(os error 30)`, which reads as a broken device when the fact is that the directory was mounted
read-only. It now says that the file device is opened for append and that its directory has to be
writable by the service user. The behaviour is unchanged, at start and in `--check-config` alike: the
device is checked by opening it the way it will be opened
([field-report-2026-08-23-b.md](../field-report-2026-08-23-b.md), finding 2).

## 0.9.0

### The control plane needs its own capability, and a policy file that says `read` there is refused

**This is the one thing to do before starting the new binary, and `--check-config` finds it without a
store or a key.** `read` used to authorize a secret's value *and* the control plane — `sys/audit`,
`sys/identities`, `sys/policies`, `sys/surface`, `sys/honeypots` — with only the path separating them,
so a broad `path = "**"` with `read` granted the audit trail and the map of the authorization model
along with every secret. It does not any more
([ADR-23](../adr/0023-the-control-plane-is-its-own-capability.md)).

Two new capabilities: **`inspect`** reads a control-plane path, **`revoke`** revokes a token. The five
existing ones mean secrets and only secrets.

**What to do**, and it is one edit per policy file:

```toml
  [[policy.rule]]
  path         = "sys/audit"
  capabilities = ["inspect"]      # was ["read"]
```

**The server refuses to start on the old form** rather than accepting a grant that would authorize
nothing, and names the capability meant instead. That refusal is deliberate: a monitoring identity
that silently sees nothing after an upgrade is worse than an edit. Run
`ciphr-server --check-config <file>` against the new binary and the policy file — since `0.8.0` that
needs neither a store nor a master key, so this is findable in review.

**Who is affected.** Any identity that reads the control plane: the viewer's token
([ui.md](../ui.md)), a monitoring identity that polls `GET /v1/audit`, anything reading
`/v1/identities`, `/v1/policies`, `/v1/surface` or `/v1/honeypots`. **Who is not:** an identity with
only secret grants, however broad — including `**`. Those files load unchanged, and they simply no
longer reach `sys/`.

**Not affected either:** the CLI's own access. It reads the trail, the identities and the policies
from the store with the master key, and no policy capability is consulted on that path.

`sys/**` with an empty capability list still works and is now belt and braces — nothing needs it, and
a deployment that wants the denial stated in its own file can keep it.

### Revoking a leaked credential no longer needs an outage, where a deployment turns it on

`POST /v1/tokens/{token_id}/revoke`, behind the new **`token_revoke`** surface entry
([ADR-24](../adr/0024-revocation-is-the-one-write-the-api-may-do.md)). Off unless a deployment names
it, and off means the route is never registered — nothing changes for anyone who leaves it alone.

```toml
[[surface]]
entry    = "token_revoke"
accepted = "2026-08-23"
reason   = "the honeypot runbook's revoke step must not take the service down"
```

The caller needs `revoke` on `sys/tokens`; the revocation takes effect on the leaked credential's next
request, because the server already checked revocation per request. **This is the only write this API
has ever had**, and the boundary is drawn in the record: issuing stays on the host because it needs
the master key and creates a credential, and `revoke-all` stays there because one request that
invalidates every credential of an identity is an availability weapon.

**Worth reading before turning it on:** a token holder with that capability can invalidate credentials
over the network. That is what the entry's `reason` field is for. `honeypots.md` step 3 now describes
both cases — with the entry, and without it.

### The token inventory can be read over the API, where a deployment turns that on

`GET /v1/tokens`, behind the new **`token_status`** entry, needs `inspect` on `sys/tokens`. It
answers the incident question — which credential, still valid, last used when — **as an
authenticated caller and in the trail**, which is what `ciphr token list` cannot do: that path
records nothing and its principal is `cli:$USER`, self-declared. The host path is unchanged and stays
available whether this entry is on or off.

```toml
[[surface]]
entry    = "token_status"
accepted = "2026-08-23"
reason   = "the on-call rotation asks which token to revoke without shell access to the host"
```

**Its own entry rather than part of `viewer_api`**, because the cost is its own: which credentials
exist, and which have never been used, is a good list of the ones nobody would notice being used.
Nothing about the response is derived from a secret — no verifier, no token — and `state` (`valid`,
`expired`, `revoked`) is now derived in one place shared with the CLI, so the two cannot disagree
about what `valid` means.

### The listener speaks HTTP/1.1 only, and now says so itself

**Nothing to do unless a client of yours negotiates HTTP/2 against this service — in which case it
was doing so by accident and stops.** `axum-server` set the ALPN list to `["h2", "http/1.1"]` while
nothing in this repository mentioned ALPN at all, so the listener that holds plaintext secrets
advertised a second framing implementation ADR-9's narrow-stack argument never chose. Issue #6 read
that out of the sources; a real handshake confirmed it.

`crate::tls::load` now sets the list itself: **`http/1.1` and nothing else.** A client offering both
gets HTTP/1.1; a client that speaks only HTTP/2 gets no handshake. `h2` stays compiled in — removing
it means replacing `axum-server` with our own accept loop and graceful shutdown, which is code on the
connection path we would then have to review ourselves — and
`crates/ciphr-server/tests/tls_alpn.rs` pins the negotiated protocol so a dependency bump cannot
quietly restore it. ADR-9 is amended to describe the artefact rather than the manifest.

**Who could notice:** an SDK or `curl --http2` call that was silently using HTTP/2. Both fall back to
HTTP/1.1 on their own; `curl --http2-prior-knowledge` does not and will fail.

### The surface list has two more entries, so three outputs grew rows

`--check-config`, `ciphr surface show` and `GET /v1/surface` all list `token_status` and
`token_revoke` now — as *off*, with their cost sentences, in every deployment that does not name
them. Five entries in total. Nothing to do; noted because a check that diffs those outputs will see
it.

## 0.8.0

### `--check-config` answers about the file first, and about the host last

**Nothing to do, and one thing to know: the output has a new shape.** The command now prints the
configuration path, the policy counts and the whole surface report before it looks at storage, then a
final `store:` section that either says `ready (schema …, seal …, key from …)` or names the reason it
is not. The first line is unchanged — `configuration and policies are usable` — and so is the exit
code: zero when the store is ready, non-zero when it is not.

**What this makes possible** is the reason for the change: the report that catches a *forgotten*
surface stanza is now reachable with only the two `.toml` files, so a configuration edit can be
checked in review or in a pipeline by the same binary that will run it. Before this it needed a store
and a key at the paths the configuration names, which on a review host means fabricating both — a gate
satisfiable by fabrication, so it protected nothing.

**Three side effects are gone**, and each one was a reason the check could not be run where it was
wanted:

- It no longer takes the store's **writer lock**, so it runs while the service is up.
- It no longer **migrates** the store. `SqliteStore::open` migrates on open, so pre-flighting a `0.7`
  store with a `0.8` binary used to perform the schema move that the pre-upgrade backup exists to
  make reversible. It opens read-only now.
- It no longer writes a **`surface-active` audit record**. That entry belongs to a process about to
  serve, and a check is not one.

`ciphr surface show <config>` is unchanged and still the CLI-side answer; it reads the file rather than
the binary, so it cannot speak for a build entry. From `docs/field-report-2026-08-23.md`, finding 1.

### `ciphr state` exits `3` when the listing is complete and a required file is absent

**Check anything that branches on this command's status.** A missing required file was exit `1` and is
now exit `3`, in all three forms; `1` still means the command failed. Nothing changed about the output
or about which files are required.

The case this is for: a backup job consuming `--exclude` from its own container, which — following
[backup.md](backup.md) — deliberately cannot see the TLS material or the master key. Its exclude list
is derived from `[storage] path` alone and is complete and correct, and its status was non-zero about
files it must not have. `2` is left to clap for a usage error, so the two cannot be confused. From
`docs/field-report-2026-08-23.md`, finding 2.

### A `ciphr backup` destination that cannot be written names its directory

The message was `unable to open database: <destination>`, one word from what an unreadable *source*
says, and it arrives while everything else on the screen is about the source. It now names the
destination *and* its directory, and says which end to check. The refusal to overwrite an existing
backup is unchanged, wording included.

### The token file and the master key file are opened once, and must be regular files

**A named pipe or a directory where a credential is expected is now refused.** Both files used to be
inspected by name and then read by name; they are opened once and read through that one descriptor, so
a file exchanged between the two steps is no longer possible (F10 of
`docs/review-2026-08-21-current-tree.md`). A FIFO passed as `--token-file` used to be a read that never
returned; it is now a refusal. Ordinary files at ordinary modes behave exactly as before, and the
world-bit rule is unchanged. The trust requirement this leaves — the file's owner and the directory it
sits in — is written down in [wrapper.md](wrapper.md), where the mount is written.

## 0.7.0

### The container refuses to start where core dumps cannot be disabled

The entrypoint has always run `ulimit -c 0` before dropping privileges, and it used to log a line and
carry on when that failed. It now **exits 1**, because a warning on a healthy start is not a defence
and [threat-model.md](../threat-model.md) lists a secret in a core dump under what is explicitly
defended against. A core dump of this process contains the master key, the root key and every value in
flight.

**Who this can affect:** a runtime that does not let the process lower its own core limit. On an
ordinary Docker or Podman host the call succeeds and nothing changes — this is not a new requirement
on the container definition, it is the existing one becoming visible when it is not met. The one
failure that is *not* a refusal is the case where the protection already holds: a limit that cannot be
set but reads back as `0` is accepted, with a line saying so.

**What to do if it refuses:** set the limit in the container definition instead — `ulimits: core: 0`
in Compose, `--ulimit core=0` for `docker run` — and start again. The message names both forms. Do not
work around it by removing the entrypoint: everything after it runs as `ciphr` rather than as root,
and the TLS key checks are in the same script.

**Not affected:** the swap half of the same defence, which still warns rather than refusing. A process
cannot change its own swap limit, and an unreadable cgroup file is not evidence that swap is on — so
that check has honest false positives and this one does not.

### A honeypot *token* now opens the tripwire — a monitor that never fired may start to

Only with the `honeypot_alert` build entry. Presenting bait wrote its audit entry and latched nothing,
so `/v1/health` answered `tripped: false` however often a planted credential was tried; it now latches
the way secret bait always has. **If your monitor polls `tripped` and pages a human, that page is now
reachable from a credential somebody is trying** — which is the event the entry exists to catch, and
the reason to check that the alert route goes somewhere a person reads before taking this.

**What to do:** nothing, if the monitoring described in [honeypots.md](honeypots.md) is in place. If a
token was planted and the tripwire has been quiet, do not read that as "nobody tried" for any period
before this release.

`ciphr honeypot clear` clears a latch the way it always did, and the audit trail is unchanged — every
presentation was already recorded, and still is.

### The honeypot fixes are behind a build entry — a derived image has to be rebuilt

`honeypot_alert` is a *build* entry (ADR-20), so **no published artefact contains any of this code** and
the two fixes above reach only a deployment that builds its own image. If you plant bait, rebuild the
derived image against `v0.7.0`:

```sh
cargo build --release --locked --features honeypot_alert --bin ciphr-server
```

For a container, the same in a derived image — copy `Dockerfile`, add the flag to its `cargo build`
line, publish under your own tag. `ciphr-server --check-config <file>` on the result reports
`honeypot_alert  build` as on, which is the check that the build and the configuration agree.

**A deployment that plants no bait needs none of this** and loses nothing by staying on the published
image, which is the whole argument for the entry: absent code has no behaviour to get wrong.

### Rotated audit archives carry the closing sequence in their name

`audit.jsonl.2026-08-19T21-04-07.912Z` becomes `audit.jsonl.2026-08-19T21-04-07.912Z-273`, where 273
is the last record in that file. Two rotations in the same millisecond used to aim at one name.

**What to do:** check anything that matches archive names by pattern — a shipping job, a retention
rule, a log collector. A `audit.jsonl*` glob is unaffected. A pattern that pins the exact timestamp
length, or anchors at the end of the name, is not. `ciphr audit cut` and `audit verify` follow the new
shape and still read the old one, so archives written by an earlier version stay in the set.

### Two client-visible transport changes

**Every `/v1` response now carries `Cache-Control: no-store`**, errors included. Nothing needs doing
unless something in the path was deliberately caching responses from this service — which would have
been caching secrets.

**`ciphr-sdk` follows no redirects.** A `3xx` reaches the caller as an error naming what was not done,
instead of being followed. If a deployment put this service behind something that answers a redirect —
a rewriting proxy, a moved listener — the SDK stops working against it, and that is the intent: this
API has no redirect contract, so following one was resolving a misconfiguration on the caller's behalf.
Point the client at the service.

**And `ciphr-run` carries the same client**, so route B gets that change through the *file*
rather than through a configuration: a host that keeps its mounted `ciphr-run` keeps following
redirects. Fetch the `0.7.0` copy ([wrapper.md](wrapper.md)) if that matters to you. Nothing
else about the wrapper changed, and the old file keeps working otherwise — this is the one
behaviour that differs between the two copies.

## 0.6.1

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
