# Field report 2026-08-22: wiring `0.6.0`'s backup into a real job

**Status:** written 2026-08-22 against `v0.6.1`, from the operating side of a private deployment,
after upgrading to it and rebuilding that deployment's backup around `ciphr backup`. The third report
from this deployment; the earlier two are [2026-08-21](field-report-2026-08-21.md) and
[2026-08-21 (b)](field-report-2026-08-21-b.md), and `0.6.0` answered what was open in them.

Not a review. It records four places where turning `0.6.0`'s new commands into an unattended job took
more than the documents suggested, and one process gap that this deployment saw from the outside.

**What the deployment did**, so the findings have a context: the nightly restic job stopped taking a
file-level copy of the live database and now runs `ciphr backup` into its staging directory, verifies
the copy with `ciphr audit verify`, and snapshots that. The store is 270 kB with a 606 kB write-ahead
log beside it, which is the case the old procedure was quietly wrong about.

## 0. What `0.6.0` closed, since a report should say so

- **`ciphr backup` is the release this deployment needed**, and the three properties that made it
  usable in a job are the three the changelog leads with: no store lock, no master key, and a
  self-contained output file. The job needed none of the arguments that would have made it awkward.
- **Finding 1 of the first report is answered and then some.** `token list` answers live; so do
  `list`, `versions` and `rotation <path>`. The ask was one command; four arrived.
- **All three findings and the four smaller notes of the `0.5.1` review are in.** `Kind::as_str` is
  the only spelling now, and `ci/check-surface-entries.sh` compares kind and cost.
- **The restore was confirmed at the deployment level, independently of the new test.** The copy was
  pulled back out of the backup repository into a scratch directory, and on the *restored* file
  `audit verify` reported 273 entries with the head at sequence 273 and `list` named both real paths.
  That is the half of a drill that does not need the break-glass key. The other half — fetching the
  master key from where it actually lives — is this deployment's homework, and the runbook is right
  that no test can do it.

## 1. `ciphr state` is a report for a human, and its natural consumer is a job

**Observed.** The command is exactly the right idea: the file set derived from the configuration
rather than from a table somebody maintains. So the backup job should consume it — and cannot. The
output is aligned columns with a two-level indent that carries meaning (`write-ahead log` and `store
lock` are indented under `store`), a `present`/absent word, and a free-text verdict per row:

```
present  store               /var/lib/ciphr/store.db       back up: everything the service holds
present    write-ahead log   /var/lib/ciphr/store.db-wal   back up with the store, or use `ciphr backup`
present    store lock        /var/lib/ciphr/store.db.lock  never back up: it names a process, not the store
```

A job that wants *the paths to include* and *the paths to exclude* has to parse that, and a parser
against aligned prose is a parser that breaks on the next wording change. This deployment's job
therefore names its paths itself — which is precisely the hand-maintained list the command exists to
replace, one layer further out.

**Asked for:** a machine-readable form — `--json`, or a stable tab-separated one — carrying per row
the path, the role, whether it exists, and the verdict as an enum rather than as a sentence
(`include` / `include-with-store` / `never`). The exit code already covers the pre-flight half well;
it is the *report* half that has no consumer it can serve.

**Two remarks that belong with it rather than as separate findings.** The two rows the command
deliberately cannot name — the anchor file and the archive's rotated siblings — are the two a job most
needs told about, so if the anchor path could be named in the configuration, `state` could complete
its own list. And the same output is the natural place to emit the *exclude* patterns a file-level job
needs; see finding 3.

## 2. "Runs with the service running or stopped" is not true of a read-only source, and *stopped* is the interesting half

**Observed, in two steps, and the second step is the finding.**

`backup.md` says `ciphr backup` runs "with the service running or stopped". On a container host the
recipe that follows from that is a throwaway container of the same image with the data directory
mounted **read-only** — which is strictly better than `docker exec` into the service container: it
writes nothing into the volume it is backing up, and it works when the service container is unhealthy,
stopped or gone. This deployment built exactly that, measured it against a live store, and it worked.

Then it was measured against the *other* state, and it does not work:

```
# a copy of the real store, checkpointed and closed, so no -wal and no -shm remain
$ ciphr --database /src/store.db backup /out/copy.db      # /src mounted read-only
ciphr: database error: unable to open database file
$ ciphr --database /src/store.db backup /out/copy.db      # same source, mounted rw
/out/copy.db (274432 bytes, schema 6)
```

**The cause is SQLite and the timing is the release's own doing.** A WAL database can only be opened
if `-shm` exists or can be created. While the service runs it exists, so a read-only source is fine.
A *clean* shutdown checkpoints the log away and removes both sidecars — and `0.6.0` is the release
that made `docker stop` reach the graceful shutdown, so that state is now the normal one after a
maintenance stop rather than a rarity. `open_read_only` cannot create the file on a read-only mount,
so the command fails in exactly the window where somebody most plausibly takes a manual backup: the
service is down, the operator has time, and the tool refuses.

For a scheduled job the shape of the failure matters as much as the failure. This deployment's job
fails loudly on purpose — a torn copy of a secret store reported as success is the thing it must never
do — so a maintenance stop would have turned into a failed nightly run and an alert about a store that
is fine.

**What this deployment does now**, offered as the recipe rather than as a complaint: mount the source
**read-write** and run the container as the service's uid. If the service is running, no file is
created at all — measured: owner and file list in the store directory are identical before and after.
If it is stopped, the `-shm` that gets created belongs to the service user, which is the part that
must not be got wrong: a root-owned `-shm` in the store directory leaves the service unable to open its
own database on the next start.

**Asked for**, in order of preference:

1. **Say it in `backup.md`.** Two sentences: a read-only source works only while the service holds the
   database open, and a containerized job should therefore mount the source read-write and run as the
   service's uid. The document already earns its place by naming the failure modes of the file-level
   path; this is the same kind of sentence for the command that replaced it.
2. **Or make the command not need it.** `ciphr backup` knows it is doing `VACUUM INTO` from a
   read-only connection; where the source has no `-wal` and no `-shm` there is by definition no writer
   and nothing to recover, and SQLite's `immutable=1` describes that state exactly. If that is safe to
   assert under the conditions the command can check, the read-only recipe becomes true as documented.
   This is a suggestion about SQLite semantics from outside the code, so it is second on the list.

**Not asked for:** anything about `docker exec`. The throwaway container is the right shape; only the
mount mode was wrong, and one sentence in the runbook is what would have prevented a deployment from
finding this the hard way.

## 3. The one file that must not be in a backup is named in prose and in no pattern

**Observed.** `store.db.lock` had been in every snapshot of this deployment since the store existed.
`ciphr state` found it in the first run — *"never back up: it names a process, not the store"* — and
[backup.md](../../operations/backup.md) has the row with the full reasoning. Both are correct, and neither
is a form a job can consume, so the exclusion is a line somebody has to write by hand in whatever
backup tool is in use, having first read a document they only reach after the incident.

For what it is worth, the failure this prevents is a good one to have prevented: a restored lock file
names a process that does not exist, and where liveness cannot be checked an unverifiable lock is
treated as held. So the restore succeeds and the CLI then refuses, for a reason nothing on the host
connects to the backup.

**Asked for:** emit the patterns. Either as part of finding 1's machine-readable output, or as
`ciphr state --exclude` printing one glob per line, so a job can be told rather than taught. One
interface, not three: this and finding 1 are the same ask seen from two sides.

## 4. `backup.md` documents the command and not the job

**Observed.** The document's example is `backup /path/to/backup/store-2026-08-21.db`, a dated
destination — the right shape for a hand-taken copy before an upgrade. A scheduled job wants the
opposite: one current file whose name does not move, so that the file-backup tool behind it
deduplicates instead of accumulating. That choice interacts with a documented refusal — an existing
destination is refused rather than truncated, correctly — so a fixed-name job needs an unlink step
first, and nothing says so. A dated-name job instead needs its own retention, and nothing says that
either.

**Asked for:** a short "in a scheduled job" subsection: pick the fixed name and unlink first, or pick
the dated name and own the retention; and either way run `ciphr audit verify` on the copy afterwards,
because `ciphr backup`'s own checks prove the file is a readable database and `verify` proves it is
this store's trail. This deployment does both, and the second one is a line the runbook could
recommend rather than a thing each deployment invents.

## 5. Nothing gates that a release publishes both images

**Observed, from the outside.** `v0.6.0` published `ciphr:0.6.0` and no `…/run:0.6.0`; the mirror this
deployment pulls from shows the same gap, because it builds the two images in two steps of one job the
same way. `0.6.1` fixed the cause — `Dockerfile.run` copied a path the renamed script no longer
produced — and the changelog diagnoses the class exactly: *"nothing caught it, because nothing builds
that file except a release."* The fix does not close that sentence. The next change to the wrapper's
build inputs can break the release the same way, and the first sign will again be a tag that exists
half.

**Asked for:** build `Dockerfile.run` in CI without pushing it. It needs no registry credentials and
no release, it is the same builder stage CI already runs the script in, and it would have failed this
in seconds. Failing that, a post-publish step that asserts both tags resolve — a release that
published half of itself should not be able to report success.

**Why this is worth a report rather than a shrug:** the deployment-side consequence is not "wait for
0.6.1". It is that the pinning rule this project is careful about — never a moving tag, always a
version somebody signed off — assumes a version is one thing. For one release it was two, and the
upgrade note is now the only place that says which of them a host mounting `ciphr-run` can use.

## What is deliberately not asked for

- **A `--force` on `ciphr backup`.** The refusal is right and finding 4 asks for a sentence, not a
  flag.
- **Anything about the wire behaviour of an inactive surface entry**, settled in the second report.
- **A backup command that writes anywhere but a file** — no remote targets, no compression, no
  encryption of its own. The file plus an existing backup tool is the correct division, and it is why
  this was easy to wire.

## Provenance

Findings 1 to 4 come from writing and running the job: `ciphr state` and `ciphr backup` were run
against this deployment's real configuration and store with the published `0.6.1` image, and the
restore was performed out of the real backup repository into a scratch directory and verified there.
Finding 2's failure was produced deliberately: a copy of the real store, `pragma
wal_checkpoint(truncate)` through `sqlite3`, the connection closed so both sidecars disappeared, then
the same `ciphr backup` invocation against that directory mounted read-only and mounted read-write.
The claim that a running service leaves the store directory untouched is a before/after comparison of
owners and file list, not an inference. Finding 5 comes from the registry listing this
deployment pulls from — `ciphr/run` skips from `0.5.1` to `0.6.1` — read together with the `0.6.1`
changelog and `Dockerfile.run`. Nothing here rests on a changelog entry alone.
