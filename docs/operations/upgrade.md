# Upgrading

**Status:** current as of 2026-08-21, covering every released version up to `0.4.0`.

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

**Read the changelog entry for every version you are skipping**, not only the one you are landing
on. The breaking notes below are per version and they accumulate.

## The order of operations

1. Back up the database, its `-wal` and `-shm` siblings, and the anchor file.
2. Stop the service.
3. Start the new image. It migrates on start; watch the log for the migration lines.
4. Run `ciphr audit verify` — with `--anchor` if a file is kept.
5. Only then update anything that consumes the API: the viewer, the SDK, `ciphr-run`.

Step 5 is last on purpose, and from `0.3.0` it is load-bearing rather than tidy — see below.

From `0.4.0` there is a step 0: **check the file modes below before stopping anything.** A refusal
there happens at start, which is the worst moment to discover it.

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
