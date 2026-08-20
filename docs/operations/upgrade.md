# Upgrading

**Status:** current as of 2026-08-20, covering every released version up to `0.3.0`.

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
