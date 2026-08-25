# Monitoring: what to poll, and what each answer means

**Status:** current as of 2026-08-25, `v0.12.1` released. Every field below was read out of `crates/ciphr-server/src/api.rs`
and `state.rs` rather than out of `openapi.yaml`, because the point of this page is what the process
actually reports. Where the two disagree, it says so.

Eighteen documents in this repository mention `/v1/health`. None of them was a runbook, which is why
the operational knowledge about it existed as a side remark in whichever document happened to touch
it — the same shape that left the store without a backup procedure until 2026-08-21.

Plan section 17 asks for three checks and calls all three necessary. That list needs correcting in
both directions: one of the three is satisfied by construction rather than by polling, one became
buildable after the plan said it was not, and the half of it the plan cared about most is still not
answerable from this endpoint at all.

## The endpoint is unauthenticated, and that shapes everything below

`GET /v1/health` is the only route without a bearer token, and the only other one that ever will be
is the deferred `POST /v1/report` (ADR-16). Two consequences worth holding onto while reading:

- **Nothing here says *why*.** A device that refuses a record names a path or a database when it
  explains itself, so the endpoint reports *whether* and the reason goes to the process log. A monitor
  that needs the reason is reading the wrong source.
- **Anything added here is public.** That is the argument that keeps some facts off it — see the
  section on backups below.

## What each field is, and whether it changes

| Field | What it is | Changes at runtime? |
|---|---|---|
| `status` | `"ok"`, or `"degraded"` when the process could not establish something it reports on | **Yes, since `0.12.0`.** It was the literal `"ok"` before that |
| `sealed` | The literal `false` | **No.** v1 unseals at startup or refuses to start |
| `seal` | The seal mechanism recorded in the store (`static`, or `static_env` in older stores) | No — a configuration fact |
| `key_source` | Where *this process* read its key: `env`, `file`, or `supplied` | No — but it is the field that shows which source is live during a migration from one to the other |
| `audit_devices[]` | One entry per configured device: `name`, `accepting`, and `quarantined_from` where it applies. The name is a label — `sqlite-1`, `file-1` — and not the configured path | **Yes**, `accepting` and `quarantined_from` do |
| `surface` | Names of the optional entries this process is running (ADR-20) | No. The date and reason a deployment recorded stay behind `inspect` on `sys/surface` |
| `tripped`, `open_tripwires` | Whether any tripwire is open (ADR-15) | Yes — **and absent in a build without `honeypot_alert`, or when the store could not be asked** |
| `degraded[]` | What this process could not establish, by name. Absent when there is nothing to report | **Yes, since `0.12.0`.** The reason `status` reads `degraded` |
| `api_version` | `"v1"` | No |

**Three fields carry live state now and the rest are facts about how the process was started.** Until
`0.12.0` there was exactly one, and this page said so — a rule on `status` was a rule on a constant.
Finding F9 of the [review of 2026-08-24](../assurance/reviews/review-2026-08-24-full-repository.md)
changed that: `status` and `degraded` say when the process could not establish part of what it
reports, which is a thing worth alerting on and previously was not expressible.

**`degraded` is not a liveness signal.** The service is serving; a load balancer must not pull it out
of rotation for it. It is for the monitor, not the proxy.

## The checks, corrected against what exists

**1. Reachability — and it covers the seal state by construction.** Plan section 17 argues that
*"a sealed service responds but is non-functional — an HTTP 200 check alone cannot distinguish that
from healthy"*. True for a seal that can become locked; not true today. v1 unseals at startup or
**refuses to start**, so an answering process is an unsealed one, and `sealed` is a hardcoded `false`
that exists so a client does not have to change shape when a split-key or HSM seal (ADR-5) makes the
field meaningful. Until then this check is "does it answer", and the container's own `HEALTHCHECK`
already performs it — over HTTPS with `--cacert`, so it also proves the listener's certificate is
verifiable, which is deliberate (ADR-8 rules out `--insecure` everywhere, including there).

**When the seal mechanism changes, this becomes a real check** and this paragraph is the note that it
was not one before.

**2. Per-device audit acceptance — the check the plan said was not buildable.** It is now.
`audit_devices[].accepting` is updated on every recorded entry, on both the success and the failure
path, so a device that has been refusing for a month is visible instead of invisible. It has to be
per-device: **one accepting device is enough for a request to succeed**, so a two-device deployment
that lost its second device keeps serving and reports nothing anywhere else.

Alert on `accepting == false` for any device. Not on the request rate, and not on the `503`s — by the
time requests fail, every device is refusing.

**And alert on `quarantined_from` being present, which is the stronger signal.** Since `0.12.0` a
device that misses a committed record is stopped rather than written to again — otherwise the next
record it accepted would carry a `prev_hash` naming a record it does not hold, and that file would
stop verifying at that point for good. The field carries the first sequence number it missed.

The difference between the two matters when writing the rule. `accepting == false` can be transient:
a volume that fills and is freed recovers on its own, because a record *no* device stored is a record
no device missed and nothing is quarantined for it. `quarantined_from` never clears while the process
runs — **it needs a human**, and the procedure is in
[audit-trail.md](audit-trail.md). A deployment running two devices to have two copies has one from
that moment on.

**A rule you already have on `accepting` fires either way.** A quarantined device reports
`accepting: false` and keeps reporting it, so this is not a state you can only see with a new rule —
`quarantined_from` is what tells you the difference is permanent. And since `0.12.1` the same state is
in the trail and on stderr at startup, so a deploy log shows it before any monitor does.

**3. Audit volume fill level — still not answerable here, and it is the one that hurts.** Nothing on
the endpoint reports free space. This matters more than the other three combined, because the audit
sink is fail-closed: a volume with no room left means no record can be stored, and a request whose
record cannot be stored is **refused**. A full disk is a total outage, not a logging gap. That is
intended (ADR-16, `threat-model.md`) and it is the conceded denial-of-service.

It needs a filesystem check, from something that can see the filesystem — a node agent, a textfile
collector, the host's own monitoring. Two paths can fill and both are fatal in the same way:

- the store's volume, which the SQLite audit device writes into alongside the database;
- the file device's path, if one is configured. **Rotation does not bound it** — rotated files are
  shipped and expired by whatever already does that on the host, and `audit-trail.md` says so
  explicitly. `ciphr audit cut` bounds the *queryable* table in the database; it does not bound the
  archive.

ADR-15 reached the same conclusion for the tripwire's marker file and it applies here: a channel that
is supposed to survive a full volume must not live on the volume that fills.

**4. Tripwire state, if the build has it.** `tripped` is a boolean when this binary was compiled with
`honeypot_alert` and **absent** otherwise — not `false`. "This build cannot detect bait" and "nothing
has been taken" are different facts. Check `surface` for the entry name before trusting the field, and
see [honeypots.md](honeypots.md) for what to do when it fires. A tripwire nobody polls is decoration.

**It is absent for a second reason since `0.12.0`, and that one is worth an alert.** If the store
cannot be asked, `tripped` and `open_tripwires` are absent, `degraded` carries `tripwires`, and
`status` reads `degraded`. Before that release the same situation produced `tripped: false`,
`open_tripwires: 0` and `status: "ok"` — an affirmative *nothing has been taken* from a process that
could establish nothing of the sort, at the one moment the answer matters. **Alert on `degraded`
containing `tripwires`**: it means the tripwire is unwatched, not that it is clear.

## Three ways to read this endpoint wrong

**`accepting: null` is not healthy.** It means no record has been written since this process started.
On a service that has served requests, that is itself the finding.

**An empty `audit_devices` array is not "nothing to check".** The server refuses to start with no
audit device, so an empty array cannot mean what it appears to mean. It has one other cause:
`AppState::audit_devices` returns an empty vector if the mutex holding that state is poisoned. Its own
doc comment says the names are reported with `accepting` unknown instead — **the comment and the code
disagree, and the code returns `[]`.** Reaching the state needs a panic while that lock is held, which
the code holding it has no path to, so this is a documentation defect rather than a live hazard. Treat
an empty array as an error either way; it costs one comparison.

**A `200` is not a working service.** `status` distinguishes `ok` from `degraded` and nothing else,
and the body is produced without touching the store beyond the tripwire count. A service that cannot
store an audit record answers `200` here — and `ok` — while answering `503` to every request that
matters. That is what `audit_devices[].accepting` is for.

## Backups are deliberately not on this endpoint

The tempting design is a configured backup interval, checked by ciphr, surfaced as a field here. It
was considered and rejected, and the reasoning is recorded so the gap is a decision rather than an
omission somebody discovers while writing an alert rule:

- **ciphr cannot verify the claim.** It could know that `ciphr backup` was invoked at a time. It cannot
  know that the file still exists, that it left the host, that it is readable, or that the master key
  is retrievable. A green field meaning "a command ran three days ago" answers the question an
  operator is actually asking with something else, and a health field that produces confident mistakes
  is worse than an absent one.
- **Every other field here is a fact about the process's own state.** `sealed`, `key_source`,
  `accepting`, `tripped` — the process knows each because it is the thing doing it. Backup freshness
  would be the first field asserting something about a file the process does not own and cannot see.
- **It would cost the property that makes `backup` usable.** `ciphr backup` takes no store lock and
  writes no audit entry, which is why it runs against a live service. For the server to know a backup
  happened, the backup would have to write to the store — which needs the lock.
- **It is public.** "Last backup 41 days ago" tells anyone who can reach the port that nobody is
  watching. The tripwire flag is exposed too, and the asymmetry is the point: "you were noticed" has
  deterrent value, "this deployment is unmaintained" has only target value.
- **The deployment's backup system is better informed.** It knows whether the file reached the target
  medium. ciphr would be a second opinion with less to go on.

### What to check instead

Run a verification against the newest backup file. It needs **neither the master key nor the store
lock**, so it runs from wherever the backups land:

```sh
ciphr --database /path/to/newest-backup.db audit verify
```

The output names the head sequence — `head <hash> at sequence N`. Compare that N with the live store's
(`ciphr audit verify` there, or the newest anchor). Green then means something worth alerting on:
**the newest backup is a readable, chain-intact store, and it is N records behind.** That is a
stronger statement than any freshness field could make, and the threshold belongs in the system that
also knows whether the file arrived.

See [backup.md](backup.md) for what else has to be in a backup for a restore to be possible, and for
what a restore undoes.

## What is not built

**No alerting, anywhere in this repository.** Every mechanism here is a field to poll or a file to
check. Nothing can page a human, by design — see ADR-15, which makes the same point about bait.

**No fill-level reporting**, for the reason in check 3: the channel would live on the volume that
fills. Whether a marker outside that volume is worth the configuration it needs is the same open
question ADR-15 records for the tripwire's marker file, and it should be answered once for both.

**No backup-freshness signal.** If one is ever wanted, the shape that fits this project is
`ciphr backup --record <file>` appending one line where the deployment chooses — exactly the pattern
`ciphr audit anchor --out` already uses, and for the same reason: the path is deployment
configuration, and inventing a location to avoid inventing a setting is the worse of the two. It is
not built, and the check above is available today without it.
