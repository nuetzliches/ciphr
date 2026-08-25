# Field report 2026-08-25: `0.12.0` gives a state that needs a human, and no place to see it

**Status:** written 2026-08-25 against `v0.12.0`, from the operating side of a private deployment,
before and during the upgrade `0.10.0 -> 0.12.0`. The sixth report from this deployment; the fifth was
[2026-08-23 (b)](field-report-2026-08-23-b.md), and `0.10.0` answered all of it.

Not a review. Both findings are about the same release feature — device quarantine (F6) — and neither
is about whether it works. It does; this report includes the measurement. They are about the two places
an operator would look to find out that it fired, and neither of them says anything.

**What the deployment did**, for context: one host, one machine identity, one human identity, six
secrets, two audit devices (`sqlite` and `file`) since day one. Both pins moved in one commit,
`0.11.0`'s registry change and `0.12.0` together, so the running binary before this upgrade was
`0.10.0` and both changelog entries were read. Store, policy set and configuration are otherwise
unchanged.

## 0. What `0.12.0` closed, and the part that is better than it needed to be

- **The startup comparison is the right call, and it is the half of F6 that actually protects
  anybody.** An in-memory quarantine would have been undone by the first thing every operator does.
  Saying so in `upgrade.md` — *a restart does not lift it* — next to the reason, is what let this
  deployment know it had a question to answer before pulling the image.
- **`upgrade.md` naming the first-start case explicitly is what made the pre-flight possible at all.**
  "A deployment whose audit file has *already* fallen behind will find it quarantined on the next
  restart" is the sentence that turned an upgrade into a measurement here. Without it the finding
  would have arrived as a red monitor after the deploy.
- **The `audit_devices[].name` change is correct and cost this deployment nothing**, which is worth
  recording because it easily could have. Our four health checks address devices by **index** and by
  `len(audit_devices) == 2`, never by name — a decision made in `0.5.0` for a different reason (the
  order of `surface` entries follows the configuration, so a name-keyed condition would break on a
  re-sort). It happened to carry a rename it was not written for. A deployment that had keyed on
  `sqlite:/var/lib/ciphr/store.db` would have gone red on upgrade, and the `0.12.0` entry says so
  plainly rather than leaving it to be discovered.
- **The `degraded` split is the right shape.** `status: "ok"` with `tripped: false` from a process that
  could establish neither was the worst kind of wrong answer — affirmative, and about the one thing
  nobody wants a guess about. Dropping the two fields rather than reporting `false` is the honest
  version.

**One measurement, since a report that only asks for things is cheap.** The pre-flight this release
demands, run against copies of the real store and audit file with a throwaway `0.12.0` server, our real
`ciphr.toml`, `policies.toml`, TLS material and master key:

```
store chain   seq 1..391   (391 records)
file device   seq 2..391   (390 lines, no gaps)
```

`seq 1` is missing from the file because it was written by `init`, before the file device existed on
disk. The startup comparison looks at the head, and the heads agree — so:

```json
"audit_devices":[{"name":"sqlite-1","accepting":true},
                 {"name":"file-1","accepting":true}]
```

No quarantine, and the deployment could stop worrying. Then the same copy truncated by ten lines, to
have the case rather than only its absence:

```json
"audit_devices":[{"name":"sqlite-1","accepting":true},
                 {"name":"file-1","accepting":false,"quarantined_from":382}]
```

Which answers the question a monitoring rule needs and the documentation does not state outright: **a
quarantined device also reports `accepting: false`**, so an existing rule on `accepting` fires. That is
a good default and it deserves a sentence in `audit-trail.md`, because the section that introduces
`quarantined_from` reads as though a new rule were required to see the state at all.

## 1. The quarantine is announced on one unauthenticated JSON route and nowhere else

**Measured, twice, and the second time with logging turned up.** The throwaway server above, holding a
file device quarantined from sequence 382:

```
$ docker ps --format '{{.Status}}'
Up 12 seconds (healthy)

$ docker logs c12          # RUST_LOG=info, both streams
                           # (empty)
```

Nothing. Not at the startup comparison that made the decision, not at the first record that was not
written to that device, not on either stream. The process reports itself healthy, its own container
health check passes, and the only place the state exists is `GET /v1/health`.

**Why that is a gap rather than a preference.** This is the one state in the release notes described as
needing a human, and the one that *never clears while the process runs*. Everything else on that route
is either transient (`accepting: false`), a configuration fact (`surface`, `seal`, `key_source`) or
already loud (`sealed`). A permanent, human-only condition is a different class of thing from its
neighbours, and it is the only one of them with no second channel.

And the release itself names the moment it will most often fire: the first start after upgrading, for
any deployment whose file device had fallen behind. That is precisely when somebody is watching a
deploy log — this deployment's own `deploy-service.sh` prints the container's output — and precisely
when a JSON field on a monitoring route has not been looked at yet, because the monitor's rule for it
was written in the same commit as the upgrade or, more likely, after it.

**Ask:** one `warn!`-level line at the startup comparison and one when a device is quarantined at
runtime, naming the device label and the sequence. Not the path — the label is exactly right here, and
for the same reason `/v1/health` now carries it. It does not need to be more than:

```
audit device file-1 is quarantined from seq 382: it missed a committed record and
will not be written to again while this process runs. See docs/operations/audit-trail.md.
```

The counter-argument we can think of is that the trail is the artefact and the log is not, so the log
should not be load-bearing. Agreed — this is not asking for the log to *carry* the state, only to say
that the state exists. `/v1/health` stays the interface.

**A second, smaller half of the same finding.** The container's own health check passes while a device
is quarantined. That is defensible on the release's own terms (`degraded` is explicitly not a liveness
signal, and this is less than `degraded`), so we are not asking for it to fail — but it means the two
signals a container platform reads, exit status and health, both say fine. Worth a line in
`audit-trail.md` so nobody concludes from a green container that the devices are green.

## 2. No published viewer reads `degraded` or `quarantined_from`

**Checked in the repository rather than inferred.** `ui-v0.3.2` is the newest viewer tag. Its `ui/`
diff against `ui-v0.3.1` is `package.json` and the lockfile — two lines of version, nothing else. The
changes that read the new fields are in `ui/src/api.ts` and `ui/src/components/HealthView.vue`, and
they sit **between `ui-v0.3.2` and `v0.12.0`**: behind the last tag, in no published image.

So a deployment that upgrades the service to `0.12.0` and the viewer to the newest available tag —
which is what this one did, in one deploy — gets a viewer that renders:

- a **quarantined** device as `refused`. That is the word this same view uses for the state that
  recovers on its own, shown for the state that does not. Red, at least, so it is not silent — but it
  reads as *look again in a minute* rather than *archive the file and restart*.
- a **degraded** service as **green**, because the old view branches only on `sealed`. This is F9's
  finding — an unverifiable tripwire state rendering as healthy — reappearing one layer out, in the
  surface a human actually looks at.

**Neither is a reason to hold the viewer pin back**, and we did not: the new fields are optional, the
old viewer does not stumble, and `0.3.2` is better than `0.3.1` in every other respect. It is a reason
that the release which introduces two states for humans has no human-facing surface for them yet, and
the operator finding out is the one who then has to decide whether to trust the UI or the JSON.

**Ask:** cut the viewer tag that carries those two files. If that is deliberately later, then say so
where a deployment will see it — a line in the `0.12.0` section of `upgrade.md` under *what to do*,
naming the newest viewer tag that reads the fields and what the previous one shows instead. The
existing ordering rule in that document covers the case where the viewer must go **after** the service
because a response shape changed; it has no shape for *the viewer cannot show this yet*, which is a
different thing and, for these two states, the more consequential one.

We are aware this may be one release's timing rather than a policy question. It is in this report
because the release notes for `0.12.0` describe `quarantined_from` as the field to alert on, and a
deployment reading only those notes would reasonably expect the bundled UI to show it.

## 3. What this deployment still owes

Unchanged, and stated so it is not mistaken for something the project is missing: **the restore drill
with the real break-glass key has not been run.** The half that needs no key was exercised again in
passing — a pre-upgrade copy taken with the `0.10.0` binary, 364544 bytes, before the pins moved, plus
a full throwaway server brought up on a copy of the store and verified through `/v1/health`. The other
half is fetching the master key from where it actually lives and opening a restored store with it, and
no test in this repository can do that for us.
