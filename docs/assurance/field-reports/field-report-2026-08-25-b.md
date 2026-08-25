# Field report 2026-08-25 (b): `0.12.1` verified, and one line reads worse than it is

**Status:** written 2026-08-25 against `v0.12.1` and `ui-v0.3.3`, from the operating side of a private
deployment, immediately after the upgrade `0.12.0 -> 0.12.1`. The seventh report from this deployment;
the sixth was [2026-08-25](field-report-2026-08-25.md), and this release answers all of it.

Not a review, and mostly not a request either. Both findings of the previous report are closed, and
this report exists to say so **with the measurement rather than the assumption** — the previous one
asked for two things that are hard to test from the outside, and a report that only asks is cheap. One
new finding, and it is cosmetic: the stderr line this release adds carries its source literal's
indentation into the output.

**How this was measured**, because it is the same rig as last time and that is the point: a throwaway
`0.12.1` server on a **copy** of a store and its audit file, the copy's audit file truncated by ten
lines so that the device stands behind the chain, `RUST_LOG=info`, both output streams captured. The
same construction that produced the previous report's `quarantined_from: 382`, so the two runs are
comparable line for line.

## 1. Finding 1 is closed, and all three channels are confirmed

The previous report measured a `0.12.0` server holding a quarantined file device: healthy, container
health check passing, `docker logs` empty on both streams, and the state present only as one field on
one unauthenticated JSON route. Re-run against `0.12.1`:

**stderr, at startup** — present, and it names both identifiers, which is the detail that makes it
usable:

```
ciphr-server: audit device file-1 (file:/var/log/ciphr/audit.jsonl) is quarantined
from seq 382: ... See docs/operations/audit-trail.md.
```

The published label to match against `/v1/health`, and the device's own name to find the file somebody
has to archive. That was not what the report asked for — it asked for the label — and it is better than
what it asked for.

**The trail** — present, read raw out of the copy's store rather than through the CLI, so the entry is
quoted as it is stored:

```
action       "audit-device-failed"
deny_reason  "device-behind-at-start: file:/var/log/ciphr/audit.jsonl"
detail       "missed from seq 382"
principal    null      allowed  false
```

`principal: null` is right and worth naming: nobody made this request, and an entry that invented a
principal for a startup decision would be the kind of thing a reader of a trail has to un-learn. The
split between `device-behind-at-start` and `device-quarantined` is the part that answers the report —
the previous entry said `device-refused` whether the device recovered or was stopped for good, so the
trail could not tell the transient case from the permanent one.

**`/v1/health`** — unchanged, as documented.

**And the two documentation asks are in.** That a quarantined device also reports `accepting: false`,
so an existing rule fires; and that the container health check stays green. The second is the one worth
having written down: this deployment's monitor reads `/v1/health` and would have caught it either way,
but a deployment that trusts container health alone now finds the sentence before the incident instead
of after.

## 2. The stderr line carries its literal's indentation

**The one new finding, and it is only cosmetic.** The line above, rendered with runs of whitespace
marked:

```
... is quarantined from seq 382: it is[→14 spaces]missing records the chain has and
will not be written to again while this[→14 spaces]process runs. See
docs/operations/audit-trail.md.
```

Two runs of fourteen spaces, mid-sentence. That is a multi-line string literal whose continuation
indentation reaches the output — the shape a `concat!` or a `\`-continued literal leaves behind when
the following line is indented to match the surrounding code.

**Why it is worth a finding at all**, given that nothing malfunctions: this line exists *because* a
human reads it in a deploy log, and it was added in this release for that reason. It is the one
artefact in this system whose entire justification is legibility, so it is the one place where reading
badly is a defect rather than a blemish. Everything else about it is right — one line, both
identifiers, the sequence, and a pointer to the runbook.

**Ask:** join the literal, or use the same wrapping style the entrypoint's swap warning uses, which
prints cleanly. No behaviour to change and no test to add beyond asserting the message contains no
run of more than one space, if that is worth a line.

## 3. Finding 2 is closed, and the rule it produced

`ui-v0.3.3` renders both states. A quarantined device reads `stopped — missed record 382 onwards`
rather than `refused`, and checking quarantine **before** `accepting` is the right order for the reason
the code gives: "refused" describes the last record the device was asked about, and a stopped device is
not being asked. A `degraded` service renders amber with a row naming the part, rather than green.

**What this cost us to find out, stated once because the shape will repeat.** A viewer on its own
release cadence has no failing check when the service gains a field the viewer does not read — nothing
is broken, and the two halves simply describe different versions of the same system. So the question a
deployment has to ask at a service bump that *adds* a field is not "does the viewer tag still fit",
which is what every ordering rule in `upgrade.md` is about, but **"does the viewer tag exist yet"**. We
have written that down on our side. It may be worth a sentence in ADR-11 or in `ui.md`, since the
answer is structural rather than about any one release.

## 4. What this deployment still owes

Unchanged: **the restore drill with the real break-glass key has not been run.** The half that needs no
key was exercised twice more in passing — a throwaway server brought up on a copy of a store and
verified through `/v1/health`, once per release. The other half is fetching the master key from where
it actually lives and opening a restored store with it, and no test in this repository can do that for
us.
