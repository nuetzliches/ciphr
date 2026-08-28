# The audit trail

**Status:** implemented and tested as of 2026-08-28. The chain, the fail-closed sink, the file
device, and the SQLite device work and are tested, and so do `ciphr audit tail`, `verify`, `anchor`,
and `cut` — the last of these is what bounds the queryable trail, and it arrived after the rest.

This is the component the project exists for. Everything below follows from one sentence: **an access
that could not be logged must not happen.**

## What is recorded

Per entry: the sequence number, an RFC 3339 UTC timestamp, the previous entry's hash, the principal
(identity name, kind, and the non-secret identifier of the token used), the **subject** where the
action was about someone other than the actor, the action, the normalized path, the version, whether
it was allowed, why it was refused, the rule that decided it, and the request context — request id,
client address, user agent, HTTP status, and the channel it arrived through.

**The subject exists for the token actions** (added 2026-08-20). An operator on the host issues a
credential *for* an identity, and those are two parties: the principal is `cli:<account>`, the
subject is the identity and the new token's non-secret id. Folding one into the other would make the
trail say the operator authenticated with a token they had just created. The recorded id is the same
one every later access with that credential carries, which is what lets a reader join the creation
of a credential to its use.

**What `user_agent` is worth, and what it is not** (the header has been recorded since the trail
existed; the clients started filling it usefully in `Unreleased`). Requests from this project's own
binaries carry `ciphr-ci/<version>` and `ciphr-run/<version>`; an application built on `ciphr-sdk`
carries `ciphr-sdk/<version>` unless it names itself. Before that they all carried the transport
crate's default, so the field was populated and identified nothing.

It answers one question: **did this read come from the tool that registers a mask for every value
before it writes any of them, or from something else?** That is worth knowing, because a job that
falls back to a hand-written request gets no masking at all — and `ci.md` spends a chapter on why
masking is the client's job.

**It is not authentication, and no rule here may treat it as one.** The value is chosen by whoever
makes the request, so `curl -H "User-Agent: ciphr-ci/0.13.2"` says exactly what `ciphr-ci` says. A
*mismatch* is evidence; a *match* proves nothing. Alerting on it is therefore a report to read, not
a tripwire to act on — ADR-15 governs what a tripwire may do, and a signal needing interpretation
does not qualify. Nothing in the policy path sees this field.

**Never recorded:** the secret value, key material, or a token. Only a token's non-secret
identifier. That is structural rather than reviewed: the types that hold secrets implement no
`Serialize` at all, so an entry field carrying one would not compile.

Every field is written out, including as `null`. Skipping absent fields would make "not applicable"
and "an older version did not record this" indistinguishable in a file read years later.

### A refused request, and what it does not say

**Since 2026-08-25**, F12 of
[the full-repository review](../assurance/reviews/review-2026-08-24-full-repository.md). The trail had
an inversion in it. A credential that *failed* authentication produced an entry — that is how a
brute-force attempt becomes visible at all. A credential that *worked*, used to ask for a path that is
not a path, a route that does not exist, or a method a route does not have, produced nothing. Somebody
holding a stolen token and mapping this API worked in silence, while the failed guess from outside did
not.

Those now write a `request-refused` entry, with a `deny_reason` of `malformed-path`,
`malformed-export`, `malformed-body`, `unmatched-route` or `unmatched-method`.

`malformed-body` is the one that needed its own machinery: a body the parser refuses is answered by
the framework *before* any handler runs and before the fallback below sees anything, so neither of the
other two places could record it. It costs nothing on the path that works — only a failed parse
authenticates a second time, for a request that was never going to be served.

**It is not a denial, and the difference is the point.** A denial means the evaluator considered a
request and said no; this means the request never reached it. So the entry carries **no rule and no
path** — there was no path, that is what was wrong with it — and `detail` says what the caller was
attempting.

**The input is not in the entry.** The malformed part is exactly the part a caller controls, and
putting unparseable bytes into the one artefact this project keeps tamper-evident is how a trail
becomes an injection surface. Who, what they attempted, and that it was refused is what the question
afterwards is about.

**Only an authenticated caller is recorded**, and that is a decision rather than an oversight. The
trail is fail-closed: a full audit volume takes the service down. If anonymous traffic wrote entries,
anybody who can reach the listener could turn a `404` into an outage by asking for pages that do not
exist — and a made-up token is exactly as cheap to produce as none, so an unknown route treats the two
the same. On a route that *does* exist a failed authentication is still recorded, because that path is
bounded by having to know a route.

### Two entries about one operation, and how to read them

**The decision is recorded before the work happens.** That is the property the whole design rests on
— nothing is served or changed before the trail says it was authorized — and it has a consequence
worth knowing before you read a trail forensically: *an "allowed, 200" entry is a record of a
decision, not proof that the operation succeeded.*

So anything other than success gets a **second entry** for the same operation, with the status the
caller actually received and a `deny_reason` that says what happened instead:

| Reason | Means |
|---|---|
| `not-found` | The read was allowed and the path did not exist. |
| `not-served` | The read was allowed and no value reached the caller — undecryptable, not UTF-8, a store that could not answer, or an export that aborted. |
| `write-failed` | The write was allowed and the store did not accept it. |
| `delete-failed` | The delete was allowed and nothing was deleted. |
| `not-listed` | The version listing was allowed and the path did not exist. |

These are **not denials**, even though they use the same field. A denial has no allowed entry before
it; a correction always does.

**`POST /v1/export` corrects every path it had recorded** (added 2026-08-21, finding F4 of the
review). One missing path fails the whole export, and the earlier paths' values never leave the
process either — so a three-path export failing on the third leaves three decisions and three
corrections. Correcting only the path that failed would leave the other two claiming reads that did
not happen.

Before 2026-08-21 the correction existed on reads and writes only, so `delete`, `export`, and the
version listing over-claimed. The direction was always conservative — the trail claimed more access
than occurred, never less — which is exactly why it went unnoticed for three phases.

## Fail closed

If **no** configured device accepts a record, the request is refused and no secret is served. If one
device of two fails, the record is written, and the failure is reported so the health endpoint and
metrics can surface it — a second device that has been failing for a month is a second device that
does not exist.

Two operational consequences, both intended:

- **A full audit volume is an outage, not a logging gap.** It is also the one check `/v1/health`
  cannot answer, so it needs something that can see the filesystem — see
  [monitoring.md](monitoring.md). Monitor free space on the audit volume,
  not just whether the service answers. This is the failure mode the design chooses on purpose.
- **The server refuses to start with no audit device configured.** A secret store without an audit
  trail is a configuration error in this project, not an operating mode.
- **And it refuses to start without the SQLite device specifically** (since 2026-08-24, F3 of
  [the full-repository review](../assurance/reviews/review-2026-08-24-full-repository.md)). The chain head a restart
  resumes from is read from the store and from nowhere else. A file-only configuration was accepted
  before that date and did something worse than fail: every restart began a *second* chain in the same
  file, with a `prev_hash` naming a record that is not the line above it. A trail that looks rewritten,
  produced by starting the service. The file device is a second copy on separate storage — which is a
  reason to run both, not a reason to run it alone.

### Who can fill the volume: anyone who can reach the listener

Added 2026-08-21, finding F5 of the review. **A rejected request writes an entry too** — a missing or
invalid token is exactly the event a trail should carry, since brute force that leaves no trace is
the worse failure. Combined with fail-closed auditing that makes the outage above reachable
**without a credential**, by anyone who can open a connection.

This is inside the threat model's stated boundary, and it turns into three operational rules:

1. **Do not publish the port.** The deploy network is the only place that needs to reach it. Ours
   has no `ports:` at all and every deploy runs through a runner on the LAN.
2. **Rate-limit unauthenticated 401s at the reverse proxy**, so they never become entries.
3. **Alert on the rate of audit growth**, not only on free space. Growth is what warns in time; a
   full volume is the outage.

Retention (below) bounds what is *queryable*, not what is on disk: `ciphr audit cut` is a scheduled
operation and not a defence against a peer writing faster than the schedule runs.

A record that no device stored does **not** consume a sequence number. A gap in the sequence is
indistinguishable from a deleted entry, and an audit trail that reports tampering after a disk error
is one nobody will read twice.

## The hash chain

Each record contains the hash of the one before it, and the hash of a record is the SHA-256 of
**exactly the bytes that are stored**. Two consequences:

- Verification hashes the stored text and compares. It re-serializes nothing, so a future change in
  how records are encoded cannot invalidate a chain written today.
- A line in the JSON Lines file *is* the hashed payload. `sha256sum` on a single line reproduces its
  hash, and the next line's `prev_hash` should equal it. The chain can be checked with shell tools if
  it ever comes to that.

### What the chain does and does not prove

It detects **partial** tampering: an entry edited, removed, reordered, or inserted.

It does **not** detect a complete forward rewrite by someone who can write to the store. They can
recompute every hash from the point they changed onward, and the result verifies. There is a test
asserting exactly that, so the limitation is stated in code as well as in prose.

Closing that gap needs an anchor **outside** the store. Two ways, and they compose:

- Configure the file device on a filesystem the service account can append to but not rewrite, or
  ship lines off the host as they are written.
- Record the head hash somewhere else periodically. That one is a command:

```sh
# take an anchor: one JSON line on stdout, appended to the file if --out is given
ciphr audit anchor --out /mnt/evidence/ciphr-anchors.jsonl

# later, verify the chain against the newest anchor in that file
ciphr audit verify --anchor /mnt/evidence/ciphr-anchors.jsonl
```

Four things about it are worth knowing before it goes into a schedule:

- **It reads without the lock and without the master key**, so it runs while the server does.
  Verification hashes stored records; it needs no key, and a reader is not a second writer.
- **It records no audit entry of its own.** An entry would move the head it just wrote down, and
  writing one would need the lock the running server holds.
- **The file it writes has to be somewhere this store's writer cannot reach**, or it proves nothing:
  another host, a backup, an append-only share. Next to the database it is decoration.
- **An existing anchor is checked before a new one is appended.** Anchoring over a chain that
  contradicts the previous anchor would hand a rewrite a fresh alibi, so it refuses instead.

A mismatch reports both of its possible causes, because they cannot be told apart from here: the
chain was rewritten, or the anchor file belongs to a different store. Both are worth stopping for.

What an anchor covers is the chain **up to the anchored sequence**. Everything after it rests on the
chain alone until the next anchor, which is the argument for taking them on a schedule rather than
after an incident.

## Two devices, one chain

The chain state lives in the sink, not in a device, so every device records the same history. Two
devices with independent sequences would produce two histories that cannot be compared, which is most
of the value of having a second one.

The SQLite device writes into the same database as the secrets; the file device is the second copy
that is deliberately *not* in that database. A break in one and not the other localizes the damage —
which is the main reason to run both.

### A device that misses a record is stopped, and how to bring it back

**Since 2026-08-24**, F6 of
[the full-repository review](../assurance/reviews/review-2026-08-24-full-repository.md). Before that,
a device that failed one write kept being written to — and because the chain is shared and advances
as soon as *any* device stores the record, the next record that device accepted carried a `prev_hash`
naming a record that is not in it. That file stops verifying at that point, permanently, and what it
looks like afterwards is a trail somebody edited. It was produced by a volume that was briefly full.

So a device that misses a committed record is **quarantined**: it is not written to again while the
process runs, and `/v1/health` reports `audit_devices[].quarantined_from` with the first sequence
number it missed. **That field is the one to alert on.** A deployment runs two devices so that it has
two copies; a value there means it has one.

**An existing rule on `accepting` already fires**, which is worth saying because the paragraph above
reads as though a new one were required to see the state at all. A quarantined device reports
`accepting: false` and keeps reporting it — it is not being asked, so it cannot succeed, and a device
that went back to `true` because nobody wrote to it would be the clearest possible way to hide this.
`quarantined_from` is what tells the two apart: `accepting: false` alone can be a volume that filled
and will free itself, and `quarantined_from` never clears while the process runs.

**It is in three other places, and one place it is not.** Since 2026-08-25, from
[the field report of that date](../assurance/field-reports/field-report-2026-08-25.md):

- **the trail**, as an `audit-device-failed` entry. `device-quarantined: <device>` for a device
  stopped while running, written on the same request as the refusal it followed;
  `device-behind-at-start: <device>` for one found behind the chain at startup, with `detail` naming
  the sequence it missed from.
- **stderr**, one line per quarantined device at startup, naming both the published label and the
  device's own name — the label to match against `/v1/health`, the name to find the file. The trail
  is still the artefact; the line only says that the state exists.
- **`/v1/health`**, as above.

**Not the container health check.** It passes while a device is quarantined, and that is deliberate on
this release's own terms — `degraded` is explicitly not a liveness signal, and this is less than
`degraded`. So both signals a container platform reads, exit status and health, say fine. Do not
conclude from a green container that the devices are green.

What quarantine trades is worth stating plainly. The quarantined copy stops growing, so it is
incomplete. What it keeps is the property that makes a copy worth having: everything in it verifies,
end to end, and where it stops is visible. **An incomplete trail that says so beats a
complete-looking one that cannot be checked.**

Three properties follow from where the quarantine decision sits, and each of them is a case that
would otherwise bite:

- **A total failure quarantines nothing.** The decision is taken *after* the chain advances, so a
  record no device stored is a record no device missed. A volume that fills and is then freed
  recovers on its own.
- **The last device standing is never quarantined.** Its refusal means nothing was committed, so the
  request is refused fail-closed and the device stays eligible. Quarantine cannot walk a deployment
  down to no devices one failure at a time.
- **A restart does not lift it.** Restarting is the first thing anybody does when a device fails, and
  an in-memory quarantine would be undone by exactly that — the first record after the restart
  splicing the file as before. So at startup each device is asked where it is and compared against
  the chain; a device holding records but standing behind the head starts quarantined.

**Bringing a device back:**

1. **Note where it stopped.** `quarantined_from` on `/v1/health` is the first sequence it missed, so
   it holds everything below that number and nothing above it.
2. **Archive it.** Move the file aside, the way a rotation would, and keep it — it is evidence for
   the window it covers, and nothing else holds an independent copy of that window.
3. **Fix the volume**, then **restart the service**. An **empty** device is not quarantined: it
   begins a new segment whose first record names a `prev_hash` that the archived file explains. That
   is the same shape a log rotation leaves behind, which is why it is not treated as a fault. A
   device brought back onto a disk that is still full is quarantined again on its next record.

**One thing this procedure cannot tell you, and it is a gap rather than a subtlety.** There is no
command that verifies a standalone audit *file*: `ciphr audit verify` reads the chain out of the
store, which is the device that kept working. So "the quarantined copy verifies cleanly up to where
it stopped" is a property this format supports — one line is exactly one hashed payload, checkable
with `sha256sum` — and not one this CLI will confirm for you. Worth knowing before an incident is the
moment you find out.

**There is no backfill**, and that is a decision rather than an omission. Copying the missed records
out of the SQLite device into the file would make the file *look* continuous while its content came
from the very device the second copy exists to be independent of. The gap is the honest artefact:
two files, a documented window between them, and both verifying.

**Fix the volume before step 3.** A device that is brought back onto a disk that is still full is a
device that is quarantined again on its next record.

### What a recorded token issuance is worth, and what it is not

`issue-token` and `revoke-token` entries do **not** defend against whoever can already read the
master key. Issuing a token needs that key, and anyone holding it plus the database decrypts every
secret directly — the threat model puts that reader outside the defended boundary deliberately (A5,
`../threat-model.md`), and no audit entry moves that line.

What the entries change is what the trail can be asked afterwards. Until 2026-08-20 no token command
wrote one, so a credential created that way was invisible, and every access made with it read as
ordinary activity of a legitimate identity — the trail answered *"who read this"* confidently and
wrongly. The chain could not help: it proves nothing was **removed**, and this was never written.

With the entry, concealing the act requires rewriting the chain forward from it, which is exactly
what an anchor kept outside the store detects. So the value is conditional and worth stating plainly:
**it is only as good as the anchor schedule.** Two anchors bracketing the issuance turn "somebody may
have minted a credential" into "the chain between these two heads was rewritten".

### Stores initialized before 2026-08-19 are missing the first line of their file copy

`ciphr init` ignored `--audit-file` until that date, so the record it writes — sequence 1, the
genesis of the chain — reached the database and not the file. Every later record reached both. The
fix went in the same day, and **it does not repair an existing store**: a chain is precisely the
thing that cannot be filled in afterwards.

What that means in practice, in decreasing order of how likely you are to meet it:

- **The database copy is complete and verifies from 1.** `ciphr audit verify` on such a store is
  unaffected. This is not a damaged trail.
- **The file copy cannot be verified from its own beginning.** Its first line is sequence 2, whose
  `prev_hash` names a record the file does not contain. Checking the file standalone therefore needs
  the genesis hash from the database — or an anchor — as its starting point.
- **The first cut that would remove sequence 1 is refused**, and this is the one that costs time if
  it is a surprise. `ciphr audit cut` looks for every record it would remove in `--archive`, by
  hash, and sequence 1 is not there. The message names it: *"the first missing sequence numbers are
  1"*. That refusal is correct — the record really is not archived — and the resolution is a
  deliberate `--assume-archived` for that one cut, after confirming the store predates the fix,
  rather than treating the check as broken.

A store initialized after the fix has none of this. To tell which you have: if the oldest line in
the file device's file is sequence 2 while the database's oldest is 1, it is a pre-fix store.

## When verification fails

A procedure invented during an incident is a procedure nobody trusts, so here it is in advance.

1. **Do not re-chain the entries.** Rewriting hashes to make verification pass destroys the only
   evidence of what happened and produces a trail that lies. If it is ever done deliberately, it
   belongs in a new entry that says so.
2. **Find where it breaks.** Verification reports the first sequence number that fails and how:
   - `HashMismatch` — this record was edited in place and the stored hash was not updated.
   - `PrevHashMismatch` — a record was removed, inserted, or reordered at this point.
   - `SequenceGap` — records are missing or duplicated.
   - `SequenceMismatch` — a record's own sequence number disagrees with where it is stored, which is
     what a copied row looks like.
3. **Compare the two devices.** The file and the database hold the same chain.
4. **Treat the gap as unknown, not as empty.** Assume every access between the break and the next
   verified record went unlogged, and treat whatever those credentials could reach as potentially
   read.
5. **Start a new chain deliberately.** Resume from the last verified head, or archive the old chain
   read-only and start fresh. Both are defensible. Silently continuing is not.

## Retention

**Deleting entries is not an option; archiving them is.** The chain verifies a gap-free sequence, so
a `DELETE` against `audit_log` makes everything after it unverifiable from genesis and reports as a
`SequenceGap` — a tampering signal. A trail that routinely claims tampering is one nobody reads,
which is why retention here is one operation rather than a time-based rule pointed at the table:

```sh
ciphr audit cut --keep 50000 \
  --anchor /mnt/evidence/ciphr-anchors.jsonl \
  --archive /var/lib/ciphr/audit.jsonl
```

Three things have to be true together, and the command does them in this order:

1. **The queryable device is bounded**, so `/v1/audit` and the viewer stay small and fast. That is
   `--keep`, a count of the newest entries to leave behind.
2. **The archive is complete.** Every record the cut would remove is looked for in `--archive` — the
   file device's file and its rotated siblings — matched by hash, which for this format means the
   line is byte-identical. A record that is not there is not removed: the cut is refused and nothing
   changes.
3. **The cut is anchored outside the store.** The anchor at the cut is appended to `--anchor` and
   synced to disk *before* the records go, then a second anchor over what survived is appended after.
   Verification of the remainder starts from the first of those.

Point 3 pays for itself twice, and that is why it is not optional. An anchor outside the store is the
only defence against a forward rewrite — anyone who can write the store can recompute every hash
forward, and the chain then verifies. Retention and that defence are the same operation when they are
done together, and two separate ones when they are not.

**Where the anchor file lives decides what all of this is worth.** Beside the database it is
decoration: whoever can rewrite the trail can rewrite it too. Another host, a backup, or an
append-only share is the point. The command says so when it notices the file sitting next to the
store.

### What a cut trail looks like afterwards

`ciphr audit verify` prints where the trail now begins and how many entries went. It exits zero: a
legitimately cut store must not report tampering, or the check stops being run. What it cannot do
alone is tell a cut from a deletion — the store's `audit_cut` row is a claim by whoever can write the
store, and the routine check rests on it. Passing `--anchor` is what settles that, by comparing the
row against the anchor the cut wrote outside. The output says which of the two you got.

Two states are refused rather than continued, and both mean records were removed without a cut
recording it: an `audit_log` that ends at or before the recorded cut, and an empty one behind a
recorded cut. The service does not start on either. That is the same fail-closed choice as everywhere
else in this component — a trail that reads as consistent while hiding a removal is worse than an
outage.

### Still true

- **Do not trim the table by hand.** A bare `DELETE` produces the `SequenceGap` above, and afterwards
  nothing distinguishes a retention run from a cover-up — including for the person who ran it. `cut`
  is the difference, because it leaves the anchor behind.
- **Watch the fill level.** Auditing is fail-closed, so a full audit volume stops the service serving
  secrets. A bound that nothing runs is not a bound: `cut` belongs in a schedule, and the fill-level
  check stays the thing that catches the case where the schedule is not keeping up.
- **The archive itself is unbounded**, and rotated files are shipped and expired by whatever already
  does that on the host. If that tooling compresses them, `cut` cannot read them — decompress what it
  needs, or use `--assume-archived` and know what the assumption is.
