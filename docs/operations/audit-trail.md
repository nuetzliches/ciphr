# The audit trail

**Status:** implemented and tested as of 2026-08-19. The chain, the fail-closed sink, the file
device, and the SQLite device work and are tested, and so do `ciphr audit tail`, `verify`, `anchor`,
and `cut` — the last of these is what bounds the queryable trail, and it arrived after the rest.

This is the component the project exists for. Everything below follows from one sentence: **an access
that could not be logged must not happen.**

## What is recorded

Per entry: the sequence number, an RFC 3339 UTC timestamp, the previous entry's hash, the principal
(identity name, kind, and the non-secret identifier of the token used), the action, the normalized
path, the version, whether it was allowed, why it was refused, the rule that decided it, and the
request context — request id, client address, user agent, HTTP status, and the channel it arrived
through.

**Never recorded:** the secret value, key material, or a token. Only a token's non-secret
identifier. That is structural rather than reviewed: the types that hold secrets implement no
`Serialize` at all, so an entry field carrying one would not compile.

Every field is written out, including as `null`. Skipping absent fields would make "not applicable"
and "an older version did not record this" indistinguishable in a file read years later.

## Fail closed

If **no** configured device accepts a record, the request is refused and no secret is served. If one
device of two fails, the record is written, and the failure is reported so the health endpoint and
metrics can surface it — a second device that has been failing for a month is a second device that
does not exist.

Two operational consequences, both intended:

- **A full audit volume is an outage, not a logging gap.** Monitor free space on the audit volume,
  not just whether the service answers. This is the failure mode the design chooses on purpose.
- **The server refuses to start with no audit device configured.** A secret store without an audit
  trail is a configuration error in this project, not an operating mode.

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
