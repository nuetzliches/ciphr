# The audit trail

**Status:** implemented and tested as of 2026-08-18 (phase 2). The chain, the fail-closed sink, the
file device, and the SQLite device work and are tested. `ciphr audit verify` and `ciphr audit tail`
arrive with the CLI in phase 3; until then verification is a library call, exercised by the tests.

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

Closing that gap needs an anchor **outside** the store:

- Configure the file device on a filesystem the service account can append to but not rewrite, or
  ship lines off the host as they are written.
- Record the head hash somewhere else periodically — another host, a ticket, a chat channel with
  retention. A single 64-character string, kept elsewhere, turns a silent rewrite into a visible
  contradiction.

Neither is implemented here, because neither is application code. Both are cheap.

## Two devices, one chain

The chain state lives in the sink, not in a device, so every device records the same history. Two
devices with independent sequences would produce two histories that cannot be compared, which is most
of the value of having a second one.

The SQLite device writes into the same database as the secrets; the file device is the second copy
that is deliberately *not* in that database. A break in one and not the other localizes the damage —
which is the main reason to run both.

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

Not yet decided, and listed as an open question in the plan. What is decided: rotation is by size,
the rotated file keeps a timestamp in its name, and nothing here deletes anything. Whatever policy is
chosen has to answer two questions — how long entries are kept, and what proves that a deletion was
the policy rather than a cover-up. The second is why the head hash belongs somewhere outside the
store before retention is enabled.
