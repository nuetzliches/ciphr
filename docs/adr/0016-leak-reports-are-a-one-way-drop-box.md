# ADR-16 — Leak reports are a one-way drop box, matched through a blind index

| | |
|---|---|
| **Status** | **Proposed.** Decision required before phase 9; nothing is implemented |
| **Date** | 2026-08-19 |
| **Affects** | `ciphr-crypto`, `ciphr-store`, `ciphr-server`, `ciphr-cli`, plan section 23, phase 9 |

## Context

A value that has escaped is discovered by whoever finds it, and that person usually holds no token
here: a developer who noticed a key in a job log, a colleague who found an `.env` attached to a
support ticket, someone reading a public repository. There is no way for any of them to tell this
system anything. The report arrives as a message to a human if it arrives at all, and until somebody
acts the store keeps serving the value as current.

The obvious endpoint — send a candidate value, get told whether it matches — is a confirmation
oracle, and an unauthenticated one. For a high-entropy value it gives away little; the sender already
had it. For a low-entropy value it is a guessing machine, and a corpus migrated from `.env` files
contains low-entropy values whether or not it should.

Plan section 10 already contains the sentence that decides this: an unauthenticated endpoint may
report **what the process enforces** and never **what is stored**. A match is what is stored.

## Decision

**Proposed, not accepted.** One unauthenticated endpoint, `POST /v1/report`, that accepts a candidate
secret value and marks the version it matches as `leaked`. Plan section 23 holds the design. Four
properties are the decision.

**1. The endpoint never answers the question.** `202 Accepted` with an empty body for a match and a
miss alike. `429` at a limit, because a limiter is a property of the process rather than of the
corpus. `400` for a malformed body. The lookup runs identically either way, so there is nothing to
measure. The reporter learns that the report was accepted and nothing more; every match is visible
only on the authenticated side, through `/v1/leaks`, `ciphr leak list`, and the audit trail.

**2. Matching goes through a blind index, not through decryption.** A key derived from the root key
with a distinct `info` string — the pattern `TokenPepper::derive` already uses — and
`HMAC-SHA256(key, value_bytes)` stored per version and indexed. One HMAC per write, one indexed
lookup and one constant-time comparison per report.

**3. `leaked` is metadata and influences no authorization decision.** The mark sits on the version,
because a value is what leaks; rotation writes a version that is not marked, so the mark ages out
through the operation that answers it, and there is no command that clears it. Nothing reads the mark
to decide anything.

**4. The limits come before the audit write and before the store lock.** This is the first request
path in the design that reaches the store without an identity, and the service is fail-closed on the
audit trail. A refused report writes no audit entry and touches no database. The endpoint is off
unless a deployment enables it.

## Why property 3 is load-bearing rather than tidy

Refusing to serve a value known to have leaked sounds like the obviously right behaviour, and it is
the one thing this feature must not do.

The mark can be set by an anonymous request. If it refused reads, then anyone who has ever seen a
value could switch that secret off for everybody, from outside, without a credential. The endpoint
would stop being a report channel and become a remote kill switch whose key is the leaked value
itself — and the operators of that switch would be exactly the population the feature exists to hear
from and not to trust.

`rotation` in plan section 8 follows the same rule for a milder reason: it is pure metadata driving
warnings. Here the rule is the security property.

## Why property 4 is load-bearing rather than politeness

Fail-closed means a request whose audit entry no device accepts is refused, and a full audit volume
is a total outage rather than a logging gap. An anonymous request that writes an audit entry is
therefore an anonymous request that spends a finite resource whose exhaustion takes the service down.

So the order is fixed: body size cap, then the limiter, then the audit write, then the store. A
refusal costs a counter increment, and refusals are summarized in one entry per window rather than one
entry each — the same reasoning as `explain_the_gap` in `crates/ciphr-server/src/state.rs`, where the
trail must say what happened without letting whoever caused it choose how much gets written. A
concurrency cap keeps anonymous traffic off the mutex that authorized secret reads also queue on.

One honest limitation: `request_context` deliberately ignores `X-Forwarded-For`, because a header a
client controls is a header a client can lie in. Per-IP buckets therefore key on the connection
address, and behind a reverse proxy every reporter in the world shares one bucket. The global budget
is the real defence there.

## What the blind index costs, stated rather than assumed away

- **Two versions holding the same value get the same index.** A reader of the database file (A4)
  learns which secrets duplicate one another without learning any value. That is genuinely new
  information, and duplicate values across services are exactly what a migration leaves behind.
- **With the index key, a dictionary attack on a low-entropy value is offline and fast.** The key
  derives from the root key, so whoever can mount that attack can already decrypt every value
  directly. The index adds no exposure that holding the master key does not already grant (A4, A5).
- **Without the key it is an HMAC under an unknown key**, no more useful than the ciphertext next to
  it.
- **Versions written before the migration have no index and cannot match.** `ciphr leak reindex` fixes
  that on the host, and until it has run a report against an older value is a miss the endpoint
  cannot admit to — the silence that property 1 buys applies here too.

## What was rejected

**Answering match or no match**, with rate limits as the only defence. That is the oracle, slowed
down. It also puts an unauthenticated endpoint in the business of describing the corpus, which section
10 rules out for `/v1/health` and would be stranger to permit here, where the caller chooses the
question.

**Decrypting every current version per report.** No schema change, no index, no duplicate visibility
— and it turns one anonymous request into a full-corpus decryption. That is a denial-of-service lever
handed out by design, and it makes the rarest operation in the system the one an outsider can trigger.

**A truncated index, or a Bloom filter, for compactness.** Both produce false positives. A false
`leaked` mark on a `breaks-data` secret (plan section 8) invites precisely the rotation that destroys
data, which makes a saving of a few bytes per row the most expensive optimization available.

**Recording anything derived from the submitted value in the audit trail** — the index, a prefix, a
length. The `file` device rotates into backups that are protected less carefully than the database,
and a fingerprint of an attacker-chosen candidate written there permanently outlives the value it
describes. A matched entry names the path, which the trail records for every other access anyway.

**A `ciphr leak clear` command.** The answer to a leak is a new version, which is unmarked. A command
that erases the mark is a delete button on evidence, and it would be reached for by exactly the person
who should be rotating instead.

## What must be true before this can be accepted

- **The external review has taken place.** This ADR adds a key derivation and the only unauthenticated
  request path that reaches the store. Both belong to the surface the review exists for, and the
  derivation lands in `ciphr-crypto`, which is in the mandatory scope.
- **Question 5 in plan section 21 is answered before the migration**: whether the value index is
  written unconditionally or only where reporting is enabled. A half-indexed corpus is the dangerous
  state, because a miss then means nothing and the endpoint is designed not to say so.
- **Question 6 is answered with question 2**: whether the endpoint gets its own listener. A drop box
  reachable only from the internal network reports nothing an internal identity could not already have
  produced in the audit trail, and exposing it is the same three-part decision — network exposure, a
  certificate, a trust boundary — that question 2 already holds open.
- **ADR-15 is built first.** A reported honeypot value is this feature's strongest signal, and it is
  only legible if honeypots exist. The dependency runs one way: ADR-15 does not need this.

## Consequences

The system gains a way to hear about a value it cannot detect on its own, at the cost of the first
unauthenticated write path in the design — bounded to one monotonic boolean per version, on values the
requester already possesses, read by nothing that makes a decision.

What it does not buy: any knowledge about the values nobody noticed, which is most of them, and any
information about who leaked one. A report proves a value was somewhere it should not have been. The
trail's history of reads is the only thing that narrows it further, and that is an argument for the
retention design in plan section 7.
