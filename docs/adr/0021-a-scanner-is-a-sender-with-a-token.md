# ADR-21 — A scanner is a sender with a token: leak reports arrive authenticated

| | |
|---|---|
| **Status** | **Proposed 2026-08-21.** Nothing is implemented; the build conditions are at the end of this record |
| **Date** | 2026-08-21 |
| **Affects** | `ciphr-crypto`, `ciphr-store`, `ciphr-server`, `ciphr-cli`, plan sections 21, 23 and 24, ADR-15, ADR-16, ADR-18, ADR-20 |

## Context

ADR-16 was deferred as a channel with no sender: wherever every consumer sits inside the boundary
the service listens on, nobody who holds no token can reach a drop box, and the deferral concluded
that "a report from them adds nothing the trail would not have carried anyway."

That sentence is true of *reads* and silent about *escapes*. The trail records that an identity read
a value; it does not and cannot record that the value later sat in a job log, a support attachment,
or a crash dump. ADR-16's own consequences named the gain precisely — "a way to hear about a value
it cannot detect on its own" — and the deferral did not decide that this hearing was worthless. It
decided that the one sender the design imagined, a stranger with no token, does not exist here.

A different sender does. Plan section 13 calls the escape of values into plaintext copies the blind
spot, and section 14 documents how easily a CI log becomes one. Masking in `ciphr run` prevents the
escape at one source, for the runner that was measured; nothing owns *detection* anywhere else. A
scanner that walks logfiles where they live is that detector — and it runs on machines inside the
boundary, which means it can hold a token. The expensive half of ADR-16 — the first anonymous write
path in a design that is fail-closed on its audit trail — is not needed to hear from it.

## Decision

A log scanner as client-side tooling, submitting candidate values to an **authenticated** report
endpoint whose matching, marking and visibility are the ones plan section 23 already designed. Six
properties are the decision.

**1. The scanner submits; the server matches.** The scanner holds no key material of any kind. It
finds candidate values in logfiles and submits them over the authenticated API; the lookup runs
server-side against the blind index of plan section 23, unchanged — one HMAC per write, one indexed
lookup and one constant-time comparison per report. What `ciphr-crypto` gains is exactly what ADR-20
property 1 already describes for this index: a general subkey derivation, present unconditionally,
reviewed once, with the index, the column and the lookup composed outside it.

**2. Reporting is a capability, not a role.** `POST /v1/report` requires an identity with `write` on
the virtual path `sys/report` — the pattern of `sys/leaks` and `sys/surface`, and no new capability.
A scanner identity holds that one rule and nothing else; deny by default does the rest. The result
is a credential that can *say* things and cannot *ask* anything: it fetches no value, lists no path,
and reads no leak. That matters because of where it lives — see property 3.

**3. The answer stays `202` and silence, even to an identity.** A match and a miss are
indistinguishable in body and in timing, exactly as ADR-16 property 1 states, and for the same
reason at one remove: the scanner token is by design the most widely distributed credential in the
system, deployed wherever logs are, which is everywhere the design worries about. An endpoint that
answered match or no-match would be a confirmation oracle keyed to the token most likely to be
stolen. So every match is visible only through the authenticated administrative half — `/v1/leaks`,
`ciphr leak list`, the audit trail — read by identities that are *not* scattered across log hosts.
The timing correction ADR-15 and ADR-16 both carry applies unchanged: the mark and the full audit
entry land after the response is flushed, or the path absorbs the same cost either way.

Keeping the semantics identical to ADR-16's buys one more thing: there is one handler with one
analysis. If ADR-16 is ever reopened, its anonymous endpoint is this handler exposed without an
identity — a build entry and a listener, not a second implementation.

**4. The trail is spent by identities, not by candidates.** A scanner run submits many values and
most of them match nothing. A matched report is audited in full — path, version, and the reporting
identity, which the anonymous design could never record. Misses aggregate into one audit entry per
identity per window carrying a count, the `explain_the_gap` reasoning again: the trail says what
happened without letting the volume of a scan decide how much gets written. A report is not an
access to any stored value — nothing is served — which is why aggregation is honest here and would
not be for a read. The ordering of section 23 stands: body cap, then the limiter — per-identity now,
which is a real bucket where per-IP was a courtesy — then the audit write, then the store, with the
concurrency cap keeping report traffic off the mutex that secret reads queue on. **Never recorded:
anything derived from a submitted value.** That rule was written against an attacker-chosen
candidate and it does not relax for a well-meaning one.

**5. The scanner is bound by ADR-1 more tightly than anything else in the design.** Its entire
purpose is to touch leaked values, so its own output is a leak surface. A finding is a location —
file, line, and which report it became — and never the value. No findings file holds a candidate, no
cache persists one, and the value exists in the scanner's memory and on the TLS connection and
nowhere else. Candidates come from patterns: the assignment shape ADR-18's naming rule makes
predictable (`NAME=…` where `NAME` is a plausible last path segment), generic high-entropy strings,
and operator-supplied names. The scanner needs no `list` capability to know what names look like —
the rule is documented, and a live list of paths on every log host would be inventory in the wrong
place.

**6. The endpoint is a surface entry of the runtime kind.** Named `report`, off by default, the
route unregistered when off, enabled as the recorded decision ADR-20 requires. It is not a build
entry, because the claim that needed absence — "no anonymous endpoint except `/v1/health`" — remains
true with this record built and enabled. That sentence in the threat model does not move, which is
most of what makes this record cheaper than the one it grew out of.

## What this settles for ADR-16, and what it leaves

ADR-16 stays deferred, anonymous, and untouched; this record does not supersede it. What changes is
the cost of reopening it: the index, the mark, `/v1/leaks`, the reindex and the handler all exist
once this is built, so reopening ADR-16 shrinks to the exposure decision — the same handler without
an identity, behind the build entry it already specifies, on the listener its question 6 holds open.

One of ADR-16's preconditions is answered here rather than left to phase 9. **Question 5 in plan
section 21 — whether the value index is written unconditionally — is answered: unconditionally**, on
every `put`, in every deployment, as the plan already recommends. A scanner makes the half-indexed
corpus more dangerous, not less: its silence is only meaningful if a miss means "not ours" rather
than "not indexed yet". The duplicate-visibility cost of the index is stated in section 23 and is
now paid by deployments that never scan; that is the price of a corpus whose silence means one
thing.

Question 6 — the anonymous listener — is untouched and stays with ADR-16.

**The interaction with ADR-15 needs one sentence, not a change.** A scanner that reports a honeypot
value produces the strongest signal the system has, and it still only alerts: the tiers that act on
an identity require a request that authenticated *as* that identity, and the scanner authenticated
as itself. The per-bait latch of ADR-15 absorbs a scanner that finds the same bait in the same log
every night.

## What was rejected

**Requiring a token on ADR-16's endpoint instead of writing this record.** The question was asked
directly: is the drop box better authenticated-only? No — anonymity is that feature's sender
definition, not an implementation detail. The person ADR-16 exists to hear from — a developer
reading a public repository, a stranger holding a leaked `.env` — is defined by having no
relationship with this system, and a drop box that demands a relationship before listening has
excluded its entire audience. Requiring a token does not make ADR-16 cheaper; it makes it this
record, which hears a different sender. The two share machinery and differ in exactly one property,
which is why they are two records and not one amended one.

**Answering match or no-match to an authenticated reporter.** Tempting, because an identity that
could read the secret learns nothing from confirmation. But the scanner identity deliberately cannot
read anything, and its token is the widely-deployed one — the answer would build the oracle back in
and key it to the most stealable credential in the design.

**Distributing the blind-index key to scanners, so matching could be local.** An offline,
unthrottled oracle in a config file on every log host. The index is safe because the key never
leaves the root key's side; this would be the design arguing with itself.

**Local matching of honeypot values.** Bait is not a secret, so shipping bait values to scanners
looks free — and it puts a list of which values are bait on every log host, which is ADR-15's
visible-flag rejection in a new shape: an attacker who reads scanner configuration learns exactly
what to avoid. Bait candidates travel to the server like every other candidate, and only the server
knows what they are.

**The server reading logs itself, by pull or by shipping.** The process holding the master key does
not grow log-parsing, file-crawling, or a reason to hold credentials for other machines' disks —
the same boundary argument that kept SMTP out of the alerting design in ADR-15. Detection goes to
where the logs are; only candidates travel.

**A new `report` capability.** The capability set is small and evaluated by one code path, and
sections 22 and 23 already answer surface-specific rights with virtual paths under the existing
verbs. A capability invented per feature is the drift the set exists to prevent.

## What must be true before this can be built

- **The external review has taken place.** The subkey derivation lands in `ciphr-crypto`, which is
  in the mandatory scope, and this record adds a write path to the reviewed composition. The same
  ordering that holds for phase 8 holds here: built after the review, not as its backlog.
- **The ADR-20 gate exists.** This may be the first surface entry to ship; if so, the check that the
  core crates declare no features and reference no surface module arrives in the same change, as
  ADR-20 requires.
- **The reindex has run before a deployment enables the entry.** Enabling `report` over a corpus
  that is partly unindexed produces the silence that means two things. The reindex is resumable and
  records its progress (section 23), and `ciphr surface` refusing to enable the entry while versions
  remain unindexed is the mechanical form of this sentence.
- **`openapi.yaml` marks the route optional, and the threat model gains the identity-held write path
  in the same commit as the endpoint** — the rule ADR-16 already states for its own exposure,
  applied to this one.
- **The scanner ships with a false-positive expectation written down.** Pattern matching over logs
  finds noise; the design absorbs noise silently by construction, but an operator reading
  `ciphr leak list` needs the sentence that a mark proves the *value* escaped, wherever the scanner
  found it, and a miss proves nothing at all.

## Consequences

The leak machinery gains its first sender that actually exists: escape into logfiles becomes
detectable inside the boundary, which is where this deployment's values and this deployment's logs
both live. The trail gains something the anonymous design could never give it — *who reported*, so a
mark arrives with provenance. And ADR-16's reopening becomes an exposure decision over built
machinery instead of a build.

The costs, stated: every database now carries a value-derived column and its duplicate-visibility
consequence, scan or no scan. Token holders gain a write path that must be limited like the
anonymous one even though its traffic is attributable, because attributable is not the same as
bounded. And the scanner is a program that must be deployed with rights to read logs and the
discipline to write none of what it finds — a small tool whose failure mode is becoming the leak it
hunts.

What it does not solve is inherited from section 23 and narrowed by pattern matching: a value that
was transformed, encoded or truncated in the log will miss; a value in a file nobody scans stays
invisible; and a miss remains evidence of nothing.
