# ADR-27 — The vault is a startup dependency, and that requirement is written down rather than cached away

| | |
|---|---|
| **Status** | **Accepted 2026-08-26.** No cache, no lease, no agent. The availability requirement `ciphr-run` has always implied is now stated where an operator reads it, in `docs/operations/availability.md`. [ADR-22](0022-the-trail-records-what-consumed-an-authority.md) and [ADR-14](0014-ciphr-run-injects-into-a-child-process.md) are unchanged, which is the substance of this record rather than its side effect |
| **Date** | 2026-08-26 |
| **Affects** | [ADR-14](0014-ciphr-run-injects-into-a-child-process.md), [ADR-22](0022-the-trail-records-what-consumed-an-authority.md), [ADR-25](0025-the-ci-side-fetch-is-its-own-binary.md), `docs/operations/availability.md`, `docs/operations/wrapper.md`, issue #52 |

## Context

`ciphr-run` fetches at exec time (ADR-14). That is the property that makes it good: the value never
enters the container definition, and if any check fails **nothing** is executed.

It also means **every container start is coupled to the vault being reachable.** The failure mode is
not a slow degradation. A host reboots, its services come up, the vault is not up yet or is being
upgraded, and every wrapped service exits `125` with nothing started. The wrapper is behaving exactly
as designed; the deployment is down.

A managed vault answers this with an SLA and a client-side cache. This project answers it with *"run
the vault where it is at least as available as the things that depend on it"* — which is true, is a
real deployment constraint, and was **nowhere written down.** Issue #52 filed that, and named "do
nothing and write the requirement down" as a serious candidate answer.

## Decision

**No cache, no lease, and no agent. The requirement is documented instead.**

`docs/operations/availability.md` is the new page, and it answers three questions an operator
currently has to work out for themselves: what depends on the vault being up, at which *moments* it
depends on it, and what therefore must not be co-located with it or restarted alongside it.

That page is the whole of the change. Nothing in `crates/` moves.

## Rationale

**A cache would take the trail's first job away from it, not degrade it slightly.** ADR-22's rule is
that the trail records what consumed an authority, and *"an entry is written where its price is
already paid."* A cached value is served without a fetch, so there is no price and no entry — and
"who read this, and when" stops being answerable for exactly the reads that happen most often. That
is not a detail to engineer around. It is why a cache is a decision rather than a feature, and having
made the decision, it is a no.

**Every place the value could live is worse than not having it.** On disk is a new plaintext location
and undoes what `ciphr-run` exists for. In memory dies with the process, which is precisely the
restart it would be there to survive. There is no third place, and this is where the idea runs out
before any of the arguments above are needed.

**A lease trades a property some deployments would refuse.** Recording one entry saying *"this
identity may hold these paths until T"* is coherent, and it changes what the trail means: from "who
read this" to "who could have read this, and until when". For a deployment whose reason for choosing
this project is the first sentence, that is a downgrade, and it would be one taken on their behalf by
a default. If a deployment ever needs it, it needs it as a named, off-by-default surface entry whose
cost sentence says what the trail stops being able to answer — not as an improvement.

**Restart-only reuse is the narrow version, and its window is the whole argument.** It covers the
reboot case and not a long outage; it keeps one entry per genuine acquisition; and it still needs a
number with a reason, a place for the value to live (see above), and a stated floor under how quickly
a revocation takes effect. Three unresolved questions to cover the one failure that a correctly
ordered host boot also covers — because the fix for "the vault was not up yet" is a dependency
ordering, and that is a thing the deployment already expresses.

**And two properties would quietly stop holding.** ADR-24 made revocation reachable without an
outage; anything cached or leased outlives a revocation by the length of the window, which puts a
floor under a mechanism whose value is that it takes effect immediately. And the audit sink refuses a
request when no device accepts a record — a cache that served during an audit outage would remove
fail-closed for the reads it covered, silently, at the one moment the property matters.

**A third consumer binary would need an audience the first two cannot serve.** ADR-14 and ADR-25 are
deliberate about this: a wrapper for a foreign image and a fetch for a CI job, each with its own
argument. An agent holding leases would be a third, and the bar those two set is that a new binary
must have an audience the existing ones cannot serve. "The same audience, but tolerant of the vault
being down" is a different availability posture for the same consumer, not a different consumer.

## Consequences

- **The requirement is now a documented deployment constraint**, which means it can be got wrong
  visibly rather than invisibly. `availability.md` names the co-location rule, the restart-ordering
  rule, and the upgrade window, and it says what each one looks like when it is violated.
- **`docs/operations/wrapper.md` gains the pointer**, because exit code `125` at boot is where an
  operator meets this, and the page they are reading at that moment is that one.
- **This is the answer that ages.** If the estate ever reaches the shape where the constraint cannot
  be met — a vault that genuinely cannot be as available as everything depending on it — the thing
  to reopen is the lease, as a surface entry, with the trail's changed meaning in its cost sentence.
  This record is not a refusal to ever have one; it is a refusal to have one by default and unstated.

## Rejected alternatives

All three are in the Rationale, because the reasoning for the answer *is* the comparison: a
client-side cache, a lease with the lease as the audit unit, and restart-only reuse within a bounded
window. The order they are rejected in is the order of how much of ADR-22 each one keeps.

**One more, which issue #52 named as explicitly not the ask and which will be proposed anyway:**
storing the consumer's credential remotely so that no secret file lies on the host. That moves trust
rather than removing it, and it adds a fetch to the path that is already the problem. The credential
question is [ADR-26](0026-oidc-federation.md), which removes the file for consumers that can
federate — and notably does *not* help here, because a federated exchange is one more thing that
needs the vault reachable at start.
