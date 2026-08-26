# What depends on the vault being up, and when

**Status:** current as of 2026-08-26. Written as the answer to issue #52
([ADR-27](../adr/0027-the-vault-is-a-startup-dependency.md)): there is no client-side cache and no
lease, so the availability requirement this project has always had is a thing an operator has to know
rather than a thing the software works around.

Nothing here is new behaviour. All of it was true before this page existed, which is the problem this
page is for.

## The requirement, in one sentence

**Run the vault where it is at least as available as the things that depend on it, and where it does
not restart alongside them.**

That is not an SLA and it is not advice about hardware. It is a statement about *ordering*: the
moments below are moments when something else cannot start, or cannot continue, unless this service
answers.

## The three moments

### 1. A wrapped container starts

`ciphr-run` fetches at exec time ([ADR-14](../adr/0014-ciphr-run-injects-into-a-child-process.md)),
which is the property that keeps the value out of the container definition and means that if any
check fails, **nothing is executed**. It is also the coupling: no vault, no start.

What it looks like: exit code `125`, no child process, and a service that is down rather than
degraded. [wrapper.md](wrapper.md) is the page an operator is reading when they meet this.

**The failure mode that matters is not the vault being broken.** It is a host rebooting and bringing
its services up in an order where the vault is not ready yet — every wrapped service on that host
exits `125` at once, and a restart policy then retries them against a vault that comes up thirty
seconds later. That resolves itself, noisily, and looks like an incident.

### 2. A CI job fetches

`ciphr-ci` runs at the start of a workflow ([ADR-25](../adr/0025-the-ci-side-fetch-is-its-own-binary.md)).
A vault that is down during an upgrade window fails the jobs that start in it. They are retried by
whoever notices, which is cheap compared to moment 1 — but it is the moment most likely to be met
*during a planned change*, because a maintenance window and a working day overlap.

### 3. A workload federates

Since federation exists, a consumer that authenticates through it
([ADR-26](../adr/0026-oidc-federation.md)) needs the vault reachable **to authenticate** as well as to
fetch. Federation removes a stored credential; it adds one more thing to the start path.

That is worth stating next to the feature: a bootstrap token in a file works while the vault is
unreachable in the sense that it is *already there*. Neither approach starts a container without the
vault, so this is not a regression — but a deployment that adopts federation should not read it as
having loosened anything about ordering.

## What an operator must therefore not do

**Do not co-locate the vault with the things that fetch from it, if that host reboots as a unit.** A
single host running the vault and the services wrapped by `ciphr-run` has a boot order problem by
construction: something has to be first, and everything else fails until it is. Where that shape is
unavoidable, the dependency has to be expressed in the supervisor — a health-gated dependency, not a
restart policy that retries until it works.

**Do not restart the vault in the same operation as its consumers.** A rolling restart that includes
both takes the consumers down for the length of the vault's own start, whatever the ordering, because
they fetch at start.

**Do not schedule the vault's upgrade window inside a deploy window.** [upgrade.md](upgrade.md)
already asks for a backup first; this adds the other half. A vault restart is short, and every
container start and CI job in that interval fails outright.

**Do not treat the vault's own administration as free.** Issuing a token needs the store's writer
lock, which the running server holds — so onboarding a consumer that cannot federate means stopping
the service ([ADR-24](../adr/0024-revocation-is-the-one-write-the-api-may-do.md) removed the outage from
*revoking* and deliberately left it on issuing). The consequence for an estate that grows:

- **Onboard in batches, in a window.** One stop, several `ciphr token issue` calls, one start. Not one
  stop per consumer.
- **Where consumers arrive with hosts, federate.** [federation.md](federation.md) is the answer to
  exactly that growth shape, and it is why the batching advice above is a fallback rather than a plan.
- **The vault's availability requirement includes its own administration.** That is the sentence issue
  #51 asked for, and it is here rather than in a runbook because it changes how the estate is designed
  and not what somebody types.

## What does *not* depend on the vault being up

Worth knowing, because it bounds the blame during an incident:

- **A running service keeps running.** `ciphr-run` fetched at exec and handed the values to a process
  that owns them now. The vault going down after that start changes nothing for it, and this is the
  reason the coupling above is a *start* problem rather than a runtime one.
- **The host-side reads.** `ciphr list`, `ciphr versions`, `ciphr token list` and the rotation read
  open the store read-only ([ADR-22](../adr/0022-the-trail-records-what-consumed-an-authority.md)):
  no lock, no master key, no entry, and they answer while the service runs *or* while it is down.
- **The viewer** is a separate container ([ADR-11](../adr/0011-ui-is-an-optional-separate-package.md)).
  It shows nothing without the API, but it does not take anything down with it.

## Why there is no cache

Because a cached value is served without a fetch, and an entry is written where its price is already
paid ([ADR-22](../adr/0022-the-trail-records-what-consumed-an-authority.md)) — so a cache would take
"who read this, and when" away for the reads that happen most often. ADR-27 is the full argument,
including the two narrower shapes that were weighed and what each of them would cost.

The practical form of it: **the fix for "the vault was not up yet" is a dependency ordering, and that
is something a deployment already knows how to express.** A cache would be a way of not expressing
it.
