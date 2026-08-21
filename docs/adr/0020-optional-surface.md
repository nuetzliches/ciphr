# ADR-20 — Optional surface, and the core it may not reach

| | |
|---|---|
| **Status** | **Accepted 2026-08-20, built 2026-08-21.** All three of the first entries exist: `honeypot_alert` (build), and `viewer_api` and `bulk_export` (runtime, and a breaking change for a deployment that does not name them). The gate arrived with the first entry, as this record required. Every condition below is discharged |
| **Date** | 2026-08-20 |
| **Affects** | `ciphr-server`, `ciphr-store`, `ciphr-cli`, `openapi.yaml`, plan sections 12 and 24, ADR-11, ADR-15, ADR-16, ADR-21 |

## Context

This project already has optional features. It has three of them, in three different shapes, and
none of the three says out loud what a deployment gains or gives up by choosing one way or the
other:

- **The viewer is a container you do not deploy** (ADR-11). Optionality by absence, and the cleanest
  of the three — but it is a property of how the thing is packaged, not a decision anybody records.
- **`[report] enabled = false`** in plan section 23. A boolean in a configuration file, invented for
  one feature, defined nowhere else.
- **ADR-15's severe tiers are designed and deliberately not built.** Optionality by not writing the
  code, which is the strongest form available and also the least adjustable: the only way to change
  your mind is a release.

Three shapes for one idea is two too many, and the gap between them is where the next feature will
invent a fourth.

There is a second reason to settle this now, and it is the one that decides the shape. The external
review covers three crates and about 1500 lines. **If optionality ever reaches those crates, "the
reviewer read the code that decides every access" becomes "the reviewer read the code that decides
every access in one configuration."** A review that has to be repeated per configuration is not a
review; it is a promise to do one later.

So the question is not whether features may be optional. It is where optionality is allowed to live.

## Decision

A named, deliberately small set of **surface entries**. Each one adds attack surface, each one is off
until a deployment turns it on, and turning one on is a recorded decision rather than a flag. Plan
section 24 holds the design and the first entries. Four properties are the decision.

**1. Nothing optional is reachable from the reviewed core.** `ciphr-crypto`, `ciphr-policy`, and the
path, pattern and secret code in `ciphr-core` know nothing about any entry: no flag, no
`#[cfg(feature)]`, no trait object that only one configuration installs. Optional behaviour composes
in `ciphr-server`, `ciphr-store` and `ciphr-cli`, which are the crates whose job is composition
anyway.

**Where a feature genuinely needs something from the core, the core gains it unconditionally.** Not a
gated function — a general one, present in every build, reviewed once, with the optional part built
on top of it outside. ADR-16 is the worked example: its blind index needs a subkey derived from the
root key, which is core material. What belongs in `ciphr-crypto` is therefore a general derivation of
the kind `TokenPepper` already uses; what belongs outside is the index, the column, the lookup and the
endpoint. **The core grows only in ways that are unconditional.** That sentence is the whole of
property 1, and every other rule here exists to keep it true.

**2. Two kinds of switch, and which kind an entry gets is a decision, not a preference.**

- A **runtime entry** is composed at startup. Off means the route is never registered and the hook is
  never installed — axum answers from the fallback and the handler sits in no reachable path. **Off
  means absent, not dormant:** no `if enabled { … } else { 404 }` inside a live handler, because a
  dormant handler is reachable code with a branch in it, and the branch is where the mistake will be.
  Absence is also observable from outside, which a branch is not.
- A **build entry** is a Cargo feature, off in the default build. Choose it when a deployment must be
  able to prove the code is **not there** rather than merely not called. The threat model's sentence
  "no anonymous endpoint except `/v1/health`" is exactly such a claim, and it is worth more when it is
  a property of the binary than when it is a property of a file somebody can edit.

The second kind costs a build matrix, so it is not the default answer. It is the answer where the
claim being made is about absence.

**3. An entry is a record, and the service repeats it back.** Three required fields — whether it is
on, the date the deployment accepted the cost, and the reason — and **the service refuses to start on
an entry that is on and cannot say since when and why.** That is the same refusal as starting without
an audit device: a configuration that cannot answer the question is a configuration error, not an
operating mode. A flag with no reason next to it is a flag whose safest-looking reading, six months
later, is to leave it on.

What is visible where follows the rule plan section 10 already states — an unauthenticated endpoint
may report **what the process enforces** and never **what is stored**:

- **`/v1/health` carries the fact.** Which entries are active is what the process enforces, and a
  monitoring check that cannot see the shape of the thing it monitors is watching a different system.
- **The reason is authenticated only**, through `ciphr surface show` and the administrative read. It
  is deployment-specific prose, and prose written by an operator describes their environment.
- **Startup writes one audit entry naming the active surface**, so the trail says when a deployment
  changed its own shape. Today that change leaves no record anywhere the trail can be asked about.

**4. There is a closed list of what may never become an entry.** The audit device requirement.
Fail-closed ordering — record stored before response produced. Deny by default. TLS at the listener.
The envelope scheme and its AAD binding. The single path normalization. Constant-time comparison of
credentials.

Adding to the surface list is an ordinary change. **Adding to *this* list, or removing from it, is a
new ADR.** The only realistic failure mode of this mechanism is that it grows inward one reasonable-
sounding step at a time, and the counter to that is a list somebody can point at.

## What "adaptive" may mean here, and what it may not

The obvious next thought is a system that adjusts its own posture: stricter under suspicion, looser
when quiet. It is rejected, for three reasons that are worth writing down because the idea will
return.

- It is the availability weapon ADR-15 declined, arriving under a friendlier name. A process that can
  make itself stricter can be made to make itself stricter.
- Self-driven state is state an adversary drives. The same reasoning rejected an automatic un-freeze:
  a posture that moves on its own is a posture nobody can reconstruct afterwards.
- A system that is sometimes stricter is a system that is never tested in the mode it is in.

**What is adaptive is the choice, not the process.** The service measures whether an entry's
precondition holds and says so; a human on the host flips the switch. Three that are worth reporting
because they are already written down as conditions somewhere and are checkable nowhere:

- **The identity granularity ADR-15 names.** Its severe tiers become worth their cost "when the
  identity set is granular enough that `disable-identity` costs one consumer instead of all of them".
  That is countable, and an administrative view can say `not met — one identity serves every target`
  instead of leaving the condition in a record nobody re-reads.
- **Whether anything polls `/v1/health` at all.** ADR-15 states that an alert nobody polls is not an
  alert, and that nothing here can check that the last step happened. Half of it can be checked: the
  process knows when its health endpoint was last fetched. That proves nothing about whether the poll
  becomes a page — it is a necessary condition and not a sufficient one — but a necessary condition
  that is currently invisible is worth making visible, and `surface enable` on the host is the right
  place to refuse when nothing has asked in days.
- **Whether the retention cut is running.** ADR-16's property 4 bounds an anonymous write path against
  a finite store; where the cut is designed and not scheduled, that bound has nothing behind it.

## What was rejected

**A `[features]` table of booleans.** The state without the trade. It answers "is export on" and never
"who decided that, when, and against what". Six months on, an unexplained flag reads as an accident,
and the safest-looking response to an accident is to restore the default.

**Feature flags inside handlers.** Cheaper to write and it keeps the route table stable. It also
leaves every optional handler compiled, wired and one boolean away from serving — and it makes the
off state unobservable from outside, so nothing but reading the configuration can tell you what a
deployment exposes.

**Cargo features for everything.** A build matrix is a distribution problem: two artefacts with the
same version and different behaviour, and a checksum that tells you nothing about which one you hold.
Reserved for entries whose claim is absence.

**A route to flip a switch.** Same answer as ADR-3 gives policies and `freeze` gives its own clearing:
a guard reachable through the door it guards is not a guard. Entries change on the host.

**Per-identity or per-path entries** — "export, but only for this identity". That is authorization,
and authorization has a mechanism: the capability set evaluated by one code path (ADR-9, and the
capability rule in section 6). A second thing that also decides who may read what is the drift that
rule exists to prevent. The surface list decides what the **process** offers; the policy decides who
may use it. Those two must never both be in the business of the same question.

**Making auditing, or fail-closed, an entry.** It is the first request anyone will make of this
mechanism — a deployment under load, an audit volume filling up, and one boolean that would make the
problem go away. Property 4 exists to answer it once, in writing, so that it is not re-argued during
an incident.

## What must be true before an entry ships

- ~~**The gate arrives with the first entry.**~~ **Built 2026-08-21** as
  `ci/check-core-no-features.sh`, with `honeypot_alert` as that entry. Four claims about the three core
  crates: no `[features]` table, no `cfg(feature)` in the sources, no code reference to a surface
  module, and no features handed to them by `[workspace.dependencies]` — the last one being the same
  claim from the other side, since a crate that declares none can still be built with some if a
  dependent asks. Comment lines are stripped before the surface check, because all three crates discuss
  attack surface in prose and should keep doing so.
- ~~**The test rule is decided before the second entry, not after.**~~ **Implemented 2026-08-21**, and
  the rule is unchanged: default (everything off), everything on, and each entry alone — n+2
  configurations, which stays affordable while n is small and stops being affordable exactly when the
  set has grown into a framework. **That is the signal to stop, and it is written here so that it is
  recognized as a signal rather than as a CI problem.**

  While n is 1, "everything on" and "each entry alone" are the same build, so CI runs two: the default
  and `--all-features`. **The default one had to be added.** `--all-features` was there first and was
  the only one, which meant the configuration a deployment actually receives was the untested one — and
  every test asserting what a build *without* the entry does is `#[cfg(not(feature = …))]`, so those
  could not run at all. A green pipeline that never compiled the shipped build is the failure this rule
  exists to prevent, and it existed here for the length of one afternoon.
- ~~**`openapi.yaml` marks an optional route as optional.**~~ **Done 2026-08-21.** Five routes carry
  `x-surface-entry` naming the entry they belong to, each says in prose that it answers `404` where the
  entry is not named, and the file's header lists the mapping in one place. A reader who only has the
  specification can now tell "this deployment does not serve it" from "this version does not have it",
  which is the distinction a specification of routes no deployment necessarily serves has to make.
- ~~**Each entry's cost sentence ships with the binary.**~~ **Done 2026-08-21.** `ciphr surface show
  <config>` reads a server configuration's stanzas and prints each entry's cost next to the operator's
  reason, and `GET /v1/surface` returns the same pair. The operator writes why they said yes; the
  software says what they said yes to.

  **One caveat, stated in the command's own output.** `surface show` reads a *file*, not a binary, so
  for a build entry it reports what the deployment asked for rather than what it got. Nothing on the
  host can see the service's build — that is what `GET /v1/health` is for. An earlier draft used a
  compile-time check in the CLI to claim "in this build", which is meaningless: the CLI never contains
  the server's optional code at all.

  **And one thing that was missing until 2026-08-21, from a field report on the `0.5.0` rollout.** All
  three interfaces printed only the entries a deployment had turned *on*. Since an entry off is absent
  from the router — property 2, and the thing this record most wants on the wire — an operator holding
  a `404` had no way to tell a route this build never had from one this deployment never named, and an
  empty `surface` array meant both. `ciphr surface show` and `ciphr-server --check-config` now print
  the entries a configuration did *not* name, each with its cost sentence, which is the sentence
  somebody deciding about an entry actually needs and was the one printed only for entries already
  decided in favour of. `ci/check-surface-entries.sh` keeps the CLI's copy of the list from silently
  losing a row.

## Consequences

The three shapes collapse into one, and the two records that were shaped by this question get a
mechanism instead of a special case: ADR-16's `[report] enabled` becomes an entry of the build kind —
and its authenticated sibling [ADR-21](0021-a-scanner-is-a-sender-with-a-token.md) becomes a *runtime*
entry, because absence is load-bearing only for the claim about anonymous endpoints, which that record
leaves standing. ADR-15's `alert` becomes a build entry too — for a feature whose central claim is that bait is
indistinguishable on the authentication path, code that is not compiled in is the strongest available
version of that claim for every deployment holding no bait.

Two things get worse, and both are the price rather than a surprise.

**Deployments diverge.** Two installations of the same version can now answer differently, and a
client cannot assume a route exists. That is why the specification has to say which ones are optional,
and it is an argument for keeping the set small enough to hold in your head.

**Every entry is a configuration nobody runs in production but CI must still build.** The n+2 rule
bounds it; nothing makes it free.

What does not change is the part worth protecting: the core stays one artefact, in one shape, for
every deployment — which is the only condition under which a review of it means anything a month
later.
