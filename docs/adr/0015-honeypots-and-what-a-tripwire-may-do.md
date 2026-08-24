# ADR-15 — Honeypots, and what a tripwire may do

| | |
|---|---|
| **Status** | **Accepted 2026-08-20 in the `alert` tier only, and built on 2026-08-21** as the `honeypot_alert` surface entry (ADR-20) — bait recognition on the authentication path, the trip on the value path, the latch, `/v1/honeypots`, and the CLI to plant it. **The marker file is the one part of the tier that is not built; see below.** The review that gated the build happened on 2026-08-21, and the obligation that replaced it is open: the surface added here does not inherit that acceptance and needs its own pass |
| **Date** | 2026-08-19 |
| **Affects** | `ciphr-store`, `ciphr-server`, `ciphr-audit`, `ciphr-cli`, plan section 22, phase 8 |

## Context

The audit trail records every access. It does not *notice* anything. A compromised deploy runner
(A3) holding a valid token reads what its policy allows, the trail dutifully records it, and whether
anyone realizes depends on a human reading the trail and recognizing that the pattern is wrong.
Section 2 of the plan states the property this project has and cannot design away: **its failures are
silent.**

A honeypot is the cheapest available counter for one class of that silence. Bait that no legitimate
consumer touches turns a read into a signal, and the signal needs no interpretation: there is no
benign reason to take it.

Two kinds are in scope, because they catch different things.

- A **honeypot token** — a credential in the documented format that authenticates nothing — planted
  where credentials should not be but often are. Presenting it proves somebody read something they
  should not have.
- A **honeypot secret** — a path holding a real-looking, useless value, authorized like any other
  path and read by nobody. Reading its value through the API proves an identity is enumerating
  rather than fetching what it needs.

## Decision

**Accepted, in one tier.** Honeypot tokens and honeypot secrets, with a per-honeypot trigger tier of
`alert`, `disable-identity`, or `freeze` — of which **`alert` is the only one that gets built**. The
other two stay in this record as designed and are not implemented; property 3 names the condition that
would bring them back. Plan section 22 holds the design. Four properties are the decision; everything
else is implementation.

**What acceptance settles, and what it does not.** It settles the shape: which tiers exist, where bait
lives, what a trip may do. It does not release the code. The external review named at the end of this
record is a condition on *building* phase 8, and accepting a narrower design did not discharge it — a
narrower thing built in the wrong order is still built in the wrong order.

**The review has since discharged it (2026-08-21), and the sentence above is why that is worth
distinguishing.** What was released is the *order*: there is now code that somebody outside this
project has read, and a tripwire built on top of it is no longer built on top of nothing. What was not
released is coverage. The acceptance in `docs/security-review.md` says in its own words that new
surface in the authentication path does not inherit it, and names this phase as the example — the
review read what a rejected credential does today, not what it does once bait exists. So the condition
at the end of this record changes shape rather than disappearing: it stops being *wait for a review*
and becomes *the behaviour added here is reviewed when it exists, against that same document*.

**1. Bait is indistinguishable from the real thing, on every axis a caller can observe.** Same token
format, same `401` with the same body, same response shape for a secret read, no additional field
anywhere on the value path, and no timing difference — recognition happens on the existing code path
with the existing constant-time comparison. Bait that announces itself is decoration, and bait that
announces itself only to whoever measures carefully is worse, because it looks like it works.

**Narrowed 2026-08-22, and the wording above is left as it was written.** Property 1 said "on every
axis a caller can observe" and "no timing difference". The response half holds and is tested; the work
half does not, and a second review of this surface
([review-2026-08-21-current-tree.md](../assurance/reviews/review-2026-08-21-current-tree.md), claim note C11) is what
established that. Three differences remain, all after the constant-time comparison: a malformed token
returns before any database work, a known identifier costs one verifier query an unknown one skips, and
recognized bait writes a larger audit payload before the `401`. The third is the one that matters,
because it separates the two cases an attacker actually wants told apart — *this credential is bait*
versus *this credential is expired or revoked* — and it is reachable by whoever holds a credential whose
secret matches.

**What this record now claims, then:** bait is indistinguishable in the *response*, on every axis of it,
and the work done is not equalized. The sentence two paragraphs up — that bait announcing itself only to
whoever measures carefully is worse than bait that announces itself — is the standard this falls short
of, and it stays where it is rather than being softened: it is the argument for closing the gap, not a
description of the code.

**Why narrowing rather than equalizing.** Equalizing means issuing a database query nobody needs and
padding every rejection entry in the trail with fields that mean nothing, to hide a difference nobody
has measured — and then the claim would rest on an unmeasured assertion again, one layer along.
`docs/security-review.md` C11 now names the three differences in its falsification column, which is
where a reviewer can attack them; that is the honest version until somebody measures remote
separability. The 48-bit random identifier is what bounds useful enumeration in the meantime, and it
does that whether or not the timings are equal.

**Indistinguishable includes what follows the decision, not only the decision.** The sentence above is
about recognition. A trip also writes a row, a marker file, a distinct audit entry and a flag on
`/v1/health`, and none of that is work an ordinary invalid token causes. So the side effects happen
**after the response is flushed**, or the path absorbs the same cost either way. It is stated here
because the property is otherwise true of the comparison and false of the request — which is exactly
the bait that announces itself to whoever measures carefully.

**2. The trigger fires after the policy allowed the read, never inside the decision.** A honeypot
secret is authorized exactly like any other path. There is no honeypot branch in `ciphr-policy`, no
new capability, and nothing about bait in the evaluator. One code path decides every access, or
reasoning about that path stops being worth anything.

**What "taking bait" means, decided 2026-08-22.** The trip is recorded and latched *before* the value
is retrieved and decrypted, so an allowed read of bait that is deleted, missing, corrupt or
undecryptable latches although nothing was served (claim note D10 of
[review-2026-08-21-current-tree.md](../assurance/reviews/review-2026-08-21-current-tree.md)). **The behaviour is
kept, and this is where that is written down.** Two reasons, and the second is the one that decides it.

Taking bait means *being allowed to read it*, not *receiving its value*. An identity that no legitimate
consumer's job requires reached a path no legitimate consumer touches and was granted it; whether the
storage layer then produced bytes is a fact about the store, not about the caller's intent, and the
signal this tier exists to raise is about the caller.

And closing it is not free in the direction that matters. It needs a store operation that establishes
readability *before* the trip entry and without releasing the value before the audit write — which is
the fail-closed ordering this whole record is built on. Paying that to remove a page whose subject is
*somebody was allowed to read bait and could not get it* would be paying to suppress an event worth
looking at: bait in that state is itself unusual.

**What the operator gets instead**, and the reason this is not a silent trade: the trail already says
no value was served. `read_secret` writes a correcting entry — `not-found` or `not-served` — under the
same request id as the decision, so the pair reads as one event. What overstates the case is
`/v1/health` and the open trip, which say `tripped` without a value having left, and
[../operations/honeypots.md](../operations/honeypots.md) now names that where somebody responding to a
page will read it.

**3. Each tier is chosen with its false-positive cost written next to it.** `alert` costs a page.
`disable-identity` costs one identity's deploys until a token is reissued on the host. `freeze` costs
every deploy until an operator clears it on the host — and while frozen the service still serves
`/v1/health`, the audit trail, and every metadata route, because whoever is investigating needs those
more than ever. A freeze is recorded in the store, so it survives a restart, and it never clears
itself on a timer.

**The middle tier costs what the identity set makes it cost.** `disable-identity` reads as bounded
next to `freeze`, and it is — while more than one identity exists. Where a single machine identity
serves every deploy target, revoking its tokens stops every deploy, and the two severe tiers then
differ only in whether already-running services can still fetch. The tiers are a granularity feature
and they inherit the granularity of the identity set: the per-service token scoping that route B makes
worthwhile (ADR-14) is also what makes this tier mean something other than `freeze`.

**So only `alert` is built.** Where one machine identity serves every deploy target — the ordinary
starting shape, because per-service scoping is work that follows a first integration rather than
preceding it — the two severe tiers are one tier under two names, and shipping them would hand out an
availability lever whose trigger condition is "somebody read a path". They become buildable when the
identity set is granular enough that `disable-identity` costs one consumer instead of all of them.
That is the condition to cite when this is revisited; not a date, and not a judgement that the tiers
were a bad idea.

**How the built tier is switched on (added 2026-08-20).** As a Cargo feature, off in the default
build — a *build entry* in the sense of [ADR-20](0020-optional-surface.md), not a line in a
configuration file. Property 1 of this record claims that bait is indistinguishable on the
authentication path; for every deployment that plants none, code which is not compiled in is the
strongest available version of that claim, because absent code has no timing to get wrong. It also
keeps this record's behaviour out of the default binary — which mattered while the external review below
was outstanding, and still does for a narrower reason now that it has happened: the accepted review
covers the authentication path *without* this code, so a deployment that plants no bait runs nothing
the acceptance does not cover. The feature is what makes that sentence true by construction rather than
by discipline.

**4. No unauthenticated request reaches a tier above `alert`.** The leak-report endpoint of ADR-16
accepts candidate values from whoever can reach it. A reported honeypot value is the strongest signal
this system can produce, and it still only alerts. The tiers that act on an identity require a
request that authenticated as that identity.

**A trip latches per piece of bait.** ADR-16 accepts candidate values from whoever can reach the
endpoint, and a reported honeypot value sets `tripped`, which monitoring turns into a page. Without a
latch that is a page an anonymous party can produce on a schedule, and alert fatigue is how a tripwire
stops being read. So one piece of bait trips at most once until it is cleared on the host — the way
`freeze` already behaves — and further reports of already-tripped bait fall into the aggregate entry
that refused reports use. Plan section 23 makes `leaked_at` monotonic for the same reason; this is
that reasoning applied to the tripwire.

## The marker file is not built (decided 2026-08-21)

The `alert` tier was specified as three channels: a distinct audit action, a flag on
`/v1/health`, and a marker file the deployment's monitoring can watch. Two are built. The
third is not, for two reasons that are worth separating because only one of them is about
this repository.

**A marker file needs a path, and a path is deployment configuration** — which this record
says honeypots do not have. "Configuration: none. A honeypot is data" was written about the
bait, and the marker is not bait; but inventing a location to avoid inventing a setting is
the worse of the two. The obvious location, beside the database, puts the marker on the
volume the conceded denial-of-service fills, so the channel that is supposed to survive a
full volume would be the one that does not.

**And for the deployment this was built for it buys nothing.** The monitoring here polls
`/v1/health` over HTTP; a file on the service's volume is not something it can see. The
marker exists for monitoring that watches a filesystem instead — a node agent, a
`textfile` collector — and that is a real shape, just not this one.

**The condition for building it** is therefore a deployment whose monitoring reads
filesystems rather than endpoints, and the design question it has to answer first is where
the file lives such that it is visible to that monitoring and not on the volume an
adversary can fill. Until then the trail is the authoritative record and `/v1/health` is
the channel, and this paragraph is here so the gap is a decision rather than an omission
somebody discovers while writing an alert rule.

## Which side effects are inside the fail-closed contract (decided 2026-08-21)

The condition list below asked for this to be *decided rather than discovered*, and reading the code
turned out to force the answer rather than leave it open. Two facts about what exists:

- **`AppState::record` is "at least one device accepted" fail-closed**, not "all devices". A device
  that refuses is noted and produces an `audit-device-failed` entry; the request proceeds.
- **`SqliteAuditDevice` opens the same file as the store, on its own connection.** So an audit record
  and a row written by the store are two transactions, not one. They cannot be made atomic with each
  other, and with a `file` device configured the audit record survives a full or locked database that
  a store write would fail on.

Together those say a `tripwire` row **can** fail while the request's audit record succeeds. That is
exactly the state property 1 forbids from being observable, and it is reachable by the named
denial-of-service lever. So the split is drawn where fate is already shared:

**The authoritative record of a trip is the request's own audit entry, and there is no second write.**
A read that takes bait, or a presented honeypot token, records the entry it was going to record
anyway — with `honeypot-triggered` as its action instead of the ordinary one. One entry either way,
the same size, through the same devices, under the same fail-closed rule. This is property 1's second
sanctioned option rather than its first: the path *absorbs the same cost either way*, so nothing needs
to be deferred past the flush to stay indistinguishable, and a trip cannot be suppressed without
refusing the request — which is what fail-closed already does for every request.

**The `tripwire` row, the `/v1/health` flag it feeds, and the marker file are outside the contract, and
they happen after the response is flushed.** They are conveniences over the authoritative entry: the
row carries the latch, the flag is derived from it, and the marker file exists for monitoring that
watches a filesystem rather than an endpoint. Each failure is recorded the way a refusing audit device
already is — the trail says the latch is missing rather than the state going quietly wrong.

**What that costs, stated rather than discovered.** An adversary who fills the volume can lose the
latch and the flag: the page may repeat, or `/v1/health` may not carry `tripped` although bait was
taken. What they cannot do is make a value read succeed where another would fail, or suppress the
record — the entry is inside the contract, and where the store is too full for the row it is usually
too full for the ordinary entry as well, at which point the request is refused rather than served
quietly.

**And a deviation from plan section 22's data model, which said the row is the record.** It is not:
the entry is the record and the row is derived state. The reason is the second fact above — a table in
the store cannot share a transaction with an audit device that holds its own connection, so a design
resting on the row resting on the audit contract does not hold. The row keeps its place for the one
thing the trail cannot do: survive `ciphr audit cut`, which bounds the trail and would otherwise
un-latch a trip by retention.

## Why alerting does not mean an outbound connection

The obvious shape for an alert is an email or a webhook. Both are rejected.

The alerting process here holds the master key. An SMTP client or an HTTP notifier inside it is a new
egress path out of the one container in the deployment that should talk to nobody, plus a
dependency — TLS client, DNS, retry state — in the crates that most need to stay reviewable. The
threat model spends its effort keeping values inside this process; adding a component whose job is to
send messages out of it on a trigger an attacker can pull is the wrong trade at any price.

So the alert is a fact on `/v1/health`, an entry in the audit trail, and a marker file. Section 17
already requires monitoring that polls `/v1/health` and watches the audit volume; a tripwire is one
more field for a check that has to exist anyway. Same reasoning that keeps the v1 audit devices to
`sqlite` and `file` when `syslog` and `http` were the easy additions.

**An alert nobody polls is not an alert.** That choice moves the last step of the mechanism out of
this process and into whatever watches it, which is right — and it means the field, the entry and the
marker file are the whole of what this project can deliver. A deployment that has not yet wired
`/v1/health` into something that pages, or that has silenced that check while the service settles in,
gets a tripwire whose entire output is a field nobody reads. That is the anchor-file failure in
another shape: the mechanism is real, the step that gives it effect is somewhere else, and nothing
here can check that it happened. It is an argument about *when* to build phase 8 — after the
monitoring it depends on is live, not before — rather than about whether.

## What was rejected

**A single trigger with no tiers.** Either it alerts, in which case it is not worth the word
"tripwire", or it freezes, in which case every deployment gets an availability weapon whose trigger
condition is "somebody read a path". Tiers are what make the mild version the default and the severe
version a deliberate choice with a written cost.

**Automatic un-freeze after a timeout.** Attractive operationally, and it converts an incident into a
graph nobody kept. A tripwire that resets quietly has, in effect, not fired.

**Freeze held in memory.** Simpler, and defeated by whoever can crash the process. State that an
attacker can clear by causing a restart is not state.

**A honeypot flag visible on the value path**, so that a caller could see what it took. That is the
whole design inverted. The flag is visible on the administrative read path instead, because an
operator who cannot tell bait from a real secret eventually rotates the bait or builds a service on
it, and both destroy it.

**Honeypots as policy configuration.** A honeypot is data — a flag on a secret or a token — and
putting it in the policy file would make it a second thing the evaluator loads and a second thing that
can drift out of step with the store. ADR-3 keeps policies in version control because they *decide*
things. Bait decides nothing.

## What must be true before this can be built

Acceptance did not clear this list. Every item is a condition on the code, and as of 2026-08-21
exactly one of them has moved — the first, which was also the only one nobody here could clear alone.

- ~~**The external review … has taken place.**~~ **Met 2026-08-21.** The review of `ciphr-crypto`,
  `ciphr-policy`, and the path and pattern code in `ciphr-core` took place against `v0.3.0` and was
  accepted; `docs/security-review.md` carries the decision and `docs/assurance/reviews/review-2026-08-21.md` the record.
  The reasoning that put it here is unchanged and still worth reading: building a tripwire into code
  that nobody outside this project has read inverts the order that matters, and it is the inversion
  that feels like progress.

  **What replaces it, because it is not simply gone.** This ADR adds behaviour to the authentication
  path, and the acceptance explicitly does not stretch to new surface there — it names this phase. So
  the obligation inverts in time: the code is now built *first* and reviewed *after*, against
  `docs/security-review.md`, instead of waiting on a review that had nothing to read. Two things follow
  for whoever builds it. The reviewer needs to be told what changed, which means the claims in that
  document covering the token path get an entry for bait rather than a reader inferring one. And the
  Cargo feature above is what keeps the gap honest in the meantime: a deployment that plants no bait is
  still running exactly the code the accepted review read.
- ~~**The timing property is a test, not a claim.**~~ **Met 2026-08-21.** The honeypot case is inside
  `every_kind_of_invalid_token_looks_the_same` in `crates/ciphr-store/src/tokens.rs`, not beside it,
  together with an expired *and* revoked honeypot token — because the dates must not be able to route
  bait back into an ordinary rejection, which is the one way a honeypot stops being one without
  anybody noticing. The server has the matching test in
  `every_kind_of_bad_token_gets_the_same_answer`, plus one that compares the whole response including
  headers against an unknown token.
- **`freeze` has an operations document before it has code.** What it closes, what stays open, how it
  is cleared, and what it looks like when it fires on a false positive. `docs/operations/` is for
  anything hard to undo, and a service that refuses to serve is exactly that. Written on 2026-08-20:
  [`../operations/freeze.md`](../operations/freeze.md).
- ~~**The false-positive surface is enumerated first.**~~ **Enumerated here, and three of the entries
  are now tests rather than sentences:** a listing does not trip, a version history does not trip, and
  a denial does not trip. A host read does not trip either, by construction — the trigger is in
  `ciphr-server`, so `ciphr dump` and `ciphr get` cannot reach it — and that was checked against a
  real store rather than assumed. The original text follows. Host-side operations that decrypt everything by
  design — `dump --format portable`, `export` on the host — must not trip anything, and neither must
  `list` or `versions`. A honeypot that fires on the nightly backup is a honeypot that gets disabled
  in week two. **The entry this list was missing is the one that matters most:** a consumer that
  fetches a whole prefix reads the value of every path under it, which is what `ciphr-run --prefix`,
  `client.environment(prefix)` and any deploy helper built on `POST /v1/export` do. Those are value
  routes, so bait under a fetched prefix trips on every service start.
- **Bait lives outside every prefix any consumer fetches**, and that placement rule is what makes the
  tier mean anything. Plan section 22 says a honeypot secret "is bait only while nobody depends on
  it" and offers the visibility rule as the safeguard: an operator sees the flag on the administrative
  path and does not build on the bait. That assumed a consumer reads *named* paths. Since the
  prefix-fetching routes (ADR-14, ADR-18) it is not an operator mistake to avoid but the ordinary
  consumption pattern, and no amount of visibility helps. Under a scheme like
  `infra/<host>/<service>/<KEY>` bait therefore belongs at a `<service>` level nobody deploys, and
  never beside the real secrets of a real service — which is the opposite of where the instinct puts
  it, because beside the real secrets is where an enumerator looks. The upside: once bait sits outside
  every fetched prefix, reaching its value *requires* enumerating and then reading something nothing
  needs, which is precisely the behaviour this ADR exists to catch.

  **And the rule is about what consumers fetch, not about what the policy allows.** Those are two
  different sets, and the gap between them is where bait belongs. A machine identity is typically
  authorized over more prefixes than any consumer actually reads — the credentials the deploy
  machinery itself uses, for instance, which no service ever pulls into its own environment. Bait
  there is authorized for the identity that would be compromised, untouched by every ordinary fetch,
  and next to the most attractive material in the corpus, which is where an enumerator goes first.
  Establishing that a prefix is unfetched means reading the code that fetches, not the policy: a
  helper that lists a prefix and then exports every path it got back will read bait the policy file
  gives no hint about, while a helper that filters that list against the names its consumer declares
  will not. The policy shows which prefixes are permitted and never which are visited, and it is the
  second question that decides whether bait is bait or a false positive on a schedule.

  **The same two sets decide whether a honeypot secret is possible at all.** Property 2 fires after
  the policy *allowed* the read, so bait needs a gap between what an identity may read and what it
  does read. An identity granted exact paths has no such gap: bait outside its grants produces a
  denial, and a denial trips nothing. Scoping exactly and planting honeypot secrets are therefore
  alternatives rather than complements — honeypot tokens are unaffected either way, and the trade is
  written out in [`../authorization.md`](../authorization.md).
- ~~**Which of the tripwire's side effects are inside the fail-closed contract is decided rather than
  discovered.**~~ **Decided 2026-08-21**, above. The reasoning that put it here is unchanged: auditing
  is fail-closed, so a full audit volume already refuses requests, and if the tripwire's row, marker
  file, or distinct entry can fail *independently* of the ordinary audit entry, there is a state — one
  an adversary can help bring about, since filling the volume is a named denial-of-service lever — in
  which bait and non-bait answer differently. Reading the code showed that the row *can* fail
  independently, which is why the record moved onto the entry instead.

## Review

A design review of this record, dated 2026-08-20, is in
[`review-adr-15-16-2026-08-20.md`](../assurance/reviews/review-adr-15-16-2026-08-20.md). Findings F1, F3, F4, F5 and
F6 concern this ADR and are addressed above. F2 concerned a precondition in plan section 23 and has
since been built. That review is by the same author as the code and does not discharge the external
review named above.

The scoping decision — one tier, and the second half of the placement rule — was taken on 2026-08-20
after reading this design against the consumption pattern of a real deployment rather than against the
plan. Both changes came from that reading; nothing else in the record moved.

## Consequences

An access that is unambiguously wrong becomes loud instead of merely recorded, and the loudest
version of it costs availability on purpose. In exchange the design gains a switch that can refuse
service, and the four properties above exist to bound who can reach it: never an anonymous request,
never above `alert` without an authenticated identity, never cleared anywhere but the host.

Honeypots detect indiscriminate behaviour — enumeration, scraping, a stolen credential tried
everywhere. That is what most real compromise looks like. An attacker who reads only what they came
for is not caught by this, and no amount of bait changes that.

**In the accepted scope the second half of that trade is not taken.** `alert` costs a page and
nothing more, so the switch that can refuse service is designed and absent. What is given up is the
automatic response; what is kept is the detection, which was the half that did not exist. If the
identity set later becomes granular enough for `disable-identity` to mean what its name says, the
design for it is here and unchanged.
