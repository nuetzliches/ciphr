# ADR-15 — Honeypots, and what a tripwire may do

| | |
|---|---|
| **Status** | **Accepted 2026-08-20, in the `alert` tier only.** Nothing is implemented; the build still waits on the external review below |
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

**1. Bait is indistinguishable from the real thing, on every axis a caller can observe.** Same token
format, same `401` with the same body, same response shape for a secret read, no additional field
anywhere on the value path, and no timing difference — recognition happens on the existing code path
with the existing constant-time comparison. Bait that announces itself is decoration, and bait that
announces itself only to whoever measures carefully is worse, because it looks like it works.

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

Acceptance did not clear this list. Every item is a condition on the code, and the first of them has
not moved.

- **The external review of `ciphr-crypto`, `ciphr-policy`, and the path and pattern code in
  `ciphr-core` has taken place.** This ADR adds behaviour to the authentication path. Building a
  tripwire into code that nobody outside this project has read inverts the order that matters, and it
  is the inversion that feels like progress. `docs/security-review.md` says whether the condition is
  met; nothing here changes that line.
- **The timing property is a test, not a claim.** `every_kind_of_invalid_token_looks_the_same` in
  `crates/ciphr-store/src/tokens.rs` is where the honeypot case belongs — inside that test, not
  beside it.
- **`freeze` has an operations document before it has code.** What it closes, what stays open, how it
  is cleared, and what it looks like when it fires on a false positive. `docs/operations/` is for
  anything hard to undo, and a service that refuses to serve is exactly that. Written on 2026-08-20:
  [`../operations/freeze.md`](../operations/freeze.md).
- **The false-positive surface is enumerated first.** Host-side operations that decrypt everything by
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
- **Which of the tripwire's side effects are inside the fail-closed contract is decided rather than
  discovered.** Auditing is fail-closed, so a full audit volume already refuses requests. If the
  tripwire's row, marker file, or distinct entry can fail *independently* of the ordinary audit
  entry, there is a state — one an adversary can help bring about, since filling the volume is a
  named denial-of-service lever — in which bait and non-bait answer differently. Whatever the answer
  is, it must not be observable on the value path.

## Review

A design review of this record, dated 2026-08-20, is in
[`../review-adr-15-16-2026-08-20.md`](../review-adr-15-16-2026-08-20.md). Findings F1, F3, F4, F5 and
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
