# ADR-15 — Honeypots, and what a tripwire may do

| | |
|---|---|
| **Status** | **Proposed.** Decision required before phase 8; nothing is implemented |
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

**Proposed, not accepted.** Honeypot tokens and honeypot secrets, with a per-honeypot trigger tier of
`alert`, `disable-identity`, or `freeze`, defaulting to `alert`. Plan section 22 holds the design.
Four properties are the decision; everything else is implementation.

**1. Bait is indistinguishable from the real thing, on every axis a caller can observe.** Same token
format, same `401` with the same body, same response shape for a secret read, no additional field
anywhere on the value path, and no timing difference — recognition happens on the existing code path
with the existing constant-time comparison. Bait that announces itself is decoration, and bait that
announces itself only to whoever measures carefully is worse, because it looks like it works.

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

**4. No unauthenticated request reaches a tier above `alert`.** The leak-report endpoint of ADR-16
accepts candidate values from whoever can reach it. A reported honeypot value is the strongest signal
this system can produce, and it still only alerts. The tiers that act on an identity require a
request that authenticated as that identity.

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

## What must be true before this can be accepted

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
  anything hard to undo, and a service that refuses to serve is exactly that.
- **The false-positive surface is enumerated first.** Host-side operations that decrypt everything by
  design — `dump --format portable`, `export` on the host — must not trip anything, and neither must
  `list` or `versions`. A honeypot that fires on the nightly backup is a honeypot that gets disabled
  in week two.

## Consequences

An access that is unambiguously wrong becomes loud instead of merely recorded, and the loudest
version of it costs availability on purpose. In exchange the design gains a switch that can refuse
service, and the four properties above exist to bound who can reach it: never an anonymous request,
never above `alert` without an authenticated identity, never cleared anywhere but the host.

Honeypots detect indiscriminate behaviour — enumeration, scraping, a stolen credential tried
everywhere. That is what most real compromise looks like. An attacker who reads only what they came
for is not caught by this, and no amount of bait changes that.
