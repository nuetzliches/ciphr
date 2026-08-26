# ADR-26 — OIDC federation, and the rule ADR-24 was reaching for

| | |
|---|---|
| **Status** | **Accepted 2026-08-26, built the same day.** `POST /v1/auth/oidc/login`, behind the `oidc_login` runtime entry, unauthenticated, recorded as `Action::FederateToken`. Amends [ADR-24](0024-revocation-is-the-one-write-the-api-may-do.md)'s sentence about one write, discharges the ADR-6 promise that has been open since v1, and answers issue #51 in the Rejected alternatives |
| **Date** | 2026-08-26 |
| **Affects** | [ADR-6](0006-auth-machine-identities-with-tokens.md) (the promise it keeps and the trait it does not), [ADR-24](0024-revocation-is-the-one-write-the-api-may-do.md) (amended), [ADR-3](0003-policies-from-configuration.md) (untouched, and that is the point), [ADR-17](0017-certificate-provenance.md) (the reason there is no fetch), [ADR-20](0020-optional-surface.md)'s entry list (a sixth entry), `ciphr-server`, `ciphr-cli`, `openapi.yaml`, `docs/operations/federation.md`, issues #50 and #51 |

## Context

Every consuming host holds a long-lived bearer token in a file. Where one collection point fetches
for everything, that is one credential in one place, rotated in one operation, and it is fine.

**It stops being fine in the deployment shape where a CI runner runs on each host.** The credential
count grows with the host count, each one is long-lived, each one sits on the machine that also runs
the workload, and rotating them is N operations. That is also the shape in which this project is
compared to a managed cloud vault, where a job authenticates by federation and stores nothing — and
it is the largest single difference in that comparison that is inside this project's reach.

Two documents had already committed to fixing it. ADR-6 states it as a design constraint rather than
a possibility: *"Authentication methods sit behind a trait so that OIDC federation can be added
without touching the surrounding code."* And `openapi.yaml` has reserved the path since phase 3, with
the reason written next to it, answering `404` so the name could not be claimed for something else.

So the argument was made. What was left was the implementation — and four decisions the
implementation could not avoid taking.

**One correction to the record above, because a reader will otherwise trust it.** *The trait ADR-6
promised does not exist.* Authentication is a concrete method on `SqliteStore`, called from one place
in `AppState`. Nothing was refactored to introduce one either: the funnel is already a single
function, so federation ends at the same store call as a bearer token — it mints a row and everything
after that is ordinary token authentication. A trait with two implementations, where the second one's
whole job is to produce an input to the first, would be indirection standing where a sentence used to
be. **What ADR-6 was actually buying was that adding a method would not require changing the
surrounding code, and that turned out to be true without the trait.**

## Decision

**A workload presents an ID token a configured provider issued and receives a short-lived ciphr
token in exchange.**

```
POST /v1/auth/oidc/login
```

- **Unauthenticated**, and it is the second route that is — `/v1/health` being the first. A caller
  makes this request precisely because it holds no credential of this system yet. What stands in for
  a bearer token is a signature from a provider the configuration names.
- **Behind a runtime surface entry, `oidc_login`** (ADR-20). Off means the route is never registered
  — the `404` the reservation has documented since phase 3, from the fallback rather than from a
  handler that decides to refuse.
- **The identity, its policies and the lifetime ceiling all come from configuration.** A binding maps
  a claim set to an identity that already exists in the policy file; a name the policy file does not
  have is a refusal to start.
- **Recorded as `Action::FederateToken`**, with the provider as the principal, the identity and the
  minted credential's non-secret identifier as the subject, and the verified `sub` in the detail.
- **`aud` is mandatory and compared exactly.** Without it, a token the provider issued for somebody
  else's service would be valid here, which is the confused-deputy case.

### ADR-24 is amended, and the amendment is the general rule

ADR-24 says *"One route, and it is the only write the API may do."* This is the second one, so that
sentence needs replacing rather than reading around:

> **The writes the API may do are the ones that cannot widen an authority.**

That is a different rule and, we think, the rule ADR-24 was reaching for. Its own argument was never
about arithmetic — it was the asymmetry: *"Revocation only ever removes an authority; a failure or an
abuse of it costs availability. Issuance mints one, and an abuse of it costs everything the identity
may read."* An exchange mints, so on a count it is on the wrong side; on the asymmetry it is not,
because **there is nothing it can mint that the configuration did not already authorize.** No new
identity, no new rule, no lifetime above the configured ceiling. The most an attacker who fully
controls this route can obtain is a credential for an identity a binding already names — which is
what the provider's own signature is the gate on.

ADR-24's boundary list said *"Issuing. It needs the master key to derive the pepper, and it creates a
credential."* The first half was a fact about the *CLI*, not about issuing: the server derives the
pepper at startup and holds it for the process lifetime, so an exchange spends no key exposure that
authenticating a bearer token does not already spend. The second half is answered by the rule above.

**ADR-3 is untouched, and that is load-bearing rather than incidental.** Identities and policies
still come from configuration and the CLI on the host. This route reads that configuration; it
cannot write it.

### The provider's signing keys are configuration, not a JWKS fetch

Written into the configuration file, beside the policies, in version control.

ADR-17 already refused this exact position, for the ACME client: *"an ACME client puts outbound
internet access, an account key, and a writable certificate path into the process that holds
plaintext secrets — ADR-8 exists to remove positions like that, not to add one."* A JWKS fetch is
the same position with a different payload, and it would be the **first** outbound request this
server makes.

It also could not be built here without undoing something else. `ureq` and `rustls` in this
workspace link no public root certificates on purpose (ADR-19), so a client that trusts the WebPKI
cannot be constructed at all — reaching a public provider's JWKS endpoint would mean putting the
WebPKI's roots into the process that holds plaintext secrets, which is the trust set ADR-17 spent
its whole argument narrowing.

**The cost is real and is not hidden.** When a provider rotates its signing key, federation stops
working until an operator copies the new one in. It stops **closed**: the exchange is refused, tokens
already issued keep working, and every bootstrap credential keeps working, so this degrades to the
situation that exists today rather than to an outage. `docs/operations/federation.md` leads with how
to see it coming.

### Claims are matched by equality, and there is no wildcard

Plan section 14 sketched glob bindings using *"the same matching semantics and the same code as the
policy evaluator — a second matcher would be the same class of bug as a second path normalizer."*
The instinct is right and the sketch does not survive contact with the code it names:

- `ciphr_core::pattern` **rejects a partial wildcard by design** — the module says so and gives the
  reason — so the plan's own example, `repo:acme/*:ref:refs/heads/main`, does not parse.
- A claim value **is not a path.** `/` is a segment separator there and an ordinary character in a
  `sub`, and `SecretPath` would NFC-normalize and length-check a string that is neither.

So the choice was a second matcher or no matcher, and the plan was right that a second matcher is out
of the question. Exact equality needs none. A deployment that federates several branches lists them,
in a file with a diff and a reviewer — which is ADR-3's own argument, not a limitation of this route.

### A refusal is recorded once a signature verifies, and not before

Four rejections that do not collapse into one: an expired token, a wrong audience, an unmapped claim
set and an ambiguous one are different findings, and the trail keeps them apart while the wire answers
one `401` that explains nothing.

**But the recording starts at the signature, and that line is a decision.** This route is
unauthenticated, so an entry per attempt would be an anonymous write into a fail-closed trail: fill
it, or make one device refuse, and every request afterwards is a `503`. The router fallback and the
body extractor already draw the line in exactly this place — *"an anonymous caller still writes
nothing … letting anybody write to it by posting garbage would turn a `400` into an outage"* — and
ADR-16 deferred an entire phase over the same cost.

A verified signature changes the answer, because the caller demonstrably holds something a provider
this deployment trusts issued, and is not anonymous any more. What is lost is stated rather than
discovered: **a forged token, an unknown issuer and a malformed one leave no line at all**, so the
trail cannot be used to count attacks against this route. It can be used to answer what it is for —
who federated, as what, and on whose word.

### Two algorithms, and the header does not choose

`RS256` and `ES256`, verified with `ring` — already in the graph because `rustls` uses it, so this is
a direct dependency and no new code. A JWT library would have brought a second signature
implementation, a second base64 implementation and its own claim-validation logic into the
authentication path; what was needed was two verify calls, and the claim rules are this project's own.

**The configured key decides the algorithm and the header only has to agree.** A verifier that reads
`alg` from the header and then goes looking for a key is the shape every algorithm-confusion attack
is written against. Here the key is found among the ones a deployment wrote down, and a header naming
a different algorithm than that key finds no key at all — `none` included.

## Consequences

- **The bootstrap credential does not disappear; it stops being the only way in.** A runner that can
  federate needs no stored token. One that cannot — and humans — still use `ciphr token issue`, and
  ADR-6's closing sentence still holds: *"The token route is needed regardless."*
- **A federated mint is not recorded as `issue-token`.** Counting credentials created means counting
  both actions. That is written into the action's own documentation, because a reader who counts one
  of them will get a number that looks right.
- **The `token_revoke` entry's cost sentence changed**, in the server, the CLI and the diagram: it
  said *"Issuing stays on the host either way"*, and that is now true only of an issuance somebody
  asked for.
- **Coverage debt.** This is new surface in the authentication path, and `docs/security-review.md`
  says explicitly that such surface does not inherit the 2026-08-21 acceptance. The verification code
  is the thing to attack: `crates/ciphr-server/src/oidc.rs`, and the RS256 known-answer test against
  RFC 7515 is the smallest place to start.
- **A provider's key rotation is an operational event with no monitoring behind it yet.** The trail
  shows the exchange stopping; nothing pages on it. Named in `federation.md` and in
  `docs/operations/monitoring.md`'s terms, this is the same shape as ADR-15's alert field: the last
  step of the mechanism is not in this repository.
- **Before enabling it, check the provider.** Forgejo shipped a security fix because the
  `…/idtoken` endpoint issued tokens without verifying `enable-openid-connect`, which mattered for
  fork pull requests; the fix landed before v15.0.0, so any v15.0.x contains it. Verify the
  equivalent for any other forge — a provider that issues ID tokens to a fork's workflow makes a
  binding on `sub` mean less than it reads.

## Rejected alternatives

**A general issuance route — issue #51, and this is its answer.** That issue asked whether an
issuance write may exist, contradicting ADR-24 on purpose, and named "it dissolves" as the option to
evaluate first. It does dissolve, and mostly. With federation, a workload receives a credential and
nobody issues anything; what is left is the bootstrap for consumers that cannot federate, and humans.
Both are rare, planned, and defensibly a scheduled window — which is exactly the argument ADR-24 made
for keeping issuance on the host, and it is untouched by this record.

The remaining case is worth naming so that nobody has to rediscover it: **a deployment whose consumer
count grows with its host count, and whose runners cannot federate.** For that one the window is not
merely inconvenient, and `docs/operations/federation.md` says what to do about it — onboard in
batches, and treat the vault's availability requirement as including its own administration. If such
a deployment ever exists, the route to build is the one issue #51 sketched as its option 2, and this
record's amended rule is the one it would be measured against.

**Issuance "because revocation got a route."** Named by issue #51 as the wrong argument, and it is.
The asymmetry in ADR-24 is real, and a count of routes was never the reasoning.

**A JWKS fetch, cached.** Above. It is the convenient answer and it costs the position ADR-17 exists
to protect.

**A JWT library.** `jsonwebtoken` and its relatives validate claims as well as signatures, which
means a second place where "is this token acceptable" is decided — and the rules that matter here
(the audience is mandatory, the binding is exact, the header does not choose the algorithm) are ones
a library would decide differently or not at all.

**Not persisting the exchanged token.** Plan section 14 says *"not persisted as a long-lived
identity"*, and it is tempting to read that as "not persisted at all". A token that is not in the
`tokens` table cannot be authenticated — `SqliteStore::authenticate` is the only verifier — and it
cannot be revoked either, which is worse: a federated credential with a fifteen-minute life would be
the one credential in the system that revocation could not reach. It is persisted, with an expiry,
and `ciphr token list` shows it with `created_by = oidc:<provider>`.

**Refusing an over-long requested lifetime instead of reducing it.** A caller that asks for a day
gets the configured ceiling rather than a `400`. The request is a preference, the ceiling is the
deployment's answer, and a job that fails because it asked for too much would teach its author to
stop asking — which would lose the case worth having, a job asking for *less*.
