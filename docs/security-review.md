# External review: scope, claims, and what would falsify them

**Status:** prepared 2026-08-18, last revised 2026-08-24. **This repository was made public on
2026-08-24 without the human review this document asks for**, which is a decision against one of the
conditions recorded below rather than a condition that was met — see *Published without a human
review* immediately after the acceptance. **A commissioned review took place on
2026-08-21 against `v0.3.0`** and is recorded in [`review-2026-08-21.md`](assurance/reviews/review-2026-08-21.md) —
findings, coverage, and the fitness statement this document asks for. The reviewer is an AI model
(Claude Fable 5), commissioned by the maintainer: a different model from the one that co-authored
the code, and not the human practitioner the *Who fits* section sketches — the record's first
section states what that is worth, and a human review obtained later supersedes it. **The
maintainer accepted that review as discharging the precondition on 2026-08-21**; what the
acceptance covers, what it does not, and what would reverse it are in *The decision to accept it*
below. Two claims below were falsified (B6, F1; D6, F2); both defects were fixed the same day,
the other four findings were disposed of the same day, and the rows say so. The design review of ADR-15 and ADR-16 on 2026-08-20 is a different document and
says of itself that it is not this one. **Three claims are newer than the acceptance** — C11, C12 and
D10, added on 2026-08-21 with the `honeypot_alert` entry — and are marked as such where they stand:
the acceptance says new surface on the authentication path does not inherit it, and named this phase
as the example. **Two of those three were narrowed on 2026-08-22 rather than defended**: a second
review of the same surface (`review-2026-08-21-current-tree.md`) found that C11 claimed equal
*work* where only the response is equal, and that C12 rested in part on a defect. The rows now say
what holds, what does not, and which of the two the reviewer should attack — narrowing a claim to
the code is the point of this document, and a claim that outruns the code is the one thing it must
not contain.

## What this document is, and is not

This is a working paper for an external reviewer. It states what the code claims, where each claim
lives, and what would disprove it — so that a reviewer spends their time attacking the claims rather
than reconstructing them.

**It is not a review.** It was written by the author of the code, and a checklist written by the
author cannot substitute for someone else reading it.

Plan section 18 makes the review a *precondition* for first production use and says self-review is
not sufficient; this document exists to make that review cheap, not to replace it.

**Who the condition binds.** It binds *this project*. It cannot bind an operator, and it does not
try to: nothing in the software refuses to serve a real secret because a review is outstanding, and
a deployment may legitimately decide the risk is acceptable for what it holds and how far its blast
radius reaches. Such a decision belongs in that deployment's own documentation — dated, saying what
it covers and what would reverse it — and it does not reach back into this document. **The status
line above changes when a review has happened, and for no other reason.** Neither the pre-review
pass below nor uneventful time in production moves it, and a reviewer should treat both as evidence
about the code rather than about the condition.

**A pre-review pass has since been made against this list** and is recorded in
[`review-2026-08-18.md`](assurance/reviews/review-2026-08-18.md). It does not discharge the precondition either — it
came from the same model that co-authored the code, so it carries the same blind spots — but it
closed B9 mechanically, corrected two claims that turned out to be weaker than the implementation,
and produced nine findings, all since addressed. **A reviewer should read it for what it says it did
*not* check at least as much as for what it found**, and should treat every claim below as one this
pass already looked at and therefore looked at with the wrong eyes.

Two consequences follow, and both matter:

- **A checklist narrows attention.** Anything a reviewer finds that is not on this list is more
  valuable than anything that is, because the list can only contain failures the author already
  imagined. The last item in every section below is therefore the same: *what else*.
- **The design is in scope, not only the code.** A reviewer who concludes that the envelope scheme,
  the policy semantics, or the audit ordering is wrong in principle has produced the most useful
  possible result. Disagreeing with a documented decision is a finding, not a misunderstanding.

## The decision to accept the review of 2026-08-21

**Decided by the maintainer on 2026-08-21.** The review recorded in
[`review-2026-08-21.md`](assurance/reviews/review-2026-08-21.md) discharges the precondition of plan section 18. That
record deliberately declines to make the call itself — it states who performed it and leaves the
judgement to its reader — so the call is recorded here: dated, and in the same shape this document
asks of an operator who proceeds on an accepted risk.

**What it covers.** The mandatory scope at `v0.3.0`, as read by the reviewer that record describes:
`ciphr-crypto`, `ciphr-policy`, and `path.rs`, `pattern.rs`, `secret.rs` in `ciphr-core`, plus the
second-tier files its coverage section names. It does not extend to what that section lists as
skimmed or taken on trust — `ciphr-audit`, most of `ciphr-store`, the server's configuration and TLS
code, `ui/`. Those are unreviewed, and this decision does not make them otherwise.

**Added 2026-08-24, after the acceptance: `ciphr-export` and `ciphr-ci` (ADR-25).** Neither is on
the authentication path and neither is in the reviewed crates, so this is a smaller note than the one
below — but the rule is the same one and it is written rather than left to be inferred. What is new
as *code*: a binary that holds a token file, opens one TLS connection, and writes to two sinks; and a
crate that renders text. What is new as *surface*: nothing in `ciphr-crypto`, `ciphr-policy` or the
path, pattern and secret code in `ciphr-core` — `ci/check-core-no-features.sh` enforces that rather
than this sentence asserting it. The masking rules themselves are **moved, not written**: the code
that produces `::add-mask::` lines and heredoc delimiters is the code the CLI has carried since
2026-08-18, with its tests, now in a crate both binaries depend on. The client half is `ciphr-sdk`,
unchanged except for the fallback described in ADR-25. A reviewer with limited time should spend it
on the two rules that were already worth attacking — the delimiter's unpredictability and the
ordering of masks against values — and on one thing that is genuinely new: `ciphr-ci` appends to a
file whose path comes from an environment variable the runner sets.

**Added 2026-08-21, after the acceptance: the `honeypot_alert` surface entry.** Claims C11, C12 and
D10 describe it, and they are marked as new for a reason the acceptance states in its own words — new
surface in the reviewed crates or on the authentication path does not inherit it. This is the case
that acceptance named in advance, so the entry in this document is written rather than left for a
later reader to infer. What changed: bait recognition inside `ciphr-store`'s token verification, a
tier lookup and a latch in `ciphr-server`, two audit actions, and two routes. What did **not** change:
`ciphr-crypto`, `ciphr-policy`, and the path, pattern and secret code in `ciphr-core` — enforced by
`ci/check-core-no-features.sh` rather than asserted here.

**What it is not.** A review by a human practitioner. The reviewer was an AI model, a different one
from the model that co-authored the code — which is why it falsified two claims the same-model pass
of 2026-08-18 had recorded as holding, and why it is still not the independent pair of human eyes
*Who fits* describes. A human review obtained later supersedes its fitness statement, and this
decision with it.

**The two conditions its fitness statement attached are met.** F1 (token secrets left in unwiped
heap buffers on every authenticated request) and F2 (the reserved-prefix refusal enforced in the
HTTP layer alone) were fixed on 2026-08-21 — decided first, fixed the same day, and recorded here
together. The honest order matters: for the hours between, the acceptance stood on a fitness
statement whose conditions were open.

**All six findings are now disposed of**, also on 2026-08-21: F4 (the missing correcting audit entry
on `delete`, `export`, and the version listing) fixed, F6 (a world-*writable* credential file
started the process) fixed, and F3 and F5 answered as the review asked — as prose, because both were
claims stronger than the code rather than defects in it. Every disposition is in the changelog and in
the claim row it belongs to, per the review record's own rule that a dated review is not
backfilled.

**What it does not stretch to cover, and what would reverse it:**

- **New surface in the reviewed crates, or in the authentication path, does not inherit it.** Phase
  8 changes what a rejected credential does; the review read the code as it stands, not as that
  phase would leave it. What that phase adds needs its own pass, against this same document.
- **A deployment whose blast radius reaches past the maintainer's own estate**, or making this
  repository public as something others are invited to run. Either raises the bar back to a human
  review, because the question stops being what one operator is willing to carry.
- **A finding that contradicts the record's coverage claims** — something wrong in a file it says it
  read end to end. That is evidence about the review rather than about the code, and it reopens this
  decision instead of joining the finding list.

## Published without a human review — decided 2026-08-24

**What the condition said.** The acceptance above lists what it does not stretch to cover, and the
second item is this one: *"A deployment whose blast radius reaches past the maintainer's own estate,
or making this repository public as something others are invited to run. Either raises the bar back
to a human review, because the question stops being what one operator is willing to carry."*

**What was decided.** The maintainer made this repository public on 2026-08-24 with no human review
having taken place. The bar this document sets was therefore not met, and publication happened
anyway. That is the whole of it: there is no reading of the condition under which it was satisfied,
and this section exists so that nobody has to reconstruct that from dates.

**What a reader is actually getting.** The mandatory scope — `ciphr-crypto`, `ciphr-policy`, and the
path, pattern and secret code in `ciphr-core` — was read at `v0.3.0` by an AI model commissioned by
the maintainer, which produced six findings and a fitness statement whose two conditions were then
met. That is more than nothing and it is not an independent security assessment. Beyond it:

- **Unreviewed by anyone**: `ciphr-audit`, most of `ciphr-store`, the server's configuration and TLS
  code, and `ui/`.
- **Newer than the acceptance**: the `honeypot_alert` surface (claims C11, C12, D10), and
  `ciphr-export` and `ciphr-ci` (ADR-25).
- **Never claimed**: that any of this was checked by somebody whose living depends on being right
  about it.

**What this is not an argument for.** It is not "the code is probably fine because an AI read it",
and it is not "publication is low risk because the repository is documentation-heavy". Both are
available and both would be reasoning backwards from a decision that was made for other reasons —
principally that a public repository is where a human reviewer is easier to find, and that the
project is more useful readable than unreadable. Those are honest reasons and they are not evidence
about the code.

**What would close it.** A review by the practitioner *Who fits* describes, against a named tag, with
the deliverable this document specifies. The package is ready and the ask is unchanged; what changed
on 2026-08-24 is only that the repository stopped waiting for it. Until then this section stays where
it is — retiring it is the reviewer's job, not the calendar's.

**And if you are weighing a deployment that holds real secrets:** read *The claims, and what would
falsify each* below and [`threat-model.md`](threat-model.md), and price the paragraph above. The
project's own recommendation for anyone who cannot carry that is in
[`why-build-this.md`](why-build-this.md), and it names OpenBao.

## Scope

### Mandatory

| Crate | Effective lines of code | Why it is in scope |
|---|---|---|
| `ciphr-crypto` | ~545 | The envelope scheme, the seal, token verifiers |
| `ciphr-policy` | ~462 | The authorization decision |
| `ciphr-core` — `path.rs`, `pattern.rs`, `secret.rs` | ~450 of 718 | See the correction below |

**Correction to the plan.** Plan section 18 names `ciphr-crypto` and `ciphr-policy`. That scope is
incomplete: path normalization and the glob matcher live in `ciphr-core`, and normalization is the
single function ADR-9 identifies as the place where routing and authorization can silently disagree.
A review that excludes `ciphr-core` misses the ADR-9 surface entirely. The mandatory scope is
therefore the three crates above — about **1500 lines** of code, plus roughly the same amount again
in comments and tests.

That size is deliberate. If these crates cannot be read end to end by one person in a couple of
days, something has gone wrong with them, and that is itself worth reporting.

### What two planned features would add, and what happened to them

Neither is implemented, and the intended order is the other way round — both ADRs name this review as
a condition of their own phase, precisely so that a reviewer is not handed the new surface and the old
surface at once. **Both records moved on 2026-08-20, and the scope above is smaller for it.**

- **ADR-15, honeypots (phase 8)** — **accepted in the `alert` tier only**, not built. It would add
  behaviour to the authentication path in `ciphr-store`: a credential that is recognized and refused
  rather than merely refused. The claim to attack is that recognizing bait is indistinguishable from
  any other rejection, in the response and in the timing. **What the narrowed scope removes** is the
  trigger that could revoke tokens or stop the service; those tiers are designed and deliberately
  absent, so there is no availability lever to attack in what would be built.
- **ADR-16, leak reports (phase 9)** — **deferred**, and the deferral is why it is not in scope. It
  would have added a key derivation in `ciphr-crypto` and the only unauthenticated request path that
  reaches the store, both in mandatory scope by their location. Nothing about the design was found
  wanting; it is worth its cost only where somebody holding no token can reach the endpoint, and that
  is not the shape it would be deployed into.

If either lands after all, its ADR belongs in the reading order below and its claims belong in the
sections above. Until then this section is a description of surface that does not exist, kept because
a scope that only lists today's code goes stale without anyone noticing.

### Recommended, second tier

`ciphr-audit` and the authorization and audit wiring in `ciphr-server` (`state.rs`, the handlers in
`api.rs`). Not mandatory per the plan, but the fail-closed ordering is the other place where a
mistake is silent: a request served before its record is stored produces no error anywhere.

### Deliberately out of scope

Reporting on these is not a finding, because they are documented boundaries rather than oversights.
They are listed so nobody spends time on them:

- **Root on the host** reading the master key from wherever the seal keeps it — a mounted file for
  `type = "static_file"`, the environment for the variable form — or reading plaintext out of process
  memory. Adversary A5; a consequence of unattended startup (ADR-5).
- **Denial of service.** A single instance with fail-closed auditing can be taken offline by filling
  the audit volume. Intended, and monitored rather than prevented.
- **Side channels beyond timing in credential comparison.** No defence against cache timing or
  speculative execution.
- **A compromised build pipeline.** Countered by supply-chain hygiene, not application code.
- **Zero-knowledge.** The server decrypts, because the audit trail and per-identity access control
  depend on it (ADR-4).

## Reading order

1. [`threat-model.md`](threat-model.md) — what is defended and what is not. Everything else follows
   from it.
2. [`crypto.md`](crypto.md) and [`authorization.md`](authorization.md) — the two designs, as
   implemented.
3. `crates/ciphr-core/src/path.rs`, then `pattern.rs`. Small, and everything else depends on them.
4. `crates/ciphr-crypto/src/envelope.rs` — the wire format and the two operations.
5. `crates/ciphr-crypto/src/token.rs`, `key.rs`, `seal.rs`.
6. `crates/ciphr-policy/src/evaluate.rs`, then `model.rs`.
7. `crates/ciphr-policy/tests/decision_table.rs` — 22 rows showing what the four semantic rules do to
   concrete inputs. The fastest way to check whether the semantics are what a reader expects.

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --no-deps --open                   # the reasoning is in the code, not only here
```

The test count differs by platform — a set of them is `#[cfg(unix)]`, because the behaviour they
check does not exist on Windows — so there is no single number to quote here. This line used to
quote one, and it was three phases out of date.

## The claims, and what would falsify each

Each item is a claim the code makes. "Verified mechanically" means a test or a grep already
establishes it and a reviewer can confirm cheaply; those are listed because a reviewer should know
which parts do *not* need their attention.

### A. Path normalization and matching — `ciphr-core`

| # | Claim | Falsified by |
|---|---|---|
| A1 | There is exactly **one** normalization, shared by the router, the policy evaluator, and the AAD construction (ADR-9). | Any second place that lower-cases, trims, or NFC-normalizes a path. Verified mechanically: no other call site exists. |
| A2 | Normalization is idempotent: `parse(parse(x)) == parse(x)`. | An input where they differ. Property-tested and fuzzed. |
| A3 | An accepted path satisfies every documented rule — segments are drawn from an **allowlist** (letters and digits of any script, plus `-`, `_`, `.`), no empty or relative segments, no `*`, within length limits. | An input that is accepted and breaks one. Fuzzed with invariant assertions rather than only for panics. *Changed 2026-08-18: this was a denylist of control characters and whitespace, which admitted every Unicode format character — see finding 1.* |
| A4 | Two spellings of one path cannot exist: NFC is applied, comparison is byte-exact and case sensitive. Invisible characters are refused by the allowlist; **confusables across scripts are not**, and that is a stated boundary. | A pair of distinct inputs that map to the same secret in a way the design did not intend, or a pair that *should* be the same and is not. The invisible-character half was the first finding of the pre-review pass; the confusable half is open by decision, and an argument that it should not be is a finding. |
| A5 | `*` matches exactly one segment; `**` matches one or more and only as the last segment; no partial wildcards. | A pattern/path pair where `matches()` disagrees with that. |
| A6 | Specificity is the number of literal segments, and it orders patterns the way the evaluator assumes. | Two patterns where the more specific one loses, or a case where specificity is not a usable total order. |
| A7 | `**` does **not** match zero segments, so `infra/**` does not cover `infra`. | — this is a decision, not a bug. Worth challenging: it is the reason listings authorize per result rather than on a prefix. |
| A8 | *What else.* | |

### B. Envelope encryption — `ciphr-crypto`

| # | Claim | Falsified by |
|---|---|---|
| B1 | Master key wraps the root key; the root key wraps one data key per secret version; the data key encrypts the value. No level is skipped and no key is used at two levels. | A code path where the master key touches a value, or a data key is reused. |
| B2 | **Nonce reuse is structurally impossible for a value**: each data key encrypts exactly one payload. The root key's own wraps use random nonces, one per version write, where the guarantee is the birthday bound (NIST SP 800-38D §8.3: 2^32 invocations) and not a structure. | A path where a data key is used twice, or where `encrypt` does not generate a fresh one. At the root-key level: a deployment scale that approaches the bound, or a claim anywhere that omits the level. *Qualified 2026-08-21 (finding F3): the claim was stated absolutely in `crypto.md`, the README, and both crate module docs, and holds exactly one level down. No code changed — the count does not reset in v1, because `rotate-master-key` re-wraps the same root key.* |
| B3 | The additional authenticated data binds the domain, the path length, the path, the version, and the data key identifier — so no two distinct locations produce the same AAD. | Two distinct `(path, version, dek_id)` triples with identical AAD bytes. The length prefix exists for exactly this; check the argument holds. |
| B4 | A ciphertext cannot be moved to another path, version, or root key. | A relocation that decrypts. Property-tested across generated paths and versions. |
| B5 | Every authentication failure returns the same error, with no distinguishable variant for wrong key, wrong AAD, tampered tag, or shredded data key. | Any path that distinguishes them, in the return value, in a message, or in observable work done. |
| B6 | Key material is wiped: keys live in `SecretBox`, and intermediate buffers are zeroized on both the success and the failure path. Both directions of the token codec work in a buffer the caller owns and allocate nothing. | A buffer that survives — the copies in `unwrap_root_key`, `unwrap_dek`, `from_hex`, and `Token::parse` are the places to look. *Falsified 2026-08-21 (finding F1): `base64url::decode`/`decode_into` freed unwiped heap copies of the token secret on every `Token::parse`, and `expose_text` dropped an unwiped temporary. **Fixed the same day**: `decode_into` and the new `encode_into` hold no buffer of their own, and the second sentence of the claim is what a reader should now attack.* |
| B7 | Secret-bearing types implement neither `Debug`, `Display` nor `Serialize`; identifiers do, and are not secret. | Any accidental impl, or a `{:?}` on something secret-bearing. Verified mechanically: only the identifier types derive `Debug`. |
| B8 | Randomness comes only from the OS CSPRNG; no seedable generator is reachable from shipped code. | A reachable `rand`. Verified mechanically: `rand` appears in `Cargo.lock` only through `proptest`, a dev-dependency, and the server graph contains none. Worth confirming independently. |
| B9 | **The known-answer tests do not validate AES-256-GCM.** The vectors were generated by this code and pinned, so they detect a format change, not a primitive error. | Nothing — this is a stated gap. **A reviewer can close it** by checking the AES-GCM plumbing (key, nonce, and AAD ordering) against NIST vectors independently. That is the single most valuable mechanical check available here. |
| B10 | `#![forbid(unsafe_code)]` holds in every crate, and the `unsafe` that exists is in reviewed dependencies (`getrandom` ~117 occurrences, `sha2` ~59, `zeroize` ~21, `subtle` and `secrecy` 2 each, `aes-gcm` and `hmac` none). | A reviewer may reasonably challenge the boundary itself: whether that dependency surface is acceptable is a judgement, not a fact. |
| B11 | *What else.* | |

### C. Tokens and the seal — `ciphr-crypto`

| # | Claim | Falsified by |
|---|---|---|
| C1 | What is stored is `HMAC-SHA256(pepper, secret)` with the pepper derived from the root key under a domain-separating label, so a database-only leak permits no offline verification of guesses. | A way to verify a guessed token with the database alone, or a derivation that collides with another use of the root key. |
| C2 | Comparison of verifiers is constant-time, and expiry and revocation are checked *after* it — so timing cannot separate "wrong secret" from "expired". | An early exit, or an ordering that leaks. Note the test for this checks behaviour, not timing: a timing assertion in a unit test is flakiness rather than evidence, so **this is a place where a human should look at the code**. |
| C3 | Password hashing is deliberately absent: a token is 256 bits of randomness, so there is no dictionary to attack. | An argument that stretching buys something here. Worth challenging. |
| C4 | One token string has exactly one spelling: base64url decoding rejects padding and non-zero trailing bits. | Two strings that authenticate as one token. |
| C5 | A change of seal mechanism re-wraps exactly one record and re-encrypts nothing. | A path where rotation touches ciphertext. Tested by asserting every stored ciphertext is byte-identical after a master key rotation. |
| C6 | Replacing the seal record with one for a *different* root key is refused. | A way to store a mismatched record — it would make every secret unreadable with no error until the first read. |
| C7 | The master key may be read from a file as well as a variable, and the source is not part of the key: a store sealed through one opens through the other. | A source that changes the key, or a path where the two disagree. |
| C8 | Both key sources cannot be active at once, so there is no precedence rule to get wrong. | A configuration or command line that accepts both. |
| C9 | A key file the world can read **or write** stops the process; group bits are accepted deliberately. | A permissive file that starts, or a legitimate group arrangement that is refused. Windows has no check, by documented omission. *Widened 2026-08-21 (finding F6): the check tested `0o004` only, so mode `0602` started. The rule now has one definition (`ciphr_core::WorldAccess`) shared with the token-file check in `ciphr-run`, which had the same half of it.* |
| C11 | **A honeypot token is indistinguishable from any other invalid credential in the response.** *Narrowed 2026-08-22*, from "to the caller" — the response is claimed, the *work* is not, and the old wording said "or work done" in its own falsification column while the code did not support it. New surface, added 2026-08-21 with the `honeypot_alert` entry, and *not covered* by the review of 2026-08-21 — that review read this crate and `ciphr-store` before bait existed. What holds: same `cph_` prefix, same length and alphabet, same `401` with the same body and the same `WWW-Authenticate`; recognition is a flag read from the row the constant-time comparison already fetched, *after* that comparison, so no branch and no query is added before it. What is **not** equalized, listed so a reviewer attacks it instead of discovering it: (1) a malformed token returns before any database work; (2) a known identifier costs one verifier query an unknown one skips, and the comment at `crates/ciphr-store/src/tokens.rs` says why closing it would mean issuing a query nobody needs; (3) recognized bait writes a larger audit payload, synchronously, before the `401` — so a caller **holding a credential whose secret matches** can in principle separate "this is bait" from "this is expired or revoked" by the work done, and that is the one direction an attacker actually wants. Since 2026-08-22 a trip also schedules a latch off the request path, at most once per piece of bait (C12). | A response that differs in any observable way — status, body, header. Three tests pin those (`every_kind_of_invalid_token_looks_the_same`, a whole-response comparison against an unknown token, and `bait_and_an_unknown_token_produce_identical_responses`). **The work is known to differ and remote separability is unmeasured**, so the question for a reviewer is not "is it equal" but "is the difference separable over a network" — and what bounds useful enumeration is the 48-bit random identifier rather than the equality. Also worth attacking: bait is checked *before* expiry and revocation, so an expired honeypot token is still recognized as bait rather than falling through to the ordinary expired path. Verify that is what the code does and that it introduces no branch before the comparison. |
| C12 | **Taking bait writes nothing extra on the path the caller waits on.** *Narrowed 2026-08-22* by the same pass, and the claim itself is unchanged where it was true: the trip replaces the action on the audit entry the request writes anyway, rather than adding an entry, a row, or a file to the request path. The latch row and the `/v1/health` flag are derived state written off it, and a failure there is recorded rather than surfaced. Two things the old wording left out. **A token trip did not do the derived write at all** until 2026-08-22 — that was finding F1, a defect behind this claim rather than evidence for it, and it is now fixed. And the latch **is** extra work: it is a store write, it contends for the process-wide store mutex, and a caller who immediately issues a second request can in principle meet that contention. It is scheduled at most once per piece of bait since 2026-08-22 (finding F5), so what bounds it is the number of planted references and not the traffic. | A second write on the request path, or any ordering where the caller waits for the latch. The `honeypot_alert` build is the one to read; a default build has none of this code, which is the strongest form of the claim and also why the *other* configuration needs reading. And for the residue: an ordering in which the latch's mutex acquisition is measurable from outside — bounded above, not eliminated. |
| C10 | *What else.* | |

### D. The authorization decision — `ciphr-policy`

| # | Claim | Falsified by |
|---|---|---|
| D1 | Deny by default: an unknown identity, no matching rule, and an empty capability set all deny. | Any input reaching an allow without a matching rule that grants the capability. |
| D2 | The most specific matching rule wins **entirely** and inherits nothing from broader rules. | — a decision, and the one most likely to surprise. It means a narrow `capabilities = ["write"]` removes a broader `read`. Challenge it: the alternative, accumulating capabilities across specificity levels, would let a denial be undone by adding an unrelated broad grant elsewhere. |
| D3 | On a tie, denial wins, and the decision is deterministic regardless of file or iteration order. | Two equally specific rules where the outcome depends on ordering. |
| D4 | Every decision names the rule that produced it, and every denial carries a reason. | An allow with no rule attached — checked by a fuzz target, because an unattributable allow makes the audit trail unable to say why. |
| D5 | There is no `admin` capability and no second authorization mechanism; `sys/audit`, `sys/identities`, and `sys/policies` are ordinary paths through the same evaluator. | Any path to a privileged operation that skips `evaluate`. |
| D6 | A real secret can never shadow a virtual `sys/` path: writes and deletes under that prefix are refused **by storage**, so the refusal holds for every caller and not only for requests that arrive over HTTP. | A way to create `sys/audit` as a secret, through any interface. *Falsified 2026-08-21 (finding F2): the refusal lived only in the HTTP layer, and `ciphr put sys/audit` through the CLI created it. **Fixed the same day**: `ciphr-store` refuses it, the prefix has one definition in `ciphr-core`, and the HTTP and CLI checks are now early errors rather than the enforcement.* |
| D7 | A policy file loads completely or not at all: unknown keys, dangling policy references, duplicate names, and duplicate patterns refuse the whole file. | A file that half-loads. A partially loaded policy set is a set of permissions nobody wrote. |
| D8 | Listings authorize **per returned path** rather than on the prefix, so a caller sees exactly the names they hold `list` on. | An information leak through listing — a way to learn of a path one may not list. Also worth challenging as a design choice: the alternative was a special case in the evaluator, which was rejected. |
| D10 | **A honeypot secret is authorized exactly like any other path, and a denial trips nothing.** New surface, added 2026-08-21, and *not covered* by the review of 2026-08-21. There is no honeypot branch in this crate, no new capability, and nothing about bait reaches the evaluator: the tier is looked up in `ciphr-server` after `evaluate` returned an allow, and only for `Capability::Read`. **Ordering, decided 2026-08-22 and kept:** the trip is recorded and latched *before* retrieval and decryption, so an allowed read of bait that is deleted, missing, corrupt or undecryptable latches although no value was served. Called a false positive if "taking bait" means receiving the value; this project reads it as *being allowed to read it*, which is what an allowed read of bait already tells an operator. The trail is not what goes wrong here — `read_secret` writes a correcting entry (`not-found` or `not-served`) under the same request id, so the two read as one event — it is `/v1/health` and the open trip that say `tripped` without a value having left. Closing it needs a store operation that establishes readability before the trip entry and without releasing the value before the audit write, which is the fail-closed ordering itself; that price buys the removal of a page whose subject is *bait somebody was allowed to read and could not get*, and that is worth a look rather than silence. | Anything in `ciphr-policy` that mentions bait. Then, in `ciphr-server`: a trip on a denied read (which would make every scoped-away probe an incident), a trip on `list` or `/v1/versions` (enumerating a name is not taking the bait), or a trip reachable from a host operation. Each of those is a test; the question for a reviewer is whether the *set* is complete. And for the ordering above: whether the correcting entry is genuinely written on every failing branch, since that is what carries the decision — if a branch exists that latches and records nothing, the decision rests on something that is not there. |
| D9 | *What else.* | |

### E. The audit trail — second tier

| # | Claim | Falsified by |
|---|---|---|
| E1 | No response leaves the process, and no change is made, before the record is stored. **Both** record the authorization decision first; they differ only in what follows. **Any** operation that then does not happen — a read that finds nothing, a delete that deletes nothing, an export that aborts, a version listing of a missing path — gets a second entry with the real outcome. | A route that answers or mutates first, or one that leaves a lone "allowed, 200" behind for work that failed. `every_endpoint_writes_an_audit_entry` covers presence; the *ordering* needs a human. *Corrected 2026-08-18: this row said reads work first and record afterwards, which the code never did. The claim was weaker than the implementation.* *Widened 2026-08-21 (finding F4): the correction existed on reads and writes only. `delete`, `export`, and the version listing now have it, `read_audit` too, and the correction is one named helper (`complete_or_record`) rather than a rule each handler remembers.* |
| E2 | If no device accepts a record the request is refused with `503`, and no sequence number is consumed. | A path that serves or writes anyway, or a gap after a device failure. *Sharpened 2026-08-21 (finding F5): a rejected request writes an entry too, so the audit fill that turns this into an outage needs no credential. Inside the threat model's boundary, which now says so, with the three deployment rules in `docs/operations/audit-trail.md`.* |
| E3 | A bulk read produces one entry per secret served, never one per call. | An export that records once. |
| E4 | An entry never contains a value, key material, or a token — only a token's non-secret identifier. | Any field that can carry one. The type system is the intended guarantee; check that it actually is. |
| E5 | The chain detects an entry that was edited, removed, reordered, or inserted. | A modification that verifies. |
| E6 | **The chain does not detect a forward rewrite** by someone with write access. | Nothing — a stated limitation, asserted by a test. The mitigation is an anchor outside the store, which is operational. |
| E7 | *What else.* | |

## What we already know is imperfect

Stated up front so a reviewer can judge whether the characterization is honest, rather than
rediscovering it:

1. ~~**The known-answer tests are self-generated** (B9)~~ — **closed 2026-08-18.** All three pinned
   vectors were reproduced byte-for-byte by an independent AES-256-GCM implementation, with the value
   AAD rebuilt from the prose in `envelope.rs` rather than copied from the pinned hex, plus negative
   controls for AAD sensitivity and argument order. They now validate the primitive and its plumbing,
   not only the format. What remains true is that they were *generated* by this code; what is no
   longer true is that nothing independent confirms them.
2. **Constant-time behaviour is not proven** (C2), only exercised for correctness at every byte
   position.
3. **The hash chain cannot detect a forward rewrite** (E6).
4. **Root on the host is not defended against** (A5 in the threat model), and the master key sits in
   a mode-0600 file the seal is pointed at. The environment-variable form of the seal still exists and
   is the weaker of the two, because a value in a container's configuration is readable by anyone who
   reaches the daemon rather than only by root.
5. **Values are UTF-8 text.** A binary secret must be encoded by whoever stores it.
6. **`getrandom` appears three times** in the dependency graph, from `ring` and `proptest` besides our
   own use. Recorded in `deny.toml` with a reason rather than resolved.
7. **Timestamps are formatted by hand-written civil-date arithmetic** rather than a date library,
   checked against independently computed values including two leap days and a century boundary.

## The deliverable

What makes a review usable later is not a verdict but a record of what was looked at. We are asking
for:

1. **Findings**, each with: where, what an attacker gets, and how confident the reviewer is. Severity
   in whatever scale the reviewer prefers, as long as "this is wrong" and "this made me uneasy" are
   distinguishable.
2. **An explicit statement of coverage** — which files were read, which claims were checked, and which
   were taken on trust. A review that does not say what it skipped cannot be relied on for what it
   skipped.
3. **A fitness statement**: whether `ciphr-crypto`, `ciphr-policy`, and the reviewed parts of
   `ciphr-core` are, in the reviewer's judgement, fit for a first production use holding real secrets.
   A qualified answer is fine and expected; an absent one is not.

Design disagreements belong in the findings even where the code implements the design correctly. That
is the part a second pair of eyes provides that tests cannot.

## Commissioning it

**This section describes what was done on 2026-08-21, and what a further review would need.** It is
kept in the present tense because the acceptance above names two things that would call for another
one — new surface in the reviewed crates, and a wider blast radius — and because the review that
happened was not by the practitioner *Who fits* describes. What follows is the package either way.

**What the reviewer needs, and nothing else.** This document, [`threat-model.md`](threat-model.md),
[`crypto.md`](crypto.md), [`authorization.md`](authorization.md), and the source at a **named tag**
rather than at a branch. The tag matters for a mundane reason: findings cite file and line, and a
moving `main` turns a citation into a puzzle a month later. The repository is private, so access is
either a read-only collaborator invitation or an archive of the three crates plus `docs/` — the
archive is enough, because the mandatory scope has no build step a reviewer must run to read it.

**What to ask for is in *The deliverable* below**, and the third item is the one that is easy to leave
out of a request and impossible to reconstruct afterwards: a fitness statement. A reviewer who is not
asked for one will not volunteer it, and a review without it produces a list of small things and no
answer to the question that made it a precondition.

**Who fits.** Someone who reads Rust without assistance and has attacked an authorization evaluator or
an envelope scheme before — an independent practitioner, a short engagement with a firm that does
applied-cryptography review, or a peer at another organization under whatever agreement makes that
possible. Two days of reading is the honest estimate, and the size stated above is deliberate so that
the estimate is checkable rather than a hope.

**What not to buy.** A penetration test against a running instance exercises the deployment, not these
crates, and the boundaries this project has already conceded (A5, denial of service) will be most of
what it returns. An automated scan returns what `cargo audit` and `cargo deny` already block in CI on
every commit. Neither answers the question this precondition asks, which is whether the two designs
that decide every access are sound and implemented as described.

**What the answer changes.** The status line at the top of this document, and nothing else — the
temptation at the end of an engagement is to treat a clean report as permission for whatever was
waiting behind it. Phase 8 was waiting behind it, and the acceptance recorded above is what released
it; note what that acceptance says about the surface phase 8 adds, which the review did not read.
Any deployment that has been running on an accepted risk rather than a met condition still records
its own decision in its own documentation, and this one does not reach into it.

## What happens to the findings

Recorded in the changelog and in the ADRs where a decision changes. A finding that invalidates the
cryptographic or authorization approach is not a defect to be patched around: plan section 2 makes
falling back to OpenBao the correct response in that case, and `ciphr dump --format portable` exists
so that route stays open. **If no review can be arranged at all, that is itself an argument for the
fallback rather than for proceeding.**
