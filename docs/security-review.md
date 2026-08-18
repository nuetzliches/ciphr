# External review: scope, claims, and what would falsify them

**Status:** prepared 2026-08-18, phase 3 complete. The review has **not** taken place.

## What this document is, and is not

This is a working paper for an external reviewer. It states what the code claims, where each claim
lives, and what would disprove it — so that a reviewer spends their time attacking the claims rather
than reconstructing them.

**It is not a review.** It was written by the author of the code, and a checklist written by the
author cannot substitute for someone else reading it.

Plan section 18 makes the review a *precondition* for first production use and says self-review is
not sufficient; this document exists to make that review cheap, not to replace it.

**A pre-review pass has since been made against this list** and is recorded in
[`review-2026-08-18.md`](review-2026-08-18.md). It does not discharge the precondition either — it
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

### Recommended, second tier

`ciphr-audit` and the authorization and audit wiring in `ciphr-server` (`state.rs`, the handlers in
`api.rs`). Not mandatory per the plan, but the fail-closed ordering is the other place where a
mistake is silent: a request served before its record is stored produces no error anywhere.

### Deliberately out of scope

Reporting on these is not a finding, because they are documented boundaries rather than oversights.
They are listed so nobody spends time on them:

- **Root on the host** reading the master key from the environment file or plaintext from process
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
cargo test --workspace --all-features        # 244 tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --no-deps --open                   # the reasoning is in the code, not only here
```

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
| B2 | **Nonce reuse is structurally impossible**: each data key encrypts exactly one payload. | A path where a data key is used twice, or where `encrypt` does not generate a fresh one. |
| B3 | The additional authenticated data binds the domain, the path length, the path, the version, and the data key identifier — so no two distinct locations produce the same AAD. | Two distinct `(path, version, dek_id)` triples with identical AAD bytes. The length prefix exists for exactly this; check the argument holds. |
| B4 | A ciphertext cannot be moved to another path, version, or root key. | A relocation that decrypts. Property-tested across generated paths and versions. |
| B5 | Every authentication failure returns the same error, with no distinguishable variant for wrong key, wrong AAD, tampered tag, or shredded data key. | Any path that distinguishes them, in the return value, in a message, or in observable work done. |
| B6 | Key material is wiped: keys live in `SecretBox`, and intermediate buffers are zeroized on both the success and the failure path. | A buffer that survives — the copies in `unwrap_root_key`, `unwrap_dek`, `from_hex`, and `Token::parse` are the places to look. |
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
| C7 | *What else.* | |

### D. The authorization decision — `ciphr-policy`

| # | Claim | Falsified by |
|---|---|---|
| D1 | Deny by default: an unknown identity, no matching rule, and an empty capability set all deny. | Any input reaching an allow without a matching rule that grants the capability. |
| D2 | The most specific matching rule wins **entirely** and inherits nothing from broader rules. | — a decision, and the one most likely to surprise. It means a narrow `capabilities = ["write"]` removes a broader `read`. Challenge it: the alternative, accumulating capabilities across specificity levels, would let a denial be undone by adding an unrelated broad grant elsewhere. |
| D3 | On a tie, denial wins, and the decision is deterministic regardless of file or iteration order. | Two equally specific rules where the outcome depends on ordering. |
| D4 | Every decision names the rule that produced it, and every denial carries a reason. | An allow with no rule attached — checked by a fuzz target, because an unattributable allow makes the audit trail unable to say why. |
| D5 | There is no `admin` capability and no second authorization mechanism; `sys/audit`, `sys/identities`, and `sys/policies` are ordinary paths through the same evaluator. | Any path to a privileged operation that skips `evaluate`. |
| D6 | A real secret can never shadow a virtual `sys/` path: writes and deletes under that prefix are refused. | A way to create `sys/audit` as a secret. |
| D7 | A policy file loads completely or not at all: unknown keys, dangling policy references, duplicate names, and duplicate patterns refuse the whole file. | A file that half-loads. A partially loaded policy set is a set of permissions nobody wrote. |
| D8 | Listings authorize **per returned path** rather than on the prefix, so a caller sees exactly the names they hold `list` on. | An information leak through listing — a way to learn of a path one may not list. Also worth challenging as a design choice: the alternative was a special case in the evaluator, which was rejected. |
| D9 | *What else.* | |

### E. The audit trail — second tier

| # | Claim | Falsified by |
|---|---|---|
| E1 | No response leaves the process, and no change is made, before the record is stored. **Both** record the authorization decision first; they differ only in what follows. A read that then finds nothing, or cannot be served, gets a second entry with the real outcome. | A route that answers or mutates first. `every_endpoint_writes_an_audit_entry` covers presence; the *ordering* needs a human. *Corrected 2026-08-18: this row said reads work first and record afterwards, which the code never did. The claim was weaker than the implementation.* |
| E2 | If no device accepts a record the request is refused with `503`, and no sequence number is consumed. | A path that serves or writes anyway, or a gap after a device failure. |
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
4. **Root on the host is not defended against** (A5 in the threat model), and the master key sits in a
   mode-0600 environment file.
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

## What happens to the findings

Recorded in the changelog and in the ADRs where a decision changes. A finding that invalidates the
cryptographic or authorization approach is not a defect to be patched around: plan section 2 makes
falling back to OpenBao the correct response in that case, and `ciphr dump --format portable` exists
so that route stays open. **If no review can be arranged at all, that is itself an argument for the
fallback rather than for proceeding.**
