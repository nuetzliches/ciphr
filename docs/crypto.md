# Cryptographic design, as implemented

**Status:** implemented and tested as of 2026-08-18, reviewed externally on 2026-08-21 and corrected
where that review found the text stronger than the code. Describes the code in
`crates/ciphr-crypto`, not an intention. The wire format and the key hierarchy have not moved since
phase 1; what has changed since is the wording of one refusal, which this document does not quote,
the zeroization of the token codec (finding F1), and the level at which the nonce-reuse claim is
stated (finding F3 — prose, not code).

The ground rule is that there are no custom constructions here. Established AEAD primitives,
composed in the standard envelope pattern, with every deviation from the obvious approach explained.
If a claim below is not backed by a test, it says so.

## The key hierarchy

```text
CIPHR_MASTER_KEY                 32 bytes, from the environment, never persisted
        │  AES-256-GCM, AAD = "ciphr/root-key/v1" ‖ root_key_id
        ▼
root key                         32 bytes, generated at init, stored only wrapped
        │  AES-256-GCM, AAD = "ciphr/dek/v1" ‖ dek_id
        ▼
data encryption key              32 bytes, exactly one per secret version
        │  AES-256-GCM, AAD = "ciphr/value/v1" ‖ len(path) ‖ path ‖ version ‖ dek_id
        ▼
secret plaintext
```

### Why a root key in the middle

So that changing the master key rewrites **one record**. Without it, a master key change would mean
re-encrypting every secret in the database — which is to say, something nobody would ever do, and a
key that is never rotated is the same as a key that cannot be. It is also what makes a change of seal
mechanism (ADR-5) a single-row migration rather than a data format change.

Tested in `crates/ciphr-store/tests/master_key_rotation.rs`, which asserts that after a rotation
every stored ciphertext is byte-for-byte unchanged and the old master key no longer opens the store.

### Why one data key per secret version

Three effects, in ascending order of importance:

1. A compromised data key exposes one version of one secret.
2. Crypto-shredding a version is deleting its wrapped data key — no ciphertext has to be found and
   overwritten, and the shred takes effect in every backup made afterwards.
3. **Nonce reuse becomes structurally impossible at the data-key level.** Each data key encrypts
   exactly one payload, so exactly one nonce ever exists under it. The best-known way to destroy
   AES-GCM — two messages under the same key and nonce — cannot occur there, as opposed to being
   avoided by careful counter management that has to stay correct forever.

   **The level matters, and this document used to state the claim without it** (corrected 2026-08-21,
   finding F3 of the review). One level up the argument is a different one: the root key wraps each
   data key under a *random* 96-bit nonce, one per version write, and that count is not structurally
   bounded. There collision is negligibly probable rather than impossible, and the applicable bound is
   NIST SP 800-38D §8.3: at most 2^32 invocations of one key with random IVs, which is 4.3 billion
   secret-version writes under one root key and puts the collision probability at about 2^-33. A
   store doing a thousand writes a day reaches 2^-63 after a decade. The master key does one such
   wrap per rotation, so its count stays in the single digits.

   Two things worth knowing rather than inferring. **The count is monotonic in v1:** it resets with a
   *new root key*, and `rotate-master-key` deliberately re-wraps the *same* root key (same
   identifier), so nothing in v1 resets it — a root key rotation, which would mean re-encrypting
   every secret, has no command. And a collision there is not a break of a secret's value: it would
   expose the XOR of two wrapped data keys and the GCM authentication key to somebody who already
   holds the database. At the scale above there is no code change worth making; what was wrong was
   the prose.

### Why AES-256-GCM and not XChaCha20-Poly1305

Hardware acceleration is available on the target platform, and AES-256-GCM is FIPS-approved, which
keeps the option of an `aws-lc-rs` FIPS build open. XChaCha20's main advantage is a nonce large
enough that random collisions are irrelevant — which the one-key-per-payload design already achieves
where a value is concerned. It would apply to the root key's random per-wrap nonces (see finding F3
above), and it does not change the answer: at 2^32 wraps the margin is 2^-33, and a second AEAD in
the same envelope would cost more than that margin is worth.

### Why path and version are authenticated

An adversary with write access to the database (a stolen backup being restored, a compromised host
process, a careless migration) could otherwise copy the ciphertext of `infra/service-a/db-password`
into the row for `infra/service-b/db-password`. Nothing about the value changes; the identity that
may read it does. That is a silent privilege transfer, and binding the path and version as
additional authenticated data turns it into a decryption failure.

## Wire format

The authenticated data is the part that must never change by accident, so it is written down exactly.

| Purpose | Additional authenticated data |
|---|---|
| Root key wrapping | `"ciphr/root-key/v1"` ‖ `root_key_id` (16 bytes) |
| Data key wrapping | `"ciphr/dek/v1"` ‖ `dek_id` (16 bytes) |
| Value encryption | `"ciphr/value/v1"` ‖ `u32be(len(path))` ‖ `path` (UTF-8, NFC) ‖ `u32be(version)` ‖ `dek_id` |

Notes on the choices:

- **Domain separators are versioned.** A future format change gets a new string rather than silently
  producing records that the old code misreads.
- **The path is length-prefixed.** With fixed-width trailing fields a bare concatenation would
  already be unambiguous, but that argument has to be re-derived by every reader, and it stops being
  true the moment a field is added. The prefix makes the property local.
- **Nonces are 96 bits from the OS CSPRNG**, stored alongside each record. A fixed nonce would be
  safe given one key per payload, and it would also look exactly like the classic mistake to anyone
  auditing the code.
- **Versions start at 1.** Zero means "no version yet", and the type refuses it, so the two cannot be
  confused inside authenticated data.

Randomness comes from `getrandom` — the OS CSPRNG, which is what `rand::rngs::OsRng` wraps. `rand` is
not a dependency at all, so no seeded generator exists anywhere in the graph to reach for by mistake.

## What the tests actually establish

| Claim | Where |
|---|---|
| The format above is exactly what the code produces | `kat_value_aad_format`, `kat_wrapped_root_key`, `kat_encrypted_value` in `crates/ciphr-crypto/src/envelope.rs` |
| Any value round-trips, for any path and version | `envelope_properties.rs::round_trips` |
| Nothing is ever reused between two encryptions | `envelope_properties.rs::nothing_is_ever_reused` |
| A record cannot be read under a different path, version, or root key | three properties in `envelope_properties.rs` |
| Any single bit flip in a stored record is detected | `envelope_properties.rs::any_single_bit_flip_is_detected` |
| Deleting the wrapped data key makes a version permanently unreadable | `shredding_the_wrapped_data_key_makes_the_version_unreadable` |
| A master key rotation re-wraps one record and re-encrypts nothing | `crates/ciphr-store/tests/master_key_rotation.rs` |

**What the known-answer tests do not do:** they do not validate AES-256-GCM. The vectors were
generated by this code and then pinned, so they detect a *change* in the format, not an error in the
primitive. Validating AES-GCM itself is the `aes-gcm` crate's job, against the NIST vectors in its
own test suite. Presenting our pinned outputs as cryptographic validation would be the sort of
claim this project should not make about itself.

Regenerating those constants is therefore never the fix for a failing known-answer test. If they
change, the stored format changed, and every secret written under the old format has become
undecryptable.

## Errors reveal nothing

Every authentication failure — wrong key, modified ciphertext, wrong path, wrong version, shredded
data key — returns the same error. Distinguishing them would tell an attacker *why* their attempt
failed, which is precisely the information they lack. This is a single variant in the error type
rather than a convention, so it cannot drift.

Error types carry paths, identities, versions, and lengths. They never carry a value or key material.

## What this design does not do

- **It does not protect against root on the host.** Root reads the master key wherever the seal
  keeps it — the mounted file for `type = "static_file"`, the environment for the variable form — and
  reads plaintext out of process memory either way. See the threat model (A5); this is a consequence
  of unattended startup, not an oversight.
- **It does not survive losing the master key.** There is no recovery path, by construction. See
  [operations/master-key.md](operations/master-key.md).
- **It is not zero-knowledge.** The server decrypts, because the audit trail and per-identity access
  control depend on it (ADR-4).
- **It does not defend against side channels beyond timing in credential comparison.** No protection
  against cache-timing or speculative-execution attacks.
- **It has been reviewed once, and by an AI model rather than a person.** The review of 2026-08-21
  ([`review-2026-08-21.md`](assurance/reviews/review-2026-08-21.md)) read `ciphr-crypto`, `ciphr-policy`, and the path,
  pattern, and secret code in `ciphr-core` end to end, reproduced the known-answer vectors with an
  independent AES-256-GCM implementation, and returned a qualified yes; its two blocking findings are
  fixed. It is not the review by an independent human practitioner that
  [`security-review.md`](security-review.md) describes, and one obtained later supersedes it. Read
  the record's first section before treating this design as verified — and note that a claim about
  anything the coverage section lists as skimmed is a claim nobody has checked.
