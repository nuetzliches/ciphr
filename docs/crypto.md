# Cryptographic design, as implemented

**Status:** implemented and tested as of 2026-08-18, re-read against the code on 2026-08-20 and
unchanged. Describes the code in `crates/ciphr-crypto`, not an intention. The wire format and the
key hierarchy have not moved since phase 1; what changed since is the wording of one refusal, which
this document does not quote.

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
3. **Nonce reuse becomes structurally impossible.** Each data key encrypts exactly one payload, so
   exactly one nonce ever exists under it. The best-known way to destroy AES-GCM — two messages under
   the same key and nonce — cannot occur here, as opposed to being avoided by careful counter
   management that has to stay correct forever.

### Why AES-256-GCM and not XChaCha20-Poly1305

Hardware acceleration is available on the target platform, and AES-256-GCM is FIPS-approved, which
keeps the option of an `aws-lc-rs` FIPS build open. XChaCha20's main advantage is a nonce large
enough that random collisions are irrelevant — which the one-key-per-payload design already
achieves, so the advantage does not apply.

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

- **It does not protect against root on the host.** Root reads the master key from the service
  environment file and reads plaintext out of process memory. See the threat model (A5); this is a
  consequence of unattended startup, not an oversight.
- **It does not survive losing the master key.** There is no recovery path, by construction. See
  [operations/master-key.md](operations/master-key.md).
- **It is not zero-knowledge.** The server decrypts, because the audit trail and per-identity access
  control depend on it (ADR-4).
- **It does not defend against side channels beyond timing in credential comparison.** No protection
  against cache-timing or speculative-execution attacks.
- **It has not been reviewed externally yet.** That review — of `ciphr-crypto`, `ciphr-policy`, and
  the path and pattern code in `ciphr-core` — is a precondition for first production use that has not
  been met, and until it happens this design should be treated as unverified by anyone but its
  author. An operator may decide the risk is acceptable for what their deployment holds; that
  decision does not change this line.
