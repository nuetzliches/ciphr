# ADR-1 — Language: Rust (edition 2024)

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | Every crate |

## Context

The service holds plaintext secrets and key material in memory and hands them to callers over
HTTP. Two failure modes dominate real-world leaks in software of this kind: a secret printed into
a log or an error message, and key material left behind in memory that is later swapped to disk
or captured in a core dump.

The choice was between Rust and Go, and it is closer than it looks. Go has two real advantages:
cryptography in the standard library — one maintained implementation rather than a set of crates
— and, since Go 1.24, a FIPS-140-3 validated module in pure Go. Its dependency surface for a
service of this size is also considerably smaller. Both points are genuine security benefits, not
footnotes.

## Decision

Rust, edition 2024.

## Rationale

Rust wins on one property that is unreachable in principle in Go: deterministic erasure and
non-printability of key material.

- `zeroize` guarantees overwriting on `Drop`, with compiler fences that stop the optimizer from
  removing the write.
- `secrecy::SecretBox` makes accidentally logging a secret a **compile error**, because the type
  implements neither `Debug`, `Display` nor `Serialize`. In Go, printing a config struct with
  `%+v` prints the master key, and no amount of review reliably prevents that line from being
  written.

The strongest witness for this is the reference product itself. OpenBao, written in Go, removed
`mlock` support entirely, with this reasoning:

> "go's garbage collector can and will move and copy memory as it sees fit. `mlock` on a
> go-managed buffer just prevents the original memory location from being swapped out to disk,
> but does nothing to the copies that the go runtime will periodically create."

A mature secret manager written in Go concluded that it cannot keep secrets from being copied
around memory uncontrollably, and dropped the protection as a result. That is the decisive
argument.

Go's advantages are answerable through discipline, in a way that the memory property is not: a
hard dependency budget, `cargo-deny` in CI, and `#![forbid(unsafe_code)]` in every crate.
FIPS-validated primitives exist in Rust through `aws-lc-rs` — just not in the standard library.

## Consequences

- Secret-bearing values live in `SecretBox` or `Zeroizing`, and error types carry paths,
  identities, and error classes but never values. Both are CI-enforced rather than reviewed.
- The dependency surface needs active management. It is budgeted per crate, and `ciphr-crypto`
  and `ciphr-policy` take no dependencies beyond the cryptographic primitives.
- `#![forbid(unsafe_code)]` in every crate root, checked by `ci/check-forbid-unsafe.sh`.
- Swap protection is **not** solved by the language. It is an operational requirement: equal
  memory and swap limits on the container, and core dumps disabled.

## Rejected alternatives

**Go.** See above — its advantages are real but dissolvable through discipline; the
memory-copying property is not.

**Anything with a garbage collector and no wipe guarantee.** Not considered further, for the same
reason.

## Notes

The honest summary is that this decision buys one specific guarantee at the cost of a larger
dependency surface and cryptography outside the standard library. Presenting it as a clean win
would misrepresent it.
