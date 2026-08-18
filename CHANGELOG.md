# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is something to version.

This file is updated in the same commit as the change it describes.

## [Unreleased]

Phases 0 and 1. The cryptographic and storage layers work and are tested; there is no HTTP server,
no CLI, no policy evaluator, and no audit trail yet.

### Added — phase 1: cryptography, storage, seal

- `ciphr-core`: normalized secret paths (NFC, no relative or empty segments, no wildcards, length
  limits) as the single normalization in the system; version numbers starting at one; the `Plaintext`
  wrapper, which implements neither `Debug`, `Display`, `Serialize` nor `PartialEq`; the five rotation
  classes, each carrying the advice for its own failure mode.
- `ciphr-crypto`: envelope encryption — master key wraps root key, root key wraps one data key per
  secret version — with path and version bound as additional authenticated data, so a ciphertext
  cannot be relocated. Known-answer tests pin the wire format; property tests cover round-tripping,
  relocation, and single-bit tampering. Every authentication failure returns one indistinguishable
  error rather than an oracle. Randomness comes from the OS CSPRNG only; `rand` is not a dependency,
  so no seeded generator exists in the graph.
- `ciphr-crypto`: the `Seal` trait and `StaticEnvSeal`, reading a 64-hexadecimal-character master key
  from the environment. The trait's `unseal` takes the wrapped record as an argument, unlike the
  sketch in the plan, which could not work — a seal must not reach into the store.
- `ciphr-store`: SQLite behind the `Store` trait, with STRICT tables, WAL, foreign keys enforced, and
  numbered migrations applied transactionally with their version marker. Secrets, versions, soft
  delete, undelete, crypto-shredding, rotation class, metadata and version listings that need no key,
  and prefix listing by range scan rather than `LIKE` — so a path containing `%` or `_` cannot be
  mistaken for a wildcard.
- `ciphr-store`: encryption is passed into `put` as a callback and runs inside the allocating
  transaction, so the version bound into a ciphertext is by construction the version it is stored
  under.
- Master key rotation, demonstrated end to end: one record is rewritten, every ciphertext is unchanged
  byte for byte, the old key stops working, and a replacement record for a different root key is
  refused.
- Documentation: `docs/README.md` (the index, the rules documentation is held to, and a table of risk
  areas), `docs/crypto.md` (the implemented design and what the tests do and do not establish), and
  `docs/operations/` for master key handling and for rotating secrets that cannot safely be rotated.
- CI gate `ci/check-docs.sh`: every document under `docs/` carries a date, and no date lies in the
  future.

### Added — phase 0: repository skeleton

- Cargo workspace with the eight v1 crates: `ciphr-core`, `ciphr-crypto`, `ciphr-store`,
  `ciphr-policy`, `ciphr-audit`, `ciphr-sdk`, `ciphr-server`, and `ciphr-cli`. The CLI binary is
  named `ciphr`.
- `#![forbid(unsafe_code)]` in every crate root, plus a denial of `print!`, `eprint!`, and `dbg!` in
  library crates.
- Workspace lint policy: `missing_docs`, `unreachable_pub`, `unused_qualifications`, and clippy's
  `all` and `pedantic` groups, all blocking through `-D warnings` in CI.
- Toolchain pinned in `rust-toolchain.toml`, formatting settings in `rustfmt.toml`.
- `deny.toml`: permissive-only licence allowlist, advisory database with a staleness limit, denial of
  duplicate crates, wildcard requirements, unknown registries, and any transitive OpenSSL binding.
- CI workflow with blocking gates — `cargo fmt`, `cargo clippy -D warnings`, `cargo test`,
  `cargo deny check`, `cargo audit --deny warnings` — and three source-rule gates in `ci/`: no output
  from library crates, `forbid(unsafe_code)` present in every crate root, and no `v-html` in the
  future UI. Third-party actions are pinned by commit hash, and `cargo-deny` and `cargo-audit` are
  installed from release binaries pinned by version and SHA-256 rather than compiled in CI.
- Decision records ADR-1 through ADR-13 in `docs/adr/`, one file each, with an index.
- `docs/threat-model.md` — adversaries A1 to A8, the boundaries that are deliberately not defended,
  and the availability trade written down as part of the model.
- `docs/why-build-this.md` — the evaluation of existing tools, the finding that OpenBao meets the
  requirement for free, and the condition under which abandoning this project is the correct
  decision.
- `AGENTS.md` with the working rules, and `SECURITY.md` with the disclosure process and scope.

[Unreleased]: https://github.com/nuetzliches/ciphr/commits/main
