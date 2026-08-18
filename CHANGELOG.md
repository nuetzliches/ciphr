# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is something to version.

This file is updated in the same commit as the change it describes.

## [Unreleased]

Phases 0 to 2. The cryptographic, storage, authorization, and audit layers work and are tested;
there is no HTTP server and no CLI yet.

### Added — phase 2: policy evaluation and the audit trail

- `ciphr-core`: the five capabilities, with no `admin` among them — a test asserts that, because an
  `admin` capability would undo ADR-3. `PathPattern`, the glob language for policies, built on the
  **same** normalization function as `SecretPath` so a pattern and a path cannot disagree (ADR-9).
- Pattern language restrictions tighter than the plan required, each for a stated reason: `**` only
  as the last segment, so matching is a linear scan with no backtracking; no partial wildcards, so
  `db*` cannot quietly mean more than its author read into it; and `**` matches one or more segments
  rather than zero, so a rule about a subtree is not also a rule about its parent.
- `ciphr-policy`: TOML policy files loaded strictly — an unknown key, an unknown capability, a
  dangling policy reference, a duplicate name, or two rules for one pattern refuse the whole file. A
  policy set that loads partially would be a set of permissions nobody wrote. `capabilities` is
  required even when empty, so an explicit denial is explicit.
- The evaluator: deny by default, most specific match wins, denial wins a tie, and an empty
  capability set is an explicit denial. Every decision carries the rule that produced it and every
  denial a reason, so the audit trail can say *why*.
- A 22-row decision table (`tests/decision_table.rs`) with a test asserting it still covers every
  capability and every deny reason, plus property tests for `**` subsuming `*` and for specificity.
- `ciphr-audit`: entries that record who, what, where, which version, the decision, the deciding
  rule, and the request context — and never a value, key material, or a token, only a token's
  non-secret identifier.
- The hash chain: each record's hash is the SHA-256 of exactly the bytes stored, so verification
  re-serializes nothing and a JSON Lines file can be checked line by line with `sha256sum`. A test
  asserts the known limitation too: a forward rewrite by someone with write access still verifies.
- Fail-closed sink: if no device accepts a record the caller must refuse the request, and the
  sequence number is **not** consumed — a gap is indistinguishable from a deleted entry, and an
  audit trail that cries tampering after a disk error is one nobody reads twice. A sink with no
  devices is refused at construction.
- The file device (JSON Lines, size-based rotation, `reopen` for `SIGHUP`, each write synced) and the
  SQLite device in `ciphr-store` with migration 002, which refuses to overwrite an existing sequence
  number because two records claiming one position is evidence.
- RFC 3339 UTC timestamps without a date dependency, checked against independently computed values
  including two leap days and a century boundary.
- `fuzz/`: three cargo-fuzz targets — path normalization, pattern matching, policy loading — that
  assert invariants rather than only checking for panics, run as a blocking CI job on a nightly
  pinned by date, with `cargo-fuzz` installed from a checksum-pinned release binary.
- Documentation: `docs/authorization.md`, `docs/operations/audit-trail.md` (including what to do when
  verification fails, and why the head hash belongs outside the store), and `docs/fuzzing.md` — which
  states plainly that a 45-second smoke run is not a fuzzing campaign.

### Changed

- `AGENTS.md` no longer claims `ciphr-policy` takes no dependencies. It takes a TOML parser and
  `serde`, which is the substance of ADR-2 rather than an exception to the dependency budget.

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
