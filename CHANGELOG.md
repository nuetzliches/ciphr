# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is something to version.

This file is updated in the same commit as the change it describes.

## [Unreleased]

Phases 0 to 3 are complete. The external review has not taken place; it remains a precondition for
first production use.

### Fixed — the server no longer discards partial audit-device failures

- Finding 6. `AuditSink::record` has always reported which devices refused a record; `AppState`
  dropped that on the floor, so a device failing every write stayed invisible in the API, on the
  health endpoint and in the logs — the exact state `device.rs` names as the thing to prevent.
- `/v1/health` now reports each audit device as `{ name, accepting }`. `accepting` is `null` until
  the first record: "nothing written yet" is a third state, and a monitor that reads it as healthy
  reports a working second device on a service that has never written to it.
- **The reason a device gave is not reported.** The route is unauthenticated and a device failure
  message names a path or a database. A test asserts the reason stays out of the response.
- Covered by two tests, one driving a sink with two devices where one refuses everything. Finding 8
  is unaffected: a gap on the lagging device remains indistinguishable from a deletion afterwards.

### Added — `/v1/health` states what the process enforces

- Plan sections 10 and 17. The design has no switch that turns a security property off: TLS is a
  non-optional config field, the workspace has no feature flag at all, and the single relaxation that
  exists (`--force` on secret output) suspends a heuristic for one invocation rather than disabling a
  property. The constructive counterpart is a service that says what it enforces, so an operator can
  check it from outside instead of trusting a claim in a README.
- Named for the endpoint: seal state (already returned), **per-device** audit state (missing, and the
  reason the third monitoring check in section 17 cannot currently be built — see finding 6), and the
  transport including certificate expiry, so a renewal deadline is monitorable rather than a surprise.
- The existing constraint still binds and is restated: the endpoint is unauthenticated, so it may
  report *what is enforced* and never *what is stored*. A device name, a boolean and an expiry date
  are properties of the process; a count of secrets, a path or an identity are not.

### Added — masking measured on a real runner, and its limit

- Finding 9 in `docs/review-2026-08-18.md`, from a run on Forgejo runner v12.7.2 in the same
  host-execution mode production jobs use. The premise behind `export --format actions-env` is
  confirmed: a runtime-fetched value with no mask registered appears in the job log in full, so the
  masking really is the product's job and not the forge's.
- Every case the format was built for holds — same step, across steps through `$GITHUB_ENV`,
  multi-line values through the heredoc form, a value inside a composed URL, and a value in the
  stderr of a failing command are all redacted. The heredoc round-trip was checked by comparing
  SHA-256 digests rather than by printing anything.
- **The limit: masks match literal substrings, and `set -x` re-quotes.** A value containing a single
  quote is rendered `'part'\''part'` and a value containing a tab is rendered `$'a\tb'`; neither
  matches, and both are printed in full. Measured across eight values differing only in which
  character they contained — exactly those two leaked. Spaces, `$`, backticks, double quotes and
  backslashes are safe, because bash leaves the content unchanged inside the quotes.
- The multi-line case is safe **because** masks are emitted per line: the same property that
  `render_actions_env` justifies with "runners match literal strings" also defeats bash's `$'…\n…'`
  form, since each line's bytes still appear verbatim between the escapes.
- The module documentation in `crates/ciphr-cli/src/formats.rs` names `set -x` as the motivation for
  the feature and does not state where the protection stops. That is the minimum to change; whether
  to additionally register the shell-quoted renderings is a judgement recorded with the finding.

### Added — developer experience as a stated goal, and ADR-14

- Plan section 1 gains a **Developer experience** subsection. Until now usability was not a criterion
  anywhere in the plan: "convenience" appeared exactly once, as a reason to reject something. That is
  the `AGENTS.md` rule working as intended, and it is also why the gap ADR-14 records went unnoticed
  — an unstated goal produces no findings.
- The section is as much a set of non-goals as goals. Managing secrets, policies, identities, or
  tokens through a web form stays ruled out by ADR-3 and section 15; environments and folders stay
  ruled out by the multi-tenancy non-goal; sharing links remain a password manager's job. Asking for
  any of them is a request to revisit an ADR, not to schedule work.
- **ADR-14 — `ciphr run` injects secrets into a child process. Proposed, not accepted**, decision
  required before phase 7. Section 13's route B currently costs one derived image per third-party
  service, which is why it is the least likely route to be carried out despite applying to the most
  images. A `run` subcommand that fetches under a prefix and `exec`s the real entrypoint reduces that
  to a bind-mounted static binary and an overridden `entrypoint:`.
- The record states four conditions that must hold before it can be accepted — a static musl build,
  a written-down original entrypoint (which trades a rebuild for a pin, and says so), settled
  fail-closed behaviour on a failed fetch, and prefix-to-variable-name semantics shared with route
  C — and three rejected alternatives, including keeping the plan as it stands.

### Added — a pre-review pass over every claim

- `docs/review-2026-08-18.md`: findings, coverage, and a fitness statement in the form
  `docs/security-review.md` asks for. It is **not** the external review and says so in its first
  section: it was produced by the same model that co-authored the code, so it carries the same blind
  spots and does not discharge plan section 18.
- **B9 is closed.** All three pinned known-answer vectors were reproduced byte-for-byte by OpenSSL's
  AES-256-GCM, with the value AAD rebuilt from the prose in `envelope.rs` rather than copied from
  `AAD_HEX`, plus two negative controls. The known-answer tests now validate the primitive and its
  plumbing, not only the stored format. This should be struck from the list of known imperfections in
  `docs/security-review.md` once that document is revised.
- Eight findings, none of them a break of the envelope scheme or the evaluator. Three are fixes
  (invisible and confusable characters accepted in paths; partial audit-device failures discarded by
  the server; a torn line left behind by a failed file-device write), three are decisions
  (`/v1/list` records an allow no rule produced; specificity ignores pattern breadth; a benign device
  gap is indistinguishable from a deletion), and two are documentation that describes an ordering the
  code does not implement.
- Claims confirmed as stated: A1–A3, A5, A6, B1–B8, B10, C1, C3–C6, D1–D3, D5–D7, E2–E6. The one
  claim that holds while its surrounding module documentation overstates it is C2.

### Added — preparation for the external review

- `docs/security-review.md`: the scope, every claim the code makes, and what would falsify each. It
  states plainly that it was written by the author and cannot substitute for the review, that a
  checklist narrows attention, and that design disagreements are findings rather than
  misunderstandings.
- It corrects the plan's review scope: section 18 names `ciphr-crypto` and `ciphr-policy`, but path
  normalization and the glob matcher live in `ciphr-core` — the ADR-9 surface — so that crate is in
  scope too. About 1500 lines of code in total.
- The known imperfections are listed up front rather than left to be rediscovered: the known-answer
  tests are self-generated and validate the format rather than AES-GCM, constant-time behaviour is
  exercised but not proven, and the hash chain cannot detect a forward rewrite.

### Added — phase 3: the CLI

- `ciphr`, working on the local store with the master key from the environment: `init`, `put`, `get`,
  `list`, `versions`, `delete`, `undelete`, `destroy`, `rotation`, `export`, `import`, `token`,
  `audit`, `rotate-master-key`, and `dump`.
- **No value is ever an argument.** There is no `--value` flag; values come from standard input.
  There is no interactive prompt either, because prompting with echo writes the secret into the
  operator's scrollback and disabling echo would need another dependency.
- **No secret goes to a pipe unasked.** `get`, `export`, `dump`, and `token issue` refuse when output
  is not a terminal unless `--force` is given. `export --format actions-env` is exempt, because
  writing into the runner's environment file is its purpose.
- `export --format actions-env` emits `::add-mask::` for every value *before* the assignments, one
  mask per line for multi-line values, and assigns those with a heredoc whose delimiter includes the
  variable name so a value containing `EOF` cannot end its own block. No forge masks a value fetched
  at runtime, so masking is part of the product rather than of the documentation.
- `import --from-dotenv` with `--dry-run` that prints paths and value *lengths*, never values. A line
  the parser cannot read stops the import rather than being skipped, and `$VAR` references are not
  expanded — storing the expansion would store something the file does not say.
- `token issue` checks the identity exists in the policy file, prints the token exactly once, and
  requires a unit on a TTL: `90` meaning seconds when days were intended is a token that expires
  mid-deploy.
- `dump --format portable` ships in v1 deliberately: it is the insurance against the scenario in the
  plan, and insurance bought after the fire is worthless.
- CLI actions are audited, metadata reads included, so the trail says the same thing whether an
  access came through the API or from the host.
- `docs/operations/cli.md` documents every command and the reasoning behind the two rules.

### Changed

- The CLI works on the local store rather than through the SDK, which the plan had assumed. Most of
  what it does needs the master key and has no endpoint by design (ADR-3); a CLI that spoke HTTP
  would need the privileged API this project deliberately does not have. `ciphr-sdk` therefore stays
  a skeleton until phase 7, where applications fetching their own secrets is the requirement.
- `SecretPath::segments` is now double-ended, so the last segment — the conventional environment
  variable name — can be taken without collecting.

### Added — phase 3: the HTTP server

- `ciphr-server`: all ten v1 endpoints on axum, with TLS terminating at the listener
  (ADR-8) — there is no option to disable it and no insecure mode, because a flag that turns off
  transport encryption is a flag that ends up set in production.
- Configuration in one strict TOML file: an unknown key is an error, and the server **refuses to
  start** without an audit device. Policies live in a separate file, named by the configuration.
- Startup refuses rather than degrading: an unreadable policy file, an uninitialized store, a
  missing or wrong master key, an audit device that cannot be opened, or unusable TLS material each
  stop the process. A certificate and key swapped by mistake is reported by name at startup instead
  of surfacing as a handshake failure for the first client.
- Audit ordering, deliberately different for reads and writes: a read does the work, records the
  real outcome, then answers — so a failed audit drops the value before it leaves the process. A
  write records the authorized intent *first*, so a failed audit leaves the store untouched. Both
  are tested, including that no value is served and no secret is written when the trail is down.
- `every_endpoint_writes_an_audit_entry` walks every route and asserts an entry appeared, which
  turns "nothing is answered before it is recorded" into a checked property rather than a
  convention a future handler can quietly break.
- Listings authorize **per returned path** rather than on the prefix, because `infra/**`
  deliberately does not match `infra`. The alternative — a special case in the evaluator so a
  subtree grant also covers its prefix — was rejected: path-based authorization is worth having
  only if there is one rule for how a decision is made.
- `/v1/export` authorizes and records path by path, so a bulk read produces one entry per secret;
  a single refusal fails the whole export rather than revealing which paths are readable.
- `/v1/audit` returns each record as the exact stored bytes plus its hash, so a client can verify
  the chain instead of trusting the endpoint, with server-side filters on identity, path, decision,
  time, and sequence.
- Values are UTF-8 text on the wire and in the store — a stated limitation rather than two
  representations that every client would have to handle.
- `openapi.yaml`, covering all ten endpoints plus the reserved `POST /v1/auth/oidc/login`, which
  returns 404 in v1 and is listed so the path is not claimed by accident.

### Changed

- `rustls-pemfile` removed: it was unused, and `cargo deny` flagged it as unmaintained. The gate
  caught a dependency that should not have been added.
- `deny.toml` records two `getrandom` duplicates with the reason for each — one from `ring`, one
  from `proptest` — rather than relaxing the duplicate rule.
- `AuditDevice` now requires `Send`, since a device is written to from whichever worker thread
  handles a request. It is deliberately not `Sync`: two threads writing one file device would
  interleave lines, which for a hash chain means a chain that does not verify.

### Added — phase 3: authentication

- `ciphr-core`: unpadded base64url, hand-written and checked against the RFC 4648 vectors. Decoding
  is strict about trailing bits and rejects the padded form, so one token cannot have two spellings
  that both authenticate.
- `ciphr-crypto`: tokens shaped `cph_<8 chars id><43 chars secret>` — 256 bits of entropy in the
  secret half, a non-secret identifier so authentication is an indexed lookup rather than a scan, and
  a `cph_` prefix that secret scanners recognize. `Token` implements neither `Debug`, `Display` nor
  `Serialize`; its text form is available once, through a wrapper that wipes itself.
- Verifiers are `HMAC-SHA256(pepper, secret)` with the pepper derived from the root key under a
  domain-separating label, so a database-only leak does not permit offline verification of guessed
  tokens. Password hashing is deliberately absent: there is no dictionary to attack, so Argon2id would
  cost CPU on every request and buy nothing.
- Comparison is constant-time through `subtle`, with a test that a difference is detected at every
  byte position — and a comment saying plainly why that is a behavioural stand-in rather than proof,
  since a timing assertion in a unit test produces flakiness rather than evidence.
- `ciphr-store`: migration 003 adds `tokens`, and there is deliberately **no identities table** — the
  policy file is authoritative for identities (ADR-3), and a second copy would drift. Authentication,
  issuing, listing, revoking one token, and revoking every token of an identity at once.
- Every kind of invalid token is indistinguishable to the caller: unknown identifier, wrong secret,
  expired, revoked. The verifier is compared before expiry and revocation are considered, so timing
  cannot separate those cases either.

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
