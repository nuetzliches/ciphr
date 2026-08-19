# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is something to version.

This file is updated in the same commit as the change it describes.

## [Unreleased]

### Added — the master key may come from a file

- `[seal] type = "static_file"` with a `path`, and `--master-key-file` on the CLI. Recorded as an
  extension of ADR-5 rather than a new decision: what ADR-5 decides is a *static* key behind a trait,
  and where that key is read is a property of one implementation. The key bytes are identical either
  way, and a store sealed through one source opens through the other — there is a test for exactly
  that.
- The reason is not only that it is smaller: section 13 of the plan tells consumers not to pass
  secrets through `environment:`, because the value is baked into the container configuration and is
  readable through the runtime's inspect API by everyone with socket access — a broader set than root.
  ciphr was doing that with its own master key. A secret manager whose deployment contradicts its own
  guidance is hard to argue for.
- What it removes: the key is no longer in the container configuration or in `/proc/<pid>/environ`.
  What it does not change, stated in ADR-5 and in the operations guide: root on the host reads the
  file just as it read the variable, the key is in process memory either way, and it is still one
  bootstrap secret per host. Whether the key is at rest on a disk depends on the runtime — Swarm and
  Kubernetes secrets are memory-backed, plain Compose bind-mounts a real file.
- **Both sources cannot be active at once.** The configuration is one tagged variant and the CLI
  refuses the two flags together, so there is deliberately no precedence rule: a rule about which
  source wins is a rule that lets a deployment use the key nobody thought was active.
- **A world-readable key file stops the process**, rather than producing a warning nobody reads.
  Group-readable is accepted: root-owned and read by a service group is legitimate, and refusing it
  would push deployments towards running as root. Windows has no equivalent bit and no check runs
  there, which is documented rather than silently skipped.
- Surrounding whitespace is trimmed, so a file written with `echo` is not a different key from one
  written with `printf %s`.
- No URL-style `file://` prefix: parsing a source out of a string is the hand-written parsing ADR-2
  rejected for policies, and the argument applies to configuration too.

### Changed

- `StaticEnvSeal` is now `StaticSeal`, since the name would otherwise describe only one of its two
  sources. The identifier recorded in a store is `static` rather than `static_env` for the same
  reason — it names the mechanism, not where the key was read. `static_env` is accepted as equivalent
  when opening an existing store and is replaced on the next re-wrap.
- `/v1/health` reports `key_source` (`env`, `file`, or `supplied`) alongside `seal`. The two
  legitimately differ while a deployment moves between sources, which is exactly when an operator
  needs to see which one is in effect.
- `docs/operations/master-key.md` was still describing phase 1, including a rotation procedure that
  said no CLI command existed for it. Both are corrected.

Phases 0 to 3 are complete. The external review has not taken place; it remains a precondition for
first production use.

### Fixed — one writer per store

- Finding 10. `StoreLock` in `ciphr-store`, taken before the store is opened: by the server for the
  life of the process, by the CLI for the duration of a command. A second writer is refused with a
  message that says what to do instead of a permanent `503` afterwards.
- It adds no constraint that was not already there. A restart was required after any such write
  anyway, because only a restart re-reads the chain head; the lock moves the discovery earlier.
- No new dependency: `create_new` for atomicity, `/proc` for liveness.
- **Two errors only the container caught.** Probing for `/proc` at runtime looked portable and was
  not — on Windows the path resolved against the drive root and reported a directory, so every
  holder looked dead and the lock was taken from a live process. And a process id alone is useless in
  a container, where the server is always process 1: a lock left by a killed container looked alive
  forever, so nothing could start after an unclean stop. The lock now records the holder's start
  time from `/proc/<pid>/stat`, verified by killing a container and starting another.
- Transition cost: a lock file written by an earlier build records only a process id, cannot be
  verified, and has to be removed by hand once.

### Found — a CLI write while the server runs takes the service down

- Finding 10, reproduced against a running instance: one `ciphr put` from the CLI while the server
  is up turns every subsequent request into `503`, and it does not recover until the process is
  restarted.
- The chain lives in memory and both processes hold one. The server resumes from the store's head at
  startup; a CLI write moves that head without telling it; the server's next record collides on a
  sequence number, no device accepts it, and fail-closed refuses the request. The chain only advances
  on a committed record, so the collision repeats forever.
- Every component behaves as designed. The assumption underneath them — that one process at a time
  writes to a store — is stated nowhere and enforced nowhere.
- It matters because the CLI is the documented way to do `token issue`, `import`, `destroy` and
  `rotate-master-key`, two of which are routine. `import` is the migration tool for an existing
  corpus; run against a live server it takes the service down on its first write.
- Fixed in the entry above, after the options were weighed: a lock is the only one that states the
  assumption rather than working around it.

### Added — a container image and a release workflow

- `Dockerfile`, `docker-entrypoint.sh` and `.github/workflows/release.yml`. Single architecture on
  purpose: this runs on one amd64 host, and a multi-arch manifest would mean a second build, a
  digest merge and a cache scope per architecture to produce an artifact nothing pulls.
- Both binaries ship in the image. The CLI is not a convenience: `init`, `token issue`, `destroy`,
  `audit verify` and `rotate-master-key` need the master key and the store and have no endpoint by
  design (ADR-3), so they run as `docker exec` against this container. A separate CLI image would
  need the same volume, the same master key and therefore the same trust.
- The health check speaks HTTPS and **verifies**, using the CA that signed the listener's own leaf.
  ADR-8 rules out `--insecure` everywhere, and a health check that skipped verification would be the
  one place that rule was quietly broken.
- The entrypoint disables core dumps before dropping privileges — a dump of this process contains
  the master key, the root key, and whatever was in flight, and `ZeroizeOnDrop` cannot help with a
  snapshot of a live process. It belongs with the process rather than in a container definition that
  a deployment can forget.
- **Built and run before being committed**, which is the only reason three of these are right. The
  `CMD` invoked a `--config` flag that does not exist; the config path is positional. The entrypoint
  accepted a key that is mode 600 *and owned by root*, which the service then cannot read — the
  likelier mistake by far, since `install -o root -g root -m 0600` is the reflex for a private key,
  and it surfaced as "Permission denied" from the TLS loader, reading like a broken certificate. And
  `docker commit` does not carry volume contents, so a store initialized that way disappears.
- Verified end to end: the container reports healthy, an authenticated request over TLS succeeds, and
  `/v1/health` shows `accepting` moving from `null` to `true` — finding 6's fix, in a running system.

### Changed — `security-review.md` brought in line with what the code now does

- **B9 is struck from the known imperfections.** The known-answer tests were reproduced against an
  independent AES-256-GCM implementation, so they validate the primitive and its plumbing rather than
  only the stored format.
- **E1 corrected.** It claimed reads work first and record afterwards. They never did — the
  authorization decision is recorded before the read, which is the stronger property. The claim was
  weaker than the implementation, and a reviewer checking the claim would have found the code
  "wrong" in the safe direction.
- **A3 rewritten** for the allowlist, with a pointer to why it changed, and **A4** now states that
  invisible characters are refused while confusables across scripts are not, and that the second half
  is a decision rather than an omission.
- The document now says a pre-review pass exists, what it closed, and — the part that matters — that
  it came from the same model that co-authored the code, so every claim it looked at was looked at
  with the wrong eyes.

### Changed — the audit record shape, for listings and for device failures

- **Findings 4 and 8.** Two additions to the stored record, both deliberate and both changing the
  known-answer test in `chain.rs` — which is what that test is for.
- `results`: how many items an operation returned, set by listing and null elsewhere. `/v1/list`
  used to write a plain allow with no rule attached, which is the falsifier D4 names for itself: an
  allow the evaluator never produced. Listings authorize per returned path, so there is no single
  decision to record; the count is what the trail can honestly carry, and its presence is what marks
  the entry as not being a decision. The listing is now produced before it is recorded, so the number
  is true — and still before anything is serialized, so a failure to record reveals nothing.
- Authorizing the prefix instead was rejected for the reason the plan already gives: `infra/**` does
  not match `infra`, so a prefix check refuses the listing to exactly the identity allowed to read
  everything beneath it. The path names are not recorded either: an entry that grows with the size of
  a listing is a way to make records unbounded.
- `Action::AuditDeviceFailed`: the devices that accepted a record now record that another one
  refused it, naming the device. The chain advances when any device accepts, so the refusing one is
  missing that sequence number for good — and a gap found later is indistinguishable from a deleted
  entry, which commits whoever finds it to treating the surrounding accesses as unlogged. The trail
  now explains its own gaps. The write is infallible and non-recursive by design.
- The `chain.rs` known-answer test carried a comment claiming a change to the stored form makes every
  existing chain fail to verify. **It does not**, and the reason is the design the module already
  documents: verification hashes the stored bytes and re-serializes nothing, so older records keep
  verifying exactly as they did. The comment is corrected.

### Documented — the sharp edge in specificity

- **Finding 5.** `docs/authorization.md` gains a worked example: `infra/**` and `*/*/*/DB_PASSWORD`
  are both specificity 1, so a broad grant and a cross-cutting exception tie, and a tie denies with
  the reason `tie` rather than the override the author meant. Writing the exception as
  `infra/*/*/DB_PASSWORD` makes it specificity 2 and it wins outright.
- Both spellings deny; what differs is the recorded reason, and the documentation says so rather than
  implying a behaviour change. A tie is also fragile — it holds only while no third rule of the same
  specificity appears. Pinned in `decision_table.rs`, because a worked example is only worth having
  while it stays true.
- The semantics are unchanged on purpose. Counting positions instead of segments would match
  intuition in this case and would have to justify itself in every other, and any such change alters
  authorization outcomes in the crate still waiting for the external review.

### Changed — path segments are drawn from an allowlist

- Finding 1. The segment rules rejected control characters and whitespace, which let every Unicode
  *format* character through: U+200B, U+00AD, U+FEFF, U+2060 and U+202E were all accepted, and each
  one produces a path that renders identically to another — or, for the bidirectional override, as a
  different one entirely. That contradicted the rule's own stated reason for refusing whitespace.
- Segments now allow letters and digits of any script plus `-`, `_` and `.`, and refuse the rest.
  **An allowlist rather than a longer denylist**, because a denylist grows with every Unicode
  revision and a gap in it stays invisible until someone finds it. Not an ASCII rule: `日本/x` is a
  valid path.
- Control characters and whitespace keep their own errors; the new one names the offending code
  point as `U+XXXX` rather than printing a character nobody can see.
- **Confusables are unchanged and are now a stated boundary.** A Cyrillic `а` and the `ﬁ` ligature
  are letters, so any rule admitting non-ASCII names admits them. A test pins that they remain
  distinct paths.
- One deliberate cost: `%` and `[` are no longer legal in paths, and a store test used them to show
  the prefix listing is a range scan rather than `LIKE`/`GLOB`. `_` is also a `LIKE` wildcard and
  still legal, so that guard survives; the `GLOB` half does not, and the test now says so.

### Fixed — three review findings that needed no decision

- **Finding 3, the one with a trap in it.** `state.rs` and the doc comment on `read_secret` both
  said reads do the work first and audit afterwards. They never did — the authorization decision is
  recorded before the read. The wording is corrected and the code left alone, because recording
  first is the stronger property and the risk was someone aligning the code to the sentence. The
  decryption-failure and non-UTF-8 paths now write the second audit entry the not-found path always
  wrote, so no outcome other than a served value is recorded as if a value had been served.
- **Finding 7, a torn line in the file device.** `write_all` is not atomic; a failure part-way
  through left bytes on disk that the next record was appended to, producing a line the chain could
  never verify again — indistinguishable from an edit, and triggered by exactly the failure this
  device is designed around. The line is now built once and the file truncated back on any error.
  Two tests assert the tracked size never drifts from the file; the `ENOSPC` path itself is stated
  as untested, because faking the error would only test the fake.
- **Finding 2, a timing difference on unknown token identifiers.** Both paths now derive the
  verifier and run the same constant-time comparison. This narrows rather than closes it — the known
  path still performs one extra query — and the code says so instead of claiming more than it does.

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

- Finding 9 in `docs/review-2026-08-18.md`, from a run on a real Forgejo runner in the same
  host-execution mode a deployment uses. The premise behind `export --format actions-env` is
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
