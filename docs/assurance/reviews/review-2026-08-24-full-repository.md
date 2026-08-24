# Full-repository security review of 2026-08-24

**Reviewed:** commit `e1940fb1db7fa5d50883cca70f28d4b77e8ed8e1` on `main`, with a clean
worktree, on 2026-08-24.

**Reviewer:** OpenCode, an AI model, commissioned by the maintainer. This is a static source review,
not a human practitioner review, formal verification, penetration test, or audit of a deployed
environment. It does not supersede the fitness statement in
[`review-2026-08-21.md`](review-2026-08-21.md). Unlike the earlier reviews, this pass covers the
complete repository: application crates, UI, images, automation, documentation, and the control-plane
surface added after `v0.5.1`.

## Executive assessment

No cryptographic break, secret-read authorization bypass, plaintext HTTP mode, or direct disclosure
of stored values was found. The envelope construction, path normalization, pattern matcher, policy
evaluator, token verifier comparison, secret-bearing types, and ordinary audit-before-release
ordering remain sound in the reviewed source.

Four high-severity defects require action:

1. Release and mirror workflows interpolate attacker-selectable ref/input text into shell source on
   jobs that publish artifacts and, on Forgejo, run on a persistent Docker-capable runner.
2. Stale store-lock takeover can admit two writers, violating the invariant that protects the
   in-memory audit head.
3. A valid file-only audit configuration starts from the SQLite audit head after restart and appends
   a new chain to the existing file.
4. `ciphr-run` accepts process-launch control variables such as `LD_PRELOAD` and `NODE_OPTIONS` from
   secret path names, making write access to fetched paths potentially equivalent to execution as the
   consumer.

The medium findings concern authenticated export amplification, audit-device recovery, token
revocation, health-state integrity, backup confidentiality, malformed dotenv errors, and unaudited
malformed requests. Severity describes impact when the affected surface is reachable; confidence is
the reviewer's confidence in the source-level conclusion.

## Findings

### F1. Release values are interpolated into privileged shell source - high, high confidence

**Where:** `.github/workflows/release.yml:93-106`, `.github/workflows/release.yml:176-181`,
`.github/workflows/release-ui.yml:55-68`, `.forgejo/workflows/build-images.yml:71-89`, and
`.forgejo/workflows/build-ui-image.yml:58-78`.

The workflows place `${{ github.ref }}`, `${{ github.ref_name }}`, and the Forgejo dispatch
`version` directly inside shell programs. Quoting the expression with shell quotes is not escaping:
a tag containing an apostrophe closes the quote and supplies new shell syntax. Git accepts ref names
containing apostrophes, semicolons, and command-substitution text; this was confirmed with
`git check-ref-format` on the reviewed host.

The GitHub jobs later receive package-write credentials. The Forgejo jobs receive clone and registry
credentials and run on the persistent `baumeister-runner`, which can invoke Docker. A repository
writer able to create a matching tag, or a user allowed to dispatch the Forgejo workflow, can execute
commands in a publication job. Repository write access is powerful, but it need not imply access to
registry passwords, package publication, or a persistent runner host.

**What an attacker gets:** arbitrary commands in release jobs, theft or misuse of publication
credentials, malicious artifacts, and potentially persistent-runner compromise through Docker.

**Fix:** pass event values through workflow `env` entries rather than substituting them into `run`
source, then validate the shell variable against exact release patterns such as
`^v[0-9]+\.[0-9]+\.[0-9]+$` and `^ui-v[0-9]+\.[0-9]+\.[0-9]+$`. Reject every other dispatch value.
Check out the immutable event commit rather than resolving an unchecked user-supplied tag after a
clone. Add a CI gate that rejects expression interpolation inside shell steps.

### F2. Stale-lock takeover can admit two concurrent store writers - high, high confidence

**Where:** `crates/ciphr-store/src/lock.rs:81-124` and ownership-blind cleanup at
`crates/ciphr-store/src/lock.rs:133-138`.

Stale recovery reads the current lock holder and later removes the pathname unconditionally. Two
processes can both classify the old lock as stale; the first removes it and creates its lock, then the
second executes its already-decided removal against the first process's new lock and creates another.
Both return success. `Drop` has the same identity problem: it removes whichever entry currently has
the lock pathname, not necessarily the file this guard created.

**What an attacker gets:** violation of the one-writer invariant after a crash or forced stop. Two
processes can hold different in-memory audit heads, producing duplicate sequence attempts, persistent
fail-closed `503` responses, and divergent audit-device histories. SQLite transaction locking limits
ordinary database corruption but does not repair the audit invariant.

**Fix:** hold an operating-system file lock through an open descriptor. If pathname locks remain,
stale takeover and cleanup must be ownership-aware and atomic with respect to replacement. Add a
synchronized multiprocess test in which two processes classify the same stale lock before either
removes it; exactly one acquisition must succeed.

### F3. File-only auditing appends a restarted chain to the existing file - high, certain

**Where:** file-only configuration is accepted at `crates/ciphr-server/src/config.rs:220-237`;
startup always obtains the chain from SQLite at `crates/ciphr-server/src/server.rs:66-73`; the file
device only opens for append at `crates/ciphr-audit/src/file.rs:58-68`.

The configuration requires at least one audit device but does not require the SQLite device. Startup
always resumes from `store.audit_chain()`. In a file-only deployment, SQLite has not received the
file's records, while `FileDevice::open` neither reads nor validates the existing file's last record.
After restart, the startup entry is appended with an empty or stale SQLite predecessor and sequence.

**What an attacker gets:** an attacker able to induce restarts can repeatedly break audit continuity.
Normal restarts alone are sufficient. The server starts successfully while the file contains duplicate
or discontinuous chain segments, making legitimate operation look like truncation or rewriting and
undermining the protected audit asset.

**Fix:** require the SQLite audit device as the canonical head, or implement file-head verification
and require all configured durable heads to agree at startup. The smaller safe change is to reject a
file-only server configuration. Add a restart test that verifies the complete file chain.

### F4. Wrapper-injected environment names can control process startup - high, high confidence

**Where:** all portable variable names are accepted at `crates/ciphr-core/src/env_name.rs:73-120`,
and every fetched pair is added to the inherited child environment at
`crates/ciphr-run/src/exec.rs:82-98`.

The final secret-path segment becomes an environment variable. No distinction is made between data
variables and variables interpreted by loaders or runtimes, including `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`NODE_OPTIONS`, `PYTHONPATH`, `RUBYOPT`, and `BASH_ENV`. `ciphr-run` then executes the configured
program with those values and the rest of the inherited environment.

**What an attacker gets:** where a writer can set a path fetched by a consumer and can reference a
usable payload or startup hook in the image, the next consumer start can execute attacker-selected
code as that service. That code receives all fetched values and can read the token file inherited by
the child. This makes a writer potentially equivalent to the reader/consumer, a stronger capability
than storing opaque data.

**Fix:** require an explicit static mapping or allowlist of expected variable names for `ciphr-run`.
A denylist of runtime variables is incomplete across languages and images. Document, until fixed,
that write access to any wrapper-fetched prefix is execution-equivalent to the consuming service.
Add tests for representative loader and runtime control names.

### F5. Bulk export permits large authenticated request amplification - medium, certain

**Where:** the unbounded request shape is `crates/ciphr-server/src/api.rs:323-329`; processing and
correction loops are `crates/ciphr-server/src/api.rs:861-937`.

`ExportRequest.paths` has no item limit, duplicate rejection, aggregate plaintext limit, or response
limit. Repeating one authorized path performs authorization, a durable audit write, a store read, and
decryption for every occurrence, then keeps another plaintext copy in the response. A late failure
adds a correcting audit write for every path already processed. The request-body limit does not bound
the response amplification when a short path names a large value.

**What an attacker gets:** a valid reader with `bulk_export` enabled can exhaust memory, force large
amounts of serialized SQLite and audit-device I/O, and contend on the process-wide store and audit
locks, denying service to unrelated identities. General load denial is a documented boundary, but
this endpoint supplies avoidable amplification within one authenticated request.

**Fix:** reject requests exceeding a small path count, reject duplicate normalized paths, and bound
aggregate plaintext response bytes before serialization. Validate all structural bounds before the
first audit or store operation. Add duplicate, count, size, and concurrent-export tests.

### F6. A recovered audit device silently rejoins with a permanent chain gap - medium, certain

**Where:** `crates/ciphr-audit/src/device.rs:130-152`; existing tests stop short of partial recovery
at `crates/ciphr-audit/src/device.rs:249-303`; health records only the latest acceptance at
`crates/ciphr-server/src/state.rs:273-294`.

The sink advances its shared chain when any device accepts a record. A device that failed therefore
misses a committed sequence. It remains active and may accept the next record, whose `prev_hash`
references the absent one. No per-device head, quarantine, replay, or resynchronization exists. Health
can later show `accepting: true` because it reports only the most recent write, although that device's
history is permanently incomplete.

**What an attacker gets:** inducing a temporary failure of one audit volume permanently weakens the
independent copy while requests continue through another device. Later green health obscures the
historical divergence. The surviving device still contains the missed record, so this is not an
audit-before-release bypass.

**Fix:** quarantine a device after it misses a committed record. Re-enable it only after verified
backfill or after starting an explicitly anchored new segment that records the gap. Health must report
historical divergence separately from latest-write acceptance. Add a two-device fail/recover test.

### F7. Unauthorized token revocation scans the complete inventory - medium, certain

**Where:** `crates/ciphr-server/src/api.rs:1395-1425` and the full materializing query at
`crates/ciphr-store/src/tokens.rs:339-371`.

The revoke handler authenticates, then calls `tokens(None)` and linearly searches the full token
inventory before checking `Capability::Revoke` on `sys/tokens`. Any authenticated identity that can
reach the enabled route can therefore force privileged inventory work and allocation while holding
the process-wide store mutex, even though it ultimately receives `403`.

**What an attacker gets:** a low-privilege valid token can create work proportional to the complete
token inventory and can observe inventory-dependent timing. Repetition contends with authentication
and secret operations.

**Fix:** authorize the control-plane capability before subject lookup, then use the existing indexed
single-token lookup rather than `tokens(None)`. Record the authorization decision first and the
concrete post-lookup outcome separately where necessary.

### F8. Token revocation can leave a false success record and race `revoked_now` - medium, certain

**Where:** `crates/ciphr-server/src/api.rs:1407-1440` and
`crates/ciphr-store/src/tokens.rs:374-390`.

The handler records an allowed revocation with status 200 before mutation, then applies the store
write with `?`. A SQLite failure produces no correcting entry, so the trail can claim a successful
revocation while the token remains usable. Separately, `revoked_now` is derived from inventory state
read before auditing and before mutation. Two concurrent requests can both read `revoked_at = NULL`,
then both report `revoked_now: true`, although only one established the timestamp.

**What an attacker gets:** during disk, lock, or corruption failures, incident responders can be told
by the audit trail that a live credential was revoked. Concurrent responders receive incorrect
causality information.

**Fix:** wrap the mutation in `complete_or_record`. Make the indexed SQL mutation atomically return
whether this call changed `revoked_at`, and derive `revoked_now` from that result. Add store-failure and
concurrent double-revocation tests.

### F9. Honeypot health suppresses store errors and performs anonymous unbounded reads - medium, certain

**Where:** unauthenticated health at `crates/ciphr-server/src/api.rs:466-490`; tripwire state at
`crates/ciphr-server/src/state.rs:620-635`.

With `honeypot_alert`, every unauthenticated health poll takes the process-wide store mutex and
materializes every open trip merely to compute a boolean and count. Any store or lock error becomes an
empty set, and the endpoint still reports `status: "ok"`, `tripped: false`, and zero open tripwires.

**What an attacker gets:** anonymous polling can create store contention. More importantly, a store
failure during an incident suppresses the tripwire state and presents an affirmative untripped/healthy
answer when the server cannot establish either fact.

**Fix:** use a bounded aggregate query or an in-memory aggregate reconciled at startup. Represent
failure as unknown/degraded, not false, and make overall health reflect inability to verify security
state. Apply listener or deployment rate/concurrency controls.

### F10. Backups inherit umask and expose substantially more than ciphertext - medium, certain

**Where:** destination creation is delegated to SQLite at
`crates/ciphr-store/src/sqlite.rs:144-178`; plaintext metadata begins in
`crates/ciphr-store/migrations/001_init.sql:22-55`; the overclaim is at
`docs/threat-model.md:35-41` and `docs/operations/cli.md:471-473`.

`VACUUM INTO` creates the destination without this code establishing an owner-only mode. The result
therefore inherits the caller's umask. A mode such as 0644 can expose the backup to other local users
or processes. Values and wrapped keys remain encrypted, but paths, rotation classes, timestamps,
writer identities, token metadata, and the audit trail are plaintext. Calling the database
"worthless without the master key" materially understates what a reader learns.

**What an attacker gets:** secret inventory and taxonomy, identity and token inventory, write/access
history, and operational timing. Plaintext values remain encrypted.

**Fix:** securely create backups with owner-only permissions independent of umask, or require a
private destination directory and verify the resulting mode. Add a Unix mode test. Correct every
"worthless" or "full ciphertext" claim to name the metadata that remains visible.

### F11. A malformed dotenv line can be copied into an error message - medium, certain

**Where:** `crates/ciphr-cli/src/formats.rs:272-307` and truncation at
`crates/ciphr-cli/src/formats.rs:332-343`.

When a dotenv line has no `=`, the parser includes its first 24 characters verbatim in the error.
Dotenv input is secret-bearing; a pasted token or password on a malformed bare line therefore reaches
stderr. For a short value, the complete value is printed. This contradicts the repository claim that
errors never carry values.

**What an attacker gets:** secret material in terminal transcripts, CI logs, monitoring capture, or
support bundles after an operator makes a common import-format mistake.

**Fix:** report only the line number and structural reason when `=` is absent. For invalid names,
include only the parsed key portion. Add tests asserting that secret-like malformed input is absent
from formatted errors.

### F12. Authenticated malformed requests can bypass request auditing - medium, high confidence

**Where:** handler-local auditing follows path parsing at `crates/ciphr-server/src/api.rs:502-515`;
extractor failures occur before handlers; current tests explicitly expect no entry at
`crates/ciphr-server/tests/api.rs:1513-1539`, while the central coverage test begins at
`crates/ciphr-server/tests/api.rs:1852`.

Auditing lives inside handlers. A request with a valid token can authenticate and then fail path
normalization without an entry. JSON/query extraction failures, unknown routes, and unsupported
methods can be answered before any handler audit call. The test named
`every_endpoint_writes_an_audit_entry` covers selected successful routes, not these pre-handler paths
or all newer optional/control-plane routes.

**What an attacker gets:** malformed traffic using a stolen valid credential, route probing, and
parser-focused attacks can be absent from the tamper-evident trail despite performing authentication
or request-parsing work.

**Fix:** add outer request accounting that records authenticated pre-handler failures, with a
request-local marker preventing duplicate records after a handler writes its authoritative entry.
Add explicit method/fallback handling and malformed-extractor tests. Anonymous malformed traffic
needs separate bounds because putting all of it in the fail-closed trail increases the documented
audit-volume denial-of-service risk.

### F13. Write with classification is a non-atomic compound operation - low, certain

**Where:** `crates/ciphr-server/src/api.rs:610-668`.

A `PUT` carrying `rotation` first commits a new secret version, then independently audits and writes
the classification. If the second audit or store operation fails, the value remains while the request
returns an error. Retrying writes another version. The source documents this behavior, but an HTTP
failure conventionally tells automation that the requested state was not established.

**Impact:** duplicated versions, a temporarily or permanently wrong rotation class, and retry
ambiguity during exactly the store/audit failures where operators need reliable state.

**Fix:** combine value creation and classification in one store transaction after the required audit
records, or introduce an idempotency mechanism and an explicit partial-success response. Add fault
injection between the two operations.

### F14. Unauthenticated health discloses audit-device filesystem paths - low, certain

**Where:** health returns device names at `crates/ciphr-server/src/api.rs:466-488`; names are copied
into state at `crates/ciphr-server/src/state.rs:200-219`; file and SQLite devices include configured
paths in their names.

Anyone able to reach `/v1/health` learns database and audit-file locations. These are not secrets, but
they are unnecessary deployment reconnaissance and conflict with the nearby choice not to expose
device failure paths.

**Fix:** publish stable labels such as `sqlite`, `file-1`, and `file-2`; keep concrete paths in
operator logs and authenticated inspection.

## Hardening observations

The following were considered but are not findings under the repository's current threat model:

- Release assets and registry tags are mutable and artifacts are unsigned. A compromised publisher or
  build pipeline is explicitly outside the application boundary, deployments are told to pin image
  digests, and reproducible builds are explicitly deferred. Removing `gh release upload --clobber`,
  refusing existing version tags, and adding signed provenance would nevertheless materially improve
  supply-chain recovery and artifact authenticity.
- Token failure classes retain known database-work differences. C11 now documents that only response
  equality is claimed and remote timing separability is unmeasured.
- Swap is reported rather than refused. The threat model states that this half is an operational
  requirement, although the heading "explicitly defended against" remains stronger than the enforced
  behavior.
- Denial of service by load and unauthenticated audit growth is explicitly accepted. F5, F7, and F9
  remain findings because they add avoidable amplification, privileged pre-authorization work, or a
  false security-state answer rather than merely reflecting the single-instance availability model.

## Positive conclusions

- No second path normalizer, wildcard authorization bypass, reserved-prefix shadow, or control-plane
  capability bypass was found.
- The AES-256-GCM envelope hierarchy and AAD bind path, version, and key identifiers; no nonce, key
  separation, relocation, or error-oracle regression was found.
- Secret and key wrappers remain non-serializable and non-printable, and key/token comparisons use
  constant-time primitives where claimed.
- Server TLS is mandatory, the SDK trusts only the supplied private CA, follows no redirects, and
  bounds response bodies.
- Every `/v1` response receives `Cache-Control: no-store`.
- The fixed honeypot token latch, bounded per-reference latch scheduling, and service-worker refusal
  remain present.
- `ciphr-run` still performs all refusal checks before fetching, reads no environment configuration,
  uses no shell for values, and preserves its `exec`/exit-code contract.
- The UI uses Vue interpolation, no raw HTML sink, a strict CSP, no clipboard path, no service worker,
  and an unprivileged image.
- GitHub Actions and container base images are commit/digest pinned; Cargo and npm dependency locks
  carry registry checksums/integrity hashes.

## Coverage

Read end to end or substantially:

- Every source file and relevant test under `crates/ciphr-core`, `ciphr-crypto`, `ciphr-policy`,
  `ciphr-store`, `ciphr-audit`, `ciphr-server`, `ciphr-cli`, `ciphr-sdk`, and `ciphr-run`.
- All store migrations and integration tests for backup, restore, audit, token, honeypot, wrapper, SDK,
  and API behavior.
- Workspace and crate manifests, `Cargo.lock`, `deny.toml`, `openapi.yaml`, and feature/surface wiring.
- Every UI source and component, Vite/nginx configuration, package manifests and lockfile, image, and
  UI budget/security gates.
- Root and wrapper Dockerfiles, entrypoint and health-check scripts.
- All GitHub and Forgejo workflows and every script under `ci/`.
- Threat model, ADRs, operational runbooks, changelog, prior reviews, and release/upgrade documentation
  relevant to the checked claims.

Dependencies were reviewed by manifest, lockfile, and use, not by independently auditing their source.
Deployment-specific reverse proxies, network boundaries, filesystem mounts, registry policy, runner
host configuration, and monitoring are outside this repository and were not reviewed directly.

## Verification and limitations

The worktree was clean at the reviewed commit. Independent passes covered core cryptography and data
integrity, server/authentication/control-plane behavior, clients/UI/supply chain, and cross-component
assumptions; candidate findings were then checked directly against current source and tests.

Rust tests could not link on this host because the local MSVC installation cannot find
`msvcrt.lib`/`kernel32.lib` (`LNK1104`). `cargo audit` and `cargo deny` were not available. Linux-only
shell gates, musl wrapper execution, fuzzing, image builds, fault injection, network timing, browser
instrumentation, and deployed-filesystem crash tests were not run here.

The UI dependency installation, production build, and high-severity npm audit completed successfully
during the review. Static workflow checks confirmed that Git accepts the release-ref characters used
in F1's injection argument.

This review can miss defects. It does not prove cryptographic constructions, constant-time behavior,
allocator zeroization, dependency safety, SQLite/filesystem durability, release-host isolation, or
operational controls. Root and runtime-administrator access, complete forward rewriting of an
unanchored audit chain, and the documented single-instance denial-of-service boundary remain outside
the protection claim.

## Fitness statement

The cryptographic core, path/pattern handling, and policy evaluator remain fit for the limited
first-production-use judgement recorded in the earlier review; this pass found no evidence that
reverses it. That remains an AI source-review opinion rather than a human practitioner review.

The repository as a complete release and operating system is **not fit for an expanded production
blast radius until F1, F2, and F3 are fixed**. F4 must either be fixed or explicitly accepted as a
trust-boundary rule that every writer of a wrapper-fetched path is equivalent to the consuming
service. The medium findings should be addressed before relying on bulk export, multi-device audit
recovery, remote revocation, or honeypot health during an incident.
