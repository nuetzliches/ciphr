# Security review of the current tree on 2026-08-21

**Reviewed:** commit `b974916d54c800783c34298e6cf50b538aa5da8d` on `main`, with a clean
worktree, on 2026-08-21.

**Reviewer:** OpenCode, an AI model, commissioned by the maintainer. This is a source review, not a
human review, formal verification, penetration test, or audit of a deployed environment. It does not
supersede the fitness statement in [`review-2026-08-21.md`](review-2026-08-21.md). It reviews the
current tree, including the newer `honeypot_alert` authentication surface that the earlier review
explicitly excluded.

## Executive assessment

No cryptographic break, authorization bypass, plaintext HTTP mode, or audit-before-release bypass was
found. The path and pattern implementation, envelope hierarchy, policy evaluator, ordinary
authentication path, and fail-closed audit ordering remain sound in the reviewed source.

The current tree is **not ready to release the `honeypot_alert` entry as documented** until F1 is
fixed: presenting token bait creates the authoritative audit entry but never opens the latch that
`/v1/health` exposes to monitoring. F2 should be fixed before relying on `actions-env` across writers
with different privileges, because a stored value can inject additional GitHub Actions environment
file commands. F3 and F4 are transport and browser-origin hardening defects around plaintext values.

Severity describes impact when the affected surface is used, not reachability in every deployment.
Confidence describes confidence in the source-level conclusion.

## Findings

### F1. Honeypot tokens do not open the monitoring latch - high, certain

**Where:** `crates/ciphr-server/src/state.rs:734-765`; compare the secret-bait latch at
`crates/ciphr-server/src/state.rs:426-439`. The incomplete test stops at the audit entry in
`crates/ciphr-server/tests/api.rs:883-919`.

When authentication recognizes a honeypot token, `record_rejection` writes the
`honeypot-triggered` audit entry and returns. It never calls `latch_off_the_request_path` with
`BaitKind::Token`. Secret bait does call that function after its audit entry is durable.

**What an attacker gets:** presenting a stolen honeypot token is recorded in the trail, but
`/v1/health` continues to report `tripped: false` and `open_tripwires: 0`; `/v1/honeypots` continues
to report that token as untripped. A deployment following `docs/operations/honeypots.md` and paging
on health therefore misses the event. This breaks the last, operationally essential step of the
tripwire mechanism.

**Fix:** after the token trip entry is accepted, schedule the same off-request-path latch with token
kind, token identifier, and identity. Add an all-features test that presents token bait and verifies
the trail, `/v1/health`, and `/v1/honeypots` after the blocking task drains.

### F2. Predictable Actions heredocs permit environment-file injection - high, certain

**Where:** `crates/ciphr-cli/src/formats.rs:111-145`, especially the delimiter at lines 131-139.

For a multiline value, `render_actions_env` uses the deterministic delimiter
`ciphr_<NAME>_EOF`. A value containing that exact string on its own line ends its assignment. The
remaining lines are interpreted by the GitHub Actions runner as additional environment-file
commands. Including the variable name only prevents accidental collision with the word `EOF`; it
does not prevent a writer from choosing the complete delimiter.

**What an attacker gets:** an identity allowed to write one exported secret can define additional
environment variables in later workflow steps. Depending on those steps, this can alter tool
configuration, loader behavior, credentials, or command execution. The normal `::add-mask::` output
does not make the structured file safe.

**Fix:** generate a delimiter from OS randomness and reject or regenerate if it occurs as a complete
line in any value. Add a regression test containing the old complete delimiter followed by a second
assignment. Treat every value written to a runner command file as untrusted structured input.

### F3. Secret-bearing API responses lack an explicit no-store policy - medium, certain

**Where:** secret and export responses at `crates/ciphr-server/src/api.rs:433-439` and
`crates/ciphr-server/src/api.rs:736-750`; the router contains no response-header layer. The viewer's
request-side mitigation is `ui/src/api.ts:58-66`.

The server does not emit `Cache-Control: no-store` for plaintext secret reads or exports. The viewer
asks Fetch not to cache its own request, but SDK, CLI, browser private caches, reverse proxies, and
other clients remain dependent on defaults. Caches normally handle authenticated responses
conservatively, but a secret service should not rely on that convention.

**What an attacker gets:** a misconfigured or permissive cache can retain plaintext after the token
or process lifetime and expose it through local cache storage or an intermediary.

**Fix:** apply `Cache-Control: no-store, private` to all `/v1` responses, including errors, and add
`Pragma: no-cache` where legacy intermediaries matter. Test secret reads, exports, metadata, and
errors.

### F4. A previously installed service worker remains able to intercept the viewer - medium, certain

**Where:** `ui/src/main.ts:14-23`; static refusals at `ui/nginx.conf:68-76`.

The viewer starts unregistering existing service workers asynchronously and mounts immediately.
Unregistering a worker does not remove its control from an already controlled document; control can
last until controlled pages close or reload. The nginx configuration refuses only two conventional
script names, while service workers may be registered from other same-origin URLs subject to scope.

**What an attacker gets:** a worker left by an earlier application on the viewer's origin can
intercept `/v1` requests, read bearer tokens and plaintext responses, modify results, and retain
values. This matters after an origin is repurposed even if the current image never ships a worker.

**Fix:** fail closed when `navigator.serviceWorker.controller` is present. Await registration cleanup
before mounting, then require a clean reload. Prefer a dedicated origin that has never hosted a
service-worker application. Do not claim that refusing two filenames makes arbitrary registration
impossible.

### F5. Repeated bait requests create unbounded blocking latch work - medium, high confidence

**Where:** `crates/ciphr-server/src/state.rs:448-505` and
`crates/ciphr-store/src/honeypots.rs:285-335`.

Every allowed read of secret bait schedules a new `spawn_blocking` task, including reads after that
bait is already latched. Tasks serialize on the process-wide store mutex, attempt an insert, and on a
uniqueness conflict query whether the trip is already open. The database latch prevents duplicate
rows, but it does not bound queued work.

**What an attacker gets:** an authenticated caller that can repeatedly read known bait can enqueue
blocking work and contend with authentication, reads, health checks, and administrative queries. Once
token latching is added for F1, anyone holding token bait could drive the same queue without
authenticating.

**Fix:** use a bounded worker queue and deduplicate pending/open references before scheduling. Keep
the database uniqueness constraint as the authoritative concurrency guard.

### F6. Audit archive names can collide within one millisecond - medium, high confidence

**Where:** `crates/ciphr-audit/src/file.rs:74-87` and rotation at lines 105-110.

A rotated filename contains only `record.ts_millis`. Two rotations with the same timestamp target the
same path. Replacement behavior can overwrite an earlier archive on some platforms; refusal behavior
can disable the file device on others. Repeated timestamps can arise from a small rotation threshold,
high throughput, or a clock adjustment.

**What an attacker gets:** loss of an independent audit archive, or a permanent gap in that device
while another device continues to accept records. Triggerability depends on deployment thresholds and
request throughput.

**Fix:** include the closing sequence number in the archive name or create archives exclusively with
a collision-resistant suffix. Never replace an existing archive. Test multiple forced rotations at
the same timestamp.

### F7. The SDK permits redirects after validating only the initial HTTPS URL - medium, high confidence

**Where:** `crates/ciphr-sdk/src/client.rs:528-555` and the absence of redirect restrictions in the
agent configuration.

The builder rejects an initial non-HTTPS base URL and installs only the deployment CA, but does not
set HTTPS-only redirect handling or disable redirects. `ureq` strips authorization across relevant
redirect boundaries, which protects the bearer token, but accepting a redirected plaintext response
still weakens the stated transport guarantee and can supply attacker-controlled secret data to the
consumer.

**What an attacker gets:** a trusted but compromised endpoint or proxy can redirect a read to HTTP and
substitute the value consumed by the application. This is an integrity failure; default redirect
credential stripping limits token disclosure.

**Fix:** configure the agent with HTTPS-only redirects and preferably zero redirects. The API has no
redirect contract, so treat any redirect as a transport/configuration failure. Add HTTPS-to-HTTP and
same-origin redirect tests.

### F8. Honeypot administrative reads can leave a false successful audit entry - medium, certain

**Where:** `crates/ciphr-server/src/api.rs:936-952`; compare `complete_or_record` on the audit route at
`crates/ciphr-server/src/api.rs:1031-1064`.

`GET /v1/honeypots` records an allowed read with status 200 before two fallible store queries, but it
does not write a correcting entry when either query fails.

**What an attacker gets:** no direct privilege escalation. During a store failure, the forensic trail
can claim that bait inventory was returned when the client received an error. This violates the
project's stated audit semantics and can mislead incident reconstruction.

**Fix:** run both queries through `complete_or_record` and test a post-authorization store failure.

### F9. Core-dump prevention fails open in the container - low, certain

**Where:** `docker-entrypoint.sh:9-19`.

If `ulimit -c 0` fails, the entrypoint logs a warning and continues, although the adjacent comment and
threat model describe core-dump prevention as a defense for master keys, root keys, tokens, and
plaintext values.

**What an attacker gets:** where the runtime permits dumps and the limit operation fails, a crash can
leave those values in a core image. Access to that image still requires local or operational access.

**Fix:** refuse startup if the limit cannot be set, unless an equivalent runtime prohibition is
positively verified.

### F10. Credential checks use a check-then-open sequence - low, high confidence

**Where:** token loading at `crates/ciphr-run/src/main.rs:188-218`, master-key loading at
`crates/ciphr-crypto/src/seal.rs:195-220`, and the shared mode rule at
`crates/ciphr-core/src/file_mode.rs:47-61`.

The path is inspected with metadata and then opened again to read it. A party able to replace entries
in the parent directory can exchange the checked file before the open. Group-writable files are
accepted deliberately; that is not itself a defect, but it makes parent and ownership assumptions
important.

**What an attacker gets:** under a writable-directory or replaceable-symlink condition, substitution
of the token or master key between validation and use. This is a local deployment-boundary attack,
not a remote API attack.

**Fix:** on Unix, open once without following symlinks, require a regular file, inspect metadata from
that descriptor, and read from the same descriptor. Document the owner and parent-directory trust
requirement.

## Review of the new honeypot claims

### C11: wire shape holds; timing indistinguishability does not

Status, stable body fields, and headers are tested as equal. The broader wording in
[`security-review.md`](security-review.md) is false if it claims equal observable work:

- malformed tokens return before database and verifier work at `crates/ciphr-store/src/tokens.rs:189-191`;
- known identifiers perform a second verifier query that unknown identifiers skip at
  `crates/ciphr-store/src/tokens.rs:193-210`;
- recognized bait writes a larger, differently shaped durable audit payload at
  `crates/ciphr-server/src/state.rs:740-759`.

Practical remote separation was not benchmarked, and the 48-bit random identifier limits useful
enumeration. The claim should be narrowed to wire-response indistinguishability unless the complete
path is equalized and measured.

### C12: the synchronous request-path claim holds narrowly

Secret bait replaces the ordinary audit action and the request does not await the latch. That narrow
claim holds. The broader wording should acknowledge that bait schedules an extra store write and can
create observable contention. F5 shows that this off-path work is currently unbounded. Token bait
does not perform the derived write at all, which is F1 rather than evidence for the intended claim.

### D10: holds in its authorization sense

No bait branch exists in `ciphr-policy`. Bait is looked up only after an allowed policy decision and
only for `Capability::Read` at `crates/ciphr-server/src/state.rs:369-391`. Denied reads, listings, and
version history do not trip. No authorization bypass was found.

There is a semantic edge to decide explicitly: the trip is recorded before retrieval and decryption,
so an allowed read of deleted, missing, corrupt, or undecryptable bait can latch even though no value
is served (`crates/ciphr-server/src/state.rs:426-439` before
`crates/ciphr-server/src/api.rs:389-431`). If "taking bait" means receiving its value, that ordering
is a false positive and needs a store operation that establishes readability before the trip entry
without releasing the value before audit.

## Positive conclusions

- Path normalization remains centralized in `ciphr-core`; no competing HTTP normalizer was found.
- Pattern matching is bounded and non-backtracking, and policy decisions remain deny-by-default with
  deny-on-tie semantics.
- The envelope hierarchy, AAD binding, OS randomness, constant-time token-verifier comparison, and
  secret-bearing type restrictions remain intact in the current source.
- Reserved `sys/` paths are enforced in storage as well as at HTTP and CLI boundaries.
- No route was found that serves a value or mutates state before its authoritative audit entry is
  accepted.
- TLS is mandatory on the server, and the SDK trust store contains only the configured private CA.
- The viewer uses Vue interpolation, a strict CSP, no `v-html` or `innerHTML`, no clipboard path, and
  no service worker of its own.
- `ciphr-run` preserves refusal ordering, reads no configuration from the environment, passes values
  without a shell, and uses `exec` with the documented exit-code contract.

## Coverage

Read end to end or substantially:

- `ciphr-core`: path, pattern, secret, base64url, environment-name, file-mode, capability, rotation,
  and version code and tests.
- `ciphr-crypto`: envelope, keys, tokens, seal, errors, and envelope property tests.
- `ciphr-policy`: model, evaluation, errors, and decision table.
- `ciphr-store`: SQLite secret operations, token authentication, honeypots, audit storage, locking,
  migrations, and relevant tests.
- `ciphr-audit`: chain, devices, file rotation, archive, verification, anchor, and entry encoding.
- `ciphr-server`: routing, authentication, authorization/audit wiring, optional surfaces, TLS,
  configuration, server startup, errors, and API tests.
- `ciphr-cli`, `ciphr-sdk`, and `ciphr-run`: secret input/output formats, TLS client construction,
  token loading, wrapper ordering, environment injection, and execution.
- `ui/`: API client, session handling, components, CSP/nginx configuration, package manifests, and
  image.
- Root images and entrypoint, GitHub and Forgejo workflows, CI gates, Cargo manifests and lockfile,
  OpenAPI, threat model, ADRs, and operational documentation relevant to these claims.

Dependencies were reviewed by manifest and use, not by reading their source. Runtime infrastructure,
reverse-proxy policy, registry controls, runner configuration, and deployment-specific permissions
are outside this repository and were not reviewed.

## Verification and limitations

The review was performed against a clean worktree. Source-level checks were split across independent
passes for the core cryptography/authorization/store, server/authentication/honeypot surface, and
clients/UI/supply chain, followed by direct confirmation of the reported code paths.

Rust tests could not be executed in this environment because the local MSVC linker could not find
the Windows runtime libraries (`LNK1104`, including `msvcrt.lib` or `kernel32.lib`). The UI dependency
tree was not installed, so its build and audit were not run. `cargo deny`, `cargo audit`, Linux shell
gates, the musl wrapper build, fuzzers, browser instrumentation, network timing measurements, and
container runtime tests were not run.

This is a static review and can miss defects. In particular, it does not prove constant-time
behavior, allocator zeroization, dependency safety, SQLite durability on a particular filesystem,
TLS behavior under a live proxy, or operational monitoring. Root and runtime-administrator access,
denial of service through audit-volume exhaustion, and forward rewriting of an unanchored audit chain
remain documented boundaries.

## Fitness statement

The reviewed cryptographic core, path/pattern handling, and policy evaluator remain fit for the
limited first-production-use judgement recorded in the earlier review; this pass found no evidence
that reverses that judgement. That statement remains an AI source-review opinion and not a human
practitioner review.

The optional `honeypot_alert` surface is **not fit for release under its current operational claims**
until F1 is fixed and C11/C12 are narrowed or their timing and work-equality requirements are met.
The Actions export format should not be used where secret writers are less trusted than the workflow
until F2 is fixed.
