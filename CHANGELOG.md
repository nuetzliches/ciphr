# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is something to version.

This file is updated in the same commit as the change it describes.

## [Unreleased]

### Added — `ciphr audit cut` bounds the queryable trail

The `audit_log` table grew for as long as a store existed, and because auditing is fail-closed a full
volume stops the service serving secrets. This is the bound. It is one operation rather than three,
because doing any part of it alone is the mistake — a `DELETE` against that table makes everything
after it unverifiable and reports as tampering afterwards, indistinguishable from a cover-up
including for the person who ran it.

```sh
ciphr audit cut --keep 50000 --anchor /path/to/anchors.jsonl --archive /path/to/audit.jsonl
```

- **`--keep`** is how many of the newest entries stay queryable. A count, not an age: the bound it
  answers is the size of the table, and age-based retention belongs on the archive where the host's
  log tooling already does it. A trail shorter than the bound is reported and exits zero — a
  scheduled cut that failed on a young trail is one somebody switches off.
- **`--archive` is required**, and it is checked rather than trusted. Every record the cut would
  remove has to be in the file device's file or one of its rotated siblings, matched by the hash of
  the line, which for this format means byte-identical. A record that is not there is not removed.
  `--assume-archived` replaces the check with an assumption — for lines shipped off the host as they
  are written, or rotated files compressed beyond what this can read — and says so on every run.
- **`--anchor` is required**, and two lines go into it: the anchor at the cut, synced to disk *before*
  the records go, and an anchor over what survived, appended after. The first is what the remainder is
  verified from. The order is the failure mode: a crash between them leaves an anchor over a record
  still present, which verifies, rather than a cut nothing outside the store can attest to.
- **`--dry-run`** verifies, checks the archive, prints what would go, and changes nothing.
- Like `anchor` and `verify`, it needs **neither the store lock nor the master key**, so it runs
  against a live service. Retention that needs downtime does not get scheduled, and a bound nothing
  runs is not a bound. It writes no audit entry of its own for the same reason `anchor` does not:
  that would need the lock the running service holds, and it would move the head just anchored.
- **Why a command and not a schedule inside the service:** a cut has to be anchored outside the
  store, and the service is the thing an anchor exists to be independent of.

### Changed — `audit verify` and `audit anchor` know a trail can begin after a cut

- `verify` prints where the trail begins and what the cut removed, and **exits zero on a cut store**.
  A legitimately cut trail that reported tampering would be a check nobody runs.
- What it cannot establish alone is stated in the output: the recorded cut is a row in the store,
  written by whatever can write the store. `verify --anchor` compares that row against the anchor the
  cut wrote outside and says which of the two answers it got.
- `audit anchor` works on a cut trail. It would have failed on one — the records no longer start at
  sequence 1, and an anchor over them has to know where they do start.
- `/v1/audit` says the same thing in `openapi.yaml`: the trail does not necessarily begin at sequence
  1, and a client verifying from genesis fails on a cut store, correctly.

### Added — schema 4 records where the audit log was cut

Nothing cuts it yet; this is the half of retention that has to exist before anything may.

- **`audit_cut`**, append-only: when a cut ran, the last sequence number it removed, that record's
  hash, how many records went, and where the anchor was appended. The hash is what verification of
  everything after the cut starts from — the first surviving record chains to a record that is no
  longer in the table, so without it the remainder cannot be checked at all.
- **The row is a claim, not evidence**, and the migration says so where a reader will meet it.
  Whoever can write the database can write that row, which is exactly what a deletion dressed up as
  retention looks like. The anchor outside the store is the copy that makes it more than a claim, and
  `ciphr audit verify --anchor` compares the two. What the row buys is the other half: without it,
  the routine check on a legitimately cut store reports tampering, and a trail that cries wolf is one
  nobody reads.
- **Opening a store whose log contradicts its cut record fails.** A log that ends at or before a
  recorded cut means records that survived the cut were removed afterwards without one; an empty log
  behind a recorded cut is a state cutting cannot produce, because a cut never empties the table.
  Both refuse rather than resume — resuming would silently start a second chain in a table that
  already had a history, or make the removal invisible. This is the same fail-closed choice the audit
  sink makes, applied at startup.
- A cut is one transaction: the records go and the record of them going lands, or neither happens.

### Added — the viewer can be published where a private deployment can pull it

- `.forgejo/workflows/build-ui-image.yml` builds the viewer image on a `ui-v*` tag and pushes it to
  the internal registry, exactly as `build-images.yml` does for the service and for the same reason: a
  private repository means a private GHCR package, and the deployment host authenticates to one
  registry that is not GHCR. Both files go away when the repository is public and the GitHub workflows
  become the single publishers again.
- The image path is nested — `<registry>/<owner>/ciphr/ui`, matching what GHCR derives from the
  repository name. A flat `ciphr-ui` reads like a second repository beside `ciphr`, and the viewer is
  not one: it is a directory in this repository with its own tag namespace and its own release
  decision (ADR-11). One artifact should not have two names.
- **`ui-v0.1.1` is the tag that carries that name**, and `ui-v0.1.0` was left where it is. The
  internal workflow builds from the tag it was triggered by, so the old tag would still publish the
  old path — and moving a tag to fix that is the thing this repository argues against everywhere else,
  including in the comment that pins base images by digest. A version number is cheaper than a
  reference that can move. The bundle is unchanged between the two; only the packaging is.
- The build context is `ui/` alone. This image is static files and a web server, and it has no reason
  to be able to see the crates.
- It refuses a tag that is not `ui-v*`, because the two tag namespaces are the mechanism that keeps
  the release cadences apart (ADR-11) and a manual run naming the wrong one would quietly undo that.

### Fixed — the strict policy broke the viewer's own dev server

- The Content-Security-Policy sat in `ui/index.html`, so `npm run dev` served it too — and the dev
  server does not serve the built artifact. It assembles the page in the browser, where Vite's HMR
  client applies styles by creating elements at runtime, which `style-src 'self'` refuses. The page
  arrived unstyled with `Applying inline style violates … 'style-src 'self''` on the console.
- The policy is now defined once in `vite.config.ts` and injected into the **built** document by a
  build-only plugin. Production and `vite preview` keep it; the dev server runs without it. That is
  the honest split rather than the tempting one: with the policy in the source document, the fix a
  developer reaches for is `unsafe-inline` — in production, where it matters.
- **This was shipped in `fa5ca00` and the verification did not catch it**, because that verification
  drove the built bundle behind the container's headers. It never loaded the dev server, which is the
  one way most people will meet this package first. Both paths are now checked in a browser.
- CI checks the built document for the policy: the directives have to be there, an `unsafe-` keyword
  fails the job, and so does a missing policy — which is what removing the plugin would look like.
  Proven by removing it and watching the check fail.

### Added — two features planned: honeypots (phase 8) and leak reports (phase 9)

Nothing is implemented. Plan sections 22 and 23 hold the designs, ADR-15 and ADR-16 hold the
decisions, and both records are **Proposed**. The three reserved paths in `openapi.yaml` return `404`
and say so.

- **Honeypots and tripwires (ADR-15, plan section 22).** Bait in two shapes — a token in the
  documented format that authenticates nothing, and a secret path no legitimate consumer reads — with
  a per-honeypot trigger tier of `alert`, `disable-identity`, or `freeze`, defaulting to the mildest.
  Four properties are the decision rather than the implementation: bait is indistinguishable from the
  real thing in both response and timing; the trigger fires *after* the policy allowed the read, so
  there is no honeypot branch in the evaluator and no new capability; each tier is named together with
  what a false positive costs; and `freeze` is recorded in the store, closes only the value-serving
  routes, keeps `/v1/health` and the audit trail open, and is cleared on the host alone.
- **Alerting deliberately means no outbound connection.** No SMTP client, no webhook, no notifier in
  the process that holds the master key. A tripwire is a field on `/v1/health`, an audit entry, and a
  marker file; the monitoring section 17 already requires is what turns it into a page. Same reasoning
  that keeps the v1 audit devices to `sqlite` and `file`.
- **Leak reports (ADR-16, plan section 23).** One unauthenticated endpoint, `POST /v1/report`, that
  accepts a candidate secret value and marks the version it matches as leaked. **It never says whether
  the value matched** — `202` with an empty body for a match and a miss alike, `429` at a limit. An
  endpoint that confirms a guess is a guessing machine for any value with little entropy, and section
  10 already draws the line it would cross: an unauthenticated endpoint may report what the process
  enforces and never what is stored.
- **Matching goes through a blind index**, `HMAC-SHA256` under a key derived from the root key by the
  pattern `TokenPepper::derive` already uses, so a report is one indexed lookup instead of a
  full-corpus decryption. What it adds to the database is stated rather than assumed away: a reader of
  the file learns which secrets hold *the same* value, and anyone who could attack the index offline
  can already decrypt every value directly. Rejected: a truncated index or a Bloom filter, because a
  false leak mark on a `breaks-data` secret invites the rotation that destroys data.
- **The leaked mark influences no authorization decision**, and here that is the security property
  rather than tidiness. It can be set by an anonymous request; if it refused reads, anyone who has
  ever seen a value could switch that secret off for everybody from outside. It sits on the version,
  so rotation ages it out — and there is deliberately no command that clears it.
- **The limits run before the audit write and before the store lock.** This is the first request path
  in the design that reaches the store without an identity, and the service is fail-closed on the
  audit trail: an anonymous request that writes an audit entry spends a resource whose exhaustion is a
  total outage. Refusals cost a counter and are summarized once per window, not once each; a
  concurrency cap keeps anonymous traffic off the mutex authorized reads queue on; and the endpoint is
  off unless a deployment enables it.
- **No unauthenticated request reaches a tier above `alert`.** A reported honeypot value is the
  strongest signal the system can produce and it still only alerts, because otherwise the report
  endpoint would be a remote off switch operated by whoever holds a leaked value. This is why the two
  features were designed together and are scheduled in this order.
- **Threat model:** adversary **A9**, the anonymous reporter, with the row marked as describing
  nothing that exists yet. **Scheduling:** phase 8 then phase 9, and neither before the external
  review — one adds behaviour to the authentication path, the other a key derivation in `ciphr-crypto`
  and the only anonymous path to the store. `docs/security-review.md` records what each would add to
  the review's scope if it lands first anyway.
- **Two open questions, added to plan section 21:** whether the value index is written unconditionally
  (recommended, because a half-indexed corpus makes a miss meaningless and the endpoint is designed
  not to admit it), and whether `POST /v1/report` needs its own listener — which is the same
  network-exposure decision as question 2 and has to be answered with it.

### Fixed — the documented server configuration could not be loaded

- The example in `crates/ciphr-server/src/config.rs` put `policies` after the `[seal]` table. In TOML
  a bare key written after a table header belongs to that table, so it parsed as `seal.policies`,
  which `deny_unknown_fields` correctly refused. Anyone configuring a server by following the
  documentation got a parse error naming a key they had put at the top level.
- The fixture in the tests had it right the whole time, which is exactly why nothing failed: the test
  named `loads_the_documented_example` was loading a *copy* of the example, and the copy stayed
  correct while the original drifted. That test now covers the fields under its real name, and a new
  one reads the TOML block out of the module documentation and loads it — an example that cannot work
  now fails the build.
- Plan section 12 had the same example without `policies` at all, and that field is required. Both
  now show it first, with the reason its position matters.

### Added — the viewer, phase 5

- **`ui/` is a read-only browser view of a deployment**: the audit trail with server-side filters,
  secret metadata with a per-value reveal, identities, policies, and health. Vue 3.5.41 and one
  runtime dependency, built with Vite, served by its own container (`ui/Dockerfile`,
  nginx-unprivileged) and released on its own tag namespace (`ui-v*`,
  `.github/workflows/release-ui.yml`). ADR-11's third argument, made concrete: an npm advisory must
  not force a new server image and therefore not a restart of the service whose restart demands the
  most care. Documented in `docs/ui.md`.
- **It cannot write anything.** No secret, no policy, no identity, no token. That keeps the reach of
  an XSS finding at "read what the signed-in human is allowed to read anyway", and it is why no
  policy-write API had to exist for the viewer to be useful (ADR-3).
- **Sign-in is a pasted token** for an identity of kind `human`, held in `sessionStorage` and gone
  when the tab closes (ADR-12). No cookie, so the CSRF class does not exist rather than being
  mitigated. The shape is checked before any request, so a truncated paste fails locally instead of
  producing an audit entry for an authentication that never had a chance; the header shows the
  token's non-secret identifier, the same one the trail records.
- **The security requirements of plan section 15 are structural where they can be.** Views are
  switched with `v-if`, so leaving one destroys its component and revealed plaintext with it. There
  is one reveal at a time and no bulk form, even though `/v1/export` exists. There is deliberately no
  copy button: the clipboard is a place a value survives the tab, the session, and the reader's
  attention, with no expiry.
- **A strict Content-Security-Policy**, sent by the container and repeated in the document so a
  bundle served by something else keeps it: `default-src 'none'`, `script-src 'self'`,
  `connect-src 'self'`, no `unsafe-inline`, no `unsafe-eval`. The build emits no inline script and no
  inline style, and CI fails if one appears. `frame-ancestors` is in the header only, because
  browsers ignore it in a meta element and log an error saying so — a page that complains about its
  own policy teaches whoever reads that console to ignore it.
- **No service worker**, and `main.ts` unregisters any it finds from an earlier deployment on the
  same origin; the container refuses to serve one. A cached response to a secret read is a secret
  without an expiry date.
- **`ci/check-ui-budget.sh`** is the viewer's own dependency budget, separate from the Rust one as
  plan section 15 requires: exactly one runtime dependency, a ceiling on the whole tree, no package
  with an install script, and every package resolved from the public registry with an integrity hash.
  CI installs with `npm ci --ignore-scripts` and runs `npm audit --audit-level=high`.
- **The chain badge says what it proves.** A page of records is checked for linkage — consecutive
  sequence numbers, each record naming its predecessor's hash — and the viewer does not recompute
  hashes: doing that in a browser means re-serializing parsed JSON and hoping the encoder agrees byte
  for byte with the server's, which is a second implementation of the hashed form and the same class
  of mistake as a second path normalizer. With a narrowing filter applied the check is skipped and
  says so, because a filtered page is a selection rather than a run. The full check is
  `ciphr audit verify`, and the one that survives a forward rewrite is `--anchor`.
- Verified in a real browser under the deployment's own policy — same origin, `/v1` proxied to a live
  service over HTTPS with a verified certificate — not only type-checked: every view renders, the
  reveal works and does not survive navigation, sign-out clears storage, no service worker is
  registered, and the console is free of errors and failed requests.

### Fixed — `/v1/audit` returns the bytes it says it returns

- The endpoint promised each record as "the exact JSON that was hashed, so a client can verify the
  chain itself". It held a `serde_json::Value`, which is a **sorted** map: the record came back with
  its fields in alphabetical order rather than the order they were written and hashed in, so any
  client that recomputed the hash got a mismatch on an untouched chain. The response now carries the
  stored text verbatim (`RawValue`, hence the `raw_value` feature on `serde_json`).
- Found by building a client against the documentation, and the reason it survived until now is in
  the old test: it read a **parsed** body, where field order is invisible. The new test
  (`the_audit_endpoint_returns_the_exact_bytes_that_were_hashed`) reads the raw response, asserts the
  stored record appears in it verbatim, and checks the reported hash against `hash_payload` of those
  bytes. It fails on the old code and passes on the new — checked, not assumed.

### Added — `ciphr audit anchor`, the head of the chain kept outside the store

- **`ciphr audit anchor [--out FILE]`** writes one JSON line — format version, timestamp, sequence
  number, hash — to standard output and appends it to `--out`. It is the half of the retention design
  in plan section 7 that closes a gap the chain cannot close itself: a hash chain detects an entry
  removed, edited, or reordered, but not a forward rewrite by someone who can write the store, because
  they recompute every hash from the point they changed and the result verifies from genesis. Evidence
  kept in the same place as the thing it is evidence about is not evidence.
- **`ciphr audit verify --anchor FILE`** checks the chain against the newest anchor in that file.
  Two shapes are accepted, and they are the two that occur: the whole chain, where the record at the
  anchored sequence must hash to the anchored hash; and a run that begins immediately after the
  anchored sequence, which is what a cut leaves behind — there the anchor is the predecessor the first
  surviving record must chain to. Anything else is refused as `AnchorUnreachable` rather than passed:
  an anchor that cannot be attached to the records in hand proves nothing about them.
- **Both commands read without the store lock and without the master key**, which is what makes them
  usable at all: verification hashes stored records, so it needs no key, and a reader is not the
  second writer the lock exists to prevent. `SqliteStore::open_read_only` is new for this, and it does
  not migrate — a reader that silently upgraded a schema would be a writer. Requiring the lock would
  have meant the trail could only be checked with the service stopped, which is the opposite of when
  a check is wanted. There is a test that holds the lock and asserts both commands still work.
- **Anchoring records no audit entry of its own.** Two reasons, and either would be enough: an entry
  would move the head the anchor just wrote down, and writing one needs the lock the running server
  holds.
- **An existing anchor is verified before a new one is appended**, and nothing is appended if it does
  not hold. An anchor written over a contradiction would give a rewrite a fresh alibi and leave the
  file looking healthy. A mismatch names both of its possible causes — the chain was rewritten, or the
  anchor file belongs to a different store — because from inside the store they are indistinguishable,
  and both are worth stopping for.
- **What an anchor covers is the chain up to its sequence number.** Everything after it rests on the
  chain alone until the next anchor, which is the argument for a schedule rather than for reaching for
  this after an incident. And the file has to live somewhere the store's writer cannot reach; next to
  the database it is decoration. `docs/operations/audit-trail.md` and `docs/operations/cli.md` say so
  where the commands are documented.
- Not built, and named as such in plan section 7: the cut itself. Nothing bounds the queryable device
  and nothing archives what a bound would remove, so `audit_log` still grows without bound.

### Changed — the review requirement says what it binds, and its scope is three crates

- **Four places said the external review is "a precondition for holding real secrets".** The project
  cannot enforce that — nothing in the software refuses to serve a value because a review is
  outstanding — so stated that way the sentence describes a gate that does not exist, and the first
  deployment to proceed without the review turns it into a false claim rather than an accepted risk.
  `README.md`, `AGENTS.md`, `docs/crypto.md` and the risk table in `docs/README.md` now say the review
  **has not happened**, that the crates deciding every access are verified by nobody but their author
  until it does, and that proceeding anyway is an accepted risk rather than a met condition.
- **`docs/security-review.md` states who the condition binds:** this project. An operator's decision
  to run without the review belongs in that deployment's documentation — dated, with what it covers
  and what reverses it — and does not reach back into this repository. The status line there changes
  when a review happens and for no other reason; neither the pre-review pass nor uneventful time in
  production moves it.
- **The mandatory scope is three crates, not two** (plan section 18, `AGENTS.md`, `docs/crypto.md`).
  `docs/security-review.md` has said so since it was written: path normalization and the glob matcher
  live in `ciphr-core`, and normalization is the one function ADR-9 names as the place where routing
  and authorization can silently disagree. The plan and the summaries quoting it still named
  `ciphr-crypto` and `ciphr-policy` alone, so a review scoped from the plan would have missed the
  ADR-9 surface entirely.
- Plan section 18 also records what operational experience is worth here: it finds defects a review
  would not — the audit-chain fix above is one — and still does not discharge the requirement, because
  it exercises the paths a deployment happens to take rather than the ones an attacker chooses.

### Changed — two limits the first migration exposed are written down

- **`docs/operations/audit-trail.md` no longer says retention is undecided.** The shape is settled
  and recorded in section 7 of the plan — queryable device bounded, file device unbounded and
  archived, and the head hash plus its sequence number written outside the store at every cut, so
  verification starts from that anchor instead of from genesis. **None of that mechanism exists.**
  The document now describes what the software does: nothing deletes, and `audit_log` grows for as
  long as the store does. Two consequences are named with it — a hand-rolled `DELETE` produces the
  same `SequenceGap` as tampering, so afterwards nothing distinguishes a retention run from a
  cover-up; and while auditing is fail-closed, the size of the audit volume is the only bound on the
  trail.
- **The plan gained "The consumer on another host" (section 13).** All three consumption routes
  assume the consumer runs where the service is reachable, and a deployment that terminates TLS at
  the service and publishes no port beyond its own host has no route for one that does not. The
  consequence is about retirement rather than convenience: a value with several consumers stops being
  duplicated only once *every* one of them can fetch it, so one consumer out of reach keeps the old
  copy authoritative — and a path prefix for shared values buys ordering, not retirement, while that
  is true. What this bounds is phase 7 rather than phase 6: a deploy that renders configuration from
  one reachable runner and copies it onward can still retire a forge secret for a host that never
  reaches the service, while runtime fetching cannot be delegated that way.
- **Three entries left the plan's open-questions list with their answers** (section 21): the source
  of the TLS certificate for ADR-8, the UI origin, and `::add-mask::` on a Forgejo runner. The first
  keeps the two consequences that belong to this repository rather than to a deployment — a leaf is
  replaceable without touching a client because the pin is the CA, and the leaf must carry the
  loopback name in its SAN because ADR-8 forbids `--insecure` and the health check speaks TLS to
  itself. The third stays half-answered on purpose: **act_runner is still unproven**, and "both are
  act derivatives" is the assumption that list refused to make about the Forgejo runner.

### Added — the changelog rule is enforced rather than trusted

- `ci/check-changelog.sh` fails a commit that changes `crates/` without changing this file, and it
  is a blocking job in `ci.yml`. The rule is not new — the header of this file has always said the
  changelog is updated in the same commit as the change it describes. What is new is that something
  checks it.
- **It was added because the rule broke.** `0f711ce` changed behaviour an operator has to know about
  and recorded it nowhere but its own commit body, and nothing noticed. Every other documentation
  discipline in this repository is a script; this was the one left to habit, and habit is what
  eroded. That is an argument the project already makes about source rules, applied to itself.
- The trigger is `crates/` and nothing else. Deployment files, CI, and documentation are outside it
  on purpose: a changelog that records every comment fix is one nobody reads, and a gate that fires
  on noise gets worked around rather than obeyed.
- A change with genuinely no observable effect opts out per commit with a `Changelog-Exempt:`
  trailer that states a reason. The gate checks that a reason exists, not that it is a good one —
  that is what a reader of the history is for. An opt-out that costs nothing to write would not be
  a gate.
- Tags are exempt from the job: a release rebuilds code that already passed this on main, and the
  range a tag push reports is not a change under review.

### Changed — the CI integration is named as a boundary, and one claim is withdrawn

- **`README.md` states the integration boundary under *Honest boundaries*.** The audit trail records
  that a runner read a value, not what it did with the value afterwards, and no forge masks a value
  fetched at runtime. That was documented — in the risk table of `docs/README.md` and in the masking
  trap section of `docs/operations/cli.md` — but not on the front page, which named runner-agnostic
  CI access only as an advantage. For a project whose name contains *CI*, having the boundary that
  affects the primary consumer sit two clicks deeper than the one that affects root was the wrong
  asymmetry.
- **`docs/threat-model.md` no longer lists reproducible builds among the countermeasures in place.**
  They are not implemented, and `docs/` describes what exists. The entry now says so and records the
  condition instead: while the repository is private every build is internal, so no third party is
  in a position to rebuild an artifact and compare it. It becomes worth the cost when the repository
  goes public, and the paragraph names itself as the thing that has to change then.
- The status line of the threat model said phase 1 while the project is at phase 3, and the same
  line claimed only the cryptographic and storage defences exist. Corrected, with the UI (A7) and
  MCP (A8) rows marked as describing components that are not built.

### Changed — base images pinned by digest

- `Dockerfile` pins `rust:1.94-bookworm` and `debian:bookworm-slim` by their multi-platform index
  digests. The workflows already pin every third-party action by commit hash on the grounds that a
  tag can be moved, and `release.yml` tells deployments to pin this image by digest for the same
  reason; the base images were the one place the argument was not applied to itself.
- The comment that justified the toolchain pin with "reproducible builds are a supply-chain
  requirement here" is gone with it. The pin is worth having because the base image must not decide
  the compiler version, which is true regardless — and the `apt-get install` in the runtime stage
  means the image is pinned rather than reproducible. The Dockerfile now says that rather than
  implying otherwise.

### Fixed — `init` records the store's own creation to every audit device

- `ciphr init` called `.with_audit(None)` and therefore ignored `--audit-file`, while every other
  command honoured it. The first record of every chain — the creation of the store itself — reached
  the SQLite device only (`0f711ce`, recorded here after the fact; the commit carried no entry).
- The damage is to the archived copy, which is the whole purpose of the file device: its first line
  is sequence 2, and that record's `prev_hash` names an entry the file does not contain. An archive
  that cannot be verified from its own beginning has lost the one property an archived hash chain
  has.
- **Stores that are already initialized keep the gap.** A chain is exactly the thing that cannot be
  amended after the fact, so nothing is backfilled and nothing attempts to be. Verification against
  the SQLite device is unaffected and remains the authoritative check; an archive from before this
  fix has to be verified from sequence 2 onwards, knowing why.
- Found on a deployed store rather than in the code — `audit.jsonl` began at sequence 2. The first
  guess was a forgotten flag, and measuring against a throwaway store with the flag set disproved
  it. The test drives the built binary, because `init` is private to a binary crate and the
  observable behaviour is a flag's effect on a file.

### Added — a second, temporary publisher for the private phase

- `.forgejo/workflows/build-images.yml` builds the image and pushes it to the internal registry the
  deployment host already authenticates to. `release.yml` and GHCR remain the intended home; this
  exists only because a private repository has a private GHCR package and the host has no
  credentials for it.
- Making the GHCR package public instead was considered and rejected. Nothing in the image is
  secret — no configuration, no keys, and the release binaries embed no paths from this
  workspace — but publishing the artefact of an unreviewed cryptographic implementation invites
  someone to run it, and plan section 18 makes the review a precondition for production use, which
  is a property of the software rather than of one deployment. A public image from a private
  repository is also unauditable.
- **The file carries its own deletion condition**: once the repository is public, the GHCR package
  can be public, `release.yml` is the single publisher again, and this goes.
- It pushes **one tag and no `latest`**. This is the one service that can read every secret in a
  deployment; an image reference that can move underneath it is exactly what it must not have.
- It also states what it cannot do: the gates run on GitHub, so a tag produces an image here whether
  or not that run was green. The GitHub run is the gate, and the deployment must not bump its pin
  until it has passed.

## [0.1.0] — 2026-08-19

The first tagged version. It is the artifact the external review is performed against, **not** a
release for production use: the review of `ciphr-crypto`, `ciphr-policy`, and the reviewed parts of
`ciphr-core` is a precondition for holding real secrets (plan section 18, `docs/security-review.md`).

Phases 0 to 3 of the plan are complete — the cryptographic layer, the store, the policy evaluator,
the audit trail, the HTTPS API with token authentication, and the CLI. 255 tests, three fuzz targets,
and a pre-review pass whose ten findings are recorded in `docs/review-2026-08-18.md`.

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

[Unreleased]: https://github.com/nuetzliches/ciphr/compare/v0.1.0...main
[0.1.0]: https://github.com/nuetzliches/ciphr/releases/tag/v0.1.0
