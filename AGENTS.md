# Working in this repository

Instructions for anyone contributing here, human or automated. They are short on purpose; the
reasoning behind them lives in [`docs/adr/`](docs/adr/) and
[`docs/threat-model.md`](docs/threat-model.md), and the full specification is in
[`.claude/plans/PLAN.md`](.claude/plans/PLAN.md).

## Where the project stands

Phases 0 to 3 are complete: the cryptographic layer, the store, the policy evaluator, the audit
trail, the HTTP server with TLS and token authentication, and the `ciphr` CLI. `openapi.yaml` is
maintained from here on.

**`ciphr-sdk` is implemented** (ADR-19) and is the client half of phase 7, route C — an application
fetching its own secrets at startup. It covers the secret-facing endpoints and `/v1/health`; the
administrative reads are not implemented there, because the consumer that needs them is the MCP
server (ADR-13, post-v1) and the CLI reads them from the store without a network hop. Two things
about it are properties of the build rather than rules to remember: it links no public root
certificates, so it cannot be pointed at the WebPKI, and it cannot set an environment variable,
because that is `unsafe` in this edition.

**`ciphr-run` is implemented** (ADR-14, accepted 2026-08-20) and is route B: it fetches, then
`exec`s the given command, so a third-party image needs no derived Dockerfile. Three rules about that
crate are not obvious from its code:

- **Its dependency list is a security boundary, not a convenience.** `ciphr-sdk`, `ciphr-core`,
  `clap`, and nothing else. This binary is bind-mounted into images this project does not own, and
  the reason no store, cryptography or master-key code can be reached from inside one of them is that
  those crates are not dependencies. Adding one is not a refactor.
- **It reads no environment variable.** It `exec`s into a program that inherits its environment, so
  anything read from there would be handed to the service too. Everything it needs comes from flags,
  which already live in the container definition, and the token comes from a file — there is
  deliberately no flag that takes a token value.
- **The order of its checks is the security property**, and the exit codes are part of the contract:
  `125` means the wrapper failed and no child was started, `126`/`127` come from the shell convention.
  Anything that reorders those checks so a fetch precedes a refusal changes what the audit trail
  means.

**`ciphr-ci` is implemented** (ADR-25, accepted 2026-08-24) and is route A: the fetch a CI job runs.
It reads over the API with `ciphr-sdk`, renders with `ciphr-export`, and writes mask commands to
standard output and assignments into `$GITHUB_ENV`. Three things about it are not obvious from its
code:

- **It is a sibling of `ciphr-run`, not a mode of it.** The wrapper `exec`s and therefore reads no
  environment variable, uses the `docker run` exit-code convention, and keeps a dependency list that
  is itself a guarantee. This one terminates, reads `$GITHUB_ENV`, exits `0` or `1`, and is
  downloaded rather than mounted. ADR-25 records why folding them together was rejected.
- **`action.yml` carries no masking logic and must not acquire any.** It downloads the asset,
  verifies the published checksum, writes the token to a mode-0600 file, and calls the binary. A
  `printf '::add-mask::…'` in that file is a second implementation of the one rule this project
  ships instead of documenting.
- **`ciphr-export` is where the rendering lives**, shared with `ciphr export` on a host. The masking
  order, the per-line masks and the random heredoc delimiter exist once. Adding a fourth format, or
  a second copy of any of those rules, is a change to that crate and to both binaries' tests.

**Phase 5 is built:** the read-only viewer in `ui/`, its own package and its own image, released on
its own cadence (`ui-v*` tags). It is documented in [`docs/ui.md`](docs/ui.md), and the rules it is
held to are in the enforced list below. Phase 5's other condition holds by construction rather than
by test: the server has no code that serves the viewer, so a stack without that container is not a
stack with a feature switched off.

Phase 4 is the first production integration: one low-risk service drawing its secrets from ciphr,
with the way back tested and `::add-mask::` demonstrated on a real runner. **Before phase 4 an
external review of `ciphr-crypto`, `ciphr-policy`, and the path and pattern code in `ciphr-core` is
a precondition** — those are the crates that decide every access, and self-review is not sufficient.
**The review happened on 2026-08-21** — recorded in `docs/assurance/reviews/review-2026-08-21.md`, accepted by the
maintainer the same day, with both of its blocking findings fixed. Two rules survive it. First, the
reviewer was an AI model rather than the human practitioner the working paper asks for: every
document that mentions the review says so, because a repository that reports a check as cleared
without saying who cleared it is useless the moment a stranger reads it. Second, the acceptance
covers the code as it was read — `docs/security-review.md` names what it does not stretch to, and
new surface in the reviewed crates or the authentication path needs its own pass rather than
inheriting this one. A deployment still records its own risk decision where the deployment is
documented, and that does not change a line here.

**OIDC federation is implemented** (ADR-26, accepted 2026-08-26) and is the post-v1 item ADR-6 named
in v1. `POST /v1/auth/oidc/login` exchanges a provider-issued ID token for a short-lived ciphr token,
behind the `oidc_login` surface entry. Four things about it are not obvious from its code:

- **It is the second write the API may do, and ADR-24's "one route" sentence is amended.** The rule
  is now *the writes the API may do are the ones that cannot widen an authority*. Anything added to
  this route that could create an identity, a rule, or a lifetime above the configured ceiling breaks
  the argument the route exists on — not a style rule, the whole justification.
- **There is no JWKS fetch and there must not be one.** The provider's keys are configuration.
  Adding a fetch would put outbound network access into the process that holds plaintext secrets,
  which ADR-17 refused for the ACME client, and it cannot be built here anyway: nothing in this
  workspace can be pointed at the WebPKI.
- **The recording line is at the signature, not at the request.** A token that does not verify
  against a configured provider is refused with no audit entry, because the route is unauthenticated
  and the trail is fail-closed — the same rule the router fallback and `AuditedJson` follow. Moving
  that line earlier makes a `401` into a `503` for anyone who can reach the port.
- **The verifier reads the algorithm from the *key*, never from the token's header.** The header only
  has to agree. A change that looks up a key by `alg` is the shape every algorithm-confusion attack is
  written against.

**The vault is a startup dependency and there is deliberately no cache** (ADR-27, accepted
2026-08-26, the answer to issue #52). `ciphr-run` fetches at exec time, so every container start needs
the service reachable; a cached value would be served without a fetch and therefore without an audit
entry, which is the one thing ADR-22 does not trade. The requirement lives in
`docs/operations/availability.md` rather than in code, and that page is the deliverable — a proposal
for a cache, a lease or a holding agent is answered there and in ADR-27, including which of the three
was closest.

Two phases are planned and not built, and as of 2026-08-20 they are in different states.

**Phase 8**, honeypots and tripwires, is **released in `v0.5.0`**, in the `alert`
tier only. `disable-identity` and `freeze` remain designed and deliberately absent, because the severe
tiers are worth their cost only once one machine identity no longer serves every deploy target. It
ships behind the `honeypot_alert` surface entry (ADR-20) and is therefore **absent from a default
build**, which is what makes ADR-15's indistinguishability claim strongest: code that is not compiled
in has no timing to get wrong.

**The coverage debt is open and is the thing to remember about it.** The accepted review read the
authentication path before bait existed, and says in its own words that new surface there does not
inherit the acceptance. `docs/security-review.md` carries three claims — C11, C12, D10 — marked as
newer than the acceptance; they are what a reviewer of this phase should attack. The core crates are
untouched, and `ci/check-core-no-features.sh` enforces that rather than a sentence claiming it.

Two things about it are easy to lose and expensive to relearn. Bait belongs outside every prefix any
consumer fetches, and whether a prefix is fetched is a question about the code that fetches rather
than about the policy that permits it. And the last step of the mechanism is not in this repository:
the alert is a field on `/v1/health` and an entry in the trail, so a deployment whose monitoring does
not page on it has bait and no tripwire. `docs/operations/honeypots.md` leads with that.

**Phase 9**, the unauthenticated leak-report endpoint, is **deferred** (ADR-16). The condition that
decides its worth is whether anyone without a token can reach the endpoint at all; where every
consumer already sits inside the boundary the service listens on, a report adds nothing the audit
trail would not have carried, and the first anonymous write path against a fail-closed audit trail is
paid for regardless. It reopens with that condition, not on its own.

Neither could precede the review above — one adds behaviour to the authentication path, the other a
key derivation and the only anonymous request path that reaches the store — and the plan says why in
section 18. That constraint is discharged as of 2026-08-21; phase 9's own deferral is not, and stands
on the condition in ADR-16 rather than on the review.

**How either gets switched on is now one mechanism rather than three** (ADR-20, plan section 24).
Optional behaviour is a named surface entry: off unless a deployment names it, enabled only with a
date and a reason or the server refuses to start, and either absent from the router or absent from the
binary — never a dormant handler behind a boolean. Two routes that exist today become entries with it,
`POST /v1/export` and the three administrative reads the viewer needs, so this is not only about the
two unbuilt phases.

Three things later phases must not undo:

- The router calls the path normalization in `ciphr-core`. Not a copy of it, not a variant that
  strips a trailing slash first (ADR-9).
- No response leaves the process, and no change is made, before the audit entry is stored. A request
  whose entry no device accepted is refused with `503`.
  `crates/ciphr-server/tests/api.rs::every_endpoint_writes_an_audit_entry` is what keeps that true
  as routes are added; extend it rather than working around it.
- A value is never a CLI argument, and a secret is never written to a pipe without `--force`.

## Hard rules

**English only, in everything that is committed.** Code, comments, commit messages, documentation,
the changelog, the plan. The repository is private but is built to be publishable from the first
commit, and retrofitting a language is worse than choosing one.

**No deployment specifics anywhere in this repository.** No organization-specific hostnames, domains,
service names, inventory counts, or infrastructure assumptions — not in `crates/`, not in docs, not in
examples. Public product names in comparisons (OpenBao, Vault, Infisical, SOPS) are fine. Integration
with a specific environment belongs in that environment's own repository, not here.

**A security improvement still lands, and compatibility is still not a reason to keep a weaker
shape** — but since 2026-08-24 it is no longer unconditional. While this repository was private, a
breaking change to a route, a flag or a default was an ordinary commit as long as the changelog and
the upgrade document said what it cost, because the consumer side was the same people making the
change. **It is public now, and the consumers are people who did not agree to that arrangement.**
From here, the same change needs a deprecation, a version, or a written argument for why it cannot
wait — and the release that carries it says which of the three it chose. The upgrade document is
where that is owed, and `0.9.0` is the shape to imitate: one mandatory edit, named, with the command
that finds it.

**Technical decisions are argued from security and technical criteria.** "We already do it this way
elsewhere" is not a reason. Where an alternative is genuinely better on some axis, the ADR says so —
see ADR-1 on Go, which concedes two real advantages and decides against it anyway.

**Optional features compose at the edge, never in the core.** `ciphr-crypto`, `ciphr-policy`, and
the path, pattern and secret code in `ciphr-core` contain no flag, no `#[cfg(feature)]`, and no trait
object that one configuration installs and another does not (ADR-20). Where an optional feature needs
something from those crates, the crate gains it *unconditionally* and the optional part is built on
top of it elsewhere. The reason is the external review: a core whose reachable code depends on
configuration cannot be reviewed once.

**Every new dependency is a reviewed decision** with a justification in the pull request, especially
in `ciphr-crypto` and `ciphr-policy`. `ciphr-crypto` takes nothing beyond the cryptographic
primitives. `ciphr-policy` takes a TOML parser and `serde` and nothing else — that is not an
exception to the budget but the substance of ADR-2, which rejected a custom DSL precisely to avoid a
hand-written parser in the authorization path.

## The rules that are enforced rather than trusted

All of these are blocking in CI (`.github/workflows/ci.yml`) and runnable locally:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny check          # licences, advisories, duplicate and banned crates
cargo audit --deny warnings
sh ci/check-no-print.sh          # no stdout/stderr from library crates
sh ci/check-forbid-unsafe.sh     # #![forbid(unsafe_code)] in every crate root
sh ci/check-no-v-html.sh         # no v-html / innerHTML in ui/
sh ci/check-ui-budget.sh         # one runtime dependency, no install scripts, integrity hashes
sh ci/check-ui-image-files.sh    # every tracked path in ui/ reaches a stage of the viewer image
sh ci/check-workflow-interpolation.sh # no workflow expression reaches a shell script
sh ci/check-surface-entries.sh   # the CLI knows every surface entry the server does
sh ci/check-sdk-reexports.sh     # a ciphr-sdk consumer needs no dependency on ciphr-core
sh ci/check-docs.sh              # every doc under docs/ carries a date
sh ci/check-doc-commands.sh      # a command a document tells you to run exists
sh ci/check-doc-index.sh         # every doc is in an index, and the ADR count matches
sh ci/check-doc-links.sh         # a relative link lands, and so does a link text written as a path
sh ci/check-changelog.sh         # a commit touching crates/ also touches CHANGELOG.md
sh ci/check-changelog-releases.sh # the released version has a section, and every section a link
sh ci/build-wrapper.sh           # ciphr-run: static musl, verified linkage, size budget
sh ci/build-ci-binary.sh         # ciphr-ci: the same two properties, its own budget
```

`build-wrapper.sh` and `build-ci-binary.sh` need the `x86_64-unknown-linux-musl` target and a musl
linker, so neither runs on Windows. CI runs both, and runs `cargo test -p ciphr-run --target
x86_64-unknown-linux-musl` and the same for `ciphr-ci` next to them — the tests execute *as* static binaries rather than merely being built as them, because static
musl is where name resolution breaks and a build-only gate would not notice.

The viewer has its own CI job, its own pinned Node version, and its own budget, because it is its own
package (ADR-11). Locally:

```sh
cd ui && npm ci --ignore-scripts && npm run build && npm audit --audit-level=high
```

Four rules for `ui/` that are not obvious from the code, and one of which no gate can catch:

- **Only documented v1 endpoints.** An endpoint that exists for the viewer alone means the CLI cannot
  do something the viewer can, which is the coupling ADR-11 exists to prevent.
- **No inline script, no inline style.** `style-src 'self'` refuses a `style` attribute, so a `:style`
  binding is a broken page rather than a slow one. Conditional appearance is a class.
- **Revealed plaintext stays in component state**, never in a store, `localStorage`, a URL, or the
  clipboard — there is deliberately no copy button, and the reasoning is in `SecretsView.vue`.
- **No service worker.** A cached response to a secret read is a secret without an expiry date.

`check-changelog.sh` takes a range in CI and defaults to `HEAD` locally, so running it bare after a
commit answers "did I forget?". A change under `crates/` with genuinely no observable effect opts out
per commit, with a reason:

```
Changelog-Exempt: pure refactor, no observable behaviour
```

The gate checks that a reason is present, not that it is a good one. It exists because this was the
one documentation rule left to habit, and it is the one that eroded — `0f711ce` changed behaviour an
operator has to know about and recorded it only in a commit body.

The fuzz targets are a fourth CI job and need a nightly toolchain, so they do not run on Windows at
all — see [`docs/fuzzing.md`](docs/fuzzing.md).

`cargo deny` and `cargo audit` are not installed by default:
`cargo install --locked cargo-deny@0.20.2 cargo-audit@0.22.2` (the versions CI pins).

The toolchain is pinned in `rust-toolchain.toml`. Bumping it is a deliberate commit, not a side
effect.

## Writing code here

**The type system does the work.**

- `#![forbid(unsafe_code)]` in every crate root.
- Every secret-bearing value lives in `SecretBox` or `Zeroizing`. Those types implement neither
  `Debug`, `Display` nor `Serialize`, which makes logging a secret a compile error instead of a
  code-review question. Do not add such an implementation, and do not enable
  `missing_debug_implementations` to pressure someone into it.
- Error types carry paths, identities, and error classes. Never values.

**Cryptography.**

- No custom constructions. The primitives and the envelope pattern are specified in the plan; follow
  them exactly.
- Randomness only from `OsRng`. A deterministic RNG in a production path is a bug, not an
  optimization.
- Token, HMAC, and tag comparisons are constant-time (`subtle`).
- Known-answer tests for the envelope scheme, so a refactor cannot silently break compatibility.

**Authorization.**

- Path normalization exists **exactly once**, in `ciphr-core`, and the router and the policy
  evaluator both call it (ADR-9). A second normalizer is an authorization bypass waiting to happen.
- Deny by default. New capabilities are added to the capability set, never as a special case in the
  evaluator.
- Never parse a suffix off a catch-all route; give each operation its own prefix.

**Auditing.** The audit record is written before the response is produced. If no device accepts it,
the request fails and no secret is served. Bulk operations write one entry per secret served, never
one per call.

## Explicitly not done

- No debug endpoint that dumps configuration or state.
- No test mode that skips authentication. Tests use real identities.
- No plaintext secrets in test fixtures that look real — that only trains people to ignore secret
  scanners.
- No endpoint that exists solely for the UI (ADR-11). If the UI needs it, the CLI needs it too.

## Branches

**Every change lands through a pull request, since 2026-08-24.** Nothing is pushed to `main`
directly, including by the maintainer, and this is enforced by a repository ruleset rather than by
habit: the `main` ruleset requires a pull request, requires five checks to pass, refuses a
force-push and refuses a deletion. **It has no bypass actors** — that is the difference between a
ruleset and the old branch protection, and it is the whole reason the rule is worth writing down.
An emergency push means deactivating the ruleset, pushing, and reactivating it, which is deliberately
awkward and leaves a trace in the organization audit log.

**Until that date work landed directly on `main`**, and the reason is recorded rather than deleted:
with a single author and no reviewer, a pull request is a diff nobody reads and a step everybody
learns to skip. Server-side branch protection was also unavailable — on the current plan, protected
branches and rulesets are both unavailable for private repositories, so a "no direct pushes" rule
would have had nothing enforcing it but good intentions. A client-side hook was considered and
rejected then, and the argument still holds: a guard that any push can walk past invites treating
the rule as satisfied.

**A pull request needs no approval.** That is not a claim that review is unnecessary; it is the
honest state of a project whose contributors are the same few people. Requiring an approval that one
of four org owners rubber-stamps buys a checkbox, and the temptation to bypass it is what erodes the
rule that matters — that everything goes through the checks. Raising it to one approval is one field
in the ruleset the day there is somebody to review.

**The five required checks** are `Format, lint, test`, `Shipped code and documentation carry their
record`, `The static binaries build, run, and fit their budgets`, `Viewer build and dependency
budget`, and `Licenses, advisories, dependency budget`. The fuzz smoke run is deliberately not
required: it needs a nightly toolchain, and a toolchain that moves under a gate turns an unrelated
merge into somebody's afternoon. `Licenses, advisories, dependency budget` **is** required although
it can go red without anything in the pull request changing — for a secret manager that is the
point of having it.

The CI gates are the same ones that ran before, and they are what actually stands between a mistake
and `main`. What changed is that they now run before the merge rather than after it.

## Documentation

Documentation is part of the change, not a follow-up. The rules and the reasoning are in
[`docs/README.md`](docs/README.md); the short version:

- **Honest.** State what is not protected next to what is. Where something buys convenience rather
  than security, say so — the seal in v1 is the standing example.
- **Dated.** Every document under `docs/` carries an ISO date, and facts that age carry the date they
  were verified. `ci/check-docs.sh` fails the build on a missing or future date.
- **About what exists.** Describe the built system. Plans for unbuilt features belong in the
  implementation plan; anything partial says which phase finishes it.
- **Executable where possible.** Code examples in rustdoc are doctests and run in CI, so an example
  that stops working fails the build. Prefer an example that runs over prose that cannot be checked.
- **Same commit as the code.** A documentation update that trails its change is a window in which the
  documentation is wrong.

- **In an index.** Four pages are indexes — `docs/README.md`, `docs/adr/README.md`,
  `docs/operations/README.md`, `docs/assurance/README.md` — and `ci/check-doc-index.sh` fails the
  build on a document none of them links to. A deliberately unindexed file goes in that script's
  allowlist with a reason.

- **Linked to something that is there.** `ci/check-doc-links.sh` resolves every relative Markdown
  target against the tree, and resolves a link *text* too where the text is written as a path —
  `[../review-x.md](../assurance/reviews/review-x.md)` is a dead path in front of a live one, and it
  reads as correct from either half alone. **Moving a file means moving the links to it, both halves.**
  External URLs and `#fragments` are not checked: a build that fails because somebody else
  reorganised their site is a build people learn to skip.

For anything hard to undo — master key handling, rotating a secret that cannot be rotated — the
document belongs in `docs/operations/` and says what breaks, what it looks like when it breaks, and
what to do instead.

**Where a document goes.** `docs/` describes the system as it is now; a page there is expected to be
kept true. `docs/assurance/reviews/` and `docs/assurance/field-reports/` hold *snapshots* — a record
of a tree on a given day — and are expected **not** to be updated, because the date is the finding's
provenance. Two gates enforce that difference rather than trusting it: `check-doc-dates.sh` does not
require a snapshot's status date to move when it is edited, and `check-doc-commands.sh` does not
require a command it quotes to still exist. Both make the same exceptions for `docs/adr/`, for the
same reason. Editing a record to match today's code destroys the only thing it was kept for.

## Commits and changelog

Imperative mood, one concern per commit, English. Update `CHANGELOG.md` in the same commit as the
change it describes — reconstructing a changelog afterwards produces a list of commits, not a
changelog. From phase 3 onward the same applies to `openapi.yaml`.
