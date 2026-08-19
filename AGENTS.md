# Working in this repository

Instructions for anyone contributing here, human or automated. They are short on purpose; the
reasoning behind them lives in [`docs/adr/`](docs/adr/) and
[`docs/threat-model.md`](docs/threat-model.md), and the full specification is in
[`.claude/plans/PLAN.md`](.claude/plans/PLAN.md).

## Where the project stands

Phases 0 to 3 are complete. Every crate except `ciphr-sdk` is implemented and tested: the
cryptographic layer, the store, the policy evaluator, the audit trail, the HTTP server with TLS and
token authentication, and the `ciphr` CLI. `openapi.yaml` is maintained from here on.

**Phase 5 is built:** the read-only viewer in `ui/`, its own package and its own image, released on
its own cadence (`ui-v*` tags). It is documented in [`docs/ui.md`](docs/ui.md), and the rules it is
held to are in the enforced list below. Phase 5's other condition holds by construction rather than
by test: the server has no code that serves the viewer, so a stack without that container is not a
stack with a feature switched off.

Phase 4 is the first production integration: one low-risk service drawing its secrets from ciphr,
with the way back tested and `::add-mask::` demonstrated on a real runner. **Before phase 4 an
external review of `ciphr-crypto`, `ciphr-policy`, and the path and pattern code in `ciphr-core` is
a precondition** — those are the crates that decide every access, and self-review is not sufficient.
**The review has not happened.** That requirement binds this repository: it stays stated as
outstanding, in every document that mentions it, until a review has actually taken place. A
deployment may decide to run without it; that decision is recorded where the deployment is
documented, and it does not change a line here.

Two phases are planned and not built: **phase 8**, honeypots and tripwires (ADR-15, plan section 22),
and **phase 9**, the unauthenticated leak-report endpoint (ADR-16, plan section 23). Neither may
precede the review above — one adds behaviour to the authentication path, the other a key derivation
and the only anonymous request path that reaches the store — and the plan says why in section 18.

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

**Technical decisions are argued from security and technical criteria.** "We already do it this way
elsewhere" is not a reason. Where an alternative is genuinely better on some axis, the ADR says so —
see ADR-1 on Go, which concedes two real advantages and decides against it anyway.

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
sh ci/check-docs.sh              # every doc under docs/ carries a date
sh ci/check-changelog.sh         # a commit touching crates/ also touches CHANGELOG.md
```

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

**While the repository is private, work lands directly on `main`.** With a single author and no
reviewer, a pull request would be a diff nobody reads and a step everybody learns to skip. Branches
are for work that benefits from one — a change large enough to want a written summary, or anything
touching `ciphr-crypto` or `ciphr-policy`, where the external review requirement applies anyway.

**When the repository is made public, this changes and pull requests become the rule.** That is also
the point at which GitHub's server-side branch protection becomes available for it — on the current
plan, protected branches and rulesets are both unavailable for private repositories, so a
"no direct pushes" rule would have nothing enforcing it but good intentions. A client-side hook was
considered and rejected: a guard that any push can walk past invites treating the rule as satisfied.

Either way, the CI gates are the same and they are blocking. They are what actually stands between a
mistake and `main`.

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

For anything hard to undo — master key handling, rotating a secret that cannot be rotated — the
document belongs in `docs/operations/` and says what breaks, what it looks like when it breaks, and
what to do instead.

## Commits and changelog

Imperative mood, one concern per commit, English. Update `CHANGELOG.md` in the same commit as the
change it describes — reconstructing a changelog afterwards produces a list of commits, not a
changelog. From phase 3 onward the same applies to `openapi.yaml`.
