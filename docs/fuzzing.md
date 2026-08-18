# Fuzzing

**Status:** current as of 2026-08-18, phase 2. Three targets exist and run as a blocking CI gate.

## Why there is a fuzzer at all

Path normalization is the function the HTTP router and the policy evaluator share (ADR-9). An input
that makes it behave unexpectedly is an input that can make routing and authorization disagree, and
that class of bug is invisible until someone reads a secret they should not have.

The property tests generate paths from a regular expression — that is, from what someone thought to
write down. A fuzzer generates what a coverage-guided search finds, which is the part nobody thought
of. For this one function, that difference is worth a second toolchain.

## The three targets

| Target | What it asserts |
|---|---|
| `path_normalization` | Every rule the accepted output must satisfy — no empty or relative segments, no wildcards, length limits, no control characters — plus idempotence and that segments rejoin to the path |
| `pattern_matching` | `**` only ever at the end, no partial wildcards, specificity never exceeds the segment count, and a wildcard-free pattern matches exactly one path |
| `policy_file` | A file loads completely or not at all; every policy reference resolves; an unknown identity is always denied; and an allow always names the rule that granted it |

The targets assert invariants rather than only checking for panics. A normalizer that returns a path
containing `..` without crashing is the failure that matters here, and a panic-only target would miss
it.

## Running it

Fuzzing needs a nightly toolchain and libFuzzer, so it runs on Linux only. On Windows it does not run
at all — that is a limitation of the tooling, not something to work around, and it is why the gate
lives in CI rather than in a pre-commit hook.

```sh
sh ci/install-fuzz-tools.sh                       # pinned cargo-fuzz, checksum verified
rustup toolchain install nightly-2026-08-01 --profile minimal

cargo +nightly-2026-08-01 fuzz list
cargo +nightly-2026-08-01 fuzz run path_normalization -- -max_total_time=60
```

A crash writes a reproducer under `fuzz/artifacts/`. To replay one:

```sh
cargo +nightly-2026-08-01 fuzz run path_normalization fuzz/artifacts/path_normalization/crash-<hash>
```

In CI the artifact directory is uploaded when the job fails, because a reproducer that only ever
existed inside a CI run is a bug report nobody can act on.

## Two pins, and why

**The nightly is pinned by date** (`nightly-2026-08-01`), for the same reason the production toolchain
is pinned to 1.94.0: a floating toolchain lets CI go red without a code change, and a gate nobody
trusts is a gate nobody reads. Bumping it is a deliberate commit.

**cargo-fuzz is pinned by version and SHA-256** in `ci/install-fuzz-tools.sh`, and installed from the
release binary rather than compiled. rust-fuzz publishes no checksums, so the hash was recorded from
the artifact on the date above: the first fetch is trust, every fetch after it is verification.

The nightly toolchain applies to `fuzz/` and nothing else. That crate has its own workspace precisely
so that a sanitizer-instrumented build can never reach the production crates, and so that the
1.94.0 pin does not have to be loosened for anything that ships.

## What the CI gate is and is not

It is a smoke run: 45 seconds per target, enough to catch a target that no longer builds or an
invariant that breaks on shallow input. It is **not** a fuzzing campaign — finding deep bugs takes
hours and a persistent corpus, which is a scheduled job and a separate decision. Saying so matters,
because "we fuzz in CI" is easily heard as a stronger claim than a 45-second run supports.

`fuzz/` is exempt from two rules that apply everywhere else, both deliberately:

- **No `#![forbid(unsafe_code)]`.** The libFuzzer target macro emits an `extern "C"` entry point, so
  the attribute cannot be applied. Nothing in `fuzz/` ships.
- **Not covered by `cargo deny`.** It is outside the root workspace, so `libfuzzer-sys` is not in the
  dependency graph that the supply-chain gate checks. It is a test tool that never reaches a build
  artifact.
