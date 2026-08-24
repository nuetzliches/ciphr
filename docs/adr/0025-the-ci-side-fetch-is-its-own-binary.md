# ADR-25 — The CI-side fetch is its own binary

| | |
|---|---|
| **Status** | **Accepted 2026-08-24, built the same day.** `ciphr-ci`, a static musl binary published as a release asset, with the export renderer moved into `ciphr-export` and shared with `ciphr export`. `action.yml` is a thin wrapper around it |
| **Date** | 2026-08-24 |
| **Affects** | Plan section 14, ADR-14 (a sibling, not a change), ADR-18 (a fourth consumer of the naming rule), `ciphr-cli`, `ciphr-sdk`, `.github/workflows/`, `docs/operations/ci.md` |

## Context

The name of this project contains *CI*, and the README says masking is *"part of the product rather
than of the documentation"*. Both were true of the code and false of what a CI job could reach.

`ciphr export --format actions-env` is where the masking discipline lives — `::add-mask::` before
anything else, one mask per line, a heredoc delimiter drawn from the OS CSPRNG and checked against
the value (finding F2 of [`../review-2026-08-21-current-tree.md`](../review-2026-08-21-current-tree.md)).
It is a **CLI command**, and the CLI works on the local store: it opens `Session`, takes the
exclusive lock, and needs the master key. A runner has none of those and must not. So the one place
this project addressed the masking trap was reachable only from a host with the store — and only
with the service stopped.

What a job could reach was `curl`, `jq`, and a page of documentation telling it to emit the mask
commands itself. That is the shape the README explicitly rejects for masking, applied to the
integration the product is named after.

Plan section 14 anticipated the answer and named it a *composite action* that "downloads the pinned,
checksum-verified static CLI binary (musl build) or falls back to curl". Two of those three do not
exist: the CLI binary cannot fetch remotely at all, and a curl fallback is the shell reimplementation
this record exists to avoid.

## Decision

**A second consumer binary, `ciphr-ci`**, beside `ciphr-run`. It fetches over the documented v1 API
with `ciphr-sdk`, renders with `ciphr-export`, and writes: mask commands to standard output,
assignments into the file named by `$GITHUB_ENV`. It then terminates.

**The renderer moves into its own crate, `ciphr-export`.** `ciphr export` and `ciphr-ci` render
through the same code, so there is one implementation of the masking order, one delimiter rule, and
one set of tests for both. `getrandom` moves with it and leaves `ciphr-cli`.

**`action.yml` is a wrapper and nothing else.** It downloads the asset, verifies the published
checksum, writes the token to a mode-0600 file in `$RUNNER_TEMP`, and calls the binary. No masking
logic, ever — a `printf '::add-mask::…'` in that file is the second implementation arriving.

**A release asset, and no image.** The wrapper needs both channels because the host that mounts it
authenticates to a registry and not to the forge ([`../operations/wrapper.md`](../operations/wrapper.md)).
A *job* always holds a credential for the forge it runs on, so the channel that is awkward for a host
is the natural one here.

### Why not a mode on `ciphr-run`

It would have cost one artefact instead of two, and it was rejected on three properties that are
each small and together decisive:

- **`ciphr-run` reads no environment variable**, because it `exec`s into a program that inherits its
  environment — so anything it read from there would be handed to the service too. `ciphr-ci` reads
  `$GITHUB_ENV` and may: it hands its environment to nothing.
- **`ciphr-run`'s exit codes are the `docker run` convention** (`125`/`126`/`127`), because a restart
  policy reads them and has to tell "my service crashed" from "it never started". A workflow step has
  no such question; `ciphr-ci` exits `0` or `1`.
- **`ciphr-run`'s dependency list is a security boundary** (ADR-14): it is bind-mounted into images
  this project does not own. The renderer needs `getrandom` and `serde_json`, and adding them to the
  mounted binary would weaken a guarantee that has nothing to do with CI.

The wrapper's own documentation states the shape this preserves: *"fetch, then exec"*, with the order
of checks as the security property. A second exit from that function is a second contract in one
binary.

### Why not a composite action alone

It is the smallest change and the one that puts the security-critical half in the least testable
place. The masking rules would exist twice — once in Rust under `cargo test`, once in shell under
nothing — and the shell copy would be the one CI jobs actually run. The delimiter alone makes the
case: 128 bits from the OS CSPRNG, verified line by line against the value, is not a thing to
maintain in two languages.

### Why not a remote mode for the CLI

`ciphr-cli` depends on `ciphr-store` with bundled SQLite. Even setting aside
[`../operations/cli.md`](../operations/cli.md)'s rule that the CLI works on the local store, the
artefact would be a multi-megabyte binary carrying a database engine onto a runner that has no
database. And the rule is not incidental: a `ciphr` that sometimes speaks HTTP and sometimes opens a
store is a tool whose failure modes depend on which half a reader is thinking of.

## Consequences

- **Two consumer binaries with the same shape and different contracts.** `--url`, `--token-file`,
  `--ca`, `--path`/`--prefix`, `--timeout`, `--report` mean the same things in both. What differs is
  what happens after the fetch, and each binary's documentation leads with that.
- **A fourth consumer of ADR-18.** `ciphr export`, `ciphr-run`, the SDK and now `ciphr-ci` derive the
  variable name from the same `EnvVarName::assign`. That was already the reason the rule has an ADR.
- **A new crate in the reviewed-surface question.** `ciphr-export` renders text and reaches no store,
  no key and no network. It is not in the set the external review of 2026-08-21 read, and
  [`../security-review.md`](../security-review.md) says what that means: new surface does not inherit
  an acceptance. The masking rules themselves are unchanged code, moved.
- **A second size budget.** `ci/build-ci-binary.sh` checks static linkage and a size ceiling for the
  same reasons as the wrapper's, against its own number, because one number for both is the weaker
  check applied to whichever binary is smaller.
- **`--report` on a runner prints names, never values**, and there is no verbosity level that would
  change that.

## What would reverse this

If the API ever gains a form of authentication that removes the long-lived token from the runner —
OIDC federation, plan section 14 — the *token file* half of this binary becomes a token exchange, and
that is an addition to it rather than a reason to fold it back. What would genuinely reverse this
record is the opposite finding: that the two binaries have drifted into one shape with one contract,
at which point they should be one binary with two subcommands rather than two documents saying
almost the same thing.
