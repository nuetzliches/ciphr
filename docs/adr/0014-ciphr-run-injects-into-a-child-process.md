# ADR-14 — `ciphr run` injects secrets into a child process

| | |
|---|---|
| **Status** | **Accepted 2026-08-20** and built as `ciphr-run`. Proposed 2026-08-18 |
| **Date** | 2026-08-18, accepted 2026-08-20 |
| **Affects** | `ciphr-run`, `ciphr-sdk`, section 13 route B, phase 7, CI and release |

## Context

Section 13 of the plan describes three routes for getting a secret into a service without leaving
plaintext at rest. Route B — the entrypoint wrapper — is the route for images that only understand
environment variables, which is most of them. As written it costs **one derived image per
third-party service**: a Dockerfile, a build, and a rebuild every time the base image moves.

That cost is why route B is the least likely of the three routes to actually be carried out, and
route B is the one that applies to the largest number of images. A route that is correct and
unaffordable does not remove any plaintext from any disk.

The same mechanism in a different shape is the signature ergonomic feature of comparable tools:
`infisical run -- <command>` fetches secrets and executes a child process with them in its
environment. This plan never considered it. Not because it was weighed and rejected — because
developer experience was not a stated goal until section 1 was amended on the same date as this
record. An unstated goal produces no findings.

## Decision

**Proposed on 2026-08-18, not yet accepted at the time of writing.** Accepted on 2026-08-20 — what
each condition below turned out to mean, and where the built thing deviates from this paragraph, is
in the section at the end. A `run` subcommand:

```
ciphr run --prefix infra/<host>/<service> -- /original/entrypoint --flags
```

It authenticates with the host's token, fetches the values under a prefix, sets them in its own
environment, and `exec`s the given command — replacing itself, so no supervisor process survives
holding the values and no shell ever sees them.

Route B then becomes: bind-mount one statically linked binary, override `entrypoint:` in the
container definition. No derived image, no rebuild when the base image moves.

## Why this is not only ergonomics

The value never reaches a file, a shell history, or the container runtime's inspect output. Those
are exactly the three exposures section 13 exists to remove, and the plan already names them.
`ciphr run` is the mechanism for route B; the ergonomic gain is what implementing it well feels
like, not the reason for doing it.

It also covers a case route B does not: an operator running a one-off command against a service
with the same credentials that service uses, audited under that identity, without exporting
anything into their own shell. Today the honest way to do that is `export`, which puts the value
in the operator's environment and leaves it there.

## What must be true before this can be accepted

Recorded as conditions rather than as a to-do list, because any one of them failing is a reason to
keep route B as it stands.

- **A statically linked build.** Bind-mounting a binary into a foreign image only works if it needs
  nothing from that image. That means a musl target and a size budget, neither of which the
  workspace has today, and a second build artifact to keep in step with the first.
- **The original entrypoint has to be written down.** Overriding `entrypoint:` means recording what
  it was. `docker inspect` yields it, but it becomes a value that silently drifts when the base
  image changes — the same class of breakage as a derived image, relocated rather than removed.
  **This trades a rebuild for a pin, and the honest accounting says so.**
- **Failure behaviour must be settled first.** If the fetch fails, `run` must not `exec`. A wrapper
  that starts the service without its secrets is worse than one that refuses: the service comes up
  in some degraded state instead of failing visibly, and fail-closed is the property this project is
  built on.
- ~~**Prefix-to-variable-name semantics.**~~ **Answered on 2026-08-20 by [ADR-18](0018-one-rule-for-the-variable-name.md).**
  The last path segment becomes the variable name; a name that is not a portable variable name is
  refused, and so is a set in which two paths want the same name. The rule lives in `ciphr-core` and
  `ciphr run` meets this condition by calling it rather than by implementing it — which is what makes
  it the same answer route C gives. This was the one condition shared with route C, so it was settled
  before either route was built rather than by whichever arrived first.

## Consequences

- **Phase 7 changes shape.** Route B stops being "one image per service" and becomes a change to a
  container definition. The phase gets cheaper, and therefore more likely to be finished — which is
  the point, since phase 7 is what actually removes plaintext from disk.
- **The startup dependency broadens.** A restart during a ciphr outage fails for every service using
  this. That trade is already stated in section 13 and does not get worse per service, but it
  applies to more services, because the route becomes affordable for more of them.
- **One more component holds plaintext**, and the first one that holds it on behalf of a process it
  does not control. It holds it for the length of an `exec` and in a process that then ceases to
  exist, which is the shortest window available, but it is a new position on the list.

## Rejected alternatives

**Keep one derived image per service** — the current plan. It works, and nothing about it is wrong.
It is also the reason route B is the route least likely to be executed: a rebuild on every
base-image bump, for services whose only requirement is an environment variable.

**A long-running agent that maintains an environment.** More moving parts, a daemon holding
plaintext for the lifetime of the host, and no benefit for a value that is read once at start. It
would also be a second process holding secrets, which ADR-11 exists to prevent.

**Do nothing; rely on routes A and C.** Route A needs the image to support a `_FILE` convention;
route C needs the source. Neither covers a third-party image that reads only environment variables,
and that is the majority case.

---

## Accepted on 2026-08-20 — what the four conditions turned out to be

Recorded here rather than in a new record, because this is the same decision reaching its
conclusion: the conditions above were the terms of acceptance, and this is what happened
when each was tested against a working implementation.

### It is `ciphr-run`, a separate crate — not a `ciphr` subcommand

The proposal above writes `ciphr run`, and the built thing is a binary named `ciphr-run`
in its own crate. Two reasons, and neither is style:

- **The dependency list is the guarantee.** This binary is mounted into images this
  project does not own, so what it *can* contain matters as much as what it does. Its
  dependencies are `ciphr-sdk`, `ciphr-core` and `clap`: there is no store, no
  cryptography and no master-key handling in reach, because those crates are not
  dependencies. A subcommand would carry them, and a `use` would be enough to reach them.
- **`ciphr` has global options that would come with it.** `--database`,
  `--master-key-env`, `--master-key-file` and `--policies` are global on that CLI, so
  `ciphr run --help` inside a foreign container would advertise a master-key flag and
  default a database path. Both are nonsense there, and the second is worse than nonsense:
  it suggests the wrapper has something to do with the master key.

**Size was not the reason, and the honest numbers say so.** Stripped `x86_64-unknown-linux-musl`
builds, measured 2026-08-20 with the pinned toolchain: `ciphr-run` **3,347,368 bytes**, the
full `ciphr` CLI **4,033,400 bytes**. Roughly 17% apart — both dominated by a large
dependency, `rustls`/`ring` on one side and bundled SQLite on the other. Anyone expecting
the separate crate to be dramatically smaller should expect otherwise; the argument is
about reachable code, not bytes.

### Condition 1 — a statically linked build: met, and verified rather than assumed

`ldd` reports `statically linked` and `file` reports `static-pie linked`. Both are checked
by `ci/build-wrapper.sh`, which is a blocking gate, because "it built" and "it needs
nothing from the image it lands in" are different claims.

**The size budget is 5 MiB on the stripped binary**, about 1.5× the measured size. It is a
review trigger, not a performance one: ordinary growth passes, and a new dependency of any
size does not. Raising the number is the wrong response to it failing.

**The tests run as static musl binaries, not merely build as them.** That distinction
earned its keep: static musl is exactly where name resolution breaks, because NSS modules
cannot be loaded into a static binary. A build-only gate would pass a binary that cannot
resolve a hostname, and the first deploy would find it.
`crates/ciphr-run/tests/wrapper.rs` covers a resolution by name for that reason, alongside
the real `exec`.

### Condition 2 — the entrypoint has to be written down: unchanged, and still a trade

Nothing built here improves this. Overriding `entrypoint:` still means recording what it
was, and that recorded value still drifts silently when the base image changes. **This
trades a rebuild for a pin, and the accounting above stands as written.**

What the implementation adds is a way to notice: `--report` prints the variable names
delivered and the program about to replace the process, on standard error, names only. A
container log then shows which entrypoint was actually invoked, so a drifted pin is visible
in the record rather than only in the failure it causes.

### Condition 3 — failure behaviour: settled, and it is the order of operations

Every check that can refuse runs before the one irreversible step, and the order is the
property rather than a detail:

1. Can this platform replace a process at all?
2. Is there a command to execute?
3. Is the token file present, and not world-readable?
4. Fetch.
5. Do the secrets produce usable variable names, with no collision (ADR-18)?
6. Only now, `exec`.

**If any of those fails, nothing is executed.** The exit codes make that legible to the
thing that actually reads them, which is a restart policy:

| Code | Meaning |
|---|---|
| `125` | `ciphr-run` failed. No child was started. |
| `126` | The command was found and could not be executed. |
| `127` | The command was not found. |
| anything else | The child's own code; the wrapper is gone by then. |

Borrowed from `docker run` and the shell rather than invented, so nobody has to learn a
third convention. `125` answers the question a wrapper otherwise makes unanswerable: *did
my service crash, or did it never start?*

Two refusals worth naming because they are not obvious failures:

- **An empty prefix is refused, not delivered as an empty environment.** `GET /v1/list`
  authorizes each path it would return, so "you may list nothing here" and "there is
  nothing here" are the same empty array. A service booting with no secrets because its
  token lacks a capability is the silent start this exists to prevent.
- **A world-readable token file stops the process**, mirroring the master-key check in
  `ciphr-crypto`. Group bits are left alone, for the reason given there.

### Condition 4 — prefix-to-variable-name semantics: ADR-18

Settled before either route was built, and shared: `ciphr-run` calls the rule in
`ciphr-core` rather than implementing it. See [ADR-18](0018-one-rule-for-the-variable-name.md).

---

## Three things this record did not anticipate

### No `unsafe` is needed, and the result is better than what was proposed

The proposal describes a wrapper that "sets them in its own environment" and then execs.
That needs `std::env::set_var`, which is `unsafe` in this edition and forbidden in every
crate here.

It is not needed. `Command::env` sets the environment of the image `exec` is about to
install, without this process ever mutating its own. **A secret therefore never appears in
`/proc/<pid>/environ` of the wrapper** — only in the service's, which is where it has to be
for an image that reads environment variables at all. The proposed version would have had a
window where both processes' environments held it.

The honest remainder: the `Command` map is not a zeroizing allocation and cannot be, because
the kernel needs a plain byte layout to build the new environment from. The window is
microseconds, in a process that then ceases to exist.

### The child can still read the token file, and no code here can change that

`exec` replaces the process image; it does not change the filesystem view. **The service
therefore inherits the ability to read `--token-file`**, and stripping environment variables
would not help, because the credential was never in the environment.

This is a real consequence of route B and it belongs in this record rather than in a
comment: **route B makes per-service token scoping matter more than it did.** A token scoped
to the prefix the service receives gives away nothing it did not already get. A per-host
token covering several services means a compromised service can read the others'. That was
true of the derived-image version of route B too — it is not a regression — but this record
is what a deployment reads, and it did not say so.

The mitigation available today is scoping, not code. `--path` exists partly for this: an
identity that names its secrets needs only `read`, which is the narrower grant.

### Anything without `exec` refuses rather than degrading

There is no non-Unix fallback. A `spawn`-and-wait would leave a supervisor alive holding
every value for the lifetime of the service, and collecting the signals meant for it — the
opposite of the reason this exists, offered under the same name. So the wrapper refuses,
before reading the token and before fetching, and says why.

That refusal is also why the crate still compiles on the development platform instead of
being gated out: a program that refuses is a program someone can run and be told why.
