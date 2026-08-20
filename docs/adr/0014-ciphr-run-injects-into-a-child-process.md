# ADR-14 — `ciphr run` injects secrets into a child process

| | |
|---|---|
| **Status** | **Proposed.** Decision required before phase 7; nothing is implemented |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-cli`, section 13 route B, phase 7 |

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

**Proposed, not accepted.** A `run` subcommand:

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
