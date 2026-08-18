# ADR-11 — The admin UI is an optional, independently deployable package

| | |
|---|---|
| **Status** | Accepted; implementation in phase 5 |
| **Date** | 2026-08-18 |
| **Affects** | `ui/`, `ciphr-server`, deployment |

## Context

The audit trail is the reason this project exists, and an audit trail that can only be read through a
CLI will not actually be read. So there will be a web UI. The question is where its code runs.

The convenient answer is to embed the built assets in the server binary (`rust-embed` or similar):
one artifact, one container, one port, a route that can be switched off.

## Decision

The UI is **not** embedded in the server binary. It is a static bundle shipped as its own container
image (`ciphr-ui`, a static file server) that talks to the ordinary public API over HTTPS from the
browser. The server has no `serve-ui` mode, no template engine, and no cookie or session code.

## Rationale

Three reasons, in order of weight.

*Attack surface.* Embedded asset serving brings static file handling, content-type sniffing, caching
headers, and cookie and CSRF questions into precisely the process that holds plaintext secrets. A
directory-traversal bug in an asset handler would then be a bug in the secret server. Kept separate,
the worst UI bug is a bug in a container that owns nothing but HTML.

*Optionality that is real rather than nominal.* "Optional" should mean that whoever does not deploy
the UI does not **run its code** — not merely that a route is disabled. The service is fully
functional without the UI; the UI is an additive stack.

*Independent release cadence.* A UI fix — an npm advisory, a layout change — does not force a new
server image and therefore no restart of the secret server. That coupling would be most expensive for
exactly the service whose restart demands the most care.

## Consequences

**Consequent rule, binding:** the UI uses **only** documented v1 endpoints. An endpoint that exists
solely for the UI is a design error, and the CLI must be able to do everything the UI can. That keeps
the API honest and the UI replaceable.

- The UI needs no volume, no environment file, and no access to the database or the master key.
- Because the browser talks to the API directly, the origin question has to be settled: same-origin
  routing through the reverse proxy (`/` to the UI container, `/v1/*` to ciphr) avoids CORS entirely
  and is the recommendation; a separate hostname would require a narrow CORS allowlist on the server.
- `ui/` has its own dependency budget and its own `npm audit`, separate from the Rust budget.
  Frontend dependency sprawl would otherwise quietly undercut the supply-chain discipline applied to
  the server.
- Phase 5 is only done when the server stack demonstrably runs **without** the UI container.

## Rejected alternatives

**`rust-embed` into the server binary.** Single-artifact convenience, but it violates all three points
above.

**A UI with its own backend-for-frontend.** Another service that sees plaintext secrets — precisely
what the separation is for.
