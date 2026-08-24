# ADR-19 — The SDK's transport: blocking, and unable to trust the public CA set

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-20 |
| **Affects** | `ciphr-sdk`, `deny.toml`, phase 7, ADR-14 |

## Context

`ciphr-sdk` was a doc comment and no code until phase 7 needed it. The workspace had no HTTP
*client* and no client-side TLS: `rustls` is here for the listener (ADR-8), and the CLI reads the
store directly rather than over the network. So the first line of the SDK is a dependency decision,
and AGENTS.md requires that to be a reviewed one.

Three things constrain it, and together they leave less room than the usual "pick an HTTP client"
question:

1. **The caller is a container start.** Route C is an application fetching its own secrets during
   startup (plan section 13). One request, then the client is idle for the life of the process.
2. **The same client has to work inside `ciphr run`** if ADR-14 is accepted — a statically linked
   binary bind-mounted into a foreign image, with a size budget.
3. **ADR-17 pins the machine path on a private CA.** `--cacert` *replaces* the trust store for that
   call rather than extending it. A client that trusted the WebPKI would trust every public root on
   the one hop whose content is plaintext secrets.

## Decision

**`ureq` 3.4, `default-features = false`, `features = ["rustls-no-provider"]`.**

Measured in this workspace on 2026-08-20 rather than assumed:

| | new crates | TLS stacks in the graph | `cargo deny check` |
|---|---|---|---|
| `ureq`, `rustls-no-provider` | **5** — `base64`, `log`, `ureq`, `ureq-proto`, `utf8-zero` | one; it reuses the existing `rustls` 0.23.43 and `ring` | **all four checks pass** |
| `reqwest` 0.13, `rustls-no-provider` + `blocking` | ~119, including `tokio`, `hyper`, `h2`, `tower`, `icu_*`, `idna` | one, plus an async runtime | **`bans` fails** — duplicate `syn`, needing a `skip` entry |

**`rustls-no-provider` is the substance of the choice, not a size saving.** That feature set pulls in
no `webpki-roots`, and ureq then *refuses* rather than falling back: with no root certificates
configured it panics with "WebPki is disabled. You need to explicitly configure root certs on
Agent". The trust anchor is consequently a required constructor argument in
[`Client::builder`](../../crates/ciphr-sdk/src/client.rs), and there is no code path — present or
future — that reaches the public root set, because the public root set is not linked into the binary.
ADR-17 becomes a property of the build instead of a rule someone has to remember.

**No redirects, added 2026-08-22.** The transport story above was about which certificates
the client will accept, and it left the client following whatever redirect it was handed —
finding F7 of [../review-2026-08-21-current-tree.md](../assurance/reviews/review-2026-08-21-current-tree.md).
`ureq` strips the authorization header across those boundaries, so the bearer token was never
at risk; a redirected plaintext response substituted for a secret is the failure, and a
consumer that fetches its own secrets at startup is the code path least likely to notice one.
The agent is now built with `max_redirects(0)`. This API has no redirect contract, so
following a 3xx preserves nothing and can only resolve a transport failure on the caller's
behalf; the response reaches them instead, named as a redirect that was not taken.

This amends the record rather than changing the decision: the reason for a narrow transport
is the one written above, and this is a door in it that the original entry did not name.

The crypto provider is passed to the client explicitly rather than installed as the process default.
A library that installs a process-wide `CryptoProvider` overrides a decision the consuming
application may have made for itself.

**Blocking, not async.** The call is one fetch at startup. An async runtime in every consuming
application would be a dependency with nothing behind it, and `ciphr run` is a single-purpose static
binary where it would be pure weight. A service that runs a runtime of its own calls this before
starting it, or from a blocking task — the direction that costs the caller nothing, whereas an async
client costs every caller that has no runtime.

**One dev-dependency comes with it: `rcgen`**, for the end-to-end test. That test needs a real
certificate for a real handshake, and the alternative was a committed key pair — test fixture
material that looks like real key material, which AGENTS.md rules out. It would also be the one file
here whose leak nobody would treat as an incident, which is how a real one gets ignored. `rcgen` is
rustls's sibling project and reuses the `ring` provider already in the graph.

## Why not a hand-written HTTP client

It was considered, because `rustls` was already here and the surface is a handful of requests. It is
rejected on the same grounds ADR-2 rejects a custom policy DSL and ADR-9 rejects a second path
normalizer: the result would be hand-written HTTP/1.1 framing inside the process that holds
plaintext. `ureq` delegates that to `httparse`, the parser hyper uses. Response framing is the boring
code where an edge case becomes a security bug, and this project's standing position is not to write
that class of code twice.

## Consequences

- **`cargo deny` needs no new exception.** Measured, not hoped: all four checks pass with the
  dependency added, and the `x86_64-unknown-linux-musl` target already in `deny.toml` covers the
  static-binary case ADR-14 would need.
- **A client cannot be built without a trust anchor, a token, and an `https` URL.** Three required
  arguments, each refusing a different way of being wrong. `http://` is refused outright: the payload
  is plaintext secrets.
- **A deployment that ever fronts ciphr with a public certificate needs a decision, not a flag.**
  This client cannot verify one. That is intentional — ADR-17 gives the public certificate to the
  browser path only — and it means the SDK does not silently accommodate a topology change nobody
  recorded.
- **`ureq` is pre-1.0 with respect to its rustls surface.** The `unversioned_rustls_crypto_provider`
  name says so: ureq will not bump its major version for a rustls change. A rustls minor bump can
  therefore be a compile break here. Acceptable for one call site in one crate, and named so that it
  is not a surprise.
- **The SDK sets no environment variable**, and it turns out it cannot: doing so is `unsafe` in
  edition 2024 and every crate here forbids `unsafe_code`. This was not planned, and it is the better
  answer — a value read straight out of the returned mapping never reaches
  `/proc/<pid>/environ` at all, which is the exposure route C otherwise still has. `ciphr run` sets
  the environment of a *child*, through `Command::env`, which needs no `unsafe`.

## Rejected alternatives

**`reqwest`.** The most familiar option, and it fails the supply-chain gate this project already
enforces: a duplicate `syn` needing a `skip` entry, plus `tokio` and `hyper` in the dependency graph
of every service that wants to read a secret at startup. Nothing it offers — connection pooling
across many requests, HTTP/2, streaming — is used by one fetch at startup.

**`ureq` with the plain `rustls` feature.** One character shorter in `Cargo.toml` and it would link
`webpki-roots`, making "trust the public CA set" reachable by deleting one builder call. The
narrower feature makes the wrong thing impossible rather than merely undone.

**Wait for phase 7 and decide then.** The condition ADR-14 lists is the *naming* rule (now ADR-18),
not the transport. Deferring this one only means writing route C twice.
