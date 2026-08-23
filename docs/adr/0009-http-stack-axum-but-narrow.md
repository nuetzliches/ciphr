# ADR-9 — HTTP stack: axum, but narrow

| | |
|---|---|
| **Status** | Accepted; **amended 2026-08-23** — "narrow" describes the artefact, `h2` is compiled in and never negotiated, and the ALPN list is set here rather than by a dependency |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-server`, `ciphr-core`, `ciphr-policy` |

## Context

An earlier version of this design hand-rolled routing directly on `hyper`, on the grounds that a
secret manager should carry as few dependencies as possible. That instinct is right in general and
wrong here.

## Decision

`axum` on `hyper`, `rustls` for TLS, `rusqlite` for storage. No `sqlx`, no broad `tower-http`
middleware stack — each middleware layer is a separate decision with a written reason.

### Amended 2026-08-23: "narrow" describes the artefact, and HTTP/2 is in it

**This record described the manifest and was read as describing the binary.** `axum` is declared with
`default-features = false, features = ["http1", "json", "query", "tokio"]`, and that is exactly what
resolves. But `axum-server` requests `hyper` with `features = ["http1", "http2", "server"]`
unconditionally — not optional, not behind a feature of its own, and not reachable through our own
`default-features = false` on it. So `hyper` resolves with `http2` and `h2` is in the tree, and its
`RustlsConfig::from_pem` set `alpn_protocols = ["h2", "http/1.1"]` where nothing in this repository
mentioned ALPN at all.

Issue #6 read that out of the sources; `crates/ciphr-server/tests/tls_alpn.rs` measured it against a
real handshake and **the reading was right**: the listener negotiated `h2`, and an HTTP/2-only client
got a working connection.

**What was decided.** `crate::tls::load` now sets the ALPN list itself — `http/1.1` and nothing else —
and the test above pins the negotiated protocol so that a dependency bump restoring `h2` fails in CI
rather than in a deployment. `h2` stays *compiled in*, because removing it means dropping
`axum-server` for our own accept loop and graceful shutdown, which is code on the connection path that
we would then have to review ourselves — the trade this record made in the other direction, and not
one to reverse for a protocol that is now never negotiated.

**So the honest statement of "narrow" is: narrow in what the listener will speak, and one framing
implementation compiled in that it will not.** The distinction matters because
`docs/security-review.md` records what the accepted review read, and `h2` was never on that list.

`crate::tls` is also the only place that could state a TLS version or cipher policy, and it states
neither — rustls' defaults stand. That is unstated rather than considered and rejected, and the module
says so.

## Rationale

Authorization in this system is **path-based**. Any divergence between how the router normalizes a
request path and how the policy evaluator normalizes it is an authorization bypass: a request that
routes as `infra/a/secret` but evaluates as something else grants access nobody wrote a rule for.
Hand-written path matching is its own class of bug, and this is the worst possible place for it.

A widely used, well-tested router is safer here than a few dependencies fewer. The dependency budget
is better spent at the storage layer and on middleware, where the code we would otherwise write is
less dangerous.

## Consequences

**Consequent rule, binding:** path normalization exists **exactly once** in the codebase, in
`ciphr-core`, and both the router and the policy evaluator call it. A second normalizer — anywhere,
for any reason — is the same class of bug and is treated as such in review.

- That rule is a testing requirement: property tests establish that normalization is idempotent, and
  a fuzzer runs against it.
- Catch-all routes must never be parsed for suffixes. A route `/v1/secrets/*path` cannot also serve
  `/v1/secrets/<path>/versions`, because a secret literally named `foo/versions` would then be
  indistinguishable from the version listing for `foo`. Every operation gets its own prefix, which is
  why the API has `/v1/versions/*path`.
- Middleware order is explicit and reviewed: authentication, then authorization, then the handler,
  with the audit record written before the response is produced.

## Rejected alternatives

**Hand-rolled routing on `hyper`.** Fewer dependencies, but it puts the most security-critical string
handling in the system into code that only we review.

**A full `tower-http` middleware stack.** Convenient, but it would pull tracing, compression, and
asset handling into the process that holds plaintext secrets. Layers are added individually, with a
reason.
