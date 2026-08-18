# ADR-9 — HTTP stack: axum, but narrow

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-server`, `ciphr-core`, `ciphr-policy` |

## Context

An earlier version of this design hand-rolled routing directly on `hyper`, on the grounds that a
secret manager should carry as few dependencies as possible. That instinct is right in general and
wrong here.

## Decision

`axum` on `hyper`, `rustls` for TLS, `rusqlite` for storage. No `sqlx`, no broad `tower-http`
middleware stack — each middleware layer is a separate decision with a written reason.

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
