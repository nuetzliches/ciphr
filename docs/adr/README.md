# Architecture decision records

**Status:** current as of 2026-08-23. Twenty-four records: twenty-two accepted — one of them in one
tier only — one deferred, and one proposed. Each file carries its own date and status.

One file per decision. Each records what was decided, why, and what was rejected — the rejected
options matter as much as the chosen one, because they are what a future reader would otherwise
propose again.

A decision is revisited by adding a new record that supersedes an old one, not by editing the old
one. The point of the format is that it keeps the reasoning as it was at the time, including the
parts that later turned out to be wrong.

| ADR | Decision | Status |
|---|---|---|
| [ADR-1](0001-language-rust.md) | Language: Rust (edition 2024) | Accepted |
| [ADR-2](0002-no-custom-configuration-dsl.md) | No custom configuration DSL | Accepted |
| [ADR-3](0003-policies-from-configuration.md) | Policies come from configuration, not the API | Accepted |
| [ADR-4](0004-no-bitwarden-compatible-api.md) | No Bitwarden-compatible API | Accepted |
| [ADR-5](0005-seal-static-key-from-environment.md) | Seal: static key from the environment, behind a trait | Accepted |
| [ADR-6](0006-auth-machine-identities-with-tokens.md) | Authentication: machine identities with tokens | Accepted |
| [ADR-7](0007-storage-sqlite-behind-a-store-trait.md) | Storage: SQLite behind a store trait | Accepted |
| [ADR-8](0008-tls-terminates-at-the-service.md) | TLS terminates at the service | Accepted |
| [ADR-9](0009-http-stack-axum-but-narrow.md) | HTTP stack: axum, but narrow | Accepted |
| [ADR-10](0010-port-4400.md) | Default port `:4400` | Accepted |
| [ADR-11](0011-ui-is-an-optional-separate-package.md) | The admin UI is an optional, separate package | Accepted; phase 5 |
| [ADR-12](0012-ui-auth-token-paste.md) | UI authentication: token paste in v1 | Accepted; phase 5 |
| [ADR-13](0013-mcp-separate-stateless-process.md) | MCP server: separate, stateless process | Accepted; post-v1 |
| [ADR-14](0014-ciphr-run-injects-into-a-child-process.md) | `ciphr run` injects secrets into a child process | Accepted; built as `ciphr-run` |
| [ADR-15](0015-honeypots-and-what-a-tripwire-may-do.md) | Honeypots, and what a tripwire may do | **Accepted** in the `alert` tier only; not built, phase 8 still waits on the review |
| [ADR-16](0016-leak-reports-are-a-one-way-drop-box.md) | Leak reports are a one-way drop box, matched through a blind index | **Deferred**; reopens if the endpoint would get a listener reachable without a token |
| [ADR-17](0017-certificate-provenance.md) | Certificate provenance: a private CA for machines, a public certificate for the browser | Accepted |
| [ADR-18](0018-one-rule-for-the-variable-name.md) | One rule for the environment variable name of a secret | Accepted |
| [ADR-19](0019-sdk-transport-blocking-ureq.md) | The SDK's transport: blocking, and unable to trust the public CA set | Accepted |
| [ADR-20](0020-optional-surface.md) | Optional surface, and the core it may not reach | Accepted; nothing implemented |
| [ADR-21](0021-a-scanner-is-a-sender-with-a-token.md) | A scanner is a sender with a token: leak reports arrive authenticated | **Proposed**; gives the leak machinery its first sender — ADR-16 stays deferred and anonymous |
| [ADR-22](0022-the-trail-records-what-consumed-an-authority.md) | The trail records what consumed an authority | Accepted; the metadata listings run read-only — no lock, no master key, no entry |
| [ADR-23](0023-the-control-plane-is-its-own-capability.md) | The control plane is its own capability | Accepted; `inspect` and `revoke` join the five secret verbs, and a secret capability under `sys/` is refused when the policy file loads |
| [ADR-24](0024-revocation-is-the-one-write-the-api-may-do.md) | Revocation is the one write the API may do | Accepted; one optional route behind `token_revoke`, `revoke` on `sys/tokens`, no master key — ADR-3 narrowed by a named exception |

Two of these carry more weight than the rest, because they describe the properties the project
exists for: ADR-1 (secrets cannot be logged) and ADR-9 (one path normalizer, shared by router and
policy evaluator). The audit design and the cryptographic design are not ADRs — they are
requirements, documented in [`../threat-model.md`](../threat-model.md) and the implementation plan.
