# Architecture decision records

**Status:** current as of 2026-08-19. Seventeen decisions: fourteen accepted, three proposed.
Each file carries its own date and status.

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
| [ADR-14](0014-ciphr-run-injects-into-a-child-process.md) | `ciphr run` injects secrets into a child process | **Proposed**; decide before phase 7 |
| [ADR-15](0015-honeypots-and-what-a-tripwire-may-do.md) | Honeypots, and what a tripwire may do | **Proposed**; decide before phase 8 |
| [ADR-16](0016-leak-reports-are-a-one-way-drop-box.md) | Leak reports are a one-way drop box, matched through a blind index | **Proposed**; decide before phase 9 |
| [ADR-17](0017-certificate-provenance.md) | Certificate provenance: a private CA for machines, a public certificate for the browser | Accepted |
| [ADR-18](0018-one-rule-for-the-variable-name.md) | One rule for the environment variable name of a secret | Accepted |

Two of these carry more weight than the rest, because they describe the properties the project
exists for: ADR-1 (secrets cannot be logged) and ADR-9 (one path normalizer, shared by router and
policy evaluator). The audit design and the cryptographic design are not ADRs — they are
requirements, documented in [`../threat-model.md`](../threat-model.md) and the implementation plan.
