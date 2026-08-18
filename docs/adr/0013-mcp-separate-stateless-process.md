# ADR-13 — MCP server: a separate, stateless process speaking Streamable HTTP

| | |
|---|---|
| **Status** | Accepted; post-v1, not implemented |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-mcp` (future), API requirements for v1 |

## Context

An MCP server would make ciphr accessible to agents: "which secrets does service X have?", "who
accessed `infra/**` last week?", "is the audit chain intact?". That is genuinely useful, and it is
mostly an inventory and audit use case — the area where an agent adds value without plaintext ever
needing to flow.

It is recorded now, before implementation, so that v1 does not build anything that blocks it.

## Decision

A separate `ciphr-mcp` binary in its own container, speaking **Streamable HTTP** (the current MCP
transport, not the superseded HTTP+SSE). **Stateless**: no server-side session state, no session
identifier bound to local storage, every request authorized on its own. It is a **pure client** of the
public v1 API — no database access, no master key, no cryptography.

## Rationale

Statelessness here is not merely an MCP convention but a security property: a server that holds no
session state cannot hold a token or a revealed secret between requests. There is no cache to read
out. It is also restartable at will and replicable, should that ever be needed.

Being a pure API client upholds the guarantee from ADR-11: **exactly one process in the system holds
plaintext secrets and key material.** The UI and the MCP server are interchangeable attachments.

## The LLM-specific hazard

Everything an MCP tool returns lands in a model context and potentially in a provider's logs. That is
a trust boundary the HTTP API does not have, and it shapes the design:

- The MCP server holds **no identity of its own**. The caller's token is passed through per request,
  authorized against **their** policy, and audited under **their** identity. A service identity with
  broad access would be a confused deputy, and the audit trail would show the same meaningless
  identity for every access.
- **Plaintext is opt-in, not the default.** Default tools return metadata, listings, and audit
  queries only, so an agent can explore the entire inventory without a single value flowing.
- Plaintext reads require a policy that **explicitly** permits them, on narrowly scoped paths. The
  mechanism is a dedicated capability — a regular member of the capability set, not a special case in
  the evaluator, so evaluation stays a single code path.
- Every such retrieval produces one audit entry, additionally marked with the MCP context, so it stays
  possible to distinguish afterwards what a human read from what flowed into a model.

## What v1 must get right for this

None of these is extra work; they are properties v1 should have anyway, recorded here as commitments.

1. A complete `openapi.yaml` from phase 3 — the MCP server is derived from it, not written alongside
   it.
2. Audit queries with usable server-side filters in the API, not just `tail` in the CLI. Without them
   the MCP server would search client-side and pull large volumes into the model context.
3. Metadata access without value access — existence, version, and timestamps for a path without
   decrypting the value. The UI's secret browser needs the same thing.
4. No server state that presupposes a session. Already true, since bearer authentication is stateless.

## Rejected alternatives

**An MCP endpoint in the main server.** Same reasons as ADR-11, plus one: MCP clients are LLM-driven
and therefore the least predictable request source in the system.

**stdio transport only.** Works on the same machine; the goal is network clients.

**HTTP+SSE.** Superseded by Streamable HTTP.

**A stateful MCP server with sessions.** Session state is exactly the cache that could leak a token or
a revealed value.
