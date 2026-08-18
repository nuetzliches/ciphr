# ADR-4 — No Bitwarden-compatible API

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | API surface, cryptographic design |

## Context

An existing open-source server (Vaultwarden) implements the Bitwarden server API, and adopting that
API would bring a mature ecosystem of clients — browser extensions, mobile apps, a desktop UI — at
no development cost. It is the obvious thing to consider before designing an API of one's own.

## Decision

A small API of our own, documented in `openapi.yaml`.

## Rationale

Two independent reasons; the second is the actual one.

*Size.* Vaultwarden needs roughly **1.26 MB of Rust** for the Bitwarden server API and still does
not implement all of it. `organizations.rs` alone is 112 KB, `ciphers.rs` 78 KB, `accounts.rs`
63 KB, plus modules for emergency access, sends, two-factor authentication, push notifications, and
icon fetching. That is the size of an entire mid-sized workspace, spent on foreign compatibility,
and all of it would have to be maintained against upstream changes.

*Architecture.* Bitwarden is zero-knowledge by design. Per its security whitepaper, encryption
happens on the client, and "the server never stores and cannot access your master password or your
cryptographic keys." A server that cannot decrypt cannot hand a plaintext secret to a CI job that
authenticates with nothing but a token. Every consumer would have to hold key material, which makes
per-identity access control cosmetic and reduces the audit trail to "who fetched which blob" — and
once fetched, that blob stays decryptable offline forever, with no server-side revocation.

This is exactly the property that also ruled out file-based encryption tools such as SOPS: whoever
holds the key decrypts without leaving a trace.

## Consequences

- No existing client works out of the box. The clients are the CLI, the SDK, `curl`, and the
  read-only UI — all of which are ours to keep small.
- Human password management is explicitly out of scope; a dedicated password manager is the right
  tool for it, and this project does not compete with one.
- Zero-knowledge is not available as a later option either. That follows from the goal of
  server-side auditing, and it belongs in the README as a boundary rather than a gap.

## Rejected alternatives

**Bitwarden API compatibility**, as above.

**Folding this need into an existing password manager** — the same conflict, and it would put
machine credentials into a system built for humans.
