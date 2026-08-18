# ADR-12 — UI authentication: token paste in v1, SSO afterwards

| | |
|---|---|
| **Status** | Accepted; implementation in phase 5 |
| **Date** | 2026-08-18 |
| **Affects** | `ui/`, identities |

## Context

The UI signs in humans, and the server so far only knows machine identities with bearer tokens
(ADR-6). A conventional web application would add a password login: a user table, password hashing,
a reset flow, lockout logic, sessions, cookies, and CSRF protection.

## Decision

Sign-in is pasting a personal token. The identity has `kind = "human"`, the token is issued through
the CLI with a short TTL, and it lives in `sessionStorage`. No password, no server-side session, no
cookie.

## Rationale

Token paste costs **zero new server code** — it is the same bearer authentication as for machines,
with an identity of a different kind. A local user store with password hashing, reset, and lockout
would be a second security-critical authentication path, added for a viewing tool. That is the wrong
effort-to-risk ratio, and it is why Argon2id does not appear anywhere in v1.

`sessionStorage` rather than `localStorage`, because a token that survives closing the tab becomes a
permanent secret on a shared workstation. No cookie, because without cookies the entire CSRF class
disappears.

## Consequences

- Human tokens are distributed by hand and have short lifetimes. That is friction, and it is the
  reason SSO is next rather than eventual.
- A revealed secret and the token both live in a browser tab, which is why the UI is read-only with
  single-value reveal, serves a strict CSP, uses no `v-html` (CI gate), and registers no service
  worker. Adversary A7 in the threat model is the browser context itself.
- Signing out is closing the tab; there is no server-side session to invalidate. Revoking the token is
  a CLI operation and takes effect immediately.

## After v1

The forge acts as an OAuth2/OIDC provider for UI login. That inherits MFA and account lockout from
the forge and removes the last manually distributed human token. It uses **the same** OIDC validation
as the Actions authentication method — one implementation, two callers — which is why the order
"Actions OIDC first, then UI SSO" is also the cheaper one.

## Rejected alternatives

**Local passwords.** A second authentication path, as above.

**Forge SSO immediately.** It would pull the OIDC work forward and couple UI login to forge
availability before the core is finished.
