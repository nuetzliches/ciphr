# ADR-6 — Authentication: machine identities with tokens

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-server`, CI integration |

## Context

The primary consumers are build and deploy jobs, not people. Whatever authenticates them has to
work on any runner, without a forge-specific agent, and it has to attribute every access to
something more specific than "the pipeline" — otherwise the audit trail says nothing useful.

## Decision

Identities with assigned policies, authenticated by bearer tokens. Authentication methods sit behind
a trait so that OIDC federation can be added without touching the surrounding code.

Token format: `cph_<id:8><secret:43 base64url>`. Stored is `HMAC-SHA256(pepper, secret)`, where the
pepper derives from the root key.

## Rationale

A bearer token over HTTPS is the one mechanism that works identically everywhere: the minimal client
is `curl`. It reduces the number of long-lived secrets held in a forge to **one per repository or
host** — the bootstrap token — with everything else moving into ciphr.

Every access is attributed to an identity, which is what makes the audit trail meaningful in the
first place. One identity per repository is the granularity that makes an entry readable as
"repository X read secret Y".

On storage: tokens carry 256 bits of entropy, so password hashing would be the wrong tool. Argon2id
would cost CPU time on every request and buy nothing where no dictionary attack is possible. An HMAC
with a pepper derived from the root key means a database-only leak does not permit offline
verification, because reconstructing the pepper needs the master key.

The `cph_` prefix is deliberate: secret scanners recognize prefixed tokens, so a token committed by
accident gets found instead of quietly rotting in a repository. The leading, non-secret `id` allows
a direct database lookup instead of a scan over HMACs; the secret part is then compared in constant
time.

## Consequences

- Tokens have TTLs and need rotation. CI tokens get shorter lifetimes than the deploy runner's,
  because they are spread across more systems.
- A leaked token is valid until it is revoked or expires. Revocation is a database write and takes
  effect immediately — which is a property zero-knowledge designs cannot offer (ADR-4).
- Token comparison, HMAC comparison, and tag comparison are constant-time. That is a test
  requirement, not a code-review note.
- The audit trail records a token's non-secret `id`, never the token.

## Rejected alternatives

**OIDC federation in v1.** It is better from a security standpoint — no long-lived secret at all —
and it is concretely implementable: Forgejo has issued OIDC ID tokens for Actions since v15.0
(workflow key `enable-openid-connect`, runner newer than v12.5.0), and GitHub Actions issues them
even to self-hosted runners. It stays out of v1 because it is a second security-critical
authentication path, and it is first on the post-v1 list. The token route is needed regardless, for
runners and hosts that cannot federate.

**mTLS.** Would require a certificate authority — exactly the piece of PKI that the non-goals keep
out of this project.
