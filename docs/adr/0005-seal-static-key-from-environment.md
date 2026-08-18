# ADR-5 — Seal: static key from the environment, behind a trait

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-08-18 |
| **Affects** | `ciphr-crypto`, operations |

## Context

Some key has to live outside the database, or the database would decrypt itself. How that key
reaches the process at startup sets the security boundary of the whole system: split keys and
hardware modules raise it, an environment variable does not.

The competing requirement is unattended startup. A deploy must not depend on a human being
available to unseal the service.

## Decision

```rust
trait Seal {
    fn unseal(&self) -> Result<RootKey>;
    fn rewrap(&self, key: &RootKey) -> Result<SealedRootKey>;
    fn id(&self) -> &str;
}
```

v1 implements `StaticEnvSeal`, reading the master key from `CIPHR_MASTER_KEY`. `ShamirSeal`,
`Pkcs11Seal`, and `TransitSeal` are anticipated in the design but not built.

## Rationale

Unattended startup is the precondition for deploys that do not stall waiting for a person. The
master key therefore sits in the same mode-0600 service environment file that already holds other
signing secrets. That is **no regression** against the status quo — and also **no cryptographic
gain**: trust shifts onto file permissions and onto whatever mechanism distributes that file. This
is an availability decision, and it belongs in the README as one.

The trait is the substance of this ADR. Because the master key only wraps the root key, and the root
key wraps the per-version data keys, a change of seal mechanism re-wraps exactly **one** record.
Moving to a split key or an HSM later is a migration of a single row, not of every secret: no data
format change, no full re-encryption.

## Consequences

- **Root on the host reads the master key.** That is adversary A5 in the threat model and is
  deliberately outside it. The same is true of OpenBao with a static seal.
- The break-glass copy of the master key needs a home outside this system: a human-oriented password
  manager plus an offline copy. Losing it is total data loss.
- The master key must not sit in the same backup as the database. With it, the backup is a complete
  secret store; without it, the backup is inert.
- Key rotation is implemented as re-wrapping the root key, and is expected to be exercised, not
  merely to be possible.

## Rejected alternatives

**Shamir with manual unsealing in v1** — every restart would need a human, which defeats the purpose
of the system for automated deploys.

**Both mechanisms in v1** — two security-critical unseal paths, each needing full test coverage, at
a point where the rest of the system does not exist yet.
