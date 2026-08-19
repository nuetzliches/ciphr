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

**Correction from implementation (2026-08-18).** The sketch above is what this decision was written
with; the implemented `unseal` takes the wrapped record as an argument, because unsealing needs a
record that lives in the store, and a seal that reached into the store would invert the dependency.
The decision — a static key behind a trait — is unchanged; only the signature was wrong. The
implemented trait is in `crates/ciphr-crypto/src/seal.rs`.

## Extension (2026-08-19): the key may also come from a file

The master key may be read from a **file** as well as from an environment variable. Configured as
`[seal] type = "static_file"` with a `path`, or `--master-key-file` on the CLI.

**Why this is an extension and not a new decision.** What ADR-5 decides is a *static* key, behind a
trait, so that startup needs no human. Where that key is read is a property of one implementation, not
of the mechanism: the key bytes are identical either way, and a store sealed through one source opens
through the other. Recording it as a separate ADR would suggest the seal decision changed, and would
split the reasoning about one topic across two files. Shamir and PKCS#11 *will* get their own ADRs,
because those change the trust model — a human or a device becomes necessary. A file does not.

**Why it is worth doing at all.** Section 13 of the plan tells consumers not to pass secrets through
`environment:`, because the value is baked into the container configuration at creation and is
readable through the runtime's inspect API — by every principal with access to the runtime socket,
which is a broader set than root. ciphr was doing exactly that with its own master key. A secret
manager whose own deployment contradicts its own guidance is hard to argue for, and that is the
stronger half of the reason.

Concretely, the file source removes two exposures:

- the key is not in the container configuration, so it does not appear in inspect output;
- the key is not in `/proc/<pid>/environ` of the ciphr process.

**What it does not buy, stated so nobody reads more into it.** Root on the host reads the file just as
it read the variable — adversary A5 is unchanged, and this does not move that boundary. The key is in
process memory either way. The number of secrets on the host is still one. And **whether the key is at
rest on disk depends on the runtime**: Swarm secrets and Kubernetes secret volumes are memory-backed,
while plain Compose outside Swarm bind-mounts a real file. The second case is still an improvement —
a file can carry permission bits and the container configuration cannot — but it is not "never at
rest", and a deployment has to know which case it is in.

**Consequent rules.**

- **Both sources cannot be configured at once.** The configuration is a tagged enum with one variant,
  and the CLI refuses the two flags together. There is deliberately no precedence rule: a rule about
  which source wins is a rule that lets a deployment use the key nobody thought was active.
- **A world-readable key file stops the process.** Not a warning — a warning in a startup log is a
  warning nobody reads. Group bits are not checked: root-owned and read by a service group is a
  legitimate arrangement, and refusing it would push deployments towards running as root. Windows has
  no equivalent bit and no check runs there, which is documented rather than silently skipped.
- **Surrounding whitespace is trimmed**, so a file written with `echo` is not a different key from one
  written with `printf %s`.
- **No URL-style source prefix.** OpenBao expresses this as `env://` and `file://` in one string.
  Parsing a source out of a string is the kind of hand-written parsing ADR-2 rejected for policies,
  and the same argument applies to configuration: the source is a typed variant.
- **The recorded seal identifier is now `static`** rather than `static_env`, because it names the
  mechanism and not the source. `static_env` is accepted as equivalent when opening an existing store
  and is replaced the next time the root key is re-wrapped. `/v1/health` reports the source this
  process used separately, since the two legitimately differ while a deployment moves between them.

The bootstrap rule is untouched by all of this: the master key must never come from ciphr itself,
whether as a variable or as a file.

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
