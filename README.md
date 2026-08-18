# ciphr

A small secret manager for machine identities: key/value secrets, gap-free access auditing,
and path-based authorization. The name contains *CI* — the primary consumer is a build and
deploy pipeline, not a human.

> **Status: design phase.** No code yet. The full design lives in
> [`.claude/plans/PLAN.md`](.claude/plans/PLAN.md).

## Why this exists

Storing deployment secrets as forge secrets and rendering them into `.env` files works, but it
cannot answer three questions:

1. **Who read which secret, and when?** There is no access log.
2. **Can service A's runner reach service B's secrets?** Yes, and nothing prevents it.
3. **Where is the authoritative value?** In two places at once — the forge and the host.

ciphr answers all three. It is deliberately small: key/value secrets, an audit trail, and
policies. No PKI, no SSH CA, no dynamic secrets. If those are ever needed,
[OpenBao](https://openbao.org/) is the right answer rather than this project.

## Design in one screen

- **Envelope encryption.** A master key from the environment wraps a root key; the root key
  wraps one data encryption key per secret *version*. One key encrypts exactly one payload, so
  nonce reuse — the best-known AES-GCM footgun — cannot occur. Path and version are bound as
  additional authenticated data, so a ciphertext cannot be moved from one path to another.
- **Fail-closed auditing.** If no audit device accepts the record, the request is refused and
  no secret is served. Entries form a hash chain, so tampering is detectable rather than
  merely unlikely. The server refuses to start without an audit device.
- **Deny by default.** Path-based capabilities with glob matching. Policies come from
  configuration under version control, not from a write API — so the commit history is itself
  an audit trail.
- **Secrets cannot be logged.** Secret-bearing types implement neither `Debug`, `Display` nor
  `Serialize`, which makes logging one a compile error rather than a code-review question.
  This is the main reason the implementation language is Rust.
- **Runner-agnostic CI access.** The API is HTTPS plus a bearer token, so the minimal client
  is `curl`. No agent, no plugin, no forge integration required.

## Non-goals

A password manager for humans, Bitwarden API compatibility, feature parity with Vault,
multi-tenancy, and high availability. The reasoning for each is in section 1 of the plan.

## Honest boundaries

Root on the host reads the master key and process memory. That is a deliberate consequence of
unattended startup and is not defended against; moving that boundary requires Shamir unsealing
or an HSM, both of which are retrofittable without a data format change. The full threat model
is section 3 of the plan.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at
your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
