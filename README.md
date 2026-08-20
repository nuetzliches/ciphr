# ciphr

A small secret manager for machine identities: key/value secrets, gap-free access auditing,
and path-based authorization. The name contains *CI* — the primary consumer is a build and
deploy pipeline, not a human.

> **Status: v0.3.0 released.** Usable end to end: envelope encryption with master key rotation,
> SQLite with migrations, the policy evaluator, the fail-closed hash-chained audit trail, the HTTPS
> API with token authentication, and the `ciphr` CLI. Since v0.1.0: the audit anchor and the
> retention cut that bounds the trail (`ciphr audit anchor`, `ciphr audit cut`), one rule for
> turning a path into an environment variable name, `ciphr-sdk` for a service that fetches its own
> secrets, and `ciphr-run` for an image that only understands environment variables. The read-only
> browser viewer in [`ui/`](ui/) ships as its own image and is released on its own cadence. Since
> v0.2.0: a secret nobody classified says so instead of claiming to be safe to rotate, the class is
> on the wire and in the viewer, and setting one is recorded in the audit trail.
> **This is the artifact the external review is performed against, not a production release — and
> that review has not happened.** Until it does, the three crates that decide every access are
> verified by nobody but their author, and a deployment holding real secrets before then has
> accepted that risk rather than met a condition
> ([`docs/security-review.md`](docs/security-review.md)). The full design lives in
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
- **The viewer is a separate container, and read-only.** It cannot write a secret, change a policy,
  or issue a token, and the server has no mode that serves it — so asset handling never runs in the
  process that holds plaintext ([ADR-11](docs/adr/0011-ui-is-an-optional-separate-package.md),
  [`docs/ui.md`](docs/ui.md)). Sign-in is a pasted token in `sessionStorage`; there is no cookie, so
  there is no CSRF class to mitigate.
- **TLS terminates at the service, not at the reverse proxy.** This deviates from the usual
  arrangement on purpose: the content of these connections is plaintext secrets, and a compromised
  container on a shared network is a realistic adversary. The proxy connects over HTTPS with a
  pinned internal certificate ([ADR-8](docs/adr/0008-tls-terminates-at-the-service.md)).

## Non-goals

A password manager for humans, Bitwarden API compatibility, feature parity with Vault,
multi-tenancy, and high availability. The reasoning for each is in section 1 of the plan.

## Honest boundaries

Root on the host reads the master key and process memory. That is a deliberate consequence of
choosing unattended startup — an availability decision, not a cryptographic one: the key sits in the
same mode-0600 environment file as other signing secrets, which is no regression against the status
quo and no gain either. Moving that boundary requires split-key unsealing or an HSM, both of which
are retrofittable without a data format change, because the master key wraps exactly one record.

**A secret that has left ciphr is the pipeline's problem.** The audit trail records that a runner
read a value, not what the runner did with it afterwards — and no forge masks a value fetched at
runtime, only its own native secrets. A bare `curl | jq` therefore puts secrets in the job log the
moment anyone adds `set -x`, and that log is usually readable by more people than the secret store
is. This is why masking is part of the product rather than of the documentation: `export --format
actions-env` emits `::add-mask::` for every value before it emits anything else. The name contains
*CI*, so the integration is not an afterthought to the security model — it is where most of the
remaining risk lives. Read [`docs/operations/cli.md`](docs/operations/cli.md) before writing the
first workflow.

The realistic end state is **one secret per host**, not zero — plus an audit trail, plus rotation,
plus a bounded blast radius per token. The full threat model, including everything else that is
deliberately out of scope, is in [`docs/threat-model.md`](docs/threat-model.md).

## Documentation

| Where | What |
|---|---|
| [`docs/`](docs/README.md) | The documentation index, including a table of risk areas |
| [`docs/adr/`](docs/adr/) | The 21 architecture records, one file each, with what was rejected and why |
| [`docs/crypto.md`](docs/crypto.md) | The implemented key hierarchy and wire format, and what the tests establish |
| [`docs/authorization.md`](docs/authorization.md) | The policy file, the pattern language, and the four rules of the decision |
| [`docs/security-review.md`](docs/security-review.md) | What an external reviewer should attack, and what would falsify each claim |
| [`docs/operations/cli.md`](docs/operations/cli.md) | Every `ciphr` command, and the two rules that shape all of them |
| [`docs/operations/upgrade.md`](docs/operations/upgrade.md) | What each version's breaking changes require, and the backup rule that holds for all of them |
| [`docs/operations/wrapper.md`](docs/operations/wrapper.md) | `ciphr-run`: where to get it, what its exit codes mean, and what it does not solve |
| [`docs/ui.md`](docs/ui.md) | The viewer: what it shows, what it refuses to do, and how it is deployed |
| [`openapi.yaml`](openapi.yaml) | The HTTP API |
| [`docs/operations/`](docs/operations/) | Procedures for what is hard to undo: the master key, and rotating secrets that break things |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversaries, defended and undefended boundaries, the availability trade |
| [`docs/why-build-this.md`](docs/why-build-this.md) | The evaluation of existing tools, and the condition under which this project should be abandoned in favour of OpenBao |
| [`AGENTS.md`](AGENTS.md) | Working rules for contributors, and the gates that enforce them |
| [`SECURITY.md`](SECURITY.md) | Disclosure process and what is in scope |
| [`.claude/plans/PLAN.md`](.claude/plans/PLAN.md) | The full specification: 23 sections, from the cryptographic design to the phase plan |

## Building

```sh
cargo test --workspace       # the toolchain pin in rust-toolchain.toml is installed automatically
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The viewer is its own package with its own toolchain and its own dependency budget:

```sh
cd ui && npm ci && npm run build      # type checks with vue-tsc, then builds
sh ci/check-ui-budget.sh              # one runtime dependency, no install scripts, integrity hashes
```

The complete set of blocking checks, including the supply-chain and source-rule gates, is listed in
[`AGENTS.md`](AGENTS.md).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at
your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
