# ciphr

A small secret manager for machine identities: key/value secrets, gap-free access auditing,
and path-based authorization. The name contains *CI* — the primary consumer is a build and
deploy pipeline, not a human.

> **Status: v0.12.1 released.** Usable end to end: envelope encryption with master key rotation,
> SQLite with migrations, the policy evaluator, the fail-closed hash-chained audit trail, the HTTPS
> API with token authentication, and the `ciphr` CLI. **v0.11.0 is the release that made the consumer
> side reachable**: `ciphr-ci` ([ADR-25](docs/adr/0025-the-ci-side-fetch-is-its-own-binary.md)) fetches
> a set of secrets on the CI side and registers a mask for every value before it writes any of them,
> which is the thing an SDK inside the build could not do. Images and binaries are multi-architecture,
> one tag, one digest to pin.
>
> **v0.12.0 finishes the review that v0.11.0 started.** All fourteen findings of
> [the full-repository review](docs/assurance/reviews/review-2026-08-24-full-repository.md) are
> answered. Six change something a deployment can observe and **five of those are a rule to rewrite**:
> an export takes at most 256 paths, an audit device is named by a label rather than by its path,
> `status` can read `degraded`, a device that misses a record is stopped and says so, and a refused
> request from an authenticated caller now leaves an entry.
>
> **Pin `0.12.1`, and take `ui-v0.3.3` with it.** The viewer moves separately (ADR-11), and that tag
> is the first one that reads the two states `0.12.0` added — `ui-v0.3.2` shows a stopped audit device
> as `refused` and a degraded service as green, because it was tagged before that code was merged.
>
> **Two things broke on purpose in `v0.11.0`**, both from the same review: the server
> refuses to start without a `sqlite` audit device, and `ciphr-run` and `ciphr-ci` refuse a secret
> whose name is a process-control variable. Both checks are one command each, and
> [what to do about each released version](docs/operations/upgrade.md) is the document that owns them
> — read the section for **every** version you are skipping, not just the newest.
> [`CHANGELOG.md`](CHANGELOG.md) is what changed; that page is what to *do* about it.
>
> **Nothing here is an independent security assessment.** The external review of 2026-08-21 was
> performed against `v0.3.0` by an AI model commissioned by the maintainer — not the human
> practitioner the working paper asks for — and it covers only what it says it read. **This repository
> was made public on 2026-08-24 without a human review**, which the working paper names as one of the
> two conditions that raise the bar back to one; that is a decision against a recorded condition
> rather than a condition that was met. [`docs/security-review.md`](docs/security-review.md) states in
> a section of its own what was read, what is unreviewed by anyone, and what would close it, and
> [`docs/assurance/`](docs/assurance/README.md) holds every review and field report behind it. If an
> independent assessment is what a deployment needs, this project's own answer is in
> [`docs/why-build-this.md`](docs/why-build-this.md) and it names OpenBao.

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
  nonce reuse — the best-known AES-GCM footgun — cannot occur **on a value**. The root key's own
  per-wrap nonces are random, where the guarantee is a bound rather than a structure:
  [`docs/crypto.md`](docs/crypto.md) states it. Path and version are bound as additional
  authenticated data, so a ciphertext cannot be moved from one path to another.
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
  is `curl`. No agent, no plugin, no forge integration required. What a job should reach for instead
  is `ciphr-ci` — the same fetch, with the masking a forge does not do for a value fetched at runtime
  ([ADR-25](docs/adr/0025-the-ci-side-fetch-is-its-own-binary.md)).
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
is. This is why masking is part of the product rather than of the documentation: the `actions-env`
render emits `::add-mask::` for every value before it emits anything else — and since 2026-08-24 a job
can reach it. `ciphr-ci` fetches over the API with a token and renders through the same code `ciphr
export` uses on a host; before it, that rendering lived only in a CLI command that needs the store,
the master key and the service stopped, so a job's honest options were `curl` and a page of
documentation. The name contains *CI*, so the integration is not an afterthought to the security model
— it is where most of the remaining risk lives. Read [`docs/operations/ci.md`](docs/operations/ci.md)
before writing the first workflow.

The realistic end state is **one secret per host**, not zero — plus an audit trail, plus rotation,
plus a bounded blast radius per token. The full threat model, including everything else that is
deliberately out of scope, is in [`docs/threat-model.md`](docs/threat-model.md).

## Documentation

**<https://nuetzliches.github.io/ciphr/>** is the short way in: what this is, the four consumer
routes with the code for each, the security notes an integration has to get right, and the security
layers as a diagram. It orders what is below rather than replacing it — every claim on it links to the
document that decided the thing, and where the two disagree the document is the one maintained with
the software.

| Where | What |
|---|---|
| [the site](https://nuetzliches.github.io/ciphr/) | Overview, integration examples, security notes, and the layer diagram |
| [`docs/`](docs/README.md) | The documentation index, including a table of risk areas |
| [`docs/adr/`](docs/adr/) | The 25 architecture records, one file each, with what was rejected and why |
| [`docs/crypto.md`](docs/crypto.md) | The implemented key hierarchy and wire format, and what the tests establish |
| [`docs/authorization.md`](docs/authorization.md) | The policy file, the pattern language, and the four rules of the decision |
| [`docs/security-review.md`](docs/security-review.md) | What an external reviewer should attack, and what would falsify each claim |
| [`docs/operations/cli.md`](docs/operations/cli.md) | Every `ciphr` command, and the two rules that shape all of them |
| [`docs/operations/backup.md`](docs/operations/backup.md) | What a backup has to contain, how to take one that is not torn, and what a restore quietly undoes |
| [`docs/operations/monitoring.md`](docs/operations/monitoring.md) | What to poll, what each `/v1/health` field means, and the check the endpoint cannot answer |
| [`docs/operations/upgrade.md`](docs/operations/upgrade.md) | What each version's breaking changes require, and the backup rule that holds for all of them |
| [`docs/operations/wrapper.md`](docs/operations/wrapper.md) | `ciphr-run`: where to get it, what its exit codes mean, and what it does not solve |
| [`docs/operations/ci.md`](docs/operations/ci.md) | `ciphr-ci` and the composite action: the workflow step, the token shape, and what is measured about masking |
| [`docs/ui.md`](docs/ui.md) | The viewer: what it shows, what it refuses to do, and how it is deployed |
| [`openapi.yaml`](openapi.yaml) | The HTTP API |
| [`docs/operations/`](docs/operations/) | Procedures for what is hard to undo: the master key, backups and restores, and rotating secrets that break things |
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
