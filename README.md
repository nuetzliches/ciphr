# ciphr

A small secret manager for machine identities: key/value secrets, gap-free access auditing,
and path-based authorization. The name contains *CI* — the primary consumer is a build and
deploy pipeline, not a human.

> **Status: v0.10.0 released.** Usable end to end: envelope encryption with master key rotation,
> SQLite with migrations, the policy evaluator, the fail-closed hash-chained audit trail, the HTTPS
> API with token authentication, and the `ciphr` CLI. Since v0.1.0: the audit anchor and the
> retention cut that bounds the trail (`ciphr audit anchor`, `ciphr audit cut`), one rule for
> turning a path into an environment variable name, `ciphr-sdk` for a service that fetches its own
> secrets, and `ciphr-run` for an image that only understands environment variables. The read-only
> browser viewer in [`ui/`](ui/) ships as its own image and is released on its own cadence. Since
> v0.2.0: a secret nobody classified says so instead of claiming to be safe to rotate, the class is
> on the wire and in the viewer, and setting one is recorded in the audit trail. Since v0.3.0: issuing
> and revoking a credential is in the audit trail, and the six findings of the external review are
> answered — two fixed as defects, two more found by the same reading, two answered as prose that
> claimed more than the code did. Since v0.4.0: optional surface entries, and honeypots. Since
> v0.5.1: a backup command, a report of the files a deployment has to keep, and listings that
> answer while the service runs. Since v0.6.1: a machine-readable form of that report, and six
> findings of a source review answered. Since v0.7.0: a configuration check that answers without a
> store, an exit code a backup job can branch on, and credential files opened once. Since v0.8.0: the
> control plane has capabilities of its own, revocation has a route, and the listener speaks HTTP/1.1
> only. Since v0.9.0: the configuration check has a status a pipeline can fail on.
>
> **v0.10.0 turns a recommended check into a usable gate.** `v0.9.0` made a policy edit mandatory and
> named `ciphr-server --check-config` in review as the way to catch a file that still has the old form.
> Review is the one host that deliberately has no store — and a host with no store and a policy file
> the binary refuses both exited `1`, so the pipeline that was supposed to protect the mandatory edit
> could not tell the finding it runs for from the host it runs on. **A host that is not ready is exit
> `3` now**, the number `ciphr state` already uses for the same shape, and `1` means the files are
> unusable and nothing else. Anything branching on that status wants a look; nothing else here asks a
> deployment to do anything, nothing migrates, and no route or default moved.
>
> Three smaller things from the same field report: `--check-config` says when a surface entry is on and
> no identity can call it, an audit device that cannot be opened names the requirement rather than only
> the OS error, and the runbooks say to issue the revoking identity's token before the incident that
> needs it — turning on outage-free revocation costs that outage once, and that belonged written down.
>
> **Pin `0.10.0`.** The viewer moves separately as `ui-v0.3.1`: it refuses to mount while a service
> worker controls its page.
>
> **v0.9.0 broke one thing on purpose, and it is the reason to take it.** `read` authorized a
> secret's value *and* the control plane — `sys/audit`, `sys/identities`, `sys/policies` — with only
> the path separating them, so `path = "**"` with `read`, the rule somebody writes for a break-glass
> identity meaning *all the secrets*, granted the audit trail and the map of the authorization model
> along with them. Now **`inspect` reads the control plane and `revoke` revokes a token**; the five
> existing capabilities mean secrets and only secrets, and a rule under `sys/` that still says `read`
> is refused when the policy file loads, naming the replacement. One edit per file, findable in review
> with `--check-config` (no store, no key).
>
> **Three things become possible.** Revoking a leaked credential no longer needs an outage —
> `POST /v1/tokens/{token_id}/revoke`, the first and only write this API has ever had, behind an entry
> that is off until a deployment names it, with no master key in reach. `GET /v1/tokens` answers *"is
> this credential still valid"* to an authenticated caller, so the trail names an identity rather than
> `cli:$USER`. And a handshake against the listener used to negotiate **HTTP/2** — a second framing
> implementation on the connection path of the process that holds plaintext, arrived through a
> transitive dependency feature and not through any decision here; the ALPN list is now ours and says
> `http/1.1`. Nothing migrates; the schema stays at 6. What to do rather than know is in
> [`docs/operations/upgrade.md`](docs/operations/upgrade.md).
>
> **v0.8.0 answered a field report, and its two main findings were the same shape.** A check whose
> verdict was about something other than what the caller asked. `ciphr-server --check-config` printed
> its whole report — the surface report included, which is a pure function of the file — only after
> opening, locking and writing to the store, so the one report that catches a *forgotten* surface
> stanza was unreachable in review, where a configuration edit is actually read. It now reports the
> file first and this host last; on the way it stopped taking the writer lock, stopped migrating the
> store, and stopped appending to the audit trail. And `ciphr state` exited non-zero about files a
> backup job must not have: a complete listing with a missing required file is `3` now, and `1` still
> means the command failed. Also: a `ciphr backup` destination that cannot be written names its
> directory rather than only the file, and the master key and token files are opened once and read
> through that descriptor (F10 of the source review, issue #13) — which also means a named pipe where
> a credential belongs is refused rather than read forever. Nothing migrates; the schema stays at 6.
> What to do rather than know is in [`docs/operations/upgrade.md`](docs/operations/upgrade.md).
>
> **v0.7.0 answered a source review and a field report.** Six findings of the review of 2026-08-21 and
> the three asks of the deployment that rebuilt its nightly backup around `0.6.0`. The two that reach a
> running deployment: `export --format actions-env` used a predictable heredoc delimiter, so a value
> could close its own assignment and define environment variables for later workflow steps; and a
> honeypot *token* wrote its audit entry and latched nothing, so a deployment doing everything the
> runbook asks still missed the event. Also: every `/v1` response now says `Cache-Control: no-store`,
> `ciphr-sdk` follows no redirects, an audit archive is named after the record it closes at and never
> replaces one, `ciphr state` has `--json` and `--exclude` for the job that keeps the files, and the
> container refuses to start where core dumps cannot be disabled. Nothing migrates; the schema stays at
> 6. Three things to do rather than know are in
> [`docs/operations/upgrade.md`](docs/operations/upgrade.md) — including that the honeypot fixes sit
> behind a build entry, so a deployment that plants bait rebuilds its derived image.
>
> And a note that outlives its release: `v0.6.0` published its server image and then
> failed to build the wrapper image, so `…/run:0.6.0` and the `v0.6.0` release assets do not
> exist. `0.6.1` is the same code with both artefacts published, and `a14d143` added the gate
> that makes half a release unreachable.
>
> **v0.6.0 is the release that makes operating this a matter of commands.** `ciphr backup` takes a
> copy that cannot be torn and needs neither the store lock nor the master key; `ciphr state`
> derives the files to keep from the deployment's own configuration and exits non-zero when one it
> requires is missing; a container stop runs the graceful shutdown at last (SIGTERM was never
> handled); and the metadata listings answer read-only while the service runs — which also means
> they no longer appear in the audit trail (ADR-22). Two things to do rather than know: the release
> asset is now `ciphr-run-x86_64-unknown-linux-musl`, and an alert that counted host-side listing
> entries counts zero from here on. Nothing migrates; the schema stays at 6.
>
> **v0.5.1 is a correction release**, and the correction worth knowing about is a claim this project
> made about itself: `bulk_export`'s recorded cost said that turning the entry off removes fetched
> prefixes and so makes a honeypot secret easier to place. It does not — `POST /v1/export` reads the
> paths a caller *names*, and whether a prefix is covered is a property of the fetching code. If you
> decided about that entry on the old sentence, [`docs/operations/upgrade.md`](docs/operations/upgrade.md)
> says what to re-read. Nothing breaks and nothing migrates.
>
> **v0.5.0 is a breaking release for a deployment's configuration.** Four routes — the three the
> viewer reads and `POST /v1/export` — are now *surface entries* (ADR-20): off until a deployment
> names them, with the date it accepted the cost and the reason. And phase 8 exists, in the `alert`
> tier only: bait that no legitimate consumer touches turns a read into a signal, behind a Cargo
> feature that is **absent from the default build**. See
> [`docs/operations/upgrade.md`](docs/operations/upgrade.md) before deploying, and
> [`docs/operations/honeypots.md`](docs/operations/honeypots.md) before planting anything.
>
> **The honeypot surface is newer than the external review, and is not covered by it.** That is why
> it is off by default: the default artefact of this release contains none of it, and turning it on
> is a decision about accepting unreviewed code on the authentication path. The three claims
> describing it are marked as uncovered in [`docs/security-review.md`](docs/security-review.md).
>
> **`v0.3.0` is the artifact the external review was performed against.** That review happened on
> 2026-08-21, against that tag, and is recorded in
> [`docs/review-2026-08-21.md`](docs/review-2026-08-21.md): six findings, an explicit statement of
> what was and was not read, and a qualified yes on fitness. Its two conditions — unwiped heap
> copies of a token secret, and a reserved-path refusal that only the HTTP layer enforced — are
> fixed. **Read who performed it before relying on it:** an AI model commissioned by the maintainer,
> not the human practitioner the working paper asks for, and the record says what that is worth. The
> maintainer accepted it as discharging the precondition; what that covers and what would reverse it
> is in [`docs/security-review.md`](docs/security-review.md). The full design lives in
> [`.claude/plans/PLAN.md`](.claude/plans/PLAN.md).
>
> **This repository was made public on 2026-08-24 without that human review.** The working paper names
> publication as one of the two things that raise the bar back to it, so this is a decision against a
> recorded condition rather than a condition that was met.
> [`docs/security-review.md`](docs/security-review.md) states it in a section of its own: what was
> read, what is unreviewed by anyone, and what would close it. **Nothing here is an independent
> security assessment**, and if that is what a deployment needs, the project's own answer for that
> case is in [`docs/why-build-this.md`](docs/why-build-this.md) and it names OpenBao.

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

| Where | What |
|---|---|
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
