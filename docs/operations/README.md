# Operations

**Status:** current as of 2026-08-27, `v0.13.1` released. Thirteen documents: twelve procedures for a system that
exists, and one design for a tier that does not. The two newest were added the day the decisions
behind them were taken, and both are about what a deployment has to *know* rather than what it
runs — federation, and what depends on the vault being reachable.

Ordered by what you are trying to do, not by subsystem. The index one level up
([`../README.md`](../README.md)) is ordered by *risk* — what goes wrong and what to read before it
does — and that is the better entry point when the question is "what could this cost me". This one
answers "what do I run".

**Read the runbook before the incident.** Three of the procedures here need something prepared in
advance — a backup taken a particular way, a revoking identity's token issued before it is needed,
bait placed outside every fetched prefix — and in all three cases doing it during the incident is
either impossible or itself an outage. Those are marked below.

## Setting up, and looking things up

| Document | What it answers |
|---|---|
| [cli.md](cli.md) | **Command reference.** Every `ciphr` subcommand, and the two rules that shape all of them: a value is never an argument, and a secret never reaches a pipe without `--force`. Includes `ciphr state`, which derives the deployment's file set from its own configuration. |
| [`../../openapi.yaml`](../../openapi.yaml) | The HTTP API, maintained beside the code. Not in this directory because it is a specification rather than a procedure. |

## Running a deployment

| Document | What it answers |
|---|---|
| [availability.md](availability.md) | **What depends on the vault being up, and at which moments.** There is no client-side cache and no lease ([ADR-27](../adr/0027-the-vault-is-a-startup-dependency.md)), so a container start, a CI job and a federated exchange all need this service answering. Names what must not be co-located with it, and what must not be restarted alongside it. |
| [monitoring.md](monitoring.md) | **What to poll, and the three ways to read it wrong.** Every field on `/v1/health`, which of them are hardcoded constants — an alert written against those watches nothing — and why backup freshness is deliberately not there. |
| [audit-trail.md](audit-trail.md) | The chain, `tail`, `verify`, `anchor` and `cut`. **A full audit volume is a total outage, not a logging gap**, which is intended and is the one condition `/v1/health` cannot answer for you. |

## Keeping the data

| Document | What it answers |
|---|---|
| [backup.md](backup.md) | **Prepare in advance.** What must be in a backup, how to take one that is not torn — a `cp` of a live write-ahead-logged database fails silently — and what a restore quietly undoes: a crypto-shred, a token revocation, a master-key rotation. |
| [master-key.md](master-key.md) | **The highest-consequence thing here.** Lose it and every secret is unrecoverable; leak it and the database is plaintext; back it up beside the database and the backup *is* the secret store. Rotation is here too. |
| [upgrade.md](upgrade.md) | What each released version requires you to *do*, and the backup rule that holds for all of them. Read the section for every version you are skipping, not just the newest. |

## Integrating a consumer

Which route to take is decided on the site's [integration page](https://nuetzliches.github.io/ciphr/integrate.html)
and in the ADRs; these say how to operate the result.

| Document | What it answers |
|---|---|
| [ci.md](ci.md) | **Route A — a CI job.** `ciphr-ci` and the composite action: the workflow step, where the binary comes from, the token's shape, and what is *measured* about masking versus what is only claimed. **No forge masks a value fetched at runtime**, which is why this is a program and not a documented `curl` line. |
| [federation.md](federation.md) | **Letting a job authenticate without a stored token.** `POST /v1/auth/oidc/login` ([ADR-26](../adr/0026-oidc-federation.md)): a workload presents an ID token its forge issued and gets one that lives minutes. **Read the key-rotation section before turning it on** — the provider's signing keys are configuration, not a fetch, so a rotation on their side is an edit here. Requires the `oidc_login` surface entry. |
| [wrapper.md](wrapper.md) | **Route B — a third-party image.** `ciphr-run`: where the file comes from, what its exit codes mean (`125` is the wrapper, `126`/`127` are the shell convention), and what route B does not solve. |

Route C — an application fetching its own secrets — is `ciphr-sdk`, documented in its rustdoc
(`cargo doc -p ciphr-sdk --open`) because its examples are doctests that run in CI.

## Changing a secret

| Document | What it answers |
|---|---|
| [rotating-secrets.md](rotating-secrets.md) | **Rotating something that does not want to be rotated.** A new value can destroy data at rest, or change nothing while looking successful. The rotation class says which, and a secret nobody classified says so rather than claiming to be safe. |

## Responding to an incident

| Document | What it answers |
|---|---|
| [honeypots.md](honeypots.md) | **Prepare in advance.** Planting bait, where it must not go — outside every prefix any consumer fetches, which is a question about the fetching *code*, not the policy — and what to do when it fires. Requires the `honeypot_alert` surface entry, which is **absent from a default build**. |
| [master-key.md](master-key.md) | Rotation, for the case where the key itself is what leaked. |
| [backup.md](backup.md) | Restoring, and the three security decisions a restore silently rolls back. |

**The last step of the honeypot mechanism is not in this repository.** The alert is a field on
`/v1/health` and an entry in the trail; nothing here can page a human. A deployment whose monitoring
does not watch for it has bait and no tripwire.

## Designed, and not built

| Document | Status |
|---|---|
| [freeze.md](freeze.md) | **Not implemented, and not being built.** ADR-15 was accepted in the `alert` tier only; this describes the `freeze` tier it deliberately left out. `ciphr lockdown` does not exist — `ci/check-doc-commands.sh` carries a named allowlist entry for that command so the gate does not have to pretend otherwise. Read it as a design record, not as a runbook. |

## What is not here

**Deployment specifics**: containers, the reverse proxy, certificates, hostnames. That is phase 4,
and it is documented where a deployment lives — this repository deliberately carries no
organization-specific names or paths, so a procedure that depended on them would be wrong everywhere
except one place.

**The viewer** is [`../ui.md`](../ui.md): its own package, its own image, its own release cadence.
