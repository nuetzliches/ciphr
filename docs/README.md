# Documentation

**Status:** current as of 2026-08-27, `v0.13.1` released; the external review was against `v0.3.0`. Phases 0-3, 7 and 8 are
in it; route A's binary (`ciphr-ci`, ADR-25) shipped in `v0.11.0`; the viewer (phase 5) ships as its own image on its own cadence. Describes what is built, and
says so where something is not.

**There is a site**, at <https://nuetzliches.github.io/ciphr/>, published from
[`site/`](../site/README.md) since 2026-08-24. It carries an overview, the four consumer routes with
their code, security notes for whoever writes a consumer, and the layer diagram. It is an ordering of
what is in this directory and not a second source: every claim there links back here.

**Phase 8 shipped in `v0.5.0`.** The `alert` tier of ADR-15, behind the `honeypot_alert` surface entry
(ADR-20) and therefore absent from a default build. The surface added by it is *newer than the accepted
review* — [security-review.md](security-review.md) marks the three claims that describe it, and that is
why the entry is off unless a deployment asks for it.

## The rules this documentation is held to

They are written down because documentation decays quietly, and a secret manager whose manual is
wrong is worse than one with no manual: it produces confident mistakes.

**Honest.** Every document states what is *not* protected alongside what is. If a mechanism buys
convenience rather than security, it says so — the seal in v1 is the standing example (ADR-5).
Nothing here is written to reassure.

**Current, with a visible date.** Every document carries a status line with an ISO date, and facts
that age — upstream versions, third-party behaviour — carry the date they were verified.
`ci/check-docs.sh` fails the build if a document under `docs/` has no date or claims a date in the
future. A date is not a guarantee of accuracy, but an undated document cannot even be *questioned*
usefully.

**About what exists.** Documentation describes the built system. Plans for unbuilt features live in
the implementation plan, not here, and anything partially built says which phase completes it. The
alternative — documenting the intended system — reads as a description of reality and quietly
becomes a lie.

**Executable where it can be.** Every code example in the API documentation is a doctest and runs in
CI, so an example that stops working fails the build rather than misleading a reader. Operational
procedures name exact commands and exact file paths, and say which of them do not exist yet.

**Changed in the same commit as the code.** A documentation update that trails the change it
describes is a window in which the documentation is wrong, and those windows never close on their
own.

## If you came here to do one thing

The table below is ordered by *risk*, which is the right order when the question is what a mistake
costs. These are the shorter paths when you already know what you are doing.

| You are | Start at |
|---|---|
| **Integrating a consumer** | The [integration page](https://nuetzliches.github.io/ciphr/integrate.html) for which of the four routes fits, then [operations/ci.md](operations/ci.md) for a CI job, [operations/wrapper.md](operations/wrapper.md) for a container, or `cargo doc -p ciphr-sdk --open` for an application |
| **Operating a deployment** | [operations/README.md](operations/README.md), ordered by task — then [operations/monitoring.md](operations/monitoring.md), which is the one to read *before* something is wrong |
| **Responding to an incident** | [operations/honeypots.md](operations/honeypots.md) if a tripwire fired, [operations/master-key.md](operations/master-key.md) if the key is what leaked, [operations/backup.md](operations/backup.md) if you are restoring — and note what a restore silently undoes |
| **Upgrading** | [operations/upgrade.md](operations/upgrade.md), the section for *every* version you are skipping |
| **Changing security-critical code** | [`../AGENTS.md`](../AGENTS.md) for the rules and the gates, [authorization.md](authorization.md) and [crypto.md](crypto.md) for the two that decide every access, [adr/](adr/README.md) for why it is shaped this way |
| **Reviewing this project** | [security-review.md](security-review.md) — scope, claims, and what would falsify each — then [assurance/](assurance/README.md) for what has already been read and by whom |
| **Deciding whether to use it at all** | [why-build-this.md](why-build-this.md), which names the condition under which OpenBao is the right answer instead, and [threat-model.md](threat-model.md) |

## By risk area

The parts where a mistake is expensive, and where to read before making one.

| Risk | What can go wrong | Read |
|---|---|---|
| **Master key handling** | Lose it and every secret is unrecoverable. Leak it and the database is plaintext. Put it in the same backup as the database and the backup *is* the secret store. | [operations/master-key.md](operations/master-key.md) |
| **A backup that is not one** | A `cp` of a running database is a snapshot of two moments, and a `store.db` copied without its `-wal` is silently missing the newest writes. Neither produces an error. `ciphr backup` has neither failure mode. | [operations/backup.md](operations/backup.md) |
| **Restoring one** | A restore rolls the store back, and three of the things it rolls back are security decisions: a crypto-shred, a token revocation, and a master-key rotation. None of them announces itself. | [operations/backup.md](operations/backup.md) |
| **Rotating a secret that cannot be rotated** | A new value can destroy data at rest, or change nothing at all while looking successful. | [operations/rotating-secrets.md](operations/rotating-secrets.md) |
| **Cryptographic format changes** | A changed wire format makes every stored secret undecryptable, with no error until the first read. | [crypto.md](crypto.md) |
| **Authorization drift** | Two path normalizations that disagree by one edge case is an authorization bypass nobody notices. | [authorization.md](authorization.md), [fuzzing.md](fuzzing.md) |
| **Writing a policy that grants more than intended** | The most specific rule wins entirely and does not inherit from broader rules — the behaviour most likely to surprise. | [authorization.md](authorization.md) |
| **Trusting the audit trail too far** | A hash chain detects partial tampering, not a forward rewrite by someone who can write to the store. | [operations/audit-trail.md](operations/audit-trail.md) |
| **A full audit volume** | Fail-closed means it is a total outage, not a logging gap. That is intended and needs monitoring — and it is the one check `/v1/health` cannot answer. | [operations/audit-trail.md](operations/audit-trail.md), [operations/monitoring.md](operations/monitoring.md) |
| **Alerting on a constant** | `sealed` on `/v1/health` is hardcoded. Three fields carry live state — `status`, `degraded`, and `audit_devices[].accepting` — and a rule written against the others watches nothing. | [operations/monitoring.md](operations/monitoring.md) |
| **A secret in a CI job log** | No forge masks a value fetched at runtime. Only the `actions-env` render does, and only if the masks are emitted first — which is why fetching in a job is a program rather than a documented `curl` line. | [operations/ci.md](operations/ci.md) |
| **A secret in shell history** | A value passed as an argument is readable by every process on the host while the command runs. | [operations/cli.md](operations/cli.md) |
| **A tripwire nobody polls** | The alert is a field on `/v1/health` and an entry in the trail. Nothing here can page a human, and bait whose output nobody reads is decoration. | [operations/honeypots.md](operations/honeypots.md) |
| **Bait under a prefix something fetches** | A prefix fetch reads the value of every path under it, so misplaced bait trips on every service start — and gets switched off in week two. | [operations/honeypots.md](operations/honeypots.md) |
| **Trusting the wrong boundary** | Assuming the container network is private, or that root on the host is excluded. | [threat-model.md](threat-model.md) |
| **Revealing a secret in a browser** | Plaintext in a DOM has its own class of failure: an XSS finding, a cached response, a value left on a screen. What the viewer does about each, and what it refuses to do at all. | [ui.md](ui.md) |
| **Going to production unreviewed** | Three crates decide every access, and their failures are silent. The external review happened on 2026-08-21 and was accepted — by an AI model, not the human practitioner the working paper asks for, and only for what it says it read. | [security-review.md](security-review.md), [review-2026-08-21.md](assurance/reviews/review-2026-08-21.md) |
| **Building this at all** | A self-built secret manager fails silently. There is a defined point at which abandoning it is correct. | [why-build-this.md](why-build-this.md) |

## Everything else

| Document | What it is for |
|---|---|
| [adr/](adr/README.md) | The twenty-eight records, one file each — one accepted in part, one deferred, one proposed — including what was rejected and why |
| [threat-model.md](threat-model.md) | Adversaries A1–A9, the boundaries deliberately not defended, and the availability trade |
| [crypto.md](crypto.md) | The implemented key hierarchy and wire format, and what the known-answer tests pin |
| [authorization.md](authorization.md) | The policy file, the pattern language, and the four rules of the decision |
| [fuzzing.md](fuzzing.md) | The three fuzz targets, how to run them, and what the CI gate does and does not prove |
| [security-review.md](security-review.md) | Scope, claims, and what would falsify them — the working paper for an external reviewer, plus the dated decision to accept the review of 2026-08-21 |
| [assurance/](assurance/README.md) | The evidence behind that paper: six reviews and five field reports, what each one read, and which single review discharged the precondition — none of them by a human |
| [why-build-this.md](why-build-this.md) | The evaluation of existing tools and the exit condition |
| [ui.md](ui.md) | The read-only viewer: the five views, the security properties and where each is enforced, and how it is deployed |
| [operations/cli.md](operations/cli.md) | Every command, and the two rules that shape all of them — including `ciphr state`, which derives the deployment's file set from its configuration |
| [operations/backup.md](operations/backup.md) | What has to be in a backup, how to take one that is not torn, what a restore undoes, and how the store's own rotation classes decide what the backup is worth |
| [operations/monitoring.md](operations/monitoring.md) | Every field on `/v1/health`, which of them change, the three ways to read it wrong, and why backup freshness is deliberately not there |
| [operations/upgrade.md](operations/upgrade.md) | What to do about each version's breaking changes, and the rules that hold for every upgrade |
| [operations/wrapper.md](operations/wrapper.md) | `ciphr-run`: where the file comes from, what its exit codes mean, and what route B does not solve |
| [operations/ci.md](operations/ci.md) | `ciphr-ci` and the composite action: the workflow step, where the binary comes from, what is measured about masking and what is only claimed |
| [operations/honeypots.md](operations/honeypots.md) | Planting bait, where it must not go, and what to do when it fires |
| [operations/](operations/README.md) | The operational index, ordered by task: setting up, running, keeping the data, integrating a consumer, rotating a secret, and responding to an incident |
| [`../openapi.yaml`](../openapi.yaml) | The HTTP API, maintained in the same commit as the code |
| [`../AGENTS.md`](../AGENTS.md) | Working rules for contributors and the gates that enforce them |
| [`../SECURITY.md`](../SECURITY.md) | Disclosure process and scope |
| `cargo doc --open` | API documentation, generated from the code, with running examples |

## What is not documented yet, and why

Deployment: containers, the reverse proxy, and certificates. That is phase 4, and it is documented
where a deployment lives rather than here — the product documentation deliberately carries no
organization-specific hostnames or paths. The viewer arrived in phase 5 and is documented in
[ui.md](ui.md). The HTTP API is documented in `openapi.yaml` rather than here, because it is
maintained beside the code.
