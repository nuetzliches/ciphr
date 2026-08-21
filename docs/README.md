# Documentation

**Status:** current as of 2026-08-21, `v0.4.0` released; the external review was against `v0.3.0`. Phases 0-3 and 7 are
in it; the viewer (phase 5) ships as its own image on its own cadence. Describes what is built, and
says so where something is not.

**Phase 8 is built and unreleased.** The `alert` tier of ADR-15, behind the `honeypot_alert` surface
entry (ADR-20) and therefore absent from a default build. The surface added by it is *newer than the
accepted review* — [security-review.md](security-review.md) marks the three claims that describe it.

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

## By risk area

The parts where a mistake is expensive, and where to read before making one.

| Risk | What can go wrong | Read |
|---|---|---|
| **Master key handling** | Lose it and every secret is unrecoverable. Leak it and the database is plaintext. Put it in the same backup as the database and the backup *is* the secret store. | [operations/master-key.md](operations/master-key.md) |
| **Rotating a secret that cannot be rotated** | A new value can destroy data at rest, or change nothing at all while looking successful. | [operations/rotating-secrets.md](operations/rotating-secrets.md) |
| **Cryptographic format changes** | A changed wire format makes every stored secret undecryptable, with no error until the first read. | [crypto.md](crypto.md) |
| **Authorization drift** | Two path normalizations that disagree by one edge case is an authorization bypass nobody notices. | [authorization.md](authorization.md), [fuzzing.md](fuzzing.md) |
| **Writing a policy that grants more than intended** | The most specific rule wins entirely and does not inherit from broader rules — the behaviour most likely to surprise. | [authorization.md](authorization.md) |
| **Trusting the audit trail too far** | A hash chain detects partial tampering, not a forward rewrite by someone who can write to the store. | [operations/audit-trail.md](operations/audit-trail.md) |
| **A full audit volume** | Fail-closed means it is a total outage, not a logging gap. That is intended and needs monitoring. | [operations/audit-trail.md](operations/audit-trail.md) |
| **A secret in a CI job log** | No forge masks a value fetched at runtime. Only the `actions-env` export does, and only if the masks are emitted first. | [operations/cli.md](operations/cli.md) |
| **A secret in shell history** | A value passed as an argument is readable by every process on the host while the command runs. | [operations/cli.md](operations/cli.md) |
| **A tripwire nobody polls** | The alert is a field on `/v1/health` and an entry in the trail. Nothing here can page a human, and bait whose output nobody reads is decoration. | [operations/honeypots.md](operations/honeypots.md) |
| **Bait under a prefix something fetches** | A prefix fetch reads the value of every path under it, so misplaced bait trips on every service start — and gets switched off in week two. | [operations/honeypots.md](operations/honeypots.md) |
| **Trusting the wrong boundary** | Assuming the container network is private, or that root on the host is excluded. | [threat-model.md](threat-model.md) |
| **Revealing a secret in a browser** | Plaintext in a DOM has its own class of failure: an XSS finding, a cached response, a value left on a screen. What the viewer does about each, and what it refuses to do at all. | [ui.md](ui.md) |
| **Going to production unreviewed** | Three crates decide every access, and their failures are silent. The external review happened on 2026-08-21 and was accepted — by an AI model, not the human practitioner the working paper asks for, and only for what it says it read. | [security-review.md](security-review.md), [review-2026-08-21.md](review-2026-08-21.md) |
| **Building this at all** | A self-built secret manager fails silently. There is a defined point at which abandoning it is correct. | [why-build-this.md](why-build-this.md) |

## Everything else

| Document | What it is for |
|---|---|
| [adr/](adr/) | The twenty-one records, one file each — one accepted in part, one deferred, one proposed — including what was rejected and why |
| [threat-model.md](threat-model.md) | Adversaries A1–A9, the boundaries deliberately not defended, and the availability trade |
| [crypto.md](crypto.md) | The implemented key hierarchy and wire format, and what the known-answer tests pin |
| [authorization.md](authorization.md) | The policy file, the pattern language, and the four rules of the decision |
| [fuzzing.md](fuzzing.md) | The three fuzz targets, how to run them, and what the CI gate does and does not prove |
| [security-review.md](security-review.md) | Scope, claims, and what would falsify them — the working paper for an external reviewer, plus the dated decision to accept the review of 2026-08-21 |
| [review-2026-08-21.md](review-2026-08-21.md) | That review: who performed it and what that is worth, six findings, coverage, and the fitness statement |
| [review-2026-08-18.md](review-2026-08-18.md) | The pre-review pass against the same list, from the model that co-authored the code — read for what it says it did *not* check |
| [why-build-this.md](why-build-this.md) | The evaluation of existing tools and the exit condition |
| [ui.md](ui.md) | The read-only viewer: the five views, the security properties and where each is enforced, and how it is deployed |
| [operations/cli.md](operations/cli.md) | Every command, and the two rules that shape all of them |
| [operations/upgrade.md](operations/upgrade.md) | What to do about each version's breaking changes, and the rules that hold for every upgrade |
| [operations/wrapper.md](operations/wrapper.md) | `ciphr-run`: where the file comes from, what its exit codes mean, and what route B does not solve |
| [operations/honeypots.md](operations/honeypots.md) | Planting bait, where it must not go, and what to do when it fires |
| [operations/](operations/) | Procedures for the things that are hard to undo: the master key, rotating secrets, the audit trail, and the freeze a tripwire can engage |
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
