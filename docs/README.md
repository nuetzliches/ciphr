# Documentation

**Status:** current as of 2026-08-18, phase 3 of 7. Describes what is built, and says so where
something is not.

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
| **Trusting the wrong boundary** | Assuming the container network is private, or that root on the host is excluded. | [threat-model.md](threat-model.md) |
| **Building this at all** | A self-built secret manager fails silently. There is a defined point at which abandoning it is correct. | [why-build-this.md](why-build-this.md) |

## Everything else

| Document | What it is for |
|---|---|
| [adr/](adr/) | The thirteen architecture decisions, one file each, including what was rejected and why |
| [threat-model.md](threat-model.md) | Adversaries A1–A8, the boundaries deliberately not defended, and the availability trade |
| [crypto.md](crypto.md) | The implemented key hierarchy and wire format, and what the known-answer tests pin |
| [authorization.md](authorization.md) | The policy file, the pattern language, and the four rules of the decision |
| [fuzzing.md](fuzzing.md) | The three fuzz targets, how to run them, and what the CI gate does and does not prove |
| [why-build-this.md](why-build-this.md) | The evaluation of existing tools and the exit condition |
| [operations/cli.md](operations/cli.md) | Every command, and the two rules that shape all of them |
| [operations/](operations/) | Procedures for the things that are hard to undo: the master key, rotating secrets, and the audit trail |
| [`../openapi.yaml`](../openapi.yaml) | The HTTP API, maintained in the same commit as the code |
| [`../AGENTS.md`](../AGENTS.md) | Working rules for contributors and the gates that enforce them |
| [`../SECURITY.md`](../SECURITY.md) | Disclosure process and scope |
| `cargo doc --open` | API documentation, generated from the code, with running examples |

## What is not documented yet, and why

Deployment — containers, the reverse proxy, certificates — and the admin UI. Those are phases 4 and
5. The HTTP API is documented in `openapi.yaml` rather than here, because it is generated from and
maintained beside the code.
