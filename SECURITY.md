# Security policy

## Status of this project

ciphr is **pre-release**. There are no supported versions, and no promise that an upgrade path
exists for anything but the documented ones.

The external review of the cryptographic and authorization crates — the condition recorded in
[`docs/why-build-this.md`](docs/why-build-this.md) — took place on 2026-08-21 and was accepted;
[`docs/assurance/reviews/review-2026-08-21.md`](docs/assurance/reviews/review-2026-08-21.md) is the record, and its first section says
who performed it, which decides what it is worth. It was not a human practitioner. Anyone weighing a
deployment that holds real secrets should read that section before the findings.

**This repository was made public on 2026-08-24 without the human review its own working paper asks
for at that point.** That is a decision against a recorded condition rather than a condition that was
met, and [`docs/security-review.md`](docs/security-review.md) states it under *Published without a
human review* — what was actually reviewed, what was not reviewed by anyone, and what would close
it. Read that before treating anything here as assessed.

## Reporting a vulnerability

Please report privately, not as a public issue.

- Use GitHub's private vulnerability reporting on this repository (**Security → Report a
  vulnerability**), which creates a private advisory visible only to the maintainers.
- **Or write to `security@nuetzliche.it`.** Added 2026-08-24, before this repository was made
  public, because a security product whose only reporting route is a platform feature has a gap: the
  platform can change the feature, and somebody who does not have an account there cannot use it at
  all. Plain mail is enough — there is no PGP key to fetch, and asking for one would be a barrier
  in front of the thing this address exists to receive.

Either channel is fine, and neither is better received than the other.

Please include what you need to make the report actionable: affected component, the behaviour you
observed, and a reproduction if you have one. A rough report of something real is more useful than a
polished report of something theoretical.

What to expect: an acknowledgement within a few working days, an assessment with a fix or a
justification for treating it as out of scope, and credit in the changelog unless you prefer
otherwise. This is a small project with no bug bounty and no guaranteed response times beyond a good
faith effort.

## Scope

The threat model is documented in full in [`docs/threat-model.md`](docs/threat-model.md), including
what is deliberately **not** defended against. Reports in these areas are known boundaries rather
than vulnerabilities:

- **Root on the host** reading the master key from the service environment file or from process
  memory (adversary A5). This follows from unattended startup (ADR-5) and is the same boundary
  OpenBao has with a static seal.
- **A compromised build pipeline.** Whoever can replace the image wins; the countermeasure is
  supply-chain hygiene, not application code.
- **Side channels beyond timing in credential comparison** — cache timing, speculative execution.
- **Denial of service through fail-closed auditing.** A full audit volume taking the service offline
  is the intended behaviour, not a bug. An access that could not be logged but happened anyway would
  be the bug.

Everything else is in scope, and these in particular are the reports worth having:

- Any path by which a secret value, key material, or a token reaches a log, an error message, an
  audit entry, or a response that should not contain it.
- Any divergence between how a request path is routed and how it is authorized (ADR-9).
- Any access that produces no audit entry, or a bulk operation that produces fewer entries than
  secrets served.
- Any way to alter or truncate the audit trail without the hash chain detecting it.
- Any escalation from a valid identity to data outside its policy.

## Cryptographic design

The key hierarchy, the choice of primitives, and the reasoning behind them are documented rather than
left implicit — see the implementation plan and [`docs/adr/`](docs/adr/). If you believe a
construction is wrong, that is a report we want, even without a working exploit.
