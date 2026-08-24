# Assurance

**Status:** current as of 2026-08-24. Eleven records: six reviews and five field reports, none of
them a review by a human practitioner.

This directory holds *evidence*, and evidence is a snapshot. Every file below describes a tree that
existed on the day named in it, and none of them is updated to stay true — that is the difference
between what is here and everything one level up in [`../`](../README.md), which describes the system
as it is now. A record that was edited to match today's code would no longer be a record of anything.

**The current assurance position is not in this directory.** It is
[`../security-review.md`](../security-review.md): the maintained working paper that states the scope,
the claims, what would falsify each one, which review was accepted and what that acceptance does
*not* stretch to. Read that first. The files here are what it cites.

**Two rules follow from these being snapshots**, and both are enforced rather than remembered.
`ci/check-doc-dates.sh` does not require a status date here to move when a file is edited — the date
records when somebody read a tree, and moving it would falsify the provenance. `ci/check-doc-commands.sh`
does not require a command quoted here to still exist — a field report shows what was actually run
against the version it names, and rewriting that would erase the evidence that a rename happened.
Both gates make the same two exceptions for `../adr/`, for the same reason. This index is held to
both.

## The one thing to know before reading any of them

**No review here was performed by a human.** Every one was performed by an AI model commissioned by
the maintainer — in two cases by a model that also co-authored the code it was reading, which is
stated in those records. `../security-review.md` asks for a human practitioner, names that condition
as unmet, and says what publishing without it cost. A record that reports a check as cleared without
saying who cleared it is useless the moment a stranger reads it, so each file says so on its own.

## Reviews

Newest first. "Scope" is what the record itself says it read.

| Record | Date | Against | Scope | Status |
|---|---|---|---|---|
| [reviews/review-2026-08-24-full-repository.md](reviews/review-2026-08-24-full-repository.md) | 2026-08-24 | `e1940fb` | The complete repository: crates, viewer, images, automation, documentation, and the control-plane surface added after `v0.5.1` | Review evidence; answered in `v0.11.0` |
| [reviews/review-0.5.1-2026-08-21.md](reviews/review-0.5.1-2026-08-21.md) | 2026-08-21 | `v0.5.0..v0.5.1` | The diff answering a field report, by that deployment's operator. Explicitly **not** a security review and extends no acceptance | Review evidence |
| [reviews/review-2026-08-21-current-tree.md](reviews/review-2026-08-21-current-tree.md) | 2026-08-21 | `b974916` | Source review of the tree *including* the `honeypot_alert` authentication surface the accepted review excluded | Review evidence; findings answered through `v0.8.0` |
| [reviews/review-2026-08-21.md](reviews/review-2026-08-21.md) | 2026-08-21 | `v0.3.0` (`964f1fa`) | The mandatory scope of the working paper: `ciphr-crypto`, `ciphr-policy`, and the path and pattern code in `ciphr-core` | **The accepted review.** Six findings, all disposed of; both blocking conditions fixed |
| [reviews/review-adr-15-16-2026-08-20.md](reviews/review-adr-15-16-2026-08-20.md) | 2026-08-20 | ADR-15, ADR-16 | A **design** review of two then-proposed records; nothing was implemented at the time | Historical snapshot |
| [reviews/review-2026-08-18.md](reviews/review-2026-08-18.md) | 2026-08-18 | pre-`v0.3.0` | A pre-review pass against the working paper's list, by the model that co-authored the code — read for what it says it did *not* check | Historical snapshot; does not satisfy the precondition |

**Which one discharged the precondition:** `reviews/review-2026-08-21.md`, accepted by the maintainer
on 2026-08-21. The two later reviews add coverage; neither replaces its fitness statement, and both
say so in their own opening. What the acceptance covers, and the three claims marked as newer than
it, are in [`../security-review.md`](../security-review.md) — that document is authoritative on scope,
not this table.

## Field reports

From the operating side of a private deployment, newest first. These are not reviews: they report
what broke, what was confusing, and what an operator needed and did not have.

| Report | Date | Against | Answered in |
|---|---|---|---|
| [field-reports/field-report-2026-08-23-b.md](field-reports/field-report-2026-08-23-b.md) | 2026-08-23 | `v0.9.0` | `v0.10.0` |
| [field-reports/field-report-2026-08-23.md](field-reports/field-report-2026-08-23.md) | 2026-08-23 | `v0.7.0` | `v0.8.0` |
| [field-reports/field-report-2026-08-22.md](field-reports/field-report-2026-08-22.md) | 2026-08-22 | `v0.6.1` | `v0.7.0` |
| [field-reports/field-report-2026-08-21-b.md](field-reports/field-report-2026-08-21-b.md) | 2026-08-21 | `v0.5.0` | `v0.5.1` |
| [field-reports/field-report-2026-08-21.md](field-reports/field-report-2026-08-21.md) | 2026-08-21 | `v0.4.0` | `v0.5.0` |

The release that answered each is in [`../../CHANGELOG.md`](../../CHANGELOG.md), and the operator
action any of them produced is in [`../operations/upgrade.md`](../operations/upgrade.md). Where a
finding changed code, the code says which finding — that provenance is why these files are kept
rather than summarized.

## Where the rest of the evidence is

| What | Where |
|---|---|
| The current assurance position, the claims, and what would falsify them | [`../security-review.md`](../security-review.md) |
| Adversaries, and the boundaries deliberately not defended | [`../threat-model.md`](../threat-model.md) |
| What the fuzz targets do and do not prove | [`../fuzzing.md`](../fuzzing.md) |
| The decisions themselves, including what was rejected | [`../adr/`](../adr/) |
| How to report a vulnerability, and what is in scope | [`../../SECURITY.md`](../../SECURITY.md) |
