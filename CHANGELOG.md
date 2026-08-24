# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is something to version.

This file is updated in the same commit as the change it describes.

## [Unreleased]

### Fixed — a stale store lock could be taken over by two processes at once

**F2 of [`docs/review-2026-08-24-full-repository.md`](docs/review-2026-08-24-full-repository.md).**
The lock was the lock *file* and nothing else, so every operation on it acted on a pathname rather
than on a holder. Two processes could both read the same dead holder and both classify it as stale;
the first removed it and created its own, and the second then carried out the removal it had already
decided on — deleting the first one's fresh lock. Both returned success, and the store had two
writers.

That is the one thing this module exists to prevent, and the consequence is the one it documents from
a measurement: two writers hold different in-memory audit heads, the second record collides on a
sequence number, no device accepts it, and fail-closed refuses **every** request until the process is
restarted.

`Drop` had the same shape, and that half is what a test can show directly: it removed whatever had the
lock path, so a guard that had finished could delete a lock somebody else was holding.

The lock now carries an identity — the bytes the guard wrote — and every operation is about those
bytes. A stale lock is removed only if it still holds what the decision was made about; a freshly
created lock is read back, and a guard that does not find its own bytes tries again instead of
returning a lock it does not hold; `Drop` releases only its own. Writing the identity is no longer
best effort, because a lock nobody can identify is not one to hold.


### Added — every image and every binary is published for arm64 as well

The rest of [issue #4](https://github.com/nuetzliches/ciphr/issues/4). The three images —
service, wrapper, viewer — are manifest lists over an amd64 and an arm64 build, and the release
attaches four binary assets instead of two.

- **One build per architecture on a runner of that architecture**, pushed by digest, with a merge job
  creating the tag. Not one runner with qemu: compiling Rust under emulation is an order of magnitude
  slower and puts the emulator inside the artefact everybody pulls.
- **The wrapper assets are still taken out of the images that were just published** — `docker create
  --platform` against the manifest digest, then `docker cp`. So each asset and the file inside its
  image are the same bytes, and the retrieval path a deployment follows is exercised on every release
  rather than the first time somebody needs it. `docs/operations/wrapper.md` gains the `--platform`
  it now needs, and says why it is needed even when it matches the host.
- **`docs/operations/wrapper.md` also says the thing that bites:** the file is not interchangeable
  between architectures. An amd64 binary mounted on an arm64 host is `exec format error` at the moment
  a service is starting without its secrets.

**And CI builds the images now.** Nothing did, before this: a release built them, and only a release,
which is how `v0.6.0` published one image and failed to build the other. Both files are built on both
architectures on every pull request, pushing nothing. The pre-flight build inside the release workflow
is gone — the gate did not disappear, it moved earlier and got wider.

### Changed — the runtime stage installs exact package versions from a Debian snapshot

`docs/threat-model.md` said the `apt-get install` in the runtime stage of the `Dockerfile` was "the
first thing that will have to give way" for reproducible builds. It has.

Until 2026-08-24 that line resolved `ca-certificates curl gosu` to whatever the archive offered on
the day of the build. The base layer was pinned by digest and this was not, so two builds of one
commit produced two images and nothing recorded which one a deployment was running. It now installs
three exact versions from a Debian snapshot named in a build argument.

**The versions were measured on both architectures before they were written down** — identical on
amd64 and arm64, including the `+b10` binNMU on `gosu`. That is the detail that decides whether one
set of pins can serve a multi-architecture build at all, and it is the kind of thing that is assumed
and then discovered during a release. Both runtime stages were then built and read back: each
contains exactly the pinned versions, the service user, and the base image's own apt sources —
untouched, because the snapshot list is handed to apt rather than written into the image.

**What this is worth, narrowly:** an image built from this commit next year installs the same three
packages. It is **not** a claim that two builds produce the same digest — the toolchain image is
pinned only by its digest, `musl-tools` in the wrapper's builder stage is not pinned, and nobody has
rebuilt a published image and compared it. The threat model says so in those words rather than
letting "pinned" stand in for "reproducible". What did change is that a third party can now check:
the repository is public.

**Bumping a version is a deliberate commit** — move the snapshot, read the three versions out of it,
say in the changelog what the bump carries. A security update arriving on its own is what this gives
up.

### Added — the gates cover arm64, and the action picks the architecture it is on

Half of [issue #4](https://github.com/nuetzliches/ciphr/issues/4), and the half it calls the one with
an *external* trigger. `ciphr-run` is mounted into images this project does not own and `ciphr-ci` is
downloaded onto whatever runner a job got, so their architecture is decided by somebody else's
machine. The first arm64 runner to mount an amd64 wrapper gets `exec format error` from inside a
foreign container, at the moment a service is starting without its secrets.

- **Every commit now builds and runs both binaries on a native amd64 and a native arm64 runner.**
  Native rather than emulated, because the tests run the binaries *as* static musl executables —
  static musl is where name resolution breaks — and under qemu that assertion would be partly about
  the emulator. The strip and linkage checks are the host's tools too, and those do not read a foreign
  ELF.
- **The size budgets are per target, and the second measurement is the argument for that.** The
  aarch64 wrapper is **2,888,088 bytes** against amd64's 3,367,856 — *smaller*. A single budget picked
  to clear the larger one would have let the smaller binary grow by half again before the gate said
  anything. All four numbers are now measured on the runners that build the artefacts rather than
  derived, which is what the scripts had been asking the next person to do. An unknown target is
  refused rather than defaulted: a target with no budget is a gate that checks nothing while reporting
  that it ran.
- **One claim became a fact on the way.** The aarch64 size was first measured in an emulated
  container, on the argument that emulation changes how long a build takes and not what comes out. The
  native runner produced the same 2,888,088 bytes, and the script records that rather than the
  argument.
- **`action.yml` reads `uname -m`** and takes the matching asset, verified against a checksum for that
  architecture — hence `sha256-amd64` and `sha256-arm64` instead of one input that can only be right
  about one of them. An architecture the releases do not carry is refused rather than handed a binary
  that cannot execute.
- **The required check keeps its name.** The matrix legs report as `Static binaries (amd64)` and
  `(arm64)`; a job carrying the name the branch ruleset requires asserts them. Requiring the legs
  directly would mean editing the ruleset whenever the matrix changes, and a required check that no
  longer exists blocks every merge without saying why.

**What this does not do yet:** publish the arm64 assets or multi-architecture images. The release
side is the other half of that issue, and the asset name carrying the target triple — done on
2026-08-21, while amd64 was the only one — is what makes it an addition rather than a rename.

### Changed — every change lands through a pull request

Since 2026-08-24, and enforced by a repository ruleset on `main` rather than by habit: a pull request
is required, five checks have to pass, force-pushes and deletions are refused. **The ruleset has no
bypass actors**, so it applies to the four organization owners too — which is the difference between
a ruleset and the branch protection this project could not have while it was private, and the reason
the rule is worth writing down at all. An emergency push means deactivating the ruleset, pushing and
reactivating it: deliberately awkward, and visible in the audit log.

No approval is required. That is the honest state of a project whose contributors are the same few
people, and `AGENTS.md` says why an approval that gets rubber-stamped would buy a checkbox and cost
the rule that matters. The required checks are the four that judge only the pull request, plus
`Licenses, advisories, dependency budget` — which can go red without anything in the pull request
changing, and is required anyway, because for a secret manager that is the point of having it. The
fuzz smoke run is deliberately not required: a nightly toolchain that moves under a gate turns an
unrelated merge into somebody's afternoon.

`AGENTS.md` also loses its "while the repository is private" framing in two places. Work no longer
lands directly on `main`, and a breaking change is no longer an ordinary commit: from here it needs a
deprecation, a version, or a written argument for why it cannot wait, because the consumers are now
people who did not agree to the old arrangement.

### Changed — this repository is public, and the site is live

Since 2026-08-24. <https://nuetzliches.github.io/ciphr/> is published from `site/` by
`.github/workflows/pages.yml`, and `README.md` and `docs/README.md` link to it — a link deliberately
absent while the site was reachable nowhere.

**The guard in that workflow did its job on the way there**, which is worth recording because it is
the only evidence that a guard of this shape is worth building. Two runs fired from pushes while the
repository was still private; both resolved the visibility check and skipped the deployment. The
first run that published anything was the manual one after the flip.

**Private vulnerability reporting is enabled**, which it was not at the moment of publication. For a
few minutes `SECURITY.md` pointed reporters at a button that did not exist — the documented channel
existed as prose before it existed as a setting. Both channels work now: the GitHub form, and
`security@nuetzliche.it`.

One thing publication does **not** do by itself, and it is the one an operator feels: the GHCR
package does not become public with the repository. Until it is switched, a deployment host without a
read credential cannot pull a new image.

### Changed — three decisions taken on the way to a public repository

Each of these was recorded in the repository as a condition, and each is now answered with a date
rather than left as an intention.

- **`SECURITY.md` names an address.** `security@nuetzliche.it`, beside GitHub's private vulnerability
  reporting. The file itself had asked for this before publication, on the grounds that a security
  product whose only reporting route is a platform feature has a gap — the platform can change the
  feature, and somebody without an account there cannot use it at all.
- **The history keeps three names.** `git.nuetzliche.it`, the `nuts` namespace and the
  `baumeister-runner` label were in the Forgejo workflows and stay in the history those workflows
  leave behind. Plan section 20 asked whether they may be searchable; the answer, dated, is that they
  may — a forge that serves a certificate under its own name has published it already (the
  consistency check ADR-17 invites), and a namespace and a runner label are not credentials. What
  that decision does not cover is a value that *would* be one, and the plan says the answer there is
  rotation rather than a rewrite.
- **The repository goes public without a human review, and the record says so.**
  `docs/security-review.md` names publication as one of the two things that raise the bar back to a
  human practitioner, and no such review has taken place. It now carries a section of its own —
  *Published without a human review* — saying that this is a decision against a recorded condition
  rather than a condition that was met, what was actually read and by what, what is unreviewed by
  anyone, and what would close it. `README.md`, `SECURITY.md` and the site's security notes carry the
  same sentence, because the front door is where somebody decides whether to run this.

### Removed — the second image build, and with it the one place that named a deployment

`.forgejo/workflows/build-images.yml` and `build-ui-image.yml` are gone. They existed for one
reason: a private repository means a private GHCR package, and the deployment host authenticates to
one registry rather than to the forge — so both images were built a second time, on another runner,
into an internal registry. The images are built here now and pulled from GHCR.

**What a deployment has to do about it:** while this repository is private that package is private
too, so the host needs a credential that may read it. That is a deployment-side arrangement and the
alternative to it is the repository going public. Nothing in this repository can check that it was
made, which is why it is the first line of this entry rather than a footnote.

Three things follow, and each is written where it was claimed:

- **One checksum instead of two.** The release asset is extracted from the image that was pushed, so
  the asset and the image carry the same bytes. `docs/operations/wrapper.md` said to expect a
  mismatch between the channels and to verify against the one you pulled from; it now says a
  mismatch is something to stop for, and that the old advice belongs to tags from before this date.
  ADR-14 carries the same amendment, dated, rather than a rewritten paragraph.
- **`release-ui.yml` is the single publisher of the viewer image**, and its header says so instead of
  naming a counterpart that no longer exists.
- **The publication checklist in plan section 20 loses an item and keeps a decision.** Deleting those
  files was a step it named; deleting them does not remove the forge hostname, the image namespace
  and the runner label from a history that is published with the repository. That decision is still
  open, and the plan still says so.

### Added — `ciphr-ci`, so the masking this project ships is reachable from a CI job

**The name contains *CI*, and the one thing this project does about the masking trap could not be
run by a CI job.** `ciphr export --format actions-env` is where the `::add-mask::` discipline lives —
masks before anything else, one per line, a heredoc delimiter drawn from the OS CSPRNG and verified
against the value. It is a CLI command, and the CLI works on the local store: exclusive lock, master
key, service stopped. A runner has none of that and must not. What a job could actually reach was
`curl`, `jq`, and a page of documentation asking it to reimplement the masking itself — the shape
the README rejects for exactly this rule.

**`ciphr-ci` is that fetch as a program** ([ADR-25](docs/adr/0025-the-ci-side-fetch-is-its-own-binary.md)).
It reads over the documented v1 API with a token, renders with the same code `ciphr export` renders
with, and writes mask commands to standard output and assignments into `$GITHUB_ENV`. A static musl
binary, published as a release asset with its checksum, beside `ciphr-run` and for the opposite
audience: a job downloads it, a host mounts the other one.

- **`action.yml`** is a composite action that downloads the asset, verifies the published checksum,
  writes the token to a mode-0600 file in `$RUNNER_TEMP`, and calls the binary. It carries **no
  masking logic**, deliberately: a second implementation in shell is the thing this release exists
  to avoid.
- **`ciphr-export` is a new crate**, holding the three render formats. `ciphr export` and `ciphr-ci`
  now share one implementation of the masking order and the delimiter rule, with one set of tests.
  `getrandom` moved with it and left `ciphr-cli`. No behaviour changed on the host side.
- **`ci/build-ci-binary.sh`** checks static linkage and a size budget, as the wrapper's script does
  and for its own reasons. Its budget is derived from the wrapper's measurement rather than measured;
  the script says so and says to replace it with the first real number.

New documentation: [`docs/operations/ci.md`](docs/operations/ci.md) — the workflow step, the token
shape (`ci-<repo>`, shorter TTLs), `paths` against `prefix`, what a failure looks like, and the
`set -x` caveat that masking does not cover.

### Added — the examples a consumer copies

Three routes were documented as prose where the reader needed code, and the fourth had one line in
an API document. That is now written down:

- **`docs/operations/wrapper.md` shows the compose file**, which is the thing somebody actually edits
  for route B — the `entrypoint:` override in list form, the two read-only mounts, and why the token
  volume is not the working directory.
- **`ciphr-sdk`'s front page carries two more examples**, both doctests so they cannot rot: the retry
  loop the crate deliberately does not contain (bounded, and only for the two failures that can
  resolve themselves), and handing the values to a child process with `Command::env` — which the
  documentation described and did not show.
- **`docs/operations/ci.md` has the `curl` route in full**, with the three things it leaves the job to
  do: the masking, telling the status codes apart, and not reading an empty listing as an empty
  prefix.

### Added — `site/` becomes a site, and publishes itself the day this repository is public

It was one page — the interactive diagram of the security layers — and it
is now four with a shared navigation: an overview, an integration page carrying the examples above,
security notes for whoever writes a consumer, and the diagram. The whole directory is English now,
including the diagram, which was German; the pages are static, carry the same strict
Content-Security-Policy as the viewer, and three of the four run no script at all.

Two corrections fell out of re-reading the diagram against the current code, and both were things
this release itself had made false: `bulk_export`'s cost is one request per path rather than "route B
cannot fetch at all", and the CI client names `ciphr-ci` rather than a CLI command a runner cannot
run. **`token_status` and `token_revoke` are drawn now as well** — they were added to the server after
the diagram was made, so it had been showing three of five entries. `ci/check-surface-entries.sh`
covers the diagram from here on: it compared the server against the CLI and left the third copy, the
one nobody compiles, unchecked.

**`.github/workflows/pages.yml` publishes the site, and refuses to while this repository is
private.** The decision that the site goes online *with* the go-public decision used to be
implemented by the workflow not existing, which stops working the moment somebody wants the file. It
is a guard now: the first job asks the API whether the repository is public and the deployment runs
only if it is — `workflow_dispatch` included. Nothing has to be remembered on the day the visibility
flips, and nothing publishes early because a branch got pushed. `site/README.md` lists what is still
manual on that day.

### Fixed — a job on a default deployment could not fetch at all

`POST /v1/export` is a surface entry and is off unless a deployment names it (ADR-20). Route B and
route C both read exclusively through it, so a deployment that had made **no** decision had a wrapper
that could not start a service and an SDK that could not assemble an environment — and a `404` to
explain it, the same status a missing secret produces.

- **`ciphr-sdk` falls back to one `GET /v1/secrets/{path}` per path** where the bulk route is absent
  (`Client::read_all`, used by `environment` and `environment_of`). This is what `openapi.yaml` has
  always said a route-C consumer does. The audit trail is unchanged: the bulk route writes one entry
  per secret served, never one per call, so only the number of requests differs. What does differ is
  a refusal — read one at a time, the paths before the refused one have been served and audited, and
  the error names the path that was refused rather than the set.
- **`SdkError::SurfaceEntryUnavailable`** is the new variant for a `404` from an optional route, and
  it names the entry and points at `GET /v1/health`, which lists what an instance has. A `404` is only
  read this way where the route has nothing else to be missing: `POST /v1/export` takes its paths in
  the body, so there is no path in its URL to be absent.
- **A `403` from the bulk route names the paths that were asked for.** It reported the literal word
  `export` before, which named nothing anybody could act on. The service still does not say *which*
  path it refused — that is the property that keeps an export from mapping what a caller may read.

### Changed — the viewer image refuses to build on an nginx configuration nginx refuses

`RUN nginx -t` after the configuration is copied in, for the same reason `vue-tsc` runs inside the
build stage: an image that cannot be produced from a file nginx rejects is better than a container that
discovers it at deploy time, with nothing serving the viewer. Nothing else in this repository can catch
it — `nginx -t` needs nginx, and neither a developer machine nor the CI runner has one. Prompted by the
`Service-Worker: script` refusal added for `ui-v0.3.1`, which is the first non-trivial directive in
that file.

## [0.10.0] — 2026-08-23

**The release that makes a recommended check into a usable gate.** `0.9.0` made a policy edit
mandatory and named `--check-config` in review as the way to catch a file that still has the old form.
Review is the one host that deliberately has no store — and a host with no store and a policy file the
binary refuses both exited `1`, so the pipeline that was supposed to protect the mandatory edit could
not tell the finding it runs for from the host it runs on. **A host that is not ready is exit `3` now**,
the number `ciphr state` already uses for the same shape, and `1` means the files are unusable and
nothing else. Anything that branches on this command's status wants a look; nothing else in this
release asks a deployment to do anything.

**Nothing migrates and nothing breaks in the API:** the schema stays at 6, no route changed, no
capability changed, no default moved. A rollback to `0.9.0` needs the image tag and nothing else.

Three smaller things, all from the same report. `--check-config` now says when a surface entry is on
and no identity can call it — the case being `token_revoke`, whose bootstrap is an outage this project
had documented nowhere. An audit device that cannot be opened names the requirement instead of only
the OS error. And the runbooks say to issue the revoking identity's token before the incident that
needs it.

**The viewer moves separately, as `ui-v0.3.1`**, and closes issue #10: it refuses to mount while a
service worker controls its page.

All of it answers
[`docs/field-report-2026-08-23-b.md`](docs/field-report-2026-08-23-b.md) — three findings, all of them
about a report that was read rather than acted on. **What to do rather than know is in
[`docs/operations/upgrade.md`](docs/operations/upgrade.md), section `0.10.0`.**

### Fixed — the viewer refuses to mount while a service worker controls its page (`ui-v0.3.1`)

**Finding F4 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md),
and issue #10.** `main.ts` started unregistering existing service workers and mounted immediately —
two mistakes. The cleanup is asynchronous, so the app could issue `/v1` requests while a worker was
still installed; and unregistering does not end a worker's control of a page that is already loaded,
which lasts until every controlled page closes or reloads. A worker left by an earlier application on
the viewer's origin could therefore read bearer tokens and revealed values out of a page that had just
"cleaned up".

The cleanup is awaited now, and the viewer mounts only when `navigator.serviceWorker.controller` is
absent. A controlled page gets a refusal and a request to reload, which is the point at which the
removal takes effect.

**The container's refusal stopped being about filenames.** A worker may be registered from any
same-origin URL, so refusing `/service-worker.js` and `/sw.js` never made registration impossible —
`nginx.conf` refuses any request carrying `Service-Worker: script`, which is what a browser sends when
it fetches a script in order to register it. The two filenames stay beside it. Neither can stop a
worker that is already installed, which is why the client fails closed.

**And `docs/ui.md` stopped claiming otherwise.** The security table said the property held in three
places, two of which were weaker than stated. It now says what each layer does, and says the operating
requirement out loud: give the viewer an origin that has never hosted an application that registers a
service worker. That is the half no code in this package can provide.

`ui/package.json` and `ui/package-lock.json` move to `0.3.1` together.

### Added — `--check-config` says when a surface entry is on and nobody can call it

Under the entry's own line: *on, and no identity in this policy file is authorized for `revoke` on
`sys/tokens` — nobody can call it.* Two entries are checked, `token_revoke` and `token_status`, the two
whose requirement is a single grant; the evaluator answers the question rather than a second
implementation of the same reasoning.

**The case it is for is `token_revoke`, and it is a bootstrap problem.** The entry exists so that
revoking a leaked credential does not stop the service — and the token that calls it is issued on the
host, under the store lock, so turning the entry on and issuing nothing leaves the job half done. The
operator who finds out is the one who reached for the endpoint mid-incident. An entry that is on and
unreachable is the same class of quiet as a stanza that was forgotten.

**Not a refusal, and the exit code is unchanged:** naming the entry before its identity exists is a
legitimate order of work. `honeypots.md` step 3 and `upgrade.md`'s `token_revoke` note now say to issue
that token before the incident that needs it. From
[`docs/field-report-2026-08-23-b.md`](docs/field-report-2026-08-23-b.md), finding 3.

### Changed — `--check-config` has an exit code for "the files are usable, this host is not"

**A check a pipeline cannot fail on is a check somebody remembers to read.** `--check-config` exited
`1` both for a policy file the binary refuses and for a host with no store, and `0.9.0` is the release
that made the difference matter: its policy edit is mandatory, and
[`upgrade.md`](docs/operations/upgrade.md) names review — the one host that deliberately has no store —
as the place to catch a file that still has the old form. So the gate the mandatory edit relies on
could not distinguish its own finding from the host it ran on, and what was left was parsing prose.

A host that is not ready is now exit **`3`**. `1` means the *files* are unusable and nothing else, `2`
stays the usage error, `0` is unchanged. **The precedent is this project's own, from the same day:**
`ciphr state` took `3` in `0.8.0` for the identical shape — a complete answer whose negative half is
about something other than what the caller asked — and the two commands now agree on what `3` means.

Anything branching on this command's status wants a look; the table is in `upgrade.md`, section
`0.10.0`. From [`docs/field-report-2026-08-23-b.md`](docs/field-report-2026-08-23-b.md), finding 1.

### Fixed — an audit device that cannot be opened names the requirement, not only the OS error

`audit device: cannot open /var/log/ciphr/audit.jsonl: Read-only file system (os error 30)` reads as a
broken device. What it means is that the file device is opened for append and its directory was mounted
read-only — the safe instinct for a command whose name says *check*, which is exactly where this
message is read. It now says that the device appends and that its directory has to be writable, in the
shape the rest of this project's messages have.

The behaviour is unchanged and is the defensible half: the device is checked by opening it the way it
will be opened. `ciphr`'s own file device carried the same sentence and got the same clause, naming
the user running the command rather than the service user. From
[`docs/field-report-2026-08-23-b.md`](docs/field-report-2026-08-23-b.md), finding 2.

## [0.9.0] — 2026-08-23

**The release that closes four issues and breaks one thing on purpose.** `read` authorized a secret's
value *and* the control plane, with only the path separating them — so the rule somebody writes for a
break-glass identity meaning *all the secrets* granted the audit trail and the map of the
authorization model along with them. That is fixed by changing what a capability means, which is a
breaking change, and **it is the one thing to do before starting this version**: a rule under `sys/`
that grants `read` becomes `inspect`, one edit per policy file, and the server refuses to start on the
old form rather than accepting a grant that would authorize nothing.

**Nothing migrates:** the schema stays at 6, so a rollback to `0.8.0` needs a policy file edited back
and nothing else.

**Three things become possible that were not.** Revoking a leaked credential no longer needs an
outage — `POST /v1/tokens/{token_id}/revoke`, the first and only write this API has ever had, behind
an entry that is off until a deployment names it. The token inventory has an authenticated answer,
`GET /v1/tokens`, where the trail can name who asked instead of `cli:$USER`. And the listener no
longer advertises HTTP/2: a handshake against it used to negotiate `h2`, which no decision in this
repository had ever made.

Issues #5, #14, #3 and #6 are answered, two of them by
[ADR-23](docs/adr/0023-the-control-plane-is-its-own-capability.md) and
[ADR-24](docs/adr/0024-revocation-is-the-one-write-the-api-may-do.md), one by an amendment to
[ADR-9](docs/adr/0009-http-stack-axum-but-narrow.md). **What to do rather than know is in
[`docs/operations/upgrade.md`](docs/operations/upgrade.md), section `0.9.0`** — five notes, of which
one is mandatory and four are switches a deployment may leave alone.

### Added — the token inventory over the API, as the authenticated answer

`GET /v1/tokens`, behind the new **`token_status`** surface entry and `inspect` on `sys/tokens`.
Issue #3's second item, unblocked by ADR-23 giving the control plane a capability to authorize
against.

**This does not make anything answerable that was not.** ADR-22 made `ciphr token list` read-only in
`0.7.0`, so expiry, revocation state and last use have been readable with the service up since then.
What the host path cannot do is name who asked: it records nothing, and its principal would be
`cli:$USER`, self-declared. Over the API the caller is an authenticated identity and the read is in
the trail — which is exactly what ADR-22's own consequences said belonged here.

No credential and nothing derived from one: no verifier, no token, and a test asserts that against the
whole document rather than field by field. `state` — `valid`, `expired`, `revoked` — moved into
`ciphr-store` beside the record it describes, because the CLI derived those three words inline and
this route would have derived them again: two readers, two answers to *"is this credential still
valid"*, waiting to disagree. `honeypot` is on this path and no path a presenter can reach, which is
where ADR-15 puts it.

**Its own entry rather than part of `viewer_api`**, and that is the one decision here: adding a route
to an existing entry widens a cost a deployment already accepted, silently, at upgrade time — the
failure ADR-23 argues against for a general `admin` capability, one layer over. Which credentials
exist and which have never been used is its own cost, so it gets its own record.

### Changed — the listener speaks HTTP/1.1 only, and this repository decides that

**Issue #6 was a reading of dependency sources, and it asked to be measured. It was, and it was
right.** `axum-server` requests `hyper/http2` unconditionally and its `RustlsConfig::from_pem` sets
`alpn_protocols = ["h2", "http/1.1"]`, while `grep -rn alpn crates/` found nothing —
`crates/ciphr-server/tests/tls_alpn.rs` completed a real handshake against the listener and got
`h2`, and an HTTP/2-only client got a working connection.

That is a second framing implementation — HPACK, stream multiplexing, flow control, CONTINUATION — on
the connection path of the one process that holds plaintext secrets, arrived through a transitive
feature rather than through a decision, and outside what the accepted review read.

`tls::load` now sets the ALPN list itself: **`http/1.1` and nothing else.** A client offering both
gets HTTP/1.1; one that speaks only HTTP/2 gets no handshake. `h2` stays compiled in, because
removing it means replacing `axum-server` with our own accept loop and graceful shutdown — code on the
connection path that we would then have to review ourselves, which is the trade ADR-9 made in the
other direction. The test pins the negotiated protocol, so a dependency bump that restores `h2` fails
in CI rather than in a deployment.

[ADR-9](docs/adr/0009-http-stack-axum-but-narrow.md) is amended: **"narrow" describes the artefact**,
and the honest form of it is narrow in what the listener will speak, with one framing implementation
compiled in that it will not. `crate::tls` is also the only place that could state a TLS version or
cipher policy, and it states neither — that is now recorded as unstated rather than left to be
discovered.

### Changed — the control plane is its own capability, and a policy file that says otherwise is refused

**BREAKING for a policy file that reaches `sys/` through a secret capability.** `read` authorized a
secret's value **and** the control plane — `sys/audit`, `sys/identities`, `sys/policies`,
`sys/surface`, `sys/honeypots` — with only the path separating them. So `path = "**"` with `read`,
the shape somebody writes for a break-glass identity meaning *all the secrets*, granted the audit
trail and the map of the authorization model along with them. Issue #5 filed it; nobody wrote down
that they wanted it, and *"which identities can read the audit trail"* was answerable only by
evaluating every rule against every reserved path.

[ADR-23](docs/adr/0023-the-control-plane-is-its-own-capability.md): **`inspect` reads a control-plane
path, `revoke` revokes a token.** Seven capabilities, and the five that existed mean secrets and only
secrets. A rule that names `sys/` and grants one of them is **refused when the policy file loads**,
with the capability that is meant instead — not accepted and quietly denied, because the reader who
would find out that way is a monitoring identity that silently stopped seeing anything.

**The evaluator did not learn the reserved prefix, and that distinction is load-bearing.** Deciding
an access is still one code path with no special case; the refusal is a *load-time validation*, which
is a different job and the one that can afford to know that `sys/` is not an ordinary prefix.
`--check-config` runs it with no store and no master key, so the edit is findable in review rather
than on the host.

**What to change**, and it is one edit per file: `capabilities = ["read"]` becomes
`["inspect"]` on a rule under `sys/`. Affected are the identities that read the control plane — the
viewer's token, a monitoring identity polling `GET /v1/audit`, anything reading `/v1/identities`,
`/v1/policies`, `/v1/surface`, `/v1/honeypots`. **Unaffected:** every identity with only secret
grants, however broad, including `**`. The trail's vocabulary is unchanged too: reading `sys/audit`
is still recorded as `read`, because the capability answers *who may* and the action answers *what
happened*.

### Added — revocation is the one write the API may do, behind an entry that is off by default

Revoking a leaked credential meant stopping the secrets service: `ciphr token revoke` takes the
exclusive store lock the running server holds, so the host sequence is stop, revoke, start — an outage
at the one moment nobody planned for, and `honeypots.md` step 3 fires exactly then. The server has
always checked revocation on every request, so the mechanism for instant revocation was built and only
the path that writes the row was missing (issue #14).

`POST /v1/tokens/{token_id}/revoke`, behind the new **`token_revoke`** surface entry
([ADR-24](docs/adr/0024-revocation-is-the-one-write-the-api-may-do.md)). **ADR-3 is narrowed by a
named exception, not repealed**, and the boundary is the record's own list: one token per request,
authorized as `revoke` on `sys/tokens` and reachable through no other capability, **no master key
involved**, idempotent by the `COALESCE` that was already in the SQL, and the audit entry names the
authenticated caller as principal and the revoked token as subject — the same shape the CLI records,
so a trail reader does not have to know which side a revocation came from.

**Issuing stays on the host** because it needs the master key and *creates* a credential, and
`revoke-all` stays there because one request that invalidates every credential of an identity is an
availability weapon. **Off means absent:** a deployment that does not name the entry has no privileged
write path at all — not a handler that refuses — and turning it on records a date and a reason like
every other entry.

The surface list therefore has a fourth entry, so `--check-config`, `ciphr surface show` and
`GET /v1/surface` each gained a row.

## [0.8.0] — 2026-08-23

**The release that answers a field report, and two of its findings are the same shape.** The fourth
report from a private deployment ([`docs/field-report-2026-08-23.md`](docs/field-report-2026-08-23.md))
names it better than a summary can: *"two of the four findings are about a check whose verdict is
about something other than what the caller asked."* **Nothing migrates:** the schema stays at 6, so a
rollback to `0.7.0` needs neither a restore nor a configuration edit.

**A gate satisfiable by fabrication protects nothing.** `--check-config` printed its whole report —
the surface report included, which is a pure function of the configuration file — only after the store
had been opened, locked and written to. The mistake it exists to catch is a *forgotten* surface stanza,
and that file is legal, so nothing else answers it. The deployment therefore built a store on every
deploy to get past the gate. The report is now in two halves, file first and host last, and the check
stopped taking the writer lock, stopped migrating the store, and stopped appending to the trail — three
side effects that each made it unrunnable somewhere it was wanted.

**An exit code about files the caller must not have.** `ciphr state --exclude` derives its rows from
`[storage] path` alone, so a backup container that follows `backup.md` and cannot see the TLS material
or the master key got a complete, correct list and a non-zero status about the files it was right not to
have. That is `3` now, distinct from `1` for a command that failed and from clap's `2` for a usage
error.

**Two things to check rather than know**, both in
[`docs/operations/upgrade.md`](docs/operations/upgrade.md): anything that branches on `ciphr state`'s
exit status, and anything that parses `--check-config`'s output, whose shape changed. And one refusal
that is new rather than moved: a named pipe or a directory where a credential file is expected is
refused for what it is, because the master key and token files are now opened once and read through
that one descriptor (F10 of the source review, issue #13).

### Changed — `--check-config` answers about the file before it looks at the host

**The gate was satisfiable by fabrication, so it protected nothing.** `ciphr-server --check-config`
was `Server::prepare` with the listener left off, so its *whole* report — including the surface
report, which is a pure function of the configuration file — printed only after the store had been
opened, locked and written to. The fourth field report from a private deployment
([`docs/field-report-2026-08-23.md`](docs/field-report-2026-08-23.md), finding 1) shows what that costs
in practice: the deploy script creates a scratch store on every run — `chown`, `ciphr init` with the
production master key, check, delete — because the alternative was not running the check. *"The
fabrication is what every validator has to build."*

And the mistake the check exists to catch is exactly the one that needs no store: a **forgotten**
`[[surface]]` stanza. That file is legal, so the parse-level refusals say nothing about it, and the
surface report is the only place the question is answered.

`Server::check` now returns the two halves separately. The file half — configuration, policy counts,
resolved surface — is printed first and holds without a host; the store half is a labelled `store:`
section at the end. Exit is unchanged: zero when the store is ready, non-zero when it is not, with the
reason in that section. So the same binary that will run a configuration can check it in review, with
nothing mounted but the two `.toml` files.

**Three side effects went with it, and each was worse than the inconvenience:**

- **No store lock.** The old check took the exclusive writer lock, which the running service holds — so
  the only host with a store was the only host where the check could not be run without an outage.
- **No migration.** `SqliteStore::open` migrates on open, so pre-flighting a store with the *newer*
  binary performed the schema move that the pre-upgrade backup, taken in the step after it, exists to
  make reversible. The check opens read-only now, and `tests/check_config.rs` winds a store's schema
  back to pin it.
- **No audit record.** `prepare` records the active surface. That entry is right for a process about to
  serve and false for one about to exit, and a check nobody can run twice without explaining the second
  line is a check nobody runs.

The check also no longer creates an empty `store.db` at the configured path on a host that has none,
which is what a read-write open did on the way to reporting "not initialized".

### Changed — `ciphr state` exits `3` when the listing is complete and a file is missing

**The exit code was about rows the caller must not have.** `--exclude` prints the paths that must never
be copied, derived from `[storage] path` alone — nothing a missing TLS leaf or key file does can change
them. A backup job in its own container, following
[`docs/operations/backup.md`](docs/operations/backup.md)'s *keep the key somewhere this backup is not*,
therefore gets a complete and correct exclude list and a non-zero status about three files it must not
see. The deployment that wired it up ignores the status by design and validates the output instead:
*"Writing that guard felt like re-implementing a check the tool had just performed"*
([`docs/field-report-2026-08-23.md`](docs/field-report-2026-08-23.md), finding 2).

All three forms now exit **`3`** for "listing complete, pre-flight failed", and `1` still means the
command failed. The report asked for `2`; `2` is what clap returns for a usage error, and a job
branching on a status must not have to tell a misspelled flag from a pre-flight result.

### Changed — a `ciphr backup` destination that cannot be written names its directory

`unable to open database: /out/store-pre.sqlite` is one word away from what an unreadable *source*
says, and the row above it in `backup.md` is that source failure. So the first guess is the store —
while every other sentence at that moment is about the source too. The failure is also *created* by
following the fix for the previous one: run as the service uid, into a directory owned by the
operator's login ([`docs/field-report-2026-08-23.md`](docs/field-report-2026-08-23.md), finding 3).

The message now names the destination and its directory and says which end to check. The refusal to
overwrite an existing backup keeps SQLite's own words, which `backup.md` documents. A row for this
failure is in *What breaks, and how it will look*, where the causal note belongs.

### Fixed — credential files are opened once, and read through that descriptor (F10)

The master key file (`ciphr-crypto`) and the token file (`ciphr-run`) inspected the path with
`metadata` and then read it again by name: two resolutions of one name, so whoever can create entries
in the directory a credential lives in could exchange the approved file for another in between. F10 of
[`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md), filed as issue #13,
low severity and cheap — and the mode check is what makes it reachable, because it is the reason a
deployment leaves a credential in a directory a service account can write.

`ciphr_core::open_credential` opens once, takes the mode from the descriptor, and hands the caller the
same open file to read from. It also **requires a regular file**: a named pipe where a token is
expected was a read that never returned, and mode bits on a pipe say nothing about who is on the other
end. `O_NOFOLLOW` is deliberately not used — it needs `libc`, and `ciphr-run`'s dependency list is
itself the guarantee there (ADR-14); the substance is the single descriptor. What is left is a trust
requirement on the file's owner and its parent directory, now written down where the mount is written
([`wrapper.md`](docs/operations/wrapper.md)) and where the key is chosen
([`master-key.md`](docs/operations/master-key.md)).

**F9 of that issue — the core-dump limit failing open — was closed in `0.7.0`** and the same field
report confirms it from the operating side: `ulimit -c` reads `0` in the `0.7.0` image, measured before
the pin moved.

### Documentation — the `--exclude` paths belong to the service's mount namespace

`--exclude` prints what the configuration names, so a backup job in its own container has to translate
the list before handing it to anything — and an exclusion that matches nothing looks exactly like one
that works: no error, a slightly larger archive, a surprise at restore. The tool cannot know the
mapping; one sentence in `backup.md` and `cli.md` is what was missing
([`docs/field-report-2026-08-23.md`](docs/field-report-2026-08-23.md), finding 4, which asked for
nothing else).

### Changed — the mirror cannot publish half a version either

`0.7.0` closed this on `release.yml` and left it open where it was first observed. Finding 5 of
[`docs/field-report-2026-08-22.md`](docs/field-report-2026-08-22.md) named **the mirror** — *"the mirror
this deployment pulls from shows the same gap, because it builds the two images in two steps of one job
the same way"* — and that is the registry a deployment actually pulls from. Fixing only the GitHub side
answered the report's argument and not its subject.

**Measured before changing anything**, through the Forgejo package API: `nuts/ciphr:0.6.0` is in that
registry and `nuts/ciphr/run:0.6.0` is not. So the mirror did run for `v0.6.0` and did fail the same
way, which until now was a hypothesis in a handoff note.

`.forgejo/workflows/build-images.yml` now **builds both images before pushing either**. One job, so this
is cheaper than the gate on the other side: no second build, no cache to warm, and nothing reaches the
registry until the pair exists locally. What remains possible is a push that fails after its image
built — a registry or credential problem rather than a build that was never going to work, and that one
cannot be designed away.

Both `0.7.0` references are in the mirror, and were before this change: `nuts/ciphr:0.7.0` at
21:09:27Z and `nuts/ciphr/run:0.7.0` at 21:09:53Z.


## [0.7.0] — 2026-08-22

**The release that answers a review and a field report.** Six findings of the source review of
2026-08-21 ([`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md)) — one
high, three medium, two low — plus the two claim notes that turned out to say more than the code did,
and the three asks of the deployment that rebuilt its nightly backup around `0.6.0`
([`docs/field-report-2026-08-22.md`](docs/field-report-2026-08-22.md)). **Nothing migrates:** the schema
stays at 6, so a rollback to `0.6.1` needs neither a restore nor a configuration edit.

**The two that reach a deployment rather than a reader.** `export --format actions-env` used a
predictable heredoc delimiter, so an identity allowed to write one exported secret could define
environment variables for later steps of every workflow that read it — that one is why this release is
worth taking promptly. And a honeypot *token* wrote its audit entry and latched nothing, so a
deployment doing all three things the runbook asks still missed the event.

**Three things to do rather than know**, all in
[`docs/operations/upgrade.md`](docs/operations/upgrade.md): the container now refuses to start where
core dumps cannot be disabled; a tripwire that was quiet for token bait can start paging; and the
honeypot fixes sit behind a *build* entry, so a deployment that plants bait has to rebuild its derived
image to get them — the published default artefact does not contain that code, which is the point of
the entry.


### Added — `ciphr state` answers a job as well as a person

`ciphr state` derives the file set from the configuration, which was the right idea pointed at one of
its two readers. Its output is aligned columns with a two-level indent that carries meaning and a
free-text verdict per row: a report a person reads. The natural consumer of *what do I have to keep*
is the job that keeps it, and a parser written against aligned prose breaks on the next rewording. A
deployment wired its nightly backup around this command, could not parse the report, and ended up
naming its paths itself — the hand-maintained list this command exists to replace, one layer further
out ([`docs/field-report-2026-08-22.md`](docs/field-report-2026-08-22.md)).

**`--json` is the same inventory with the verdict as a value.** One self-describing document:
`format`, the configuration it read, and an object per piece carrying `role`, `path`, `state`
(`present`, `absent`, `missing`, `not-a-file`), `required` and `verdict` — one of `include`,
`include-with-store`, `never`, `separately`, `reissue`, `unknown`. Branch on `verdict`; `note` carries
the table's sentence for whoever reads the job's log and is the one field here that may be reworded.
The two rows no configuration can name — the anchor file and the archive's rotated siblings — are in
the document too, under `not_derivable`, because a job building a file list is exactly what needs to
be told about them rather than shown a paragraph on standard error.

**`--exclude` prints the paths that must never be copied**, one per line and nothing else, which is
the form a backup tool's exclude list can be handed rather than taught. Until now the one file that
must not be in a backup — `store.db.lock`, whose restored copy names a process that does not exist
and is for that reason treated as **held** — was named in prose in two documents and in no pattern, so
the exclusion was a line somebody wrote by hand after reading a page they reach only during an
incident. The `-shm` is in that list as well, and appears in the table for the first time: a
file-level job that globs `store.db*` picks it up, and SQLite rebuilds it anyway. Absent files are
printed too, deliberately — the lock exists only while the service does, which is after whoever
configured the job read this output.

**The master key is deliberately not in `--exclude`.** Its verdict is `separately`, not `never`, and
that distinction is the reason the field exists: a job fed the key here would be excluding it from
every backup it takes, which is how a key is lost rather than how it is kept out of the store's
archive.

Both forms exit non-zero on a missing required file, exactly as the table does — the pre-flight half
of this command does not depend on who reads its output. Four tests pin the part that is a contract:
the verdict spellings, that no `role` carries the table's indent, that the key never reaches the
exclude list, and that the two forms refuse to be combined.

### Documentation — the read-only backup recipe stops working exactly when the service does

[`backup.md`](docs/operations/backup.md) said `ciphr backup` runs "with the service running or
stopped", and on a container host the recipe that follows from that sentence is a throwaway container
of the same image with the data directory mounted **read-only**. It works while the service runs and
fails when it does not, which is the opposite of what the sentence suggests. The store is
write-ahead-logged, SQLite can only open such a database if the `-shm` file is there or can be
created, and a *clean* stop checkpoints the log away and removes both sidecars. `0.6.0` is the release
that made `docker stop` reach the graceful shutdown, so that state became the ordinary one after a
maintenance stop rather than a rarity — and `open_read_only` cannot create the file on a read-only
mount, so the command fails in exactly the window where somebody is most likely taking a copy by
hand: the service is down and there is time.

The document now says so, and says what to do instead: **mount the source read-write and run as the
service's uid.** While the service holds the database open, nothing is written at all. The `-shm`
created against a stopped store belongs to whoever created it, and a root-owned one in the store
directory leaves the service unable to open its own database on the next start, which is the half that
must not be got wrong. The "what breaks, and how it will look" table has a row for the failure too.

**And a section about the job rather than about the command.** The documented example is a dated
destination, which is the right shape for a copy taken by hand before an upgrade. A scheduled job
usually wants one fixed name so that the file-backup tool behind it deduplicates instead of
accumulating — and that choice interacts with a documented refusal, because `ciphr backup` will not
overwrite an existing file. So a fixed-name job needs an `rm` immediately before it and a dated-name
job owns its retention, and neither was written anywhere. Schedule, retention and where the copies go
stay out of this document; which of the two shapes needs an `rm` does not, because that is this
command's own behaviour and nothing else said it. The section also recommends running `ciphr audit
verify` on the copy inside the job: `backup`'s own checks prove the file is a readable database, and
`verify` proves it is *this store's* trail — two different claims, both cheap, neither needing the
master key or the store lock.

No code changed. Both halves were measured by the deployment that reported them
([`docs/field-report-2026-08-22.md`](docs/field-report-2026-08-22.md), findings 2 and 4).

### Changed — a release can no longer publish half of itself

`v0.6.0` published its server image, moved `:latest` to it, and then failed to build
`Dockerfile.run`. `0.6.1` fixed the cause and named what would have caught it — a CI step that builds
that file — then priced that step and declined it, because it doubles a job on every push for a file
that changes rarely. The decision was right and it left the class open: the next change to the
wrapper's build inputs can break a release the same way, and the first sign is again a tag that exists
half.

`release.yml` now builds `Dockerfile.run` in a job that **pushes nothing, and that both publishing
jobs wait for.** That is the part which had gone unnoticed: the two of them hung off `verify` alone and
ran in parallel, so one could publish while the other failed. The gate needs no registry credentials,
runs on a release rather than on every push, and reads the same `scope=wrapper` cache the publishing
job reads afterwards — so the second build of that image is a cache hit and not a second compile.

This is the cheaper of the two shapes the field report asked for, and it answers the failure that
happened rather than the class it generalizes to: a wrapper that cannot be built now costs a failed
release instead of a version that means two different things
([`docs/field-report-2026-08-22.md`](docs/field-report-2026-08-22.md), finding 5). Building the file on
every push stays undone, with the reasoning `0.6.1` already recorded.

### Fixed — a honeypot token was recorded and paged nobody

Findings F1, F5 and F8 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md),
filed as [issue #7](https://github.com/nuetzliches/ciphr/issues/7). All three are in the
`honeypot_alert` entry, which is off in a default build — so a deployment that plants no bait was
never affected, and one that plants bait was affected in the way that is hardest to notice.

**F1 (high). Token bait wrote its entry and latched nothing.** `record_rejection` recognized the
credential, wrote the `honeypot-triggered` entry, and returned. So `/v1/health` went on answering
`tripped: false` with `open_tripwires: 0`, and `/v1/honeypots` went on calling that token untripped.
[`honeypots.md`](docs/operations/honeypots.md) names three things that must be true or the bait is
decoration, and the third is that something polls health and pages a human — a deployment that did all
three correctly still missed the event. The runbook's own sentence turned out to be about the
implementation rather than about a misconfiguration: *bait that cannot fire looks exactly like bait
nobody took.* It now latches, off the request path, exactly as secret bait has since `0.5.0`.

One detail that came out of writing the test, and that is a decision rather than a translation: **the
trip records no identity.** That column means who took the bait, and presenting a honeypot token
authenticates nobody — which is what the route's own response documented while the code had no path to
write it. *Which* bait it was is the token id, and `/v1/honeypots` maps that to the identity the bait
was issued for. Writing that identity onto the trip would have made it read as "deploy took it", which
is the one thing that did not happen.

**F5 (medium). One task per touch became one task per piece of bait.** Every touch of bait scheduled a
`spawn_blocking` latch write, including touches of bait whose trip was already open, and those tasks
serialize on the store mutex — so anyone who could reach known bait could queue work against
authentication, reads and health checks. The database's partial index refused the duplicate *rows* and
bounded nothing else. A claim set now decides whether a write is worth scheduling: the first touch of a
reference schedules, every later one is a set lookup. And this is why F5 belongs in the same release as
F1: once token bait latches, that queue is reachable **without authenticating at all**.

What the bound is, stated rather than implied: work in flight is limited by the number of distinct
pieces of bait, which is a number an operator chose when planting them. It is not limited by how often
anybody touches them, and that was the half reachable from outside. A failed write releases its claim,
so a transient database failure costs one latch rather than every later one on the same bait.

**F8 (medium). `GET /v1/honeypots` could claim it served an inventory it did not.** Two fallible store
queries ran *after* the entry that says "allowed read, 200" on `sys/honeypots`, and nothing corrected
it when either failed. Both now run through `complete_or_record`, which is the shape finding F4 put on
`delete`, `export` and the version listing in `0.5.1`. No privilege escalation, and worth fixing for
where the entry gets read: reconstructing the incident this route exists for.

**Tests.** Two through the router — the latch after a presented bait token, in the trail, on
`/v1/health` and on `/v1/honeypots`; and three presentations latching once while the trail records all
three. Three unit tests for the claim set, which is the part the router cannot see: with or without
deduplication the end state is identical, because the index already refused the second row, so the only
place to assert that the work is not queued is where the decision is made.

### Fixed — a stored value could close its own heredoc and write into a workflow's environment

Finding F2 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md) —
high, certain — filed as [issue #8](https://github.com/nuetzliches/ciphr/issues/8).

`export --format actions-env` wrote a multi-line value with the delimiter `ciphr_<NAME>_EOF`.
Including the variable name kept a value containing the word `EOF` from ending its own block, and it
did nothing about a writer who knows the format: a value carrying that exact line on its own **closed
its own assignment**, and every line after it was read by the GitHub Actions runner as further
environment-file commands. An identity allowed to write one exported secret could therefore define
environment variables for later steps of every workflow that reads it — tool configuration, loader
behaviour, credentials, command execution, depending on what those steps do.

**The delimiter is now 128 bits from the OS CSPRNG, drawn per value and checked against that value.**
Both halves, because neither is the property on its own: randomness is what makes the delimiter
unguessable to whoever wrote the value, and the check is what keeps the guarantee from resting on the
entropy source being everything it claims. Four candidates are drawn and then the export is refused
with a message naming which of the two happened — a loop that can only end in success would hide a
machine with no entropy behind a delimiter somebody could have predicted.

**What is not done to the value: anything.** It is written out exactly as it was stored. The property
is that the payload stays *inside* the block, and an export that sanitized a secret would be a
different defect.

Why this is worth the severity the review gave it rather than the severity of a CI convenience:
`--format actions-env` exists because of the boundary `README.md` states in its own voice — no forge
masks a value fetched at runtime, so masking is part of the product rather than of the documentation.
[`docs/README.md`](docs/README.md) lists "a secret in a CI job log" as a risk area whose mitigation is
this exact code path. So the one feature that exists because the pipeline is where the remaining risk
lives was also the one place a value crossed from data into command. Masking never covered it:
masking and injection are different problems, and `::add-mask::` does not make a structured file safe.

`getrandom` is now a declared dependency of `ciphr-cli`. It adds nothing to the graph — `ciphr-crypto`
is already a dependency there and already takes it for keys, nonces and tokens — and it is declared
rather than reached through a re-export because a heredoc delimiter is not a cryptographic operation
and hiding it behind one would suggest it is.

**Tests.** The attack as a regression test: a value carrying `ciphr_KEY_EOF` and an `INJECTED=` line
after it, asserting that exactly one line equals the delimiter, that it is the last one, and that the
value went out unchanged. Plus one that two renders of the same value do not share a delimiter, which
is what fails if the randomness is not there.

### Fixed — two audit rotations in one millisecond aimed at one file name

Finding F6 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md) —
medium, high confidence — filed as [issue #11](https://github.com/nuetzliches/ciphr/issues/11).

A rotated audit file was named after the timestamp of the record that triggered the rotation, and
nothing else. Two rotations sharing a millisecond therefore targeted one path, and `fs::rename`
answers that differently on each platform: **it replaces the earlier archive on Unix and refuses on
Windows.** One loses a segment of the trail; the other takes the file device down. Getting there needs
only a small rotation threshold, a burst of records, or a clock that steps backwards.

That is worse here than a name collision usually is. The trail is one of the four assets this project
protects, `audit verify` walks a chain and `--anchor` compares it against a head recorded outside the
store — so a replaced archive is a gap that verification finds *later*, during whatever made somebody
look. And auditing is fail-closed per device: requests keep succeeding while one device has quietly
stopped being complete, which is the case `docs/ui.md` argues is worth putting on a screen.

**The name now carries the sequence the archive closes at**, after the timestamp:
`audit.jsonl.2026-08-19T21-04-07.912Z-273` is the file whose last record is number 273. Sequences are
unique per record, so two archives cannot collide however fast they rotate — and the name says
something an operator wants anyway. **And rotation never replaces a file:** if the name is somehow
taken, it takes the next free one and refuses after a hundred rather than overwriting.

**The reader follows, and keeps reading the old shape.** `rotation_set` recognizes an archive by the
shape of its suffix, so the sequence had to be added there too — and the timestamp-only name stays
recognized, because an archive written by an earlier build is evidence. A reader that skipped it would
report its records as unarchived and tell an operator to keep what they already have.

**Tests.** Six records at one hard-coded millisecond, forcing several rotations at the same timestamp:
every archive name distinct, and every record still on disk exactly once across the set. One that the
name carries the sequence of the last record *in* the archive rather than the first of the next file.
And the recognizer's boundaries: the new shape, the collision counter, the old shape, and the things
that only look like a sequence — `-abc`, a bare `-`, and `.gz`, which must stay out because a
compressed archive read as text would count garbage lines as records.

### Fixed — `ciphr-sdk` followed redirects it had validated nothing about

Finding F7 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md) —
medium, high confidence — filed as [issue #12](https://github.com/nuetzliches/ciphr/issues/12).

The builder refuses a non-`https` base URL and installs only the deployment CA, and then handed the
agent its default of ten redirects. `ureq` strips the authorization header across the relevant
boundaries, so **the bearer token was never at risk** — the failure is the other direction: a
trusted-but-compromised endpoint or proxy redirects a read to plaintext and substitutes the value the
application consumes. An integrity failure rather than a disclosure one, in the code path least likely
to notice: a consumer fetching its own secrets at startup.

**The agent is now built with `max_redirects(0)`.** Zero rather than "https only", because there is
nothing to keep working: this API has no redirect contract, so any 3xx is a transport or configuration
failure, and following one can only resolve it on the caller's behalf. The response reaches the caller
instead, reported as a redirect that was not taken rather than as a body of the wrong shape.

Why the severity is not "a CI convenience": ADR-19 makes a point of what this client *cannot* do — built
without `webpki-roots`, so a client that trusts the public CA set cannot be constructed at all.
Redirects were the one door left open in that story, and the ADR now names it.

**One test, not two, and deliberately.** The review asked for HTTPS-to-HTTP and same-origin cases; at
zero redirects there is no code path that looks at the target, so both are the same assertion. The
configuration is read from the same function `build` uses — a test that rebuilt the builder chain
itself could pass while the real one drifted — and a second test pins that a 301, 302, 307 and 308 all
say what was not done.

### Fixed — the server said nothing about caching, for plaintext reads as much as for anything else

Finding F3 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md) —
medium, certain — filed as [issue #9](https://github.com/nuetzliches/ciphr/issues/9).

There was no response-header layer on the router at all. Secret reads and exports went out with no
cache directive, and the only mitigation in the tree was the viewer asking Fetch not to cache **its
own** request — so the SDK, the CLI, browser private caches, reverse proxies and anything else in the
path were left with their defaults. Caches usually treat an authenticated response conservatively, and
"usually" is a convention rather than a guarantee; a permissive or misconfigured one retains a
plaintext value past the token's lifetime and exposes it through local cache storage or an
intermediary.

**Every `/v1` response now carries `Cache-Control: no-store`.** The argument was already written one
layer up, in [`docs/ui.md`](docs/ui.md): *a cached response to a secret read is a secret without an
expiry date* — which is why no service worker is allowed anywhere near the viewer. The server made that
argument only in the browser, and only for one client. Now the property is the server's, and the
viewer's table row says so rather than resting on politeness.

**Everything, and not only the value routes.** A `404` says a path does not exist, a `403` says an
identity may not read it, and a route a deployment turned off answers from the fallback with no handler
involved. All of them are worth keeping out of a shared cache, and a per-route list of which responses
deserve the header is a list somebody has to keep correct forever. One layer, applied after the routes,
so a route added later cannot forget it. `no-store` and not `no-cache`: the first says do not write it
down, the second says revalidate before reuse, and only the first is the property wanted.

`openapi.yaml` documents the header, and the test walks nine cases — a value, two metadata routes, the
two unauthenticated ones, three refusals, and a path no build serves.

### Fixed — the core-dump limit failed open, and the entrypoint carried on

Finding F9 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md) —
low, certain — filed as [issue #13](https://github.com/nuetzliches/ciphr/issues/13).

`docker-entrypoint.sh` runs `ulimit -c 0` before it drops privileges, and when that failed it logged a
line and continued. [`docs/threat-model.md`](docs/threat-model.md) lists "a secret in a core dump or in
swap" under what is **explicitly defended against**, and says in the same breath that part of it is an
operational requirement. A warning on a healthy start is not an operational requirement; it is a line
nobody reads. Where the runtime permits dumps and the limit operation failed, a crash writes the master
key, the root key and every value in flight into a core image.

**It now refuses to start**, with a message that names both ways to set the limit in the container
definition. The one case allowed through is the one where the protection already holds: a limit that
cannot be *set* but reads back as `0` is accepted, verified rather than inferred from the failure.

**And the contrast with the swap check beside it is now the point rather than an inconsistency.** That
one still reports without refusing, because a process cannot change its own swap limit and an
unreadable cgroup file is not evidence that swap is on — honest false positives. The core-dump limit is
one this script owns, on the process it is about to exec: it either took effect or it did not.

Both branches were exercised against a stubbed `ulimit` rather than reasoned about.
[`upgrade.md`](docs/operations/upgrade.md) says who can be affected — a runtime that does not let a
process lower its own core limit — and what to do about it.

**Not in this release: F10**, the check-then-open on credential files, which is the other half of issue
#13. It touches three crates through Unix-only code paths, and it is deferred rather than forgotten.

### Documentation — the indistinguishability claim is narrowed to the response, in all four places that made it

Claim notes C11 and C12 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md),
the part of [issue #7](https://github.com/nuetzliches/ciphr/issues/7) that was a decision rather than a
defect. Written after the three fixes above rather than before them, so it describes the code that is
now in the tree.

**What was claimed:** that bait is indistinguishable from any other invalid credential *on every axis a
caller can observe*, with "no timing difference" — and C11's own falsification column said "or work
done". **What holds:** the response. Same `cph_` prefix, length and alphabet; the same `401` with the
same body and the same `WWW-Authenticate`; no extra field anywhere on the value path; recognition is a
flag read from a row the constant-time comparison already fetched, after that comparison, so nothing
branches before it. Three tests hold that line.

**What does not:** equal work. A malformed token returns before any database work. A known identifier
costs one verifier query an unknown one skips — declined deliberately, because closing it means issuing
a query nobody needs. And recognized bait writes a larger audit payload, synchronously, before the
`401`. That third one is the one worth naming: it separates the two cases an attacker actually wants
told apart — *this credential is bait* against *this credential is expired or revoked* — and it is
reachable by whoever holds a credential whose secret matches, which is exactly the position somebody who
found a credential is in.

**Narrowed rather than equalized, deliberately.** Equalizing means issuing a database query nobody
needs and padding every rejection entry in the trail with fields that mean nothing, to hide a difference
nobody has measured — and the claim would then rest on an unmeasured assertion again, one layer along. So
the three differences are named in C11's falsification column, where a reviewer can attack them, and the
open question becomes "is this separable over a network" instead of "is it equal". Unmeasured, and what
bounds useful enumeration in the meantime is the 48-bit random identifier rather than the timing.

**C12 loses the half that rested on a defect.** "Taking bait writes nothing extra" was true of the
request path and quietly untrue beside it: a token trip did not do the derived write at all, which was
finding F1 rather than evidence for the claim, and the latch that does happen is a store write that
contends for the store mutex. The claim is now about the path the caller waits on, and says that the
contention is bounded by the number of planted references rather than by the traffic — which is what
finding F5's fix bought.

**Four places, one commit**, because `site/README.md` records that coupling as a rule:
[`security-review.md`](docs/security-review.md) rows C11 and C12, ADR-15's property 1 as an amendment
that leaves the original wording standing, [`honeypots.md`](docs/operations/honeypots.md) with a section
saying what a caller can and cannot tell and what that means for where to plant, and the
`honeypot_alert` panel in `site/layers.js`. ADR-15's sentence that *bait announcing itself only to
whoever measures carefully is worse than bait that announces itself* stays exactly where it is: it is
the standard this falls short of, and it is the argument for closing the gap rather than a description
of the code.

### Documentation — a trip is recorded before retrieval, and that stays the behaviour

Claim note D10 of [`docs/review-2026-08-21-current-tree.md`](docs/review-2026-08-21-current-tree.md),
the last part of [issue #7](https://github.com/nuetzliches/ciphr/issues/7) and a decision rather than a
defect. The review found no authorization bypass; what it found is an ordering question: the trip is
recorded and latched **before** the value is retrieved and decrypted, so an allowed read of bait that is
deleted, missing, corrupt or undecryptable latches although nothing was served. The review's own words
were that keeping the behaviour is a legitimate answer as long as it is written down. **It is kept, and
this is it being written down.**

**Taking bait means being allowed to read it, not receiving its value.** An identity that no legitimate
consumer's job requires reached a path no legitimate consumer touches and was granted it. Whether the
storage layer then produced bytes is a fact about the store; the signal this tier raises is about the
caller.

**And the alternative is not free in the direction that matters.** Closing it needs a store operation
that establishes readability *before* the trip entry and without releasing the value before the audit
write — which is the fail-closed ordering the whole design rests on. Paying that to remove a page whose
subject is *somebody was allowed to read bait and could not get it* would be paying to suppress an event
worth looking at.

**What the operator gets instead, so this is not a silent trade.** The trail already distinguishes the
two: a read that served nothing carries a correcting entry — `not-found` or `not-served` — under the
same request id as the decision, so the pair reads as one event. What overstates the case is
`/v1/health` and the open trip, which say `tripped` without a value having left, and that is now named
in [`honeypots.md`](docs/operations/honeypots.md) under *When it fires*, where somebody answering a page
will read it. ADR-15 carries the decision, and the D10 row in
[`security-review.md`](docs/security-review.md) carries it with one thing for a reviewer to attack: the
decision rests on the correcting entry existing on **every** failing branch, so a branch that latches
and records nothing would take the argument with it.

## [0.6.1] — 2026-08-22

**The release that finishes `0.6.0`.** Same code, same schema, no configuration change — the one
difference is that the wrapper image and the release assets exist this time. `v0.6.0` published its
server image and then failed to build `…/run`, because the asset rename in `1f82928` left
`Dockerfile.run` copying a path the build no longer produces.

**Which artefacts to use:** `0.6.1` for both images. `ghcr.io/nuetzliches/ciphr:0.6.0` is a valid
server image and identical in code to this one, so a deployment already on it is not wrong — but a
host that mounts `ciphr-run` cannot obtain a `0.6.0` copy, because there is none.
[`docs/operations/upgrade.md`](docs/operations/upgrade.md) says it under `0.6.1`, and the tag `v0.6.0`
is left where it is on purpose: a tag that moves is what this project pins digests against.

### Fixed — `v0.6.0` could not build its wrapper image, so it published half of its artefacts

`1f82928` renamed the release asset to carry its target triple: in
[`ci/build-wrapper.sh`](ci/build-wrapper.sh), which derives the name from `$TARGET`, and in
`release.yml`, which declares it once for three steps. **`Dockerfile.run` was the third consumer and
kept copying `/out/ciphr-run`** — a path that stops existing the moment the script runs. Nothing
caught it, because nothing builds that file except a release: CI builds the wrapper *binary* with the
same script and holds it to its linkage and size budget, while the image around it is built only by
the release workflow and the mirror.

So `v0.6.0` is a partial release. The server image `0.6.0` was published and `:latest` moved to it;
the wrapper image and both release assets were not. **`v0.6.1` publishes the same code with the
wrapper included, and the tag `v0.6.0` stays where it is** — a tag that moves is the thing this
project pins digests against, and rebuilding that tag would overwrite a server image already
published from it. The same answer `ui-v0.1.1` gave to the same question.

**The fix leaves the triple named in one place instead of three.** The builder stage normalizes the
file name after running the script, so `Dockerfile.run` names no target at all, and the path *inside*
the image stays `/ciphr-run` — which it has to, because ADR-14 and every document that says
`docker cp …:/ciphr-run` depend on it. The checksum the script writes is deleted rather than kept, so
it cannot match the glob, and a glob that ever matches two binaries makes the build fail loudly
instead of picking one. Verified by building the image, not by reading it.

**What would have caught this is a CI step that builds `Dockerfile.run`**, and that is a decision with
a price: the wrapper job roughly doubles, on every push, to exercise a file that changes rarely. It is
recorded here as a choice rather than made quietly — the same shape of argument `31732b7` made when it
added the default-build configuration to CI, and that one was worth its cost because it ran on every
release.

## [0.6.0] — 2026-08-22

**The release where operating a deployment stops being a procedure and starts being a command.**
`ciphr backup` takes the copy ADR-7 promised in the first week and nothing implemented; `ciphr state`
derives the files a deployment has to keep from that deployment's own configuration instead of from a
table somebody maintains; and the metadata listings answer *while the service runs*, where before the
question "is this token still valid" cost the outage it was asked during. Nothing migrates — the
schema stays at 6 — so a rollback to `0.5.1` needs neither a restore nor a configuration edit.

**One fix here is the kind only a new artefact can deliver.** `docker stop` sends SIGTERM and the
graceful shutdown awaited SIGINT, so an ordinary container stop terminated the process: a request
already recorded in the audit trail and not yet answered was dropped, leaving an entry for an access
the client never received. Every running `0.5.1` behaves that way and no configuration changes it.

**Two things to do rather than merely know**, both in [`docs/operations/upgrade.md`](docs/operations/upgrade.md).
The release asset is now `ciphr-run-x86_64-unknown-linux-musl`: a fetch script naming the old file
fails loudly, deliberately, with no compatibility copy published beside it. And the CLI's metadata
listings no longer write audit entries (ADR-22), so an alert or report that counted host-side listing
entries counts zero from here on — the note says what stays audited, and why that count was never the
measure it looked like.

**What this release does not change** is the coverage debt: `honeypot_alert` is still absent from the
default build, and the three claims in [`docs/security-review.md`](docs/security-review.md) marked
newer than the accepted review — C11, C12, D10 — are still newer than it. Turning that entry on is
still a decision to run unreviewed code on the authentication path.

**A review of `v0.5.1` by the deployment that filed the report it answers**, recorded in
[`docs/review-0.5.1-2026-08-21.md`](docs/review-0.5.1-2026-08-21.md). It confirms all four findings
answered and the corrected `bulk_export` sentence accurate against the code it describes — read end
to end, not taken from the changelog. Three things it asked for, and four smaller ones.

### Fixed — the changelog lost the section saying what `0.5.1` shipped, and a gate now holds that line

`15191e1` deleted the line `## [0.5.1] — 2026-08-21` while inserting its own entries at that
position, and nothing here noticed: `cargo fmt`, `clippy`, the tests and every gate are indifferent
to a markdown heading, and [`ci/check-changelog.sh`](ci/check-changelog.sh) only asks whether the
file was touched at all. The result was a tree whose `Cargo.toml` said `0.5.1` while the changelog's
newest release was `0.5.0` — so **everything `0.5.1` shipped sat under `[Unreleased]`, where this
release's heading would have claimed it**, and the only remaining record of what that release
contained was a commit body. The section is restored verbatim from the tag.

**The release commit had left the other half undone from the start.** `[0.5.1]` never got a compare
link, and `[Unreleased]` kept comparing from `v0.5.0` — so the link a reader follows for "what is not
released yet" returned one release too much, which is also why the deleted heading stayed invisible.
Both are corrected.

**`ci/check-changelog-releases.sh` makes the state unreachable**, and the invariant it checks needs
neither a tag nor a network because it holds in both states this repository is ever in: between
releases `Cargo.toml` carries the last released version, and in a release commit it carries the new
one. Either way that version has a section, and that section is the newest. It also checks both
directions of the link section — a heading without a definition, a definition without a heading — and
that `[Unreleased]` compares from the newest release.

**Measured against the history rather than reasoned about.** It passes on `v0.1.0` through `v0.5.0` as
those tags were published, fails on the tree before this commit naming the missing section, and fails
on `v0.5.1` as published naming the missing link *and* the stale `[Unreleased]` — so it would have
caught this at the moment it was made, which is the only test of a gate that matters. It runs in the
job that runs on a tag push too, unlike the range gates: "does the version in this tree have a
section of its own" is exactly the question a release asks.

**What it does not check**, in the same spirit as the gates around it: whether the entries under a
heading describe what that version actually shipped (a reader's job), whether a section's date is the
day the tag was pushed, and anything about git tags at all — a gate that passes because a shallow
clone gave it nothing to compare is worse than no gate.

### Documentation — the two unreleased changes that had no upgrade note

[`docs/operations/upgrade.md`](docs/operations/upgrade.md) carried notes for the backup command, the
SIGTERM fix, the rotation class and the renamed release asset, and none for the two changes with the
most for an operator to do or know.

**The read-only listings needed one most**, because the thing to do is not in the code: `ciphr list`,
`versions`, `rotation <path>` and `token list` stop writing audit entries, so an alert or a report
that counted host-side listing entries counts zero from this version on. The note says that, says
what stays audited and why (`get` spends the master key; the API's `list` still records an
authorization a caller cannot route around), and says that the count was never the measure it looked
like — the same rows are readable with `sqlite3` and leave nothing behind. The lock refusal that now
names the live route is there too, with the reason it announces rather than routes.

**`ciphr state` gets the ordering that is its whole value:** run it *before* the service is stopped.
A file the configuration requires and does not have is a service that will not start, and finding it
while the old one is still serving is a correction rather than an outage.

### Added — `ciphr state`, so the file set is derived from the configuration instead of remembered

*What do I have to keep* had no machine-readable answer. The file set lived in a table in
`docs/operations/backup.md`, in the defaults in `config.rs`, and in a `VOLUME` line in the image —
three places that agree until one of them is edited, and the table was written by hand two days ago
from the other two. `ciphr state <config>` derives it from the deployment's own configuration, so a
moved store, a second audit device or a key that changed from a variable to a file all produce an
answer about *those* files without anybody remembering to update a document. `backup.md` now leads
with the command and keeps its table as the explanation of why each row matters.

**A non-zero exit means a file the configuration requires is not there**, which makes it a pre-flight
check and not only a report: a store before `init`, a policy file that did not mount, TLS material
that is not where the configuration says. Each of those is a service that will not start, found
before the running one is stopped.

**Two rows are deliberately not failures**, and saying which is the difference between a check and an
alarm. The write-ahead log exists only between checkpoints. The audit archive is created by the file
device on its first record, so an absent archive on a service that has never started is correct — and
nothing here can tell that apart from an archive somebody deleted, so it reports and does not fail
rather than crying wolf on every fresh deployment.

**No store lock and no master key.** It checks whether the key file exists and never opens it, which
is the same line `/v1/health` draws when it names the key source without the key — and a test asserts
the key's value never reaches the output, because this command reads a configuration that says exactly
where that value lives.

Two things it cannot list, because no configuration names them: the anchor file, which is an argument
to `audit anchor --out`, and the archive's rotated siblings. It says so in its own output rather than
leaving a reader to discover the gap.

### Added — `ci/check-doc-commands.sh`: a command a document tells you to run has to exist

`docs/README.md` promises that operational procedures "name exact commands and exact file paths, and
say which of them do not exist yet". Every other documentation discipline here is enforced by a
script; that one was left to habit, which is the same argument `ci/check-changelog.sh` makes in its
own header about the rule that eroded.

**It is bounded on purpose, and the bound is worth stating because it does not cover the failure that
prompted it.** ADR-7's `VACUUM INTO` claim was a sentence about a capability, and no script can judge
one. What this refuses is the narrower and more common version: a code block handing somebody a
subcommand that is not there.

Measured before it was written, because the design question was whether it would be noise. Over prose,
`ciphr <word>` yields 28 candidates of which 0 are real — "ciphr is", "ciphr keeps". Restricted to
fenced code blocks it yields 2, both genuine: `ciphr run` in ADR-14, whose own text says twelve lines
later that the built thing is `ciphr-run`, and `ciphr lockdown` in `freeze.md`, which declares itself
unimplemented in its third line. ADRs are exempt for the reason `check-doc-dates.sh` exempts them —
rewriting a proposal falsifies the record — and `freeze.md` is in an allowlist that requires a reason
per entry.

The subcommand list comes from the `Command` enum rather than from `--help`, so the gate needs no
build, the way `check-surface-entries.sh` reads Rust source. It validates only the first word after
`ciphr`: teaching a shell script clap's whole tree would catch a typo inside a command that exists,
which is visible the first time anybody runs the line, and this catches a command that never existed,
which is invisible until an incident.

### Added — the entrypoint reports the swap limit it cannot set

`docs/threat-model.md` lists one mitigation with two halves: "memory limit equal to swap limit, and
core dumps disabled". The entrypoint has disabled core dumps since it existed, with the reasoning that
"a limit belongs with the process it protects: a deployment that forgets a `ulimits:` entry would
otherwise silently lose the protection". The other half had nothing but that sentence, and key
material in swap outlives `ZeroizeOnDrop` exactly the way a core dump does.

A process cannot change its own swap limit, so this reports: it reads `memory.swap.max` on cgroup v2,
falls back to comparing `memsw` against the memory limit on v1, and prints what to put in the
container definition when swap is available. Verified against real containers rather than reasoned
about — `--memory-swap` equal to `--memory` yields `memory.swap.max` of 0 and silence, a larger value
yields the warning.

**A warning and not a refusal**, deliberately. The core-dump limit is one this script owns; this is an
observation about someone else's container definition, and a refusal would stop the service on every
host where those cgroup files are laid out differently, unreadable, or absent — a development machine,
a CI runner — none of which is evidence that swap is on. Where it cannot tell, it says so, because "no
warning" must not be readable as "checked and fine".

### Added — `ciphr backup`, so the backup this project has always asked for has a command

ADR-7 chose SQLite in part because *"backup is `VACUUM INTO` plus an existing file-backup job"*. That
sentence was written in the first week and described something nobody could run: no subcommand did it,
and the runtime image has no `sqlite3`. What a deployment had instead was `cp` — and `cp` on a live
write-ahead-logged database reads a file that is moving underneath it, so its result can be a snapshot
of two different moments. **It is the one backup mistake with no error attached to it**, which is why
this is an `Added` entry and not a convenience.

```sh
ciphr --database /var/lib/ciphr/store.db backup /path/to/backup/store-2026-08-21.db
```

**It needs neither the store lock nor the master key**, which puts it in the same short list as
`audit anchor`, `verify` and `cut`. That is the property that decides whether it gets used: a copy
obtainable only inside a maintenance window is a copy that stops being taken, and a backup job does
not need the highest-value secret in the deployment in its environment to run.

**The source is opened read-only, and that is load-bearing rather than cautious.** `SqliteStore::open`
migrates on open, so a pre-upgrade backup taken with the *new* binary any other way would migrate the
database first — destroying the rollback the backup exists for. `open_read_only` checks the schema and
does not apply it, so the one moment this command matters most is the one it cannot get wrong.
`docs/operations/upgrade.md` now says "with the old binary" in step 1 anyway, because that ordering is
free and this reasoning is not obvious from the outside.

**It verifies what it wrote.** `PRAGMA integrity_check` on the copy, and the copy's schema version
against the source's, both through a separate read-only connection. A backup command whose exit code
means "the statement returned" rather than "there is a readable database there" is a command that
reports success on a full disk. Both checks are free at this data volume, and the report on stdout is
the path, the size and that version.

**Three refusals, each of them a mistake that has happened to somebody.** An existing destination is
refused rather than truncated, so a mistyped path cannot destroy the previous backup — SQLite's own
*"output file already exists"*, surfaced rather than worked around. A destination that is not valid
UTF-8 is refused rather than lossily converted, because a lossy path writes the backup somewhere other
than where it was asked to. And the filename is a bound parameter rather than interpolated into the
statement: the filename in `VACUUM INTO` is an ordinary SQL expression, and a quote in a path would
otherwise be a quoting bug in the one command whose output has to be trustworthy.

**It writes no audit entry**, and that is a decision with two reasons. An entry would need the lock,
which costs exactly the property above. And whoever can run this can already read the database file,
so `cp` was available to them regardless — the command adds convenience, not access. `audit anchor` is
treated the same way, for the related reason that recording itself would move the head it just wrote
down. A third reason is structural: an entry written after the copy could not be in the copy it
describes.

The output is one self-contained file in rollback-journal mode whatever the source uses, so there is
no `-wal` beside a backup to remember — and a `ciphr backup` copy, unlike a file-level copy, reads
fine from a read-only mount. Nine tests: five in `crates/ciphr-store/tests/backup.rs` on the store
method, including that the source is byte-identical afterwards and that the copy still decrypts under
the same key, and four in `crates/ciphr-cli/tests/backup.rs` through the binary — that it runs while
another process holds the lock, that it runs with no master key in the environment while `list` in the
same environment fails, and that a refused second backup leaves the first one untouched.

### Added — a restore is now a checked property, not a documented one

`docs/operations/backup.md` was written with a section admitting that nothing proved a backup comes
back. `crates/ciphr-server/tests/restore.rs` closes that: it performs the procedure the document
describes — remove the live database and its sidecars, move a backup into their place — and then
serves a secret out of the result **over the real router**, with a token issued before the backup was
taken.

**One assertion, four claims underneath it, each of which turns a restore into an outage on its own.**
The restored seal record opens with the same master key. The wrapped data key survived the copy. The
token authenticates against a verifier peppered from the root key that came out of the *restored*
record. And the audit chain resumes from the restored head, so fail-closed accepts the record instead
of refusing it. None of the four is visible from the file's size, and the store-level tests added
alongside `ciphr backup` cover none of them — proving a copy is a readable database is a different
claim from proving it works as the deployment's store.

**Two of the four tests pin consequences rather than features**, because a documented consequence with
no test is how this project ended up with a runbook whose procedure was wrong. A secret written after
the backup is absent from the restore (`404`), and a token revoked after the backup **authenticates
again** (`200`) — the second is documented behaviour with a "re-revoke before the service is
reachable" instruction attached, and it now fails CI if it silently changes.

**Writing it found two defects in itself, both worth recording because they are the failure modes the
test exists to catch.** The fixture first built its store through the raw store API, which writes no
audit entries — so the backup carried an empty trail and the chain-continuity claim was being checked
against nothing. It now serves a request before the backup is taken. And the harness built its sink
with `Chain::new()` rather than `store.audit_chain()`, the way `Server::prepare` does; every request
against the restored store then reused a sequence number the restored trail already held, no device
accepted the record, and all four tests turned into `503`. That is precisely the stale-head collision
the store lock exists to prevent between two live processes, reproduced accidentally — which is the
best argument available that the test drives the real startup path rather than a convenient
approximation.

**What it proves and what it does not, measured rather than assumed.** The suite was re-run with the
restore step replaced by a no-op. Two tests still passed: they establish that the store at that path
works, and cannot tell a restored file from the original. The other two failed, and they are what
makes the suite about the *backup* — each asserts something true of the copy and false of the live
database it replaced. The file header records the split, so neither half is mistaken for the whole.

A rehearsal is still not covered and cannot be: no test fetches this deployment's break-glass key from
wherever it actually lives, and that is the half that fails in practice.

### Fixed — SIGTERM did not reach the graceful shutdown, so a container stop never ran it

`docker-entrypoint.sh` `exec`s the server specifically so the process is PID 1 and *"receives SIGTERM
directly. Without it a shell would sit in between, the signal would not reach the server, and the
graceful shutdown that exists to answer already-audited requests would never run."* The comment was
right about the mechanism and the code listened for the wrong signal: `tokio::signal::ctrl_c` is
SIGINT on Unix and nothing else, so SIGTERM had no handler at all, the default action terminated the
process, and the graceful shutdown never ran on an ordinary stop.

**What that cost is the trail rather than the data.** `synchronous = FULL` and WAL mean an abrupt stop
loses no committed write. What it loses is a request that had been audited and not yet answered — so
the trail records an access the client never received, which is precisely the confusion the graceful
shutdown was added to prevent. Its second cost is quieter: a database that is never closed cleanly
always leaves a `-wal` behind, and a file-level backup that omits it is silently short of the newest
writes.

`stop_requested` now waits on the first of SIGINT or SIGTERM, with both streams registered before
either is awaited — a signal arriving during startup is then queued rather than fatal. Windows keeps
`ctrl_c`, which is all it has.

**The test is in a binary of its own, deliberately.** Checking this means raising a real signal, and a
signal with no handler kills the process it is raised in — which is the defect itself. Alone in
`crates/ciphr-server/tests/shutdown.rs`, a regression costs two tests; sharing a binary, it would cost
every result in it. Two tests rather than one, because the fix must not become "SIGTERM instead of
SIGINT": Ctrl-C on a foreground process has to keep working. Both were run against a Linux container
and then re-run with the fix reverted, to confirm the SIGTERM test fails and the SIGINT one still
passes — a test that cannot fail is worse than no test, and `#[cfg(unix)]` means this one is invisible
on the machine most of this was written on.

### Fixed — `Kind::as_str` was the second spelling rather than the only one

Added in `0.5.1` with the comment *"so a report on the host and a response on the wire cannot end up
calling the same thing by two names"*, and it left both other names in place: `GET /v1/surface` built
its `kind` from its own `match` in `api.rs`, and the derive on `Kind` carried
`#[serde(rename_all = "lowercase")]`. **A doc comment claiming a property the code does not have is
the same defect `0.5.1` existed to correct**, which is what makes this the first item rather than a
footnote.

Both route through `as_str` now: the response calls it, and `Kind`'s `Serialize` is hand-written in
terms of it rather than derived. The derive is gone rather than kept beside a function that disagrees
with it — a serde attribute describing a wire format nothing reaches is the dormant-flag shape
`0.5.0` removed a check for. `ActiveEntry` keeps its `Serialize`, which now produces the same words
the wire does.

Pinned in two places, both against the function rather than a literal: a unit test that
`serde_json` and `as_str` agree for every variant, and the `/v1/surface` integration test asserting
`entry["kind"] == Kind::Build.as_str()`.

### Changed — `ci/check-surface-entries.sh` compares kind and cost, not only names

It bounded the field whose drift is loudest and left two that change meaning quietly.

**`kind` decides whether a stanza can turn an entry on at all.** A runtime entry that is off can be
switched on by editing the file; a build entry cannot, and needs a different artefact. A drifted
`kind` makes `ciphr surface show` print `(runtime, not named by this file)` for something no file can
name into existence — losing exactly the distinction the server's report is careful to draw, in the
interface an operator reaches first, because the host is where a configuration gets edited.

**The cost sentence became a decision input in two implementations.** `0.5.1` made `show` print it for
entries that are *off*, which is the state somebody is still deciding about. Each copy was pinned by a
test and each test asserts a fragment, so a half-edited sentence passed both. `GET /v1/surface` is the
authority and cannot drift from the binary, but reaching it needs a running service, a token and a
network hop — not the situation of somebody reading `show` on a host with the service stopped. The
gate compares the text with whitespace normalized, which is what the different wrapping in the two
files needed rather than a reason to skip it.

The header now also records *why* the list is copied at all. The comment `0.5.1` replaced planned to
move it into `ciphr-core` once it grew; the list grew and the move was already illegal, because
`ci/check-core-no-features.sh` and ADR-20 property 1 close the reviewed core to knowing that entries
exist. The shapes that stay legal are named there for whoever needs them.

### Changed — four smaller things the review named

- **`surface: 2 of 3 entries on` counted an entry this binary cannot have.** It now reads
  `2 of 3 entries on, 1 not in this binary`. The off lines said so two rows down; this is the line
  people quote.
- **Both wrappers measured bytes.** `line.len()` wraps a cost sentence early the moment one acquires
  a non-ASCII character, and these are prose. Characters now, in the server binary and the CLI.
- **`ciphr surface show` printed its framing before a list on the other stream.** `<file> turns
  nothing on` went to stderr and the off list to stdout, an order nothing defines — in a captured run
  the sentence landed after the list it framed. The prose now sits with the rest of the prose at the
  end, which keeps the stdout-is-data convention and removes the question rather than betting on
  buffering.
- **A comment said "the record" and printed part of it.** `--check-config`'s active line prints name,
  kind and `accepted`, not the reason; it now says so, and says why the reason is not there.

### Added — the rotation class is in the listing, and can be filtered on

`GET /v1/list/{prefix}` gains an `entries` array carrying each visible path with its rotation class,
and an optional `?rotation=<class>` filter. The corpus question the class exists for — *what has
nobody classified yet?* — was answerable only through `ciphr list --rotation`, and the CLI takes the
exclusive store lock, so it was answerable only with the service stopped. That is the gap this
closes; nothing else about the class changes.

**Additive on the wire, and that is a compatibility decision rather than a stylistic one.** `paths`
stays exactly as it was and carries the same set in the same order as `entries`. Making `paths` a
list of objects would have been the cleaner shape and would have broken an older `ciphr-run` against
a newer service — a wrapper is bind-mounted into images this project does not own (ADR-14), so that
pair is version-skewed by construction, and it fails at the moment a service is starting and its
secrets are not there. The SDK sets no `deny_unknown_fields`, so an added field costs an old client
nothing.

**Authorization is unchanged, and the filter runs after it.** Every path in `entries` survived the
same per-path `list` check as before. The class filter is applied to the authorized set, never
before it, and the audit entry records the number of paths actually returned — what was revealed,
not what the caller was entitled to see. An unknown class is a `400` naming what was sent and what
the classes are, the same asymmetry the write path already had: open on the way out, closed on the
way in.

**No new disclosure.** `GET /v1/versions/{path}` already returns the class against the same `list`
capability, so this saves one request per secret rather than opening anything.

**Only the class, not `needs_care` and `advice`.** Both are pure functions of the class, so a client
derives them instead of receiving a paragraph of prose on every row.

`Store` gains `list_with_rotation`, one statement with a wider projection — not `list` followed by
`metadata` per path, which is two more statements per secret. `list` and the new method share their
range bounds so they cannot disagree about what "at or below this prefix" means, and stay separate
statements so a listing that needs only names does not start failing because a metadata column is
unreadable. `ciphr list --rotation` now goes through the same method instead of calling `metadata`
per path, so the host and the API answer from one place rather than agreeing by coincidence.

**`ciphr-sdk` deliberately does not gain a method for this.** Its scope is the endpoints a service
uses to fetch its own secrets, and no such consumer wants a rotation class. The consumers that do —
an operator, the viewer, and eventually the MCP server of ADR-13 — reach it over the API or would
bring the administrative reads as a set.

### Documentation — a broad wildcard reaches the control plane, and `docs/authorization.md` now says so

`read` is one capability for two kinds of object: a secret's value, and the virtual administrative
paths under `sys/`. Only the path separates them, and `**` matches one or more segments — so a rule
granting `read` on `**` grants the audit trail, the identity inventory and the whole policy structure
along with every secret. Nothing about that is new and no code changed; it was simply not written
down anywhere an author of such a rule would look.

The document now names the fence — `path = "sys/**"`, `capabilities = []`, which wins over `**` by
rules 2 and 4 — and says why it matters beyond tidiness: `sys/audit` reports which paths are actually
fetched, which is the complement of where ADR-15 says bait belongs.

Whether the control plane should require a capability of its own instead, so the fence is the default
rather than a rule somebody remembers, is open in the issue tracker with an ADR draft attached. The
recommendation above is the interim answer and works with the evaluator exactly as it is.

### Changed — the `ciphr-run` release asset carries its target triple

**Breaking, for a fetch script.** The file attached to a release tag is now
`ciphr-run-x86_64-unknown-linux-musl` and its checksum `ciphr-run-x86_64-unknown-linux-musl.sha256`.
Both were unqualified. No compatibility copy is published under the old name: one release shipping
both names is exactly the inconsistent pair this removes, and while the repository is private the
consumer side is the same people making the change. [`docs/operations/upgrade.md`](docs/operations/upgrade.md)
says what to edit; the failure mode if it is not edited is a missing asset, not a wrong file.

**Nothing about the artefact moves.** The binary is byte-identical, a wrapper already mounted on a
host is untouched, and the registry route is unchanged — the file inside `<image>/run` is still
`/ciphr-run`, because an image states its architecture in its manifest while a file pulled from a tag
states it only in its name.

**Why with one architecture, and why this is not multi-arch.** `.github/workflows/release.yml` defers
multi-arch on the grounds that a second build produces an artifact nothing pulls, and that reasoning
is unchanged. This is the one part of that deferral that gets more expensive by waiting: qualifying
the name later means either breaking every script written against the documented one or publishing a
qualified binary beside an unqualified checksum. `ci.yml` has always named its artifact this way, so
this also ends a disagreement between the two workflows.

`ci/build-wrapper.sh` derives the name from its `$TARGET` rather than spelling it out, and
`release.yml` holds it in one workflow-level variable that three steps read — in both cases so a
second target cannot inherit the first one's name. The size budget in `build-wrapper.sh` now records
that it is per target: an aarch64 static binary differs in size for reasons unrelated to
dependencies, so a second target gets its own number rather than this one being raised to fit both.

### Documentation — `/v1/health` gets a runbook, and the plan's three checks are corrected

Eighteen documents mentioned `/v1/health` and none of them was a runbook, so what an operator needs
from that endpoint existed as a side remark in whichever document happened to touch it. That is the
same shape that left the store without a backup procedure, and
[`docs/operations/monitoring.md`](docs/operations/monitoring.md) is the owner plan section 17 never
had. `audit-trail.md` and `honeypots.md` now point at it rather than each carrying a fragment.

**One field on that endpoint carries live state.** `status` is the literal `"ok"` and `sealed` is the
literal `false`; `seal`, `key_source`, `surface` and `api_version` are facts about how the process was
started. Only `audit_devices[].accepting` changes while it runs. A rule written against `status` is a
rule against a constant, and that is worth knowing before writing one rather than after.

**Section 17's list needed correcting in both directions.** Its second check — a sealed service that
answers but cannot serve — is not a check today: v1 unseals at startup or refuses to start, so an
answering process is an unsealed one, and the field exists for a seal mechanism that does not exist
yet. Its third check said in the plan's own words that it *"is not buildable against the current
`/v1/health`"*; the device half became buildable and is now the check that matters most. The volume
half is still not answerable there, and that is the half fail-closed turns into a total outage — it
needs something that can see a filesystem, and ADR-15's marker-file reasoning applies unchanged: a
channel meant to survive a full volume must not live on the volume that fills.

**Three ways to read the endpoint wrong are written down**, because each looks like the healthy answer:
`accepting: null` means nothing has been recorded since startup rather than "fine"; an empty
`audit_devices` array cannot mean what it appears to, since the server refuses to start without a
device; and a `200` is produced without the store being consulted beyond the tripwire query, so a
service that cannot record an audit entry answers `200` here and `503` to everything that matters.

**A backup-freshness field was considered and rejected**, and the reasoning is on the page so the gap
is a decision rather than an omission somebody discovers while writing an alert rule. ciphr could know
that `ciphr backup` was invoked; it cannot know that the file exists, left the host, is readable, or
that the master key is retrievable — and a green field meaning "a command ran three days ago" answers
the question an operator is asking with something else. Every other field there is a fact about the
process's own state. Knowing a backup happened would also cost the property that makes the command
useful, since the server could only learn it if the backup wrote to the store, which needs the lock.
And the endpoint is unauthenticated: "last backup 41 days ago" is a targeting signal with no
deterrent half.

What to check instead needs nothing new: `ciphr --database <newest-backup> audit verify` needs neither
the master key nor the lock, and its head sequence compared against the live store's says *the newest
backup is a readable, chain-intact store, N records behind* — a stronger statement than a freshness
field could make, with the threshold in the system that also knows whether the file arrived.

**One defect found while reading rather than while writing.** `AppState::audit_devices` returns an
empty vector when the mutex holding device state is poisoned; its doc comment says the names are
reported with `accepting` unknown instead, on the reasoning that health *"answers as much as it can
rather than failing"*. The comment and the code disagree. The state needs a panic while that lock is
held and the code holding it has no path to one, so this is a documentation defect rather than a live
hazard — recorded here and on the page, and not silently fixed in either direction, because which way
it should be fixed is a decision about behaviour.

### Documentation — backups and restores have a runbook, and one procedure in `upgrade.md` was wrong

No code changed. The backup rule that matters most was written down early and never grew the
procedure around it: *"the master key must not be in the same backup as the database"* was in
`master-key.md`, ADR-5 and ADR-7 from the start, while how to take a copy that is not torn, what else
has to be in it, and what a restore undoes existed nowhere. What was written down instead was
scattered across four documents as consequences of other topics.
[`docs/operations/backup.md`](docs/operations/backup.md) is that procedure, and the index gained two
risk rows for it.

**One correction, and it is a procedure people follow.** `upgrade.md` said to back up the database and
*then* stop the service, and listed the `-shm` file as part of the backup. A `cp` of a running SQLite
database can produce a snapshot of two different moments, and an upgrade backup is the one copy that
has to be good; the order is now stop-then-copy, with `VACUUM INTO` named for the case where a copy
genuinely must be taken while the service is up. The `-shm` file is recreated by SQLite and is not
part of the database — the `-wal` file is, and a `store.db` copied without it is silently missing the
newest writes, which is the failure shape the list should have been guarding against.

**Three things a restore rolls back that no document said out loud.** Each is a security decision, and
none of them announces itself: a `destroy` (an earlier backup still holds the wrapped data key, so
restoring across a shred ends it), a token revocation (`revoked_at` is a column, so the token is valid
again and its holder is whoever the revocation was about), and a master-key rotation (the seal record
is four rows in `meta`, so an older backup needs the *older* key — and a wrong key is
indistinguishable from a corrupted record by design, which makes the wrong conclusion the easy one).
`cli.md` and `master-key.md` now carry the halves that belong to them, including the retention rule
that follows: every key any retained backup was sealed under is kept as long as that backup is.

**What the backup is worth is derived rather than asserted.** There is no honest single answer to how
critical the store is — it is the criticality of the least replaceable value in it, and the
classification added for rotation already records that. Read on the axis of loss rather than of
rotation, `breaks-data`, `volume-bound` and `seed-only` are the values ciphr holds rather than copies,
so a `put` of one is an event after which a backup is due, `?rotation=` answers *how critical is this
backup*, and `unclassified` is the state in which the store cannot answer that question at all. The
two axes do not sort the six classes identically, so the new document carries its own table instead of
reusing `needs_care`.

**ADR-7's backup sentence is amended rather than left standing.** Its rationale reads *"backup is
`VACUUM INTO` plus an existing file-backup job"*, which for three releases described a SQLite
capability and not a command this project shipped — and the runtime image contains `ca-certificates`,
`curl` and `gosu` and no `sqlite3`, so it could not even be run with `docker exec`. `ciphr backup`,
above, closes that; the record now says what was missing and what the command adds over the raw
statement. The decision itself is unchanged.

### Changed — the metadata listings run read-only, so credential state is readable during the incident that asks about it

Issue #14 named the cost: the only way to ask "is this token still valid, when was it last used" was
`ciphr token list`, which opened a session, took the exclusive store lock the running server holds,
and therefore required stopping the secrets service — the opposite of when the question gets asked.
It paid the lock and the master key while recording nothing, which was simultaneously the outage and
the outlier against "the CLI audits what it does".

The resolution is [ADR-22](docs/adr/0022-the-trail-records-what-consumed-an-authority.md): **the
trail records what consumed an authority.** `get` spends the master key, so its entry measures
something nobody affected can route around, and it stays audited and session-bound, as does every
mutation. The plaintext-metadata listings — `list` (including `--rotation unclassified`),
`versions`, `rotation <path>` without a class, and `token list` — consume nothing: their columns are
plaintext in the database file, and whoever can run them could read the same rows with `sqlite3` and
leave no entry at all. An entry only the polite reader writes measures politeness, not access. All
four now take `SqliteStore::open_read_only`, the path `backup` and the `audit` maintenance commands
already use: **no lock, no master key, no audit entry — and they answer while the service runs.**
The two goals genuinely exclude each other, which the ADR states plainly: recording advances the
chain, advancing the chain needs the lock, and the lock is the outage. The API's `list` entries are
untouched — an API caller cannot read the file, so there the entry still measures an authorization
that cannot be routed around. The audited, authenticated answer to "is this token valid" remains
issue #3's proposed `GET /v1/tokens`; the CLI listing is the unaudited host-side fallback, not the
replacement.

### Changed — a lock refusal names the live route, for the commands the running service can answer

`get`, `put`, `delete` and `export` refused under the lock used to say only *"stop it, run this,
start it again"* — correct for the host-only commands, and the wrong first advice for the four the
API serves live. The refusal now also names the equivalent request (`GET /v1/secrets/{path}`,
`PUT /v1/secrets/{path}`, `DELETE /v1/secrets/{path}`, `POST /v1/export`) and says out loud that the
CLI will not make the call itself. That last part is deliberate and issue #14 argued it: a CLI that
silently routed to the API when it found a lock file would make one command mean two identities —
the operator with the master key here, an authenticated token there — decided by whether a file
exists. The hint announces; it never routes. `token revoke` and the other host-only commands keep
the plain message, because for them it is the truth.

### Fixed — the honeypot runbook now says that revoking stops the service

`docs/operations/honeypots.md` step 3 said *"Revoke. `ciphr token revoke <id>`"* with no mention
that the command opens a session, takes the lock the running server holds, and therefore stops the
secrets service. Whoever followed the runbook during a trip — the one moment it runs — discovered
the outage mid-incident. The step now says it where it is needed: stop, revoke, start, planned as
part of the sequence, with the one consolation stated too (a stopped service answers the stolen
credential nothing either). Step 2 gains the counterpart: `token list` is read-only now, so *which*
credential to revoke is established before the outage begins, not during it. Whether revocation
should ever work against a running service is issue #14's remaining question and is deliberately not
answered here — it waits on the capability split in issue #5.

### Documentation — ADR-22's rationale is sharpened, and the API's strictness is defended rather than assumed

Review asked two fair questions. First: was auditing `ciphr list` ever deliberate? It was — first
CLI commit, rationale stated in place — so the record now quotes the decision it revises instead of
treating it as an accident. Second: if the CLI's listing entries measured politeness, is the API
over-auditing too — should `list` entries and the `sys/audit` read entry go? The record now answers
no, and says why the asymmetry is the principle: at the API boundary the entry is unbypassable by
its subject *and* costs no outage, and the two entries in question carry weight the host ones never
did — the `list` entry is the only trace of enumeration in a design where enumeration deliberately
does not trip (`honeypots.md`: bait appears in listings unmarked, and listing is not taking it),
and the `sys/audit` entry watches the read issue #5 already calls an oracle on the detection layer.

The sharpening also corrects the record's own overclaim: `get`'s entry is not unbypassable —
whoever holds the master key and the file decrypts offline and writes nothing (A5) — so every host
entry is cooperative, and what actually decides is the price. An entry advances the chain, the
chain needs the lock, the lock is the outage; `get` pays that price anyway, the listings paid it
with the answer itself. Bypassability breaks the tie, it does not carry the decision. The
2026-08-21 field report moved from supporting evidence to the load-bearing kind: the second
`sqlite3` connection an operator opened beside the running server is the "channel that records
less" the original comment warned about — manufactured by the rule that warned about it.

## [0.5.1] — 2026-08-21

**The release that corrects `0.5.0` rather than adding to it**, and the first patch release here.
Nothing breaks, nothing migrates, the schema stays at 6 and no interface moves — a rollback to `0.5.0`
needs neither a restore nor a configuration edit.

**One change reaches an operator only through a new artefact, and it is the reason to tag this.**
`bulk_export`'s cost sentence ships compiled into the binary and `GET /v1/surface` serves it, so a
running `0.5.0` keeps answering the question "what does turning this off cost me?" with a claim the
handler does not support. That is the one artefact a deployment cannot correct locally. The new
`--check-config` output is in the same position for a weaker reason: `docs/operations/upgrade.md`
recommends the command, and only a new image can run it.

**A field report on the `0.5.0` rollout, and four things it found.** Recorded in
[`docs/field-report-2026-08-21-b.md`](docs/field-report-2026-08-21-b.md), written from the operating
side of a private deployment after upgrading it. Two of the four are claims this project made about
itself that the code does not support, and one of those shipped compiled into the binary.

### Fixed — a claim about `bulk_export` that the handler does not support

`bulk_export`'s cost sentence said that turning the entry off *removes fetched prefixes*, and
therefore makes a honeypot secret easier to place (ADR-15). It does not, and the sentence pointed a
deployment at the one lever that cannot move what it claimed to move.

`POST /v1/export` reads the paths a caller **names** — `ExportRequest` has one required property,
`paths`, and no prefix — so whether a prefix is covered is a property of the fetching code rather
than of this route. `GET /v1/list/{prefix}` is not an entry, so a caller that lists a prefix and then
reads each path covers the same prefix with `bulk_export` off, at one audit entry per secret and more
round trips. And a consumer that already names its paths has ADR-15's property while the entry is
*on*, so turning it off buys that one nothing either.

What turning it off actually costs is now what the sentence says: `ciphr-run` entirely, because both
`--prefix` and `--path` fetch through this route and it refuses with exit code `125`; and one request
per path for an SDK consumer. Corrected in five places that repeated it — `surface.rs`, the CLI's copy
of the entry list, the router comment in `api.rs`, the route description in `openapi.yaml`, and
`docs/operations/upgrade.md`, whose "take the loss where you can" advice rested on it. The `0.5.0`
section below is left as it was written; it is where the claim was made.

**Why this one is worth the length.** The cost sentence is the artefact ADR-20 designed to be the
input to a deployment's decision, `GET /v1/surface` exists to put it in front of an operator, and it
is the one thing a deployment cannot correct locally, because it ships in the binary.

### Added — every surface interface now names the entries a deployment left *off*

`ciphr-server --check-config <file>` prints the resolved surface, and `ciphr surface show <config>`
prints the entries the file did not name, each with its cost sentence. Both listed only the active
entries before.

**The gap that closes.** An entry that is off is absent from the router, so its `404` is
byte-identical to a path that never existed — which is what ADR-20 wants on the wire, and nothing
here changes it. But nothing answered the operator's question on the other side: *is this route
missing because this build never had it, or because this deployment did not name it?* `/v1/health`
carried the active names, `/v1/surface` the active records, and `surface show` the stanzas in the
file; the closed `ENTRIES` list — which exists precisely so that "what can a deployment turn on" has
an answer rather than needing a search — was the one thing no interface printed. An empty `surface`
array meant both "this deployment turned nothing on" and "this build has no entries".

**`--check-config` is the sharp case**, because `upgrade.md` recommends it for this release
specifically, and a *missing* runtime stanza is legal: the `0.5.0` binary accepted the previous
version's file without a word about surface at all. The command a careful operator is told to run
before stopping anything could not report the mistake this release made possible. It exits zero on
that file still — off is a legitimate deployment, and most deployments should have `viewer_api` off —
but it now says what was left off and what each absence costs.

The cost sentence moves with the off entries for the same reason: it is what somebody deciding *about*
an entry needs, and it was printed only for entries already decided in favour of.

`ci/check-surface-entries.sh` is new and blocking, because the CLI keeps its own copy of the entry
list — it does not depend on the server crate, which would pull axum, rustls and a tokio runtime into
a host tool. An entry missing from that copy is silently missing from the off list, which is the whole
point of the list. The gate compares the names in both files.

### Added — `ciphr-sdk` re-exports the `ciphr-core` types in its own signatures

`SecretPath`, `Plaintext`, `SecretVersion`, `EnvVarName`, `Rotation`, `PathError` and `EnvNameError`
are now reachable as `ciphr_sdk::…`. They were unavoidable in ordinary use and reachable only through
a second dependency: `SecretPath` is an argument to every call, `Plaintext` is what a value *is*,
`EnvVarName` is what `Environment` hands back, and the two error types sit inside `SdkError` variants.
The crate's own shortest-useful-program example opened with `use ciphr_core::SecretPath;`, which is
the tell.

**Why it mattered beyond tidiness.** A consumer had to name `ciphr-core` in its manifest and keep the
two versions in step by hand — a versioning trap for a client crate whose reason to exist is that an
application depends on it. Re-exported rather than wrapped: a newtype around `SecretPath` would be a
second public face for path normalization, and ADR-9's one-normalization rule is worth more than a
tidier dependency graph.

Invisible from inside the workspace, which is why `ci/check-sdk-reexports.sh` is new and blocking:
every crate here can already reach `ciphr-core`, so the omission compiled fine and broke only for
somebody outside.

### Changed — two documents that stopped one step short

- **`docs/operations/upgrade.md`: the `0.5.0` rollback is two-part.** `Config` has
  `deny_unknown_fields`, so the configuration `0.5.0` requires is one `0.4.0` cannot parse — a
  rollback needs the `[[surface]]` stanzas removed as well as the database restored. The note had the
  database half only, so an operator following it got a TOML error naming the stanza the note told
  them to add, in a moment they believed was about the schema. The refusal fires before the store is
  touched, which is the helpful order; the sentence was what was missing.
- **`docs/operations/honeypots.md`: precondition 1 names the build.** The runbook led with "the
  service has to be built with the entry" and a `curl` for checking, and said nothing about how to get
  such a build. `Dockerfile` and both release workflows build without `--features`, so every published
  image and every release binary answers that check with `no` — a dead end for anyone not building
  from source. Step 1 now carries `cargo build --release --locked --features honeypot_alert`, says
  plainly that published artefacts are default builds, and states the decision that has to precede a
  second artefact: `docs/security-review.md` marks C11, C12 and D10 as newer than the accepted review.


## [0.5.0] — 2026-08-21

**The release that makes optionality a mechanism, and pays for it once.** Two things run through
everything below. Optional behaviour now lives in a named set of *surface entries* (ADR-20), each off
until a deployment records that it wants it and why — and the first feature built on that mechanism is
phase 8, the `alert` tier of honeypots and tripwires (ADR-15).

**Read [`docs/operations/upgrade.md`](docs/operations/upgrade.md) before deploying.** Three things there
matter and none of them is optional reading: four routes stop existing unless the configuration names
them, schema 6 is a one-way door, and the service gains two ways to refuse its own configuration.
`ciphr-server --check-config` exercises the last of those without stopping anything.

**Why a release that ships unreviewed surface is nevertheless safe to make.** The honeypot code is a
Cargo feature absent from the default build, so the default artefact contains none of it. The accepted
external review read the authentication path before bait existed and says in its own words that new
surface there does not inherit it; the three claims describing it are marked as uncovered in
[`docs/security-review.md`](docs/security-review.md). Turning the entry on is therefore a deliberate
decision about running code nobody outside this project has read — which is exactly the shape ADR-20's
build entries exist to make visible.

### Changed — **breaking:** the viewer routes and the bulk export are surface entries now

`GET /v1/audit`, `/v1/identities`, `/v1/policies` and `POST /v1/export` were unconditional. They are
now the `viewer_api` and `bulk_export` entries of ADR-20, off until a deployment names them:

```toml
[[surface]]
entry    = "viewer_api"
accepted = "2026-08-21"
reason   = "the audit viewer runs beside the service"

[[surface]]
entry    = "bulk_export"
accepted = "2026-08-21"
reason   = "ciphr-run fetches whole prefixes on service start"
```

**Without those stanzas the four routes answer `404`.** The viewer stops working; `ciphr-run` refuses
with exit code `125` rather than starting a service without its secrets. The CLI is unaffected — it
reads the trail, the identities and the policies straight from the store, with no network hop.

**Why in this release rather than the next one.** Plan section 24 always said these two should become
entries, and doing it after the mechanism shipped would mean releasing the surface list twice with a
deployment-visible break in between. One break, one upgrade note.

**Why they were always optional in substance.** The three viewer routes exist for a component that is
already an optional container (ADR-11), so a deployment without the viewer has been serving them to
nobody — while putting the policy structure and the identity inventory on the network for anyone
holding any token. And `bulk_export` is the route that reads the value of every path under a prefix,
which is exactly what makes bait placement hard: a deployment whose consumers name their paths has no
fetched prefixes for a honeypot to stay out of. ADR-20 asked for the two entries to be read together
for that reason.

`openapi.yaml` can now say "optional" as a third state beside "exists" and "reserved": five routes
carry `x-surface-entry`, each says in prose that it answers `404` where the entry is not named, and the
header lists the mapping in one place.

**A check was removed as part of this, and the removal is the interesting half.** The `/v1/honeypots`
route was gated on both the Cargo feature *and* the entry being named — but `resolve` refuses to start a
service whose binary has a build feature its configuration does not declare, so the second condition
could never be false where it mattered. A check that is never false is worse than none, because a reader
has to work out when it fires. The route now hangs on the same single condition as the behaviour it
reports on, so the two cannot disagree about whether bait is being watched.

`surface::only` is new beside `surface::resolve`, for tests and for anything composing the router
in-process: ADR-20 property 3 is a rule about a service *starting on a configuration*, and requiring a
date and a reason from a test would mean inventing prose no operator wrote.

### Added — the honeypots runbook, and the review claims phase 8 owes

`docs/operations/honeypots.md`: planting bait, where it must not go, what does not trip, and what to do
when it fires. It leads with the three things that have to be true before any of it works — the service
built with the entry, the configuration naming it, and **something that polls `/v1/health` and pages a
human**. That last one is the step this software cannot perform and cannot check, so a tripwire whose
whole output is a field nobody reads is decoration, and the runbook says so before it says anything
about planting.

**`docs/security-review.md` gains C11, C12 and D10**, the obligation ADR-15 wrote down when the review
gate fell: the acceptance covers the code it read, and the authentication path it read had no bait in
it. The claims are marked as newer than the acceptance where they stand, so a later reader is not left
to infer which parts of this document the accepted review actually covered. Two of them carry the same
caveat as C2 — timing is behaviour-tested and not asserted, so it is a place where a human should look
at the code.

**ADR-15 records that the marker file is not built**, with its reasons rather than as an omission
somebody discovers while writing an alert rule. A marker needs a path, and a path is deployment
configuration the record says honeypots do not have; the obvious location, beside the database, puts it
on the volume the conceded denial-of-service fills, so the channel meant to survive a full volume would
be the one that does not. And for the deployment this was built for it buys nothing, because the
monitoring polls HTTP. The condition for building it is named: monitoring that reads filesystems rather
than endpoints.

Also struck through in ADR-15: the timing-property condition, now a test with an expired *and* revoked
honeypot token in it, and the false-positive enumeration, three entries of which are tests rather than
sentences. `AGENTS.md`, `docs/README.md`, `docs/threat-model.md` and `docs/operations/freeze.md` now say
phase 8 is built — and `freeze.md` says the two things that changed nothing on its own page, since a
cleared gate is permission for the work behind it and not for the work dropped in front of it.

### Added — `GET /v1/honeypots`, `GET /v1/surface`, and `ciphr surface show`

`/v1/honeypots` was a *reserved* path returning `404` and is now implemented — as the first **optional
route**, which is a third state `openapi.yaml` had to learn to express. It exists only in a build
carrying `honeypot_alert`, so against a default binary it answers `404` from the router's fallback: off
means absent, never dormant, because a handler answering `404` from inside itself is compiled, wired and
one boolean from serving. `GET /v1/health` lists the entries an instance has, which is how a client
learns this instead of inferring it from a status code.

Authorized as `sys/honeypots` through the ordinary evaluator, and **the only place the honeypot flag is
ever visible.** Not on a secret read, not in `/v1/list`, not in `/v1/versions` — bait that announces
itself to a caller is not bait, and an operator who cannot tell bait from a real secret eventually
rotates it or builds a service on it, which destroys it just as thoroughly. There is a test that an
identity without the grant gets `403`: a caller who can enumerate the honeypots can avoid them.

`/v1/surface` is always present, authorized as `sys/surface`, and returns the record behind each active
entry — date, reason, and the cost sentence that ships with the binary. Empty is the ordinary answer,
and the route does not disappear when the list is empty: that would make "this deployment turned nothing
on" and "this build has no surface mechanism" the same answer. It is authenticated although the entry
*names* are on `/v1/health`, which is plan section 10's split and is worth a test because the two
endpoints deliberately disagree about what they will say.

`ciphr surface show <config>` reads a server configuration's `[[surface]]` stanzas and prints each with
its cost sentence. **It reads a file and not a binary**, which is the whole caveat and is printed: for a
build entry a stanza is one half of being switched on and the compiled feature is the other, the server
refuses to start when the two disagree, and nothing on the host can see the server's build. An earlier
draft used `cfg!` in the CLI to claim "in this build" — meaningless, since the CLI never contains the
honeypot behaviour at all, and the compiler said so.

`ciphr-cli` gains a direct `toml` dependency for that. Nothing new in the graph: `ciphr-policy` is
already a dependency and already takes `toml`, so this declares a crate that was compiled either way.

### Fixed — two errors reported themselves as audit failures

`CliError::Audit` prints "the audit trail could not be written", and an earlier draft of this work used
it for a TOML parse error and for "that path holds nothing" — so an operator reading either would go
looking at the wrong subsystem. There are now `Config { path, reason }` and `BaitNeedsASecret { path }`,
the second of which explains what bait is rather than reporting a bare not-found. Found by running the
commands, not by a test.

**Noted, not fixed:** `ciphr dump` still reports a non-UTF-8 value through `CliError::Audit`. Same
misuse, pre-existing, and out of this change's scope.

### Added — planting bait: `ciphr honeypot` and `token issue --honeypot`

Phase 8 was unreachable without this: the store could hold bait and nothing could create any.

`ciphr honeypot add <path>` marks an existing secret, `remove` unmarks it, `list` shows every piece of
bait with whether it has been taken, and `clear` frees the latches so bait can fire again. On the host
and nowhere else — there is no route that marks bait and none that clears a trip, for the reason ADR-3
gives policies: a guard reachable through the door it guards is not a guard.

`add` refuses a path that does not exist, and says why rather than reporting a bare "not found": a tier
on an empty path is bait that answers `404` to whoever takes it. Both `add` and `token issue
--honeypot` print the two things that decide whether the bait works at all — that it must sit outside
every prefix a consumer fetches, and that detection needs the service built with the feature *and* a
`[[surface]]` stanza naming it. Without both, taking the bait is recorded as an ordinary rejected
credential and nothing pages.

**Two audit actions were wrong and are now their own**, found by running the commands rather than by a
test. `honeypot clear` recorded `honeypot-triggered`, so the trail claimed bait had been taken every
time an operator tidied up after a trip — and the count of trips became the number nobody can use. And
`honeypot add` recorded `classify`, whose documented meaning is how safe a secret is to rotate; two
questions sharing one label would leave "when did this path become bait" answerable only from a field
the entry did not carry. There are now `honeypot-marked`, with `marked` or `unmarked` in `detail`, and
`honeypot-cleared`.

Verified end to end against a real store: a marked secret still reads exactly as before through the
CLI, `ciphr list` does not reveal it, and a host read does **not** trip — which is ADR-15's rule that
`dump` and `export` on the host decrypt by design and a backup must not fire every honeypot nightly.

### Added — a honeypot secret trips on the value route, and `/v1/health` says so

The second kind of bait: a path holding a real-looking value nobody legitimately reads.
Reading its value through the API is a trip; naming it is not.

**The trigger lives in `authorize_and_record`, so no handler can forget it.** It fires only for an
allowed `Capability::Read`, which is exactly "this route serves a value" here — `list` and
`/v1/versions` authorize as `Capability::List` and so cannot trip, which is what ADR-15 means by
"enumerating a name is not taking the bait". A **denial** trips nothing either: bait outside an
identity's grants produces a `403`, and paging somebody for that would make every scoped-away probe an
incident. There is no honeypot branch in `ciphr-policy` and no new capability; the evaluator is asked
the same question it always is, and the answer is consulted afterwards.

**The lookup costs one indexed row on every allowed read, bait or not, and that is the design.**
Property 1's second sanctioned option is that the path absorbs the same cost either way, and this is
that option taken deliberately rather than a cost that slipped in. A build without the entry performs
no lookup at all.

**The trip replaces the entry's action; the decision it records is untouched.** `honeypot-triggered`,
with the path, the principal and the deciding rule still on it, and `attempted: read` in `detail`. One
entry, exactly as before — a second would be work an ordinary read does not do.

**`/v1/health` gains `tripped` and `open_tripwires`, and they are absent rather than `false` in a
build without the entry.** "This build cannot detect bait" and "nothing has been taken" are different
facts, and a monitor that conflates them reports a working tripwire on a service that has none. A
boolean and a count, never a name: plan section 10 lets an unauthenticated endpoint say what the
process is doing, and *which* bait was taken is stored rather than enforced.

**The latch write is off the request path**, in a blocking task, because a row is work an ordinary read
does not do and must not sit where the caller can time it. The claim is stated at its real strength in
the code: axum offers no post-flush hook here, so what is guaranteed is that the request does not wait
for the write — not that the write happens afterwards. The residue is one lock acquisition's worth of
contention against a millisecond-scale insert. A failed latch is recorded in the trail as
`latch-failed` rather than failing the request, per ADR-15's dated fail-closed decision: the
authoritative record is already stored, and refusing a request because a *derived* row could not be
written is precisely the observable difference property 1 forbids.

Six tests, including the two negatives that matter — a listing does not trip, a denial does not trip —
and one that reads the same bait three times and finds one open trip and three trail entries: the latch
bounds the paging, not the record.

### Added — the store side of bait: a tier, a latch, and a history

`set_honeypot`, `honeypot_tier`, `honeypots`, `latch_trip`, `open_trips` and `clear_trips`. General
functions on the store, in every build: `honeypot_alert` is a build entry, but nothing here *behaves*
differently depending on whether a deployment planted anything, so gating it would only mean the code
was compiled in fewer configurations than it is tested in.

**A tier can only be set on a path that exists.** Bait is a real secret holding a real-looking value,
and a tier on an empty path is a honeypot that answers `404` to whoever takes it. Reading the tier,
though, treats an unknown path as simply not-bait: that question is asked on the value path *after* the
policy allowed the read, and a second opinion about existence in front of the real one is how two
answers to "does this exist" start disagreeing.

**`latch_trip` reports whether it latched**, and the answer comes from the database rather than from a
check the caller remembered. The uniqueness is the partial index from schema 6, so two concurrent reads
of the same bait cannot both open a trip. The constraint violation is therefore *translated* rather
than avoided — and translated carefully: every other constraint on that table describes the row's
shape, which this function builds itself, so a violation of one of those is a defect here and must not
be swallowed as "already tripped". It is told apart by asking whether a trip is open, not by parsing
SQLite's message, because the extended codes do not separate a unique index from a `CHECK` and matching
on English stops working at the next upgrade.

**Clearing sets `cleared_at` rather than deleting.** A tripwire that resets quietly has, in effect, not
fired, and what an investigation wants is exactly the part a delete would remove. The same bait can
trip again afterwards, and both trips stay on record.

An unknown stored tier is refused rather than guessed, `freeze` and `disable-identity` included: a
database holding one of those was written by something that is not this build.

Eight tests, on the properties rather than on the calls — each piece of bait latches independently, a
clear frees the latch and keeps the history, and the administrative view shows both kinds of bait with
whether each is currently tripped.

### Added — a value written over the API can carry its rotation class

`SecretInput` grows an optional `rotation`, `PUT /v1/secrets/{path}` applies it, and
`Client::put_classified` is the SDK method for it. From the field report of 2026-08-21, finding 3.

**The two features pulled against each other.** `PUT` works against a running service, which is the
whole reason the API path is attractive for migrating an existing estate one service at a time.
Setting the class needed `ciphr rotation`, `ciphr put --rotation` or `ciphr import --rotation` — all
CLI, all taking the store lock, therefore all requiring the service stopped. So a no-downtime import
produced a store in which every imported value said `unclassified` — *nobody has looked at this* —
and making that honest cost exactly the downtime the API path had just avoided. The pessimistic
default was working as intended: it made the gap visible instead of quietly writing "safe to rotate"
across an estate nobody had examined.

**Absent means unchanged, in both directions.** A path written for the first time without the field
still lands `unclassified`, so nothing about the default moves; a value written over an existing
classification does not reset it. There is no way to say it with `null` — the field means unchanged
by being missing.

**An unknown class is `400`, never a default.** Parsed with the other request checks, before the
authorization entry, so a typo leaves no allowed write in the trail that was never going to happen.
The asymmetry with the way out is deliberate: `Classification.class` stays an open string in every
response, because a client must not break on a class a later service added, while an input is closed,
because storing a word this build cannot interpret would be a claim nobody made.

**It produces a second audit entry, `classify`, beside the `write`.** Not a detail. The CLI funnels
its three classifying paths through one function precisely because they drifted once, and the
direction of the drift is what matters: a class that moves inside a `write` entry is a `breaks-data`
downgraded to `rotatable` with nothing in the trail saying so, immediately before the rotation that
destroys the data. The capability is `write` on the path and nothing more — naming what a value is
safe for is not a broader privilege than setting the value, and the class reaches no authorization
decision.

**Applied after the version exists**, because a class cannot be recorded for a path that is not there
yet. The consequence is worth knowing: if the classification fails, the value is already written and
the response is an error, so a caller that retries writes a second version of the same value. That is
the ordering `ciphr put --rotation` has had all along, and classifying first cannot work for a new
path.

**Deliberately not changed: the write response.** The class belongs to the secret rather than to the
version just written, and `GET /v1/versions/{path}` is where it is read; a second copy in a write
response is a copy that drifts. That matters against a service older than this field, which ignores
an unknown property in silence — one version listing after the first import confirms the field
arrived, rather than a whole estate quietly staying `unclassified`.

### Added — a honeypot token is recognized, and the trail says so

ADR-15's first kind of bait: a credential in the documented format that authenticates nothing. It is
issued by the same function as a real token, with the same generator and the same verifier derivation,
into the same row — `issue_token` takes a `TokenPurpose` rather than gaining a twin, because two code
paths are two chances for bait and credentials to drift, and bait that is distinguishable in the
database is bait an operator eventually tidies away.

**Recognition is a flag on a row the comparison already fetched, read after that comparison.** No
extra query, no extra derivation, no branch before the constant-time check — so there is nothing here
for somebody holding several credentials to measure. It is checked *before* expiry and revocation on
purpose: bait is refused whatever its dates say, and asking about the dates first would let an expired
honeypot token fail as an ordinary expired token and go unrecorded, which is the one way a honeypot
stops being one without anybody noticing.

**One rejection path, and bait does not get its own.** `authenticate` now returns three outcomes, and
`AppState::authenticate` turns the third into a `Rejection` that carries the error *and*, separately,
the bait. The error is produced without consulting what the credential was, and the handler's single
`return` uses it either way — ADR-15's indistinguishability as a property of the code's shape rather
than of somebody remembering it at each call site.

**A trip replaces the entry the request was going to write; it does not add one.** The action becomes
`honeypot-triggered`, `subject` names which bait (the identity it was issued for, plus the non-secret
token id — `subject` and not `principal`, because nobody authenticated), and `detail` carries the
attempted action, since "they tried to read" and "they tried to write" are different facts about a
compromise. One entry, same size, same devices, same fail-closed rule: a second write would be work an
ordinary rejected credential does not cause, and therefore measurable. Presenting bait also updates
nothing on the token row, for the same reason and because bait never authenticates.

**In a build without the entry this is the previous behaviour exactly**, with an argument that is
ignored, and there is a test for that rather than a claim: a deployment that plants no bait runs the
code the accepted review read.

The honeypot case went **inside** `every_kind_of_invalid_token_looks_the_same` and inside the server's
`every_kind_of_bad_token_gets_the_same_answer`, which is where ADR-15 asks for it — an expired *and*
revoked honeypot token is in there too, because the dates must not be able to route bait back into an
ordinary rejection. A further test compares the whole response, headers included, against an unknown
token: a `WWW-Authenticate` that differed would be the bait that announces itself to whoever measures
carefully.

### Added — schema 6: bait, and where a trip is remembered

`secrets.honeypot_tier` (NULL means not bait), `tokens.honeypot`, and a `tripwire` table. Additive:
no row is rewritten, nothing is dropped, and a database that has never seen a honeypot is
indistinguishable from one that never will. **Schema 6 is a one-way door** — a `0.4.0` binary refuses
it with `SchemaTooNew` — so the release notes will say back up first.

**The schema is unconditional although the behaviour is not.** `honeypot_alert` is a build entry, so
the code that recognizes bait is absent from the default binary; the columns are present in every
build. Two schemas for one version number is a distribution problem — two artefacts with the same
version and different databases, and a checksum that says nothing about which one you hold. Plan
section 24 settled this shape already for ADR-21's value index: what is optional is the route, not the
column.

`honeypot_tier` admits only `alert`. The severe tiers are designed and deliberately unbuilt, and a
column that accepts `freeze` in a binary that honours nothing by that name is the dormant-flag failure
ADR-20 rejects — the value would sit there looking like protection. Widening it is a migration, which
is the right price for turning on an availability lever.

**The latch is two partial unique indexes, not application logic.** One open trip per piece of bait,
stated as a database invariant, so two concurrent reads of the same bait cannot produce two open trips
— which application-side checking would have to get right under a lock it does not hold. Clearing sets
`cleared_at`, which frees the slot without erasing the history: the same bait can trip again and both
trips are still there. A `CHECK` also requires exactly one reference column matching the kind, because
a row naming neither could not be traced to any bait and one naming both leaves which piece tripped to
interpretation.

Four tests, each on a claim rather than on the DDL: an existing database comes out not-bait, an unbuilt
tier is refused, the latch holds and survives a clear, and a mismatched reference is refused.

**Noted and deliberately not changed:** `ciphr dump --format portable` does not carry the bait flag.
It lists its columns explicitly, so this is a decision rather than an oversight — that document is
insurance for moving to another system, which has no honeypots, and there is no portable *import*, so
it is an exit and not a restore path. The consequence is worth knowing: a store reconstructed from that
file has no bait in it, and re-planting is a deployment step.

### Added — the optional surface mechanism, and its first entry

ADR-20 decided where optionality is allowed to live and said the gate arrives with the first entry.
Phase 8 is that entry, so the mechanism arrives with it: `[[surface]]` stanzas in the server
configuration, each naming an entry, the date the deployment accepted the cost, and the reason.
**All three are required and the server refuses to start without them** — the same refusal as
starting with no audit device, because a configuration that cannot answer the question is a
configuration error rather than an operating mode.

`honeypot_alert` is the first and so far only entry: ADR-15's `alert` tier, as a Cargo feature absent
from the default build. Nothing of the tier itself is implemented yet — this release adds the switch,
the record, and the refusals, so that the behaviour lands on a mechanism instead of beside one.

**A build entry is checked in both directions, and the second one is the reason it is a check at
all.** Compiled in and not named in the configuration means a deployment is running surface it never
recorded a decision about. Named in the configuration and *not* compiled in is worse: the deployment
believes it has bait recognition, has written down when and why, and has none — and nothing would
ever say so, because bait that cannot fire looks exactly like bait nobody took. So both refuse.

`GET /v1/health` gains `surface`, an array of the active entry names, and it is unauthenticated for
the reason plan section 10 gives: which entries are active is what the process *enforces*. The date
and the reason are prose about somebody's environment and stay behind an authenticated read. An empty
array is the ordinary answer.

**Startup writes one audit entry**, `surface-active`, naming the active entries or the literal
`none`. A deployment that changes its own shape otherwise leaves no record the trail can be asked
about — "which routes did this service offer in March" is answerable from a configuration file only
if somebody kept the March version of it, and the interesting case is the one where nobody did.

Audit records gain a `detail` field for that entry, and it is deliberately **not** a second
`deny_reason`: a `surface-active` entry refuses nothing, so putting its content there would make the
trail claim a denial that never happened. `audit-device-failed` keeps naming its device in
`deny_reason` and is right to — a device did refuse. Records written by an older build do not carry
the key at all; from here it is present as `null`, which is the rule the whole record follows.

**The known-answer test for the record encoding moved**, because `detail` changes the stored shape.
Old records keep verifying — verification hashes the stored bytes and re-serializes nothing — and the
new hash was recomputed independently rather than copied from the failure output. The method was
checked by reproducing the *previous* pinned hash from the previous payload first: a calculation that
cannot reproduce the old answer is not evidence about the new one.

### Added — a gate for the property the external review's scope depends on

`ci/check-core-no-features.sh`. Four claims about `ciphr-crypto`, `ciphr-policy` and `ciphr-core`: no
`[features]` table, no `cfg(feature)` in the sources, no code reference to a surface module, and no
features handed to them by `[workspace.dependencies]`. That last one is the same claim from the other
side — a crate that declares none can still be built with some if a dependent asks.

What it protects is the meaning of "three crates, about 1500 lines, read end to end": a claim about
the code every build runs. One `cfg(feature)` in those crates turns it into a claim about one
configuration, and a review that has to be repeated per configuration is a promise to do one later.

Comment lines are stripped before the surface check, because all three crates discuss attack surface
in their doc comments and should keep doing so. Verified by making each claim false in turn — the
`cfg(not(feature = …))` form included — and by appending prose to confirm the check stays quiet.

### Fixed — the specification said "Draft. No code written yet." through four releases

`.claude/plans/PLAN.md` is the full specification and has been amended twenty-two times, most
recently by the commit that recorded the external review. Its own status line never moved from the day
it was written. Everything below the line was current; the line was four releases behind.

**The mechanism is the finding, not the line.** Both documentation gates scanned `docs/`, and a
specification does not live there — so the one document that describes the whole system was the one
document neither gate could see. `ci/check-docs.sh` and `ci/check-doc-dates.sh` now cover
`.claude/plans/` as well, by two named roots rather than a repository-wide sweep, because everything
else under `.claude/` is not documentation.

**Widening the scope was two steps, and the second is easy to miss.** `PLAN.md` carried its status
inside the metadata table (`| **Status** | … |`), which `check-doc-dates.sh` deliberately does not
read — that is the ADR form, and ADRs are exempt because their date records a decision rather than a
claim about currency. Adding the file to the scope would therefore have changed nothing. It has a real
`**Status:**` line now, and the gate says out loud that a file added to its scope without one is
silently unchecked.

The new line also stops duplicating something: *where the project stands* is in `AGENTS.md`, and the
plan now points there instead of keeping a second phase-status list to drift against it.

**One date per status paragraph, and the first draft of this line got it wrong.** `check-doc-dates.sh`
takes the *latest* date in the status paragraph as the claim — deliberately, because a careful author
writes two ("implemented as of X, re-read against the code on Y") and the later one is the claim about
currency. The consequence for anyone writing such a line is the inverse: a second date that is *not* a
currency claim silently becomes the thing enforced, and the currency date can then move backwards
unnoticed. The first version of this status line mentioned the review date, which pinned the enforced
claim to it and made the gate unable to fire on the file it had just been widened to cover. Verified by
building a commit that should fail the gate and watching it pass. The paragraph now carries one date and
says why.

### Fixed — the viewer image never contained the favicon its own document asks for

`ui/public/favicon.svg` has been committed, linked from `index.html`, and listed in `ui/README.md`'s
layout since the viewer existed, and no image ever contained it. `ui/Dockerfile` copies named paths
rather than the whole build context — deliberately, so that nothing lying in the directory rides into
the image — and the list did not name `public/`. Vite skips a public directory it cannot find without
saying so, so every viewer image through `ui-v0.3.0` built, type checked, carried its policy, and
then answered `/favicon.svg` with the 404 `try_files` is configured to give. A browser shows its
blank-document icon and reports the miss in a console nobody has open, which is how all four viewer
tags went out with it.

**That no gate had a chance of catching it is the part worth fixing.** The bundle CI builds is not the
bundle the image serves: CI builds from the whole tree, the image from the COPY list, and nothing
compared the two. Two checks now do, and they cover different halves on purpose:

- `ci/check-ui-image-files.sh` — every tracked top-level path under `ui/` is either named by a COPY in
  `ui/Dockerfile` or listed in the script as deliberately absent, with the reason next to it
  (`Dockerfile`, `.dockerignore`, `README.md`). It runs beside the other source gates in the `build`
  job rather than in the viewer's, because it needs neither Node nor a build. Run against the tree as
  it was, it named `public/` and nothing else.
- The built-document step in `.github/workflows/ci.yml` now also checks that every local `href` and
  `src` in `dist/index.html` resolves to a file the bundle contains. A reference that 404s violates no
  policy, so the CSP checks beside it could not see this; equally, that step cannot see a file missing
  from the *image*, which is why the static gate above exists rather than replacing it.

**For an operator: nothing to do.** The fix is in how the image is built, so it arrives with the next
viewer tag; an icon is not a reason to cut one. The service image is untouched, and no deploy ordering
changes.

### Fixed — five documents still said the external review was pending

The review took place on 2026-08-21 and `docs/security-review.md`, `SECURITY.md`, `AGENTS.md`,
`docs/README.md` and `openapi.yaml` were all brought up to it the same day. Five places were not, and
they are the five where the claim was load-bearing rather than descriptive: ADR-15's status line said
"the build still waits on the external review below", its condition list said the first item "has not
moved", ADR-16 said a reopened record would find the review "still the first condition on its list",
ADR-21 said the same, and `docs/operations/freeze.md` said phase 8 "may not be built before the
external review in any case". A reader who started from any of them concluded that phase 8 is
forbidden, which it no longer is.

**The correction is not a strike-through, because the condition did not disappear — it changed
shape.** All three ADRs add surface to `ciphr-crypto` or to the authentication path, and the
acceptance says in its own words that new surface there does not inherit it, naming phase 8 as the
example. So each condition now reads as its second form: *built on top of reviewed code, and then
reviewed itself*, rather than waiting on a review that had nothing to read. ADR-15 also gains the
consequence for whoever builds it — the claims in `docs/security-review.md` covering the token path
need an entry for bait, rather than a later reviewer inferring one.

**Two places where a cleared gate implies nothing, now said out loud.** `freeze.md` describes a tier
that was dropped for an unrelated reason (one machine identity serves every deploy target), so the
review changes nothing on that page. And ADR-15's Cargo feature keeps a narrower justification than
it had: the accepted review covers the authentication path *without* honeypot code, so a deployment
that plants no bait runs nothing the acceptance does not reach.

The doc comment on `ciphr-crypto` said the crate "must pass external review before the first
production use" and now says that it did, against `v0.3.0`, and that new surface here needs its own
pass. Nothing but comments and documents changed.

### Fixed — a comment invited exactly the wrong conclusion from the review

`.forgejo/workflows/build-images.yml` explains why the GHCR package stays private while the source
is: publishing "the artefact of an unreviewed cryptographic implementation invites someone to run
it". The word that reasoning turns on is *unreviewed*, so the short inference from a cleared gate is
that the package can now be public. It cannot, and the comment now says why before somebody acts on
it: the acceptance raises the bar back to a *human* review for making this repository public as
something others are invited to run, and the second half of the argument never mentioned the review
at all — a public image from a private repository is unauditable whatever its provenance. The
condition for deleting that file is unchanged and is the repository going public.

### Changed — the viewer is released as `ui-v0.3.0`

Its own image and its own cadence (ADR-11), so it moves on its own tag rather than with the service.
What is in it is the `Subject` column, which shipped in the service's `0.4.0` entry below and had no
viewer image behind it until now.

**No deploy ordering constraint this time**, and that is worth stating because the previous viewer
release had one. `subject` is optional in the response type and the column falls back to the path, so
against a `0.3.0` service the table is complete rather than degraded — that service records no token
actions at all, so there is no row whose subject would be missing.

`ui/package.json` moves to `0.3.0` and **`ui/package-lock.json` moves with it**. The lock was left at
`0.1.0` when the package went to `0.2.0` — the same slip that entry called out about the package
file, one file further along. The image version comes from the tag, so nothing was broken; the number
in the file said something untrue.

## [0.4.0] — 2026-08-21

**The release the external review is on the other side of.** It happened on 2026-08-21, against
`v0.3.0`, and it is recorded in [`docs/review-2026-08-21.md`](docs/review-2026-08-21.md) with the
maintainer's decision to accept it in [`docs/security-review.md`](docs/security-review.md). Read who
performed it before relying on it — an AI model commissioned by the maintainer, not the human
practitioner the working paper asks for — and read what the acceptance does **not** cover, because
that list is short and specific. Everything else here is that review's six findings and one audit
gap found by a user's question.

**What this is not**, and this is the sentence that changes: holding real secrets no longer runs
ahead of the stated precondition. What it runs ahead of instead is a *human* review, and the
acceptance says so in as many words. `ciphr-audit`, most of `ciphr-store`, the server's
configuration and TLS code, and `ui/` were not read by anybody but their author.

**Three things to do about this upgrade**, and
[`docs/operations/upgrade.md`](docs/operations/upgrade.md) is the runbook that outlives this entry.

1. **Check the mode of your master key file and every token file before deploying.** The refusal for
   a world-accessible credential now covers world-*writable* as well as world-readable, so a file at
   mode `0602` or `0666` that started the service before will stop it now. This is the only change
   here that can turn a working deployment into one that will not start.
2. **No migration, and a rollback is safe** — schema stays at 5. The first release in this project
   where the one-way door is absent, after schema 4 in `0.2.0` and schema 5 in `0.3.0`. An older
   binary reads the new audit records too: nothing on the read path parses them into a strict
   struct.
3. **A strict consumer of `GET /v1/audit` needs a look.** Records carry a `subject` field, and
   `deny_reason` has two new values (`delete-failed`, `not-listed`). Both are additions, and both are
   the reason this is a minor rather than a patch. Our own consumers — the CLI and the viewer — are
   in this release.

### Security — a token secret no longer survives in a buffer nothing wipes

Finding F1 of the review of 2026-08-21, which falsified claim B6. `base64url::decode_into` reached
its result through `decode`, so every `Token::parse` — that is, every authenticated request — left
two heap copies of the 32-byte token secret to be freed intact while the caller dutifully wiped its
own stack array. `Token::expose_text` had the same shape at issue time, through the temporary
`String` that `base64url::encode` returns.

Nothing about this is reachable remotely. It matters against memory disclosure, a core dump, or
swap — the adversaries the zeroization discipline exists for in the first place, and the discipline
was not holding on the hottest path in the codebase.

- **`decode_into` allocates nothing.** It validates the whole input, then writes into the caller's
  buffer, so the decoded bytes exist in exactly one place. `decode` keeps the convenient form and now
  delegates, the way the hexadecimal module has always been arranged.
- **`encode_into` is new**, and `expose_text` builds the token in one buffer of exactly the right
  capacity: no temporary, and no reallocation to leave a copy behind. A test pins the capacity,
  because a reallocation would be invisible otherwise.
- The two functions that carry credentials are documented as the pair that does, and `decode` and
  `encode` say in as many words that what they return is not wiped by anything.

### Security — the reserved `sys/` prefix is refused by storage, not only over HTTP

Finding F2 of the same review, which falsified claim D6. The refusal lived in `ciphr-server` alone,
so `ciphr put sys/audit` created a real secret at a path that names a virtual one. One rule granting
an auditor `read` on `sys/audit` — the natural grant — then authorized two different things: the
audit trail, and whatever an operator had planted there.

Creating the shadow took host CLI access, so this was not an escalation path. It was a claim
enforced at the wrong layer, and the layer that was missing it is the one the claim speaks about.

- **`ciphr-store` refuses writes and deletes under the prefix** (`StoreError::Reserved`), so every
  caller is covered rather than the ones that arrive over HTTP. `put` is the gate that matters — it
  is the only way a secret comes into existence — and `delete` checks too, because the claim names
  deletes.
- **The prefix has one definition**, `ciphr_core::path::RESERVED_PREFIX`, with
  `SecretPath::is_reserved` beside it. Two places deciding what "reserved" means is how they come to
  disagree.
- The HTTP and CLI checks stay as early, specific errors, and both now call the shared refusal. A
  refused `put` reaches the store no more than it reaches the audit trail.

### Documented — the conceded audit denial of service needs no credential

Finding F5 of the review of 2026-08-21. Two decisions this project defends compose into one the
threat model described imprecisely: **every request with a missing or invalid token writes an audit
entry** (so brute force is visible), and **auditing is fail-closed** (so a full volume refuses
everything). Together, anyone who can reach the listener can fill the volume and take the instance
offline without holding a credential. The threat model conceded denial of service by "filling the
audit volume" in a paragraph that read as though it took load or a token.

Inside the stated boundary, so this is a sharpening and not a defect. It turns into deployment rules
rather than code: do not publish the port, rate-limit unauthenticated 401s at the reverse proxy, and
alert on the *rate* of audit growth rather than on free space alone — growth warns in time, a full
volume is the outage. `docs/operations/audit-trail.md` carries them, and notes that `ciphr audit cut`
bounds what is queryable rather than what a peer can write.

### Documented — "nonce reuse is structurally impossible" now says at which level

Finding F3 of the review of 2026-08-21. The claim is exactly true for a value: one data key, one
payload, one nonce. One level up it is a different argument — the root key wraps each data key under
a *random* 96-bit nonce, one per version write, with no counter and no uniqueness structure, so the
guarantee there is the birthday bound and not impossibility. `docs/crypto.md`, the README, and both
crate module docs stated it absolutely.

The bound is NIST SP 800-38D §8.3: at most 2^32 invocations of one key with random IVs — 4.3 billion
secret-version writes under one root key, at which point a collision stands at about 2^-33. No code
changed, at this or any plausible scale.

- **Two facts a reader should not have to derive** are now written down: the count does **not** reset
  in v1, because `rotate-master-key` re-wraps the *same* root key by design and nothing issues a new
  one; and a collision would expose the XOR of two wrapped data keys and the GCM authentication key
  to somebody who already holds the database, not the plaintext of a secret.
- The XChaCha20 comparison in `crypto.md` said its large nonce buys nothing here. It does apply at
  the root-key level, and the answer is still no — that is now the stated reasoning rather than an
  argument that quietly skipped the case.
- Claim B2 in `docs/security-review.md` carries the level, and the property test says which half of
  the guarantee it can pin.

### Fixed — the audit trail no longer claims a delete or an export that did not happen

Finding F4 of the review of 2026-08-21. The decision is recorded before the work, which is the
property the design rests on, and it means an "allowed, 200" entry has to be corrected when the work
then fails. Reads and writes did that. `delete`, `POST /v1/export`, and `GET /v1/versions/{path}` did
not, so their trails said an authorized operation happened at `200` when nothing had.

Nothing was under-claimed — the trail over-stated access rather than hiding it, which is why this
survived three phases. It matters when the trail is read forensically: "who deleted this" answered
confidently and wrongly is worse than answered not at all.

- **`delete` and the version listing** record `delete-failed` / `not-listed` with the status the
  caller received, the way a failed write records `write-failed`.
- **An export corrects every path it had already recorded**, not only the one that failed. One
  missing path fails the whole export, so none of the earlier values left the process either — a
  three-path export failing on the third now leaves three decisions and three corrections.
- **Reads correct on every error**, not only on `404`. A store that could not answer served no value
  either; that was the narrower residue the finding named.
- **`GET /v1/audit` has the correction too.** Not in the finding's list, same shape.
- The rule is now one named helper, `AppState::complete_or_record`, instead of something each
  handler remembers. `openapi.yaml` lists the new reasons and says in as many words that a
  correction is not a denial.

### Security — a credential file the world can write is refused, like one it can read

Finding F6 of the same review. `check_not_world_readable` tested `mode & 0o004` and nothing else, so
a master key at mode `0602` started the process — and the token-file check in `ciphr-run`, written as
a mirror of it, mirrored the gap too.

World-*writable* key material is arguably the worse of the two. A local unprivileged account that
can replace the file does not need to read it: before `init` it plants a key the attacker knows, and
afterwards it manufactures an unseal failure on the next restart. For the wrapper's token file the
substituted credential fetches secrets under an identity the attacker controls.

- **`ciphr_core::WorldAccess` is the rule**, in one place, for both callers — the same move F2 made
  for the reserved prefix, and for the same reason: a rule written down twice is a rule enforced
  once.
- **The refusal names the bit that is actually set** ("world-writable" at `0602`), because a message
  naming the other one sends the reader to look at a permission nobody granted. That is the same
  failure mode the mode-0777 bind-mount hint exists to undo.
- **Group bits are still accepted**, read and write alike. Root-owned and used by a service group is
  a legitimate arrangement, and narrowing it is a deployment's decision, not this check's.
- The check and its error are renamed to what they now do (`check_not_world_accessible`,
  `MasterKeyFileWorldAccessible`, `TokenFileWorldAccessible`); the review's own note was that the old
  name was honest about its scope, so widening the scope moves the name.

### Documented — the external review happened, and the decision to accept it is written down

The review that plan section 18 makes a precondition took place on 2026-08-21 against `v0.3.0` and is
recorded in [`docs/review-2026-08-21.md`](docs/review-2026-08-21.md). The maintainer accepted it the
same day. Every document that carried the requirement as outstanding now says so — README,
`AGENTS.md`, `SECURITY.md`, `docs/crypto.md`, `docs/why-build-this.md`, the risk table in
`docs/README.md`, and plan section 18 — and each of them says who performed it in the same breath.

- **The acceptance is a dated decision with a scope**, in `docs/security-review.md`: what it covers,
  what it is not, and the three things that would reverse it. The record itself declines to make that
  call, so a repository that just moved a status line would have hidden a judgement rather than
  recorded one.
- **Who reviewed is not a footnote.** An AI model, commissioned by the maintainer, and a different
  model from the one that co-authored the code — which is why it falsified two claims the same-model
  pass of 2026-08-18 had recorded as holding, and why a human review obtained later supersedes it. A
  repository that reports a check as cleared without saying who cleared it is useless the moment
  somebody outside reads it.
- **Phase 8 is unblocked; it is not pre-reviewed.** The acceptance covers the authentication path as
  it stands, not as a tripwire would leave it. Claims B6 and D6 are annotated as falsified and fixed,
  so the two rows now describe code rather than a state that lasted one day.

### Documented — what publication has to decide about the one file that names this deployment

`.forgejo/workflows/` carries a registry hostname, an image namespace and a runner label, because a
workflow that pushes to a private registry has to name it. Those files already say to delete
themselves once the repository is public. Two things were missing around that, and plan section 20 —
the publication checklist — now carries both.

- **The deletion was a comment at the top of a CI file** and nowhere else. The day it matters is the
  day nobody re-reads CI plumbing, so it belongs on the list that gets read then.
- **Deleting a file does not remove it from the history**, and the history is published with the
  repository. So the open decision is not whether to delete but whether a forge hostname, a
  namespace and a runner label matter once they are searchable — recorded as a decision to take,
  with the two ways out if the answer is that they do. ADR-17 declines public certificates partly
  because Certificate Transparency makes internal names searchable over time, which is the same
  question asked about a different channel.

Nothing else in the repository carries deployment specifics: a sweep of every tracked file found the
three names above and nothing more. The handoff notes that do carry them are `.gitignore`d and have
stayed out of the record.

### Documented — which scope a machine identity should get, and what it costs the bait

Two questions were being asked as one: what the **policy grants** (a sub-path against exact paths)
and what the **consumer fetches** (`--prefix` against `--path`). They are independent, and they are
not equally worth changing. [`docs/authorization.md`](docs/authorization.md) now says so, and
[`docs/operations/wrapper.md`](docs/operations/wrapper.md) carries the flag-level version of it.

- **Fetch by name wherever the set is known when the consumer is written.** Two failure modes belong
  to the prefix form alone. A listing that shrinks does so silently — `GET /v1/list` authorizes every
  path it returns, so removing one path's `list` capability makes the set one shorter, and the
  wrapper refuses an *empty* result rather than an incomplete one. And a set in which two paths want
  the same variable name is refused whole, so under a prefix a secret written for one service can
  refuse another service's next start. Named fetching has neither: `POST /v1/export` refuses on a
  single denial instead of answering partially, and a named set does not change when the store does.
- **Grant per service rather than per host.** What exact paths buy over a sub-path is that the set
  does not grow without a decision — and most of that is already bought by the first narrowing, from
  "everything on this host" to "more secrets for this service". The remainder costs one policy commit
  per secret and a second place that can drift.
- **Exact grants and honeypot secrets are alternatives, not complements.** A trip fires only after
  the policy *allowed* the read (ADR-15, property 2), so bait needs the gap between what an identity
  may read and what it does read. Exact grants close that gap: bait outside them produces a denial,
  and a denial trips nothing. Honeypot tokens are unaffected. ADR-15's placement rule now says this
  where the rule is stated, because a deployment that scopes exactly is choosing one half of phase 8
  over the other without being told.

Neither exact grants nor named fetching reduce what a compromised *service* can read — it holds its
own values already — and neither changes the audit trail, which records one entry per secret served
either way. What they bound is what a stolen *token* reaches afterwards.

### Added — a proposed record: the leak drop box's first sender holds a token

ADR-16 was deferred as a channel with no sender: nobody without a token can reach an anonymous drop
box that only listens inside the boundary. [ADR-21](docs/adr/0021-a-scanner-is-a-sender-with-a-token.md)
(proposed, nothing implemented) names the sender that does exist — a log scanner running where the
logs are, holding a token — and gives it an **authenticated** `POST /v1/report`, gated by `write` on
the virtual path `sys/report` and enabled as an ADR-20 runtime entry. The matching, the `leaked`
mark and the visibility are plan section 23's design unchanged; the endpoint still answers `202` and
silence even to an identity, because the scanner token is the most widely distributed credential in
the design and an answer would be an oracle keyed to it.

The question the record answers directly: no, ADR-16 is not better authenticated-only — anonymity is
that feature's sender definition, and a drop box that demands a relationship has excluded its
audience. ADR-16 stays deferred and anonymous; once ADR-21 is built, reopening it shrinks to an
exposure decision over existing machinery. Question 5 of plan section 21 is answered along the way:
the value index is written unconditionally, because a scanner makes the half-indexed corpus more
dangerous, not less. Rejected, with reasons in the record: answering match/no-match, shipping the
index key to scanners, local matching of honeypot values, and the server reading logs itself.

### Added — one mechanism for optional features, and a list of what may never be one

This project already had three kinds of optional feature and no rule covering any of them: a
container you do not deploy (the viewer, ADR-11), a boolean invented for one endpoint
(`[report] enabled`, plan section 23), and a design deliberately left uncoded (ADR-15's severe
tiers). [ADR-20](docs/adr/0020-optional-surface.md) replaces the three with one mechanism and plan
section 24 carries the design. **Nothing is implemented**; what changed today is the decision.

**The load-bearing half is a restriction rather than a feature.** Nothing optional may be reachable
from `ciphr-crypto`, `ciphr-policy`, or the path, pattern and secret code in `ciphr-core` — no flag,
no `#[cfg(feature)]`, no trait object one configuration installs. Where an optional feature needs
something from those crates, the crate gains it *unconditionally* and the optional part is composed
outside. The reason is the external review that is still outstanding: a core whose reachable code
depends on configuration cannot be reviewed once, and a review that has to be repeated per
configuration will not be repeated.

- **Off means absent, not dormant.** A runtime entry is never registered on the router; a build entry
  is not in the binary. There is no `if enabled { … } else { 404 }` inside a live handler, because
  that leaves the handler compiled, wired, one boolean from serving, and invisible to anything except
  whoever can read the configuration.
- **Enabling one is a record, not a flag.** Whether it is on, the date the deployment accepted the
  cost, and the reason — and the server refuses to start on an entry that is on and cannot say since
  when and why, the same refusal it already makes when no audit device is configured.
- **The service says what it is.** Which entries are active goes on `/v1/health`, because that is what
  the process enforces; the reason text is authenticated, because it is prose about someone's
  environment. Startup writes one audit entry naming the active surface, which is a change a
  deployment can currently make without the trail recording anything.
- **Two routes that exist today become entries**, and both are off unless named: `POST /v1/export`,
  and the three administrative reads the viewer needs (`/v1/audit`, `/v1/identities`, `/v1/policies`).
  The second is the one that pays for itself — those routes serve a component that is already
  optional, and a deployment without the viewer has been putting its policy structure and identity
  inventory on the network for nobody.
- **ADR-15 and ADR-16 become entries of the build kind.** For a record whose central claim is that
  bait is indistinguishable on the authentication path, code that is not compiled in is the strongest
  form of that claim; and "no anonymous endpoint except `/v1/health`" is worth more as a property of
  the artefact than of a file an operator can edit.

**What may never become an entry is a closed list**: the audit device requirement, fail-closed
ordering, deny by default, TLS at the listener, the envelope scheme and its AAD binding, the single
path normalization, constant-time credential comparison. Adding an entry is an ordinary change;
changing that list is a new ADR. The failure mode of a mechanism like this is that it grows inward one
reasonable step at a time.

**Adaptive means the choice adapts, not the process.** A service that adjusts its own posture is the
availability weapon ADR-15 declined, arriving under a friendlier name, and it is state an adversary
can drive. What the service will do instead is report whether an entry's precondition holds — the
identity granularity ADR-15's severe tiers wait on, whether anything polls `/v1/health` at all, and
whether the retention cut is running — and leave the switch to a human on the host.

`AGENTS.md` also states a working rule that was practice and not written down: while the repository is
private, a security improvement lands immediately and the consumer side pays for it. That is what
makes changing two built routes an ordinary commit, and it stops being unconditional when the
repository is public.

### Fixed — creating a credential is in the audit trail

**No token command wrote an audit entry.** Not `issue`, not `revoke`, not `revoke-all`. The
`tokens` table grew a row and the trail said nothing, and there was no decision recorded anywhere
that this was intended — `init` and `rotate-master-key`, the other local administrative operations,
have been audited from the start.

**What this does not do is defend against anyone.** Issuing a token needs the master key, and
whoever holds that and the database decrypts every secret directly; the threat model puts that
reader outside the boundary on purpose (A5) and no entry moves that line. It is also not the
shortest path for such a reader — a token is the long way round to data they already have.

**What it changes is what the trail can be asked.** A token minted that way was invisible, and every
access made with it afterwards read as ordinary activity of a legitimate identity — so the trail
answered *"who read this"* confidently and wrongly. The chain could not help: it proves nothing was
**removed**, and this was never written into it. With the entry, concealing the act requires
rewriting the chain forward, which is what an anchor kept outside the store detects. The value is
therefore conditional and the documentation says so: it is only as good as the anchor schedule.

- **`issue-token` and `revoke-token` are new actions**, and `openapi.yaml` carries both.
- **Audit entries gain a `subject` field.** An operator on the host issues a credential *for* an
  identity, and those are two parties: `principal` is `cli:<account>`, `subject` is the identity and
  the token's non-secret id. Folding one into the other would have made the trail say the operator
  authenticated with a token they had just created. The recorded id is the one every later access
  with that credential carries, which is what joins the two.
- **The stored record format therefore changed**, and the pinned known-answer vector in
  `ciphr-audit` changed with it. Records written before and after differ in shape; **records written
  earlier keep verifying exactly as they did**, because verification hashes the stored bytes and
  re-serializes nothing. That property was designed in and is now exercised.
- **`revoke-all` writes one entry per token**, not one for the batch, because the question asked
  afterwards is when *this* credential stopped working. Revoking an identity twice records nothing
  the second time, and revoking a token that does not exist records nothing at all.
- **The CLI and the viewer both show the subject** where they used to show only a path — an
  `issue-token` row that says a credential was created and refuses to say for whom is not worth
  printing. The viewer's column is now `Subject` rather than `Path`.

The token itself never enters the trail, only its non-secret identifier; a test asserts it.

### Changed — the masking claim now covers the runner that was measured, and stops there

`docs/operations/cli.md` said that verifying `::add-mask::` "by a Forgejo runner and by act_runner is
a phase 4 task". Half of that had been done on 2026-08-18 and the sentence hid it, while the other
half was work nobody in a position to do it had: an act_runner is a Gitea runner, and one has to
exist to be measured on. Where none does, the choice is not between measuring and waiting but between
measuring and assuming — and "both are act derivatives" is exactly the assumption that would have
made the Forgejo measurement look unnecessary, which is the measurement that found finding 9.

- **What the document says now is what was measured**: a real Forgejo runner, same binary and
  execution mode as a job, values differing from one another in a single character; effective for the
  same step, across steps through `$GITHUB_ENV`, multi-line values, a composed URL and the stderr of
  a failing command, with the multi-line round trip checked by digest rather than by printing.
- **The `set -x` exception is stated where the reader is, not only in the review.** A mask matches as
  a literal substring and bash re-quotes before xtrace prints, so a value containing a single quote
  or a tab reaches the log in clear text. That is the operationally important half and it holds
  regardless of which runner is in front of it: for a job holding fetched values the rule is `set -x`
  off, not "the mask will catch it". Hex and base64 values cannot contain either character; a
  password from a full punctuation alphabet contains a single quote roughly every third time.
- **Plan section 21, question 4 is closed as a scoped claim rather than as evidence.** It reopens as
  a product question the day Gitea compatibility is something this project promises. Section 14 loses
  the assumption it made in passing — "Forgejo and Gitea runners honour the same convention, being
  act-based" — and says instead that the convention is shared and the claim is not.

### Changed — phase 8 is decided and narrowed, phase 9 is deferred

Nothing is implemented and nothing is scheduled to be. Both planned features were read against the way
a real deployment actually consumes this service rather than against the plan, and both records moved
on 2026-08-20. **The external review has still not happened**, and neither decision touches that line:
acceptance settles a design, and a condition on the code is a condition on the code.

- **ADR-15 is accepted in the `alert` tier only.** `disable-identity` and `freeze` stay in the record
  as designed and are not being built. The reason is in the record already and is now the decision:
  the tiers inherit the granularity of the identity set, and where one machine identity serves every
  deploy target the two severe tiers are one tier under two names. They become buildable when
  revoking one identity stops one consumer instead of all of them — a condition, not a date.
- **The placement rule for bait gained its second half**, which is the part that decides whether a
  honeypot works or pages on a schedule: bait belongs outside every prefix any consumer fetches, and
  *whether a prefix is fetched is a question about the code that fetches, not about the policy that
  permits it*. A machine identity is normally authorized over more prefixes than anything reads —
  which is where bait belongs, because it is also where an enumerator looks first. A helper that lists
  a prefix and then exports everything it got back reads bait the policy file gives no hint about.
- **An alert nobody polls is not an alert**, so phase 8 is worth building after the monitoring it
  depends on is live. The flag, the entry and the marker file are pull-based by design; the step that
  turns them into a page is outside this process and nothing here can check that it happened. Same
  failure mode as an anchor file written next to the store.
- **ADR-16 is deferred**, not rejected. Its third precondition — whether anyone holding no token can
  reach the endpoint — is not one condition among five: it decides whether the feature has a user.
  Where every consumer already sits inside the boundary the service listens on, a report adds nothing
  the audit trail would not have carried, while the cost is unchanged: the first anonymous write path
  in a design that is fail-closed on its audit trail. It reopens with question 2 in plan section 21
  and not on its own.
- **`docs/threat-model.md` now expects "no anonymous endpoint except `/v1/health`" to stay true**
  rather than to expire with phase 9. `docs/operations/freeze.md` documents a tier that is no longer
  being built and says why it is kept: the condition that would bring `freeze` back is named, and
  whoever revisits it should read what it closes before rediscovering it.

### Added — how to commission the external review

`docs/security-review.md` had the scope, the claims and the deliverable, and nothing about the step
that is actually outstanding. It now says what a reviewer needs (this document, three design
documents, and the source at a **named tag** — findings cite lines, and a moving `main` turns a
citation into a puzzle), who fits, what two days of reading means, and what not to buy: a penetration
test exercises the deployment rather than these crates, and an automated scan returns what `cargo
audit` and `cargo deny` already block on every commit. Its scope section also records what the two
decisions above removed from the review surface.

### Fixed — two documents still said the master key lives in an environment file

Finding F9 of the ADR-15/16 design review, second bullet, closed where it was still open.
`docs/threat-model.md` was corrected when the finding was written; `docs/crypto.md` and
`docs/security-review.md` were not, and both are documents a reviewer reads. Since the `static_file`
seal the key is a mounted file, and a deployment following current guidance has none in its
environment at all. The sentences were not wrong about A5 — they were wrong about where to look, which
in the paper handed to an external reviewer is the more expensive kind of wrong.

## [0.3.0] — 2026-08-20

Nothing new to build with; four corrections to things that were already there, two of which were
saying something untrue. The classification a secret carries is the theme: it now has a state for
"nobody has said", it is visible over the API and in the viewer, and every way of setting it is
recorded. **What this is not** is unchanged from `0.1.0`: the external review of `ciphr-crypto`,
`ciphr-policy` and the reviewed parts of `ciphr-core` still has not happened, and holding real
secrets before it does is a risk a deployment accepts rather than a condition it has met.

**Three things to do about it**, and
[`docs/operations/upgrade.md`](docs/operations/upgrade.md) is the runbook that outlives this entry.

1. **Deploy the service before the viewer.** `GET /v1/versions/{path}` returns an object where it
   returned a bare array, and the viewer built for this version reads the object; against `0.2.0` it
   finds no `versions` field. The viewer image is published after this one for that reason. Any other
   client that parsed the array needs the same upgrade.
2. **Schema 5 is the second one-way door**, after schema 4 in `0.2.0`. Back up the database and the
   anchor file first, and do not plan an image rollback after the first start — an older binary
   refuses a migrated database with `SchemaTooNew`.
3. **Run `ciphr list --rotation unclassified` afterwards and work the list.** Every secret that was
   `rotatable` now says `unclassified`, including the ones somebody classified deliberately, because
   nothing recorded which was which. They warn rather than reassure until reclassified, which is the
   safe direction and not urgent.

### Fixed — the audit trail records the address a request came from

`request_context` set `client_ip: None` unconditionally, while the doc comment above it explained why
the address comes from the connection and not from `X-Forwarded-For`. The reasoning was right and had
never been implemented: no extractor took the peer address, so **every record in every trail carried
no source at all**. The one request-origin field that was populated is `user_agent`, which the client
chooses.

It matters most exactly where the trail has nothing else to identify a caller by. An unauthenticated
denial records `principal: null` — a series of guessed tokens is countable and, until now, not
attributable to anything.

- **The listener is served with `into_make_service_with_connect_info`**, without which the address
  never reaches a handler regardless of what the handler asks for.
- **An extractor that cannot fail.** `Origin` reads the `ConnectInfo` extension and yields `None` when
  there is none, with `Rejection = Infallible`. A router driven without connection information — every
  test in `ciphr-server` uses `oneshot`, and so would anything embedding the router — has no address
  to offer, and that is a missing field rather than a rejected request. A mandatory extractor would
  have turned those into `500`s.
- **The IP without the port, canonicalized.** A port is per-connection noise. An IPv4 peer on a
  dual-stack listener arrives as `::ffff:10.0.0.7`, and recording it that way would file one host
  under two spellings in the same trail.
- **`X-Forwarded-For` is still ignored**, deliberately and unchanged: a header a client controls is a
  header a client can lie in. Behind a reverse proxy the recorded address is the proxy, which is the
  truth about that hop and is documented as such.

Plan section 23 keys the leak-report rate limit on this address and its audit section records it, so
this is a precondition for that endpoint rather than a detail of it — and it lives in `ciphr-server`
rather than in the crates the external review must cover, which is why it could be built now. Found
in the design review of ADR-15 and ADR-16 (`docs/review-adr-15-16-2026-08-20.md`, F2), against a
deployment whose trail showed two unauthenticated denials with no source.


### Changed — the rotation class is on the wire, and the viewer shows it

The class said what happens when a value is rotated, and **no API response contained it**. The plan
said it "drives warnings in the CLI and the UI"; the CLI half was true and the UI half could not be,
because the viewer had no way to learn it. Someone looking at a secret in a browser could not see
that rotating it destroys data.

- **`GET /v1/versions/{path}` now returns an object** — `{ path, rotation, versions }` — where it
  returned a bare array of versions. **This is a breaking change to that endpoint**, and it is the
  one place a shape change was unavoidable: the class belongs to the secret rather than to any one
  version, and a top-level JSON array cannot grow a field at all, so the next piece of per-secret
  metadata would have met the same wall. Changed once, while the consumers could be counted.
- **The class travels with `needs_care` and `advice`.** `needs_care` is the service's own answer to
  whether this should stop somebody, so no client re-derives the rule — one that decided "anything
  but `rotatable`" would be right today and wrong the moment a class is added. `advice` is prose in a
  payload, which is unusual and deliberate: the text is defined next to the classification precisely
  so whoever shows it shows it at the moment of the decision, and a copy in the viewer's TypeScript
  is a copy that drifts from what the CLI prints.
- **`class` is an open string, not a closed enum**, for the same reason: a client that could not
  parse a class a later service added would break for a reason that has nothing to do with it.
- **The viewer shows it above the versions**, styled from `needs_care` — so `unclassified` reads as a
  warning rather than an all-clear, which is the entire point of the class. Selecting a second path
  before the first has answered drops the superseded response: the panel already raced, but with a
  classification on it a stale answer would print "safe to rotate" under the name of a secret that is
  not.
- `ciphr-sdk`'s `versions()` returns `History { rotation, versions }` instead of
  `Vec<VersionSummary>`, with `Classification` carrying the three fields. The end-to-end test over a
  real TLS socket asserts the classification arrives from the real service.

**Two things a deployment has to sequence.** The viewer built from this commit requires the new
response shape, so **it must not be deployed ahead of the service** — against 0.2.0 it will find no
`versions` field. And any client of `/v1/versions/{path}` that parsed a bare array needs the same
upgrade; `openapi.yaml` carries the new schema.

`ui/package.json` also moves to `0.2.0`. It had been left at `0.1.0` while the tag was `ui-v0.1.1` —
the image version comes from the tag, so nothing was wrong, but the number in the file said something
untrue.

### Added — `import --stdin`, and the boundary an import cannot cross

`import --from-dotenv` presumed a file exists. A service whose container definition reads its
variables straight from the deploying process's environment has no `.env`, so the migration route
had no source for it and every value went in through `put` individually — the majority case for
anything deployed by CI rather than by hand.

`--stdin` reads the same format with the same parser. One parser, deliberately: a second set of
quoting rules is a second set to get wrong, and the two would drift exactly where a stray quote
character ends up inside a stored secret. The two flags are mutually exclusive and one is required.
Nothing has to be written to disk in order to be imported any more. It refuses a terminal, like every
other standard-input read here: without that the command waits with no prompt and no output, and
whatever is typed before Ctrl-D is parsed as a `.env` file.

**The other half of that gap is not a defect and is now written down instead of left open.** A forge
does not give a secret back: once a value is stored as a CI secret it can be overwritten and used,
not read out. No import can have a forge as its source, and none ever will. For a value whose only
copy lives in one, the documented answer is to generate a new value, `put` it, switch the consumer,
and remove the forge secret — a deliberate rotation instead of a copy, which also retires a value
that has been inside every job log's blast radius for years. Values that cannot be regenerated
(`breaks-data`, `volume-bound`) have to be recovered from the system that holds them.
`docs/operations/cli.md` carries it as a procedure.

**`--rotation-map` is deliberately not built**, and plan section 11 now says so rather than
promising it. It was meant to let one import express several classes. The larger problem was that an
import expressing *no* class silently claimed the safest one, and that is what the default change
fixes; with `unclassified` and `ciphr list --rotation unclassified` the map is ergonomics rather
than damage control. If it is ever built, a TOML file mapping name to class is the form to prefer
over a repeatable flag — reviewable, and able to live in the deployment's own repository.

### Changed — a secret nobody classified no longer claims to be safe to rotate

`secrets.rotation` defaulted to `rotatable` from migration 001. A default is what a value gets when
nobody decides, and `rotatable` is a decision — *safe to rotate* — so **every secret written without
an explicit `--rotation` asserted the one property whose being wrong destroys data**, and the
shortest path through both `put` and `import` was the path that asserted it. `Rotation::parse` has
always refused an unknown class rather than defaulting, on the grounds that defaulting to
`rotatable` "would turn a typo into safe to rotate". The same argument had never been applied to the
absence of an answer.

It also made the phase 6 completion criterion — *every value classified* — impossible to check: a
deliberate `rotatable` and an untouched default were the same value in the same column.

- **`unclassified` is the new default class**, and it counts as needing care. `Rotation::needs_care`
  is now true for everything except `rotatable`, so the absence of an answer stops an operator
  exactly like `breaks-data` does. Its advice says what to find out, and warns that the classes
  which destroy data are indistinguishable from this one from the outside.
- **`ciphr list --rotation <class>`** filters a listing by class. `--rotation unclassified` is the
  one that matters: it answers *what has nobody looked at yet*, which is the question the field
  exists for and which nothing could answer before.
- **`ciphr rotation <path>` without a class now reads it** instead of being a usage error. The class
  was previously not readable from the CLI at all — it could only be set — so the new default would
  have been invisible to the person expected to act on it.
- **Migration 005 rewrites existing rows, and only the ambiguous ones.** `rotatable` becomes
  `unclassified`; `seed-only`, `breaks-data`, `volume-bound` and `invalidates-sessions` are left
  exactly as they are. Nobody types those by accident, so they carry a real decision, while a stored
  `rotatable` carries either a decision or the old default and **nothing distinguishes them**.
  Resetting costs a re-classification of values somebody did look at; keeping would preserve a
  possibly-unmade claim that a rotation is safe. `updated_at` is not touched, so nothing looks
  freshly modified.
- **The migration swaps the column instead of rebuilding the table**, and the reason is recorded in
  the migration itself: SQLite's documented rebuild (create, copy, `DROP TABLE`, rename) was written,
  tested, and **fails at COMMIT with a foreign key violation even under `PRAGMA defer_foreign_keys`**
  — `DROP TABLE` counts an implicit delete per referencing row, and re-populating under a different
  name never discharges it. The documented remedy needs `foreign_keys = OFF`, which cannot be set
  inside a transaction, and every migration here runs inside one. The swap never drops the table,
  deletes no row, and moves no `id`, so no version is ever momentarily orphaned.

**What a deployment does about it:** upgrade, then run `ciphr list --rotation unclassified` and work
the list. Values that had been marked `rotatable` deliberately are in it and have to be marked again
— that is the cost of the old column never having recorded who said so.

### Fixed — `classify` is its own action, and every way of setting a class records one

Changing a rotation class wrote **no audit entry at all**, while `docs/operations/cli.md` stated that
every command including the metadata ones is audited. All three ways of setting a class — `ciphr
rotation <path> <class>`, `ciphr put --rotation`, and `ciphr import --rotation` — now write a
`classify` entry naming the path and the operator.

It is a separate action rather than a `write` because a reclassification produces no version and
would otherwise be invisible among the value writes — and **downgrading a class to `rotatable` is
the step that comes immediately before a rotation that destroys data.** "Who decided this was safe?"
has to be answerable from the trail. `openapi.yaml` carries the new label.

The three call sites go through one function, because they had already drifted apart once: a secret
classified `breaks-data` could be silently made `rotatable` by `ciphr put --rotation rotatable`,
which left a `write` in the trail and nothing else, and an `import --rotation` classified a whole
corpus with no trace at all. Five tests hold the property, three of which fail against the code that
had it wrong.

## [0.2.0] — 2026-08-20

Everything phase 7 needed, plus the bound the audit trail never had. Four blocks landed after
`v0.1.0`: the audit cut and its anchor, one rule for turning a path into a variable name (ADR-18),
`ciphr-sdk` as route C, and `ciphr-run` as route B. **What it is not** is unchanged from `0.1.0`:
the external review of `ciphr-crypto`, `ciphr-policy`, and the reviewed parts of `ciphr-core` still
has not happened, and holding real secrets before it does is a risk a deployment accepts rather than
a condition it has met (plan section 18, `docs/security-review.md`).

**Three things to read before upgrading.**

1. **`ciphr export --format dotenv` and `--format actions-env` can now refuse where they used to
   succeed.** Two paths under one prefix that share a last segment used to export as the same
   variable name, and the second one won — a service received a valid secret that was the wrong one,
   silently, with both reads recorded in the audit trail as successful. That is now a refusal naming
   both paths, and a path segment that cannot be a variable name is a refusal too. Nothing is written
   when either fires. `--format json` is keyed by full path and is unaffected. This is the one change
   here that breaks working behaviour, and it is deliberate: the alternative was the wrong secret.
2. **Schema 4 is a one-way door.** The server migrates on start, and an older binary then refuses the
   database with `SchemaTooNew`. Back up before the upgrade, and do not plan an image rollback after
   the first start. `ciphr audit cut` refuses on a database that has not been migrated yet — and,
   since `bf28d41`, refuses before writing anything, including to the anchor file.
3. **`import --from-dotenv` now rejects a key with a leading digit** (`1FOO=x`), which it used to
   accept. No shell could ever source such a line, and accepting it produced a path the export can
   never render.

### Added — the wrapper reaches a deployment through a registry, not only a release

`ciphr-run` is bind-mounted into images this project does not own, so what a deployment needs is the
file. The release workflow attaches it to the tag, and that was written down as if it settled the
question. It does not while the repository is private: **a release asset is readable only by
something that can authenticate to the forge**, and the host that has to mount the file authenticates
to a registry instead. The server image already had that problem and already had an answer; nobody
had drawn the same line for the wrapper, which left route B correct here and unreachable outside.

- **`Dockerfile.run` packages the wrapper as an image whose entire filesystem is that one binary**
  (`FROM scratch`), pushed as `<image>/run:<version>` beside the service image, in both registries.
  No shell, no libc, nothing to run: it is a transport, not a runtime.
- **The file comes out with `docker create` and `docker cp`, without starting anything.** The release
  job runs exactly those steps against the image it has just pushed and computes the published
  SHA-256 from what comes out — so the retrieval path a deployment follows is exercised on every
  release instead of the first time somebody needs it, and the release asset and the image cannot
  disagree about what they contain.
- **No `:latest` for the wrapper.** The service image has one; a moving tag on a file that gets
  mounted into other people's containers would be a way to change those bytes with nothing recording
  that it happened.
- **Each channel publishes its own checksum**, and a deployment verifies against the channel it
  pulled from. The internal registry builds from source on its own runner, so its image comes from a
  second build of the same commit, and neither build is claimed to be reproducible — the base layer
  is pinned, the `apt-get` inside it is not.
- The reasoning is in [ADR-14](docs/adr/0014-ciphr-run-injects-into-a-child-process.md) as a fourth
  thing that record did not anticipate, and the operator-facing half is the new
  [`docs/operations/wrapper.md`](docs/operations/wrapper.md): where the file comes from, what each
  exit code means, and what route B does not solve.
- A `.dockerignore` keeps `target/` out of the build context. It changes no image — both Dockerfiles
  copy explicit paths — only what has to be transferred before a build starts.

### Changed — a refusal at mode 0777 names the cause that platform actually has

A world-readable master key file or token file stops the process, and that check does not change.
The message did. **A bind mount from a filesystem without Unix permissions reports mode 0777 for
every file** — a Windows or macOS host under a Linux container engine, or a CIFS share — whatever the
file is on that host. The refusal was correct and sent the reader looking for a permission nobody had
set, which cost an hour the first time it happened and would have cost it again for every new
contributor on such a platform.

At mode 0777 exactly, both refusals now say so and name the fix: **a named volume, not a weaker
check.** At any other mode the sentence does not appear — a hint attached to every refusal would
teach readers to skip the part that matters, and 0777 is not a state anyone reaches deliberately for
a credential. The text lives once in `ciphr-core` (`file_mode`), shared by `ciphr-crypto` and
`ciphr-run`, with tests on both sides pinning that it appears at 0777 and only there.
`docs/operations/master-key.md` carries the same thing for someone reading ahead of the failure.

### Fixed — stores initialized before the `init` audit fix say so in the documentation

`ciphr init` ignored `--audit-file` until 2026-08-19, so the genesis record of every store created
before then reached the database and not the file device. The fix cannot repair an existing store,
and the consequence had never been written down where an operator would meet it: the **first cut that
would remove sequence 1 is refused**, because that record genuinely is not in the archive.
[`docs/operations/audit-trail.md`](docs/operations/audit-trail.md) now describes how to recognize
such a store, why its database copy is unaffected, and why the resolution is one deliberate
`--assume-archived` rather than treating the check as broken.

### Added — `ciphr-run`, so route B costs a bind-mount instead of a derived image

[ADR-14](docs/adr/0014-ciphr-run-injects-into-a-child-process.md) is **accepted** and built. A
third-party image that only reads environment variables no longer needs a Dockerfile of its own: mount
one static binary, override `entrypoint:`, and the image is untouched.

```
ciphr-run --url https://host:4400 --token-file /run/secrets/token --ca /etc/ciphr/ca.crt \
          --prefix infra/host/service -- /original/entrypoint --flags
```

- **It is `ciphr-run`, its own crate, not a `ciphr run` subcommand.** The dependency list is the
  guarantee: `ciphr-sdk`, `ciphr-core`, `clap`, and nothing else, so no store, cryptography or
  master-key code can be reached from inside a container this project does not own. A subcommand would
  also have inherited the CLI's global `--master-key-file` and `--database` options into a context
  where both are nonsense. **Size was not the argument, and the measured numbers say so:** stripped
  musl builds are 3,347,368 bytes for `ciphr-run` against 4,033,400 for the full CLI, about 17% apart.
- **The order of the checks is the security property.** Platform support, then a command, then the
  token file, then the fetch, then the naming rule, and only then `exec`. If any of those fails
  **nothing is executed** — that was ADR-14's third condition, and it is now four end-to-end tests
  rather than a sentence.
- **Exit codes borrowed from `docker run` and the shell**, because the thing reading them is a restart
  policy: `125` the wrapper failed and no child started, `126` the command could not be executed, `127`
  it was not found, anything else the child's own. `125` answers the question a wrapper otherwise makes
  unanswerable — did my service crash, or did it never start?
- **No environment variable is read**, deliberately. This process `exec`s into one that inherits its
  environment, so anything taken from there would be handed to the service too. The token comes from a
  file and there is no flag that accepts a token value.
- **A world-readable token file stops the process**, mirroring the master-key check in `ciphr-crypto`.
- **No `unsafe`, and the result is better than what ADR-14 proposed.** The record described a wrapper
  that sets the values in *its own* environment; that needs `std::env::set_var`, which is `unsafe`
  here. `Command::env` sets the environment of the image `exec` installs instead, so **a secret never
  appears in `/proc/<pid>/environ` of the wrapper** — only the service's, which is where it has to be.
- **Anything without `exec` refuses rather than degrading.** A spawn-and-wait would leave a supervisor
  alive holding every value for the lifetime of the service and swallowing its signals. The wrapper
  refuses before reading the token, and says why.
- **Two consequences a deployment has to read, not code:** the entrypoint pin is unchanged — a rebuild
  traded for a pin that drifts when the base image moves — and the child can still read the token
  file, because `exec` does not change the filesystem view. The second one means **route B makes
  per-service token scoping matter more than it did**; `--path` exists partly for that, needing only
  `read` where `--prefix` needs `list` too.

### Added — the wrapper is a released artefact, and its linkage is a gate

- `ci/build-wrapper.sh` builds `ciphr-run` for `x86_64-unknown-linux-musl`, **verifies it is
  statically linked** rather than assuming the target implies it, and holds it to a **5 MiB budget** on
  the stripped binary. The budget is a review trigger: a jump means a dependency arrived in the thing
  mounted into other people's containers, and raising the number is the wrong response.
- CI runs `cargo test -p ciphr-run --target x86_64-unknown-linux-musl`, so the tests execute **as**
  static binaries instead of merely being built as them. That distinction earned its keep: static musl
  cannot load NSS modules, so a binary that builds fine may be unable to resolve a hostname, and
  `tests/wrapper.rs` covers one resolution by name for exactly that reason.
- The release workflow attaches `ciphr-run` and its SHA-256 to the tag. It is the one artefact here
  that is not an image, because there is nothing for a deployment to pull it out of.

### Added — `ciphr-sdk`, the client half of route C

The crate was a doc comment and thirteen lines of it. It is now a working client for the v1 API, and
it exists for one job: an application fetching its own secrets at startup, so that no plaintext is
rendered to a file, none is baked into the container configuration, and the audit entry names the
**service** rather than the runner that deployed it (plan section 13, route C).

- **`Client::builder` takes three arguments and all of them are required**: an `https` base URL, a
  token, and the certificate authority to trust. Each refuses a different way of being wrong — `http`
  is refused outright, because the payload is plaintext secrets.
- **The client cannot be pointed at the public CA set.** Not "does not by default": the transport is
  compiled without `webpki-roots`, so the public root bundle is not linked into the binary at all,
  and the trust anchor is a constructor argument rather than a builder call someone can forget.
  [ADR-17](docs/adr/0017-certificate-provenance.md) is a property of the build here instead of a rule
  in a document. Verified by test: a certificate from an unrelated authority fails the handshake.
- **`client.environment(prefix)` is route C in one call**, with names from
  [ADR-18](docs/adr/0018-one-rule-for-the-variable-name.md) — the same names `ciphr export` produces
  and `ciphr run` will. Names are assigned *before* the values are fetched, so a layout that cannot
  produce an environment is refused without reading a secret and without the audit entries that
  reading them would have written.
- **An empty prefix is a refusal, not an empty environment.** `GET /v1/list` authorizes every path it
  would return, so "you may list nothing here" and "there is nothing here" arrive as the same empty
  array. A consumer asking for its own prefix is misconfigured either way, and a service that boots
  with no secrets because its token lacks a capability is the silent start this refuses to allow.
- **It cannot set an environment variable**, which was not planned: that is `unsafe` in this edition
  and every crate here forbids `unsafe_code`. It turns out to be the better answer — a value read
  straight from the returned mapping never reaches `/proc/<pid>/environ`, which is the exposure route
  C otherwise still has. `Command::env` covers the child-process case, which is the same mechanism
  `ciphr run` would use.
- **Errors are cut along what a caller can do about them.** `SdkError::is_retryable` is deliberately
  narrow: a transport failure and a `503` from the audit trail, and the latter carries the documented
  guarantee that nothing was served and nothing changed — which is what makes retrying safe for a
  write as well as a read. A `401` is not retryable, because a retry sends the same credential.
- **Tested against the real service over a real TLS socket** — the same router, authentication,
  evaluator and audit sink, reached over a TCP connection with a real handshake, including the
  refusals (`401`, `403`, `404`, `400` on the reserved prefix). The certificate is generated per run
  rather than committed: a checked-in key pair is fixture material that looks like real key material.
- **Not implemented, on purpose:** the administrative reads (`/v1/audit`, `/v1/identities`,
  `/v1/policies`), whose consumer is the MCP server (ADR-13, post-v1); any `from_env()` convention,
  because inventing one here would make it the convention by accident; and any retry loop, because
  how long a service waits for its secrets is the service's policy.
- **One new dependency and one new dev-dependency**, both recorded in
  [ADR-19](docs/adr/0019-sdk-transport-blocking-ureq.md) with the measurements behind them: `ureq`
  (5 new crates, one TLS stack, `cargo deny` green) over `reqwest` (~119 new crates and a `bans`
  failure needing an exception), and `rcgen` for the test certificate.
- `openapi.yaml` is unchanged: the client adds no endpoint and reads only documented ones.

### Fixed — an export could hand a service the wrong secret, silently

`ciphr export` derived the environment variable name from the last path segment and checked nothing
about the result. Two paths under one prefix that share a last segment — `infra/a/db/PASSWORD` and
`infra/a/cache/PASSWORD` — both rendered as `PASSWORD=`, and in a `.env` file or in the file a runner
reads from `$GITHUB_ENV` the second wins. **The service then received a valid secret that was the
wrong one, with no error anywhere and both reads recorded in the audit trail as successful**, because
both reads were successful. It is the worst failure mode this project has room for: silent, correct
from every angle, and confirmed by the audit.

The second half of the same gap: a legal path segment is not necessarily a legal variable name. A
segment may contain `-`, `.`, and letters from any script, so `infra/a/db-password` exported as
`db-password='…'` — a line no shell can source, and one this program's own `import --from-dotenv`
refuses.

- **The rule now lives once, in `ciphr-core`** as `EnvVarName`, and is recorded as
  [ADR-18](docs/adr/0018-one-rule-for-the-variable-name.md). The convention is unchanged and was
  never in question: the name is the last path segment. What is new is that a name which is not a
  portable variable name is refused, and a set in which two paths want the same name is refused
  naming **both** paths — repairing either one would invent a name no consumer asked for.
- **Nothing is emitted when a set is refused.** The check runs before the first byte, which matters
  most for `--format actions-env`: a value printed before its `::add-mask::` is a leak, so the refusal
  has to precede the rendering rather than interrupt it.
- **`--format json` is unaffected**, being keyed by the full path. A secret at `infra/a/db-password`
  is exportable as JSON and not as `dotenv`, which is the honest asymmetry — JSON promises a path,
  `dotenv` promises something a shell can read.
- **`import --from-dotenv` validates keys with the same rule**, so the round trip holds: every name
  the export can produce, the import accepts. It consequently now refuses a key beginning with a
  digit, which it previously accepted; `1FOO=x` is a line no shell can source, and accepting it
  created a path the export could never render.
- **This settles the fourth of ADR-14's four open conditions**, the one shared between route B
  (`ciphr run`) and route C (the SDK), before either of them is built rather than by whichever
  arrived first. Neither route implements the rule; both call it.
- Found by reading the export path while planning phase 7, not in the field. It was unreachable in
  the migration run so far and becomes reachable the moment something fetches a whole prefix at
  startup — which is what phase 7 is.

### Documented — where the certificates come from, and why not from a public CA

- **ADR-17** answers the question ADR-8 left open. The machine path — CI clients and the reverse
  proxy — keeps a private CA with the pin on the CA rather than the leaf; the browser path gets a
  publicly resolvable name and a public certificate over ACME DNS-01 at the proxy. That second half
  revises what plan section 21 said, which was a second leaf from the internal CA for the viewer.
- **The private CA is the narrower trust set, not the wider one**, and the record says so plainly
  because the opposite is the intuitive reading. `--cacert` replaces the trust store for that call
  instead of extending it, so a CI client trusts exactly one key this deployment holds, where a
  public certificate would mean trusting every WebPKI root — on the one hop whose content is
  plaintext secrets. ACME there would additionally publish internal names to Certificate
  Transparency, require a credential that can rewrite public DNS, and put an account key and a
  writable certificate path beside the plaintext.
- **Two conditions make that answer true, so they are part of the decision rather than advice:** the
  CA carries X.509 name constraints, and it goes into no system or browser trust store. An
  unconstrained root in a trust store is a universal key for everything that machine speaks — the
  real attack surface behind the question, and the one thing a private CA can genuinely get wrong.
  A CA already issued without constraints is re-issued before the deployment holds real secrets.
- **The browser is the case that inverts the argument**, which is why it gets the other answer: a
  private leaf reaches it only through an installed root or a click-through warning on the page
  where someone pastes a bearer token (ADR-12), and a user trained to dismiss that warning has lost
  more than the certificate protects.
- No code changes. The service still loads two PEM files and acquires no ACME client.

### Added — `ciphr audit cut` bounds the queryable trail

The `audit_log` table grew for as long as a store existed, and because auditing is fail-closed a full
volume stops the service serving secrets. This is the bound. It is one operation rather than three,
because doing any part of it alone is the mistake — a `DELETE` against that table makes everything
after it unverifiable and reports as tampering afterwards, indistinguishable from a cover-up
including for the person who ran it.

```sh
ciphr audit cut --keep 50000 --anchor /path/to/anchors.jsonl --archive /path/to/audit.jsonl
```

- **`--keep`** is how many of the newest entries stay queryable. A count, not an age: the bound it
  answers is the size of the table, and age-based retention belongs on the archive where the host's
  log tooling already does it. A trail shorter than the bound is reported and exits zero — a
  scheduled cut that failed on a young trail is one somebody switches off.
- **`--archive` is required**, and it is checked rather than trusted. Every record the cut would
  remove has to be in the file device's file or one of its rotated siblings, matched by the hash of
  the line, which for this format means byte-identical. A record that is not there is not removed.
  `--assume-archived` replaces the check with an assumption — for lines shipped off the host as they
  are written, or rotated files compressed beyond what this can read — and says so on every run.
- **`--anchor` is required**, and two lines go into it: the anchor at the cut, synced to disk *before*
  the records go, and an anchor over what survived, appended after. The first is what the remainder is
  verified from. The order is the failure mode: a crash between them leaves an anchor over a record
  still present, which verifies, rather than a cut nothing outside the store can attest to.
- **`--dry-run`** verifies, checks the archive, prints what would go, and changes nothing. Every
  refusal behaves the same way: nothing is removed, and nothing is appended to the anchor file
  either — a line there for a cut that never happened would be one somebody has to explain later.
- Like `anchor` and `verify`, it needs **neither the store lock nor the master key**, so it runs
  against a live service. Retention that needs downtime does not get scheduled, and a bound nothing
  runs is not a bound. It writes no audit entry of its own for the same reason `anchor` does not:
  that would need the lock the running service holds, and it would move the head just anchored.
- **Why a command and not a schedule inside the service:** a cut has to be anchored outside the
  store, and the service is the thing an anchor exists to be independent of.

### Changed — `audit verify` and `audit anchor` know a trail can begin after a cut

- `verify` prints where the trail begins and what the cut removed, and **exits zero on a cut store**.
  A legitimately cut trail that reported tampering would be a check nobody runs.
- What it cannot establish alone is stated in the output: the recorded cut is a row in the store,
  written by whatever can write the store. `verify --anchor` compares that row against the anchor the
  cut wrote outside and says which of the two answers it got.
- `audit anchor` works on a cut trail. It would have failed on one — the records no longer start at
  sequence 1, and an anchor over them has to know where they do start.
- `/v1/audit` says the same thing in `openapi.yaml`: the trail does not necessarily begin at sequence
  1, and a client verifying from genesis fails on a cut store, correctly.

### Added — schema 4 records where the audit log was cut

Nothing cuts it yet; this is the half of retention that has to exist before anything may.

- **`audit_cut`**, append-only: when a cut ran, the last sequence number it removed, that record's
  hash, how many records went, and where the anchor was appended. The hash is what verification of
  everything after the cut starts from — the first surviving record chains to a record that is no
  longer in the table, so without it the remainder cannot be checked at all.
- **The row is a claim, not evidence**, and the migration says so where a reader will meet it.
  Whoever can write the database can write that row, which is exactly what a deletion dressed up as
  retention looks like. The anchor outside the store is the copy that makes it more than a claim, and
  `ciphr audit verify --anchor` compares the two. What the row buys is the other half: without it,
  the routine check on a legitimately cut store reports tampering, and a trail that cries wolf is one
  nobody reads.
- **Opening a store whose log contradicts its cut record fails.** A log that ends at or before a
  recorded cut means records that survived the cut were removed afterwards without one; an empty log
  behind a recorded cut is a state cutting cannot produce, because a cut never empties the table.
  Both refuse rather than resume — resuming would silently start a second chain in a table that
  already had a history, or make the removal invisible. This is the same fail-closed choice the audit
  sink makes, applied at startup.
- A cut is one transaction: the records go and the record of them going lands, or neither happens.

### Added — the viewer can be published where a private deployment can pull it

- `.forgejo/workflows/build-ui-image.yml` builds the viewer image on a `ui-v*` tag and pushes it to
  the internal registry, exactly as `build-images.yml` does for the service and for the same reason: a
  private repository means a private GHCR package, and the deployment host authenticates to one
  registry that is not GHCR. Both files go away when the repository is public and the GitHub workflows
  become the single publishers again.
- The image path is nested — `<registry>/<owner>/ciphr/ui`, matching what GHCR derives from the
  repository name. A flat `ciphr-ui` reads like a second repository beside `ciphr`, and the viewer is
  not one: it is a directory in this repository with its own tag namespace and its own release
  decision (ADR-11). One artifact should not have two names.
- **`ui-v0.1.1` is the tag that carries that name**, and `ui-v0.1.0` was left where it is. The
  internal workflow builds from the tag it was triggered by, so the old tag would still publish the
  old path — and moving a tag to fix that is the thing this repository argues against everywhere else,
  including in the comment that pins base images by digest. A version number is cheaper than a
  reference that can move. The bundle is unchanged between the two; only the packaging is.
- The build context is `ui/` alone. This image is static files and a web server, and it has no reason
  to be able to see the crates.
- It refuses a tag that is not `ui-v*`, because the two tag namespaces are the mechanism that keeps
  the release cadences apart (ADR-11) and a manual run naming the wrong one would quietly undo that.

### Fixed — the strict policy broke the viewer's own dev server

- The Content-Security-Policy sat in `ui/index.html`, so `npm run dev` served it too — and the dev
  server does not serve the built artifact. It assembles the page in the browser, where Vite's HMR
  client applies styles by creating elements at runtime, which `style-src 'self'` refuses. The page
  arrived unstyled with `Applying inline style violates … 'style-src 'self''` on the console.
- The policy is now defined once in `vite.config.ts` and injected into the **built** document by a
  build-only plugin. Production and `vite preview` keep it; the dev server runs without it. That is
  the honest split rather than the tempting one: with the policy in the source document, the fix a
  developer reaches for is `unsafe-inline` — in production, where it matters.
- **This was shipped in `fa5ca00` and the verification did not catch it**, because that verification
  drove the built bundle behind the container's headers. It never loaded the dev server, which is the
  one way most people will meet this package first. Both paths are now checked in a browser.
- CI checks the built document for the policy: the directives have to be there, an `unsafe-` keyword
  fails the job, and so does a missing policy — which is what removing the plugin would look like.
  Proven by removing it and watching the check fail.

### Added — two features planned: honeypots (phase 8) and leak reports (phase 9)

Nothing is implemented. Plan sections 22 and 23 hold the designs, ADR-15 and ADR-16 hold the
decisions, and both records are **Proposed**. The three reserved paths in `openapi.yaml` return `404`
and say so.

- **Honeypots and tripwires (ADR-15, plan section 22).** Bait in two shapes — a token in the
  documented format that authenticates nothing, and a secret path no legitimate consumer reads — with
  a per-honeypot trigger tier of `alert`, `disable-identity`, or `freeze`, defaulting to the mildest.
  Four properties are the decision rather than the implementation: bait is indistinguishable from the
  real thing in both response and timing; the trigger fires *after* the policy allowed the read, so
  there is no honeypot branch in the evaluator and no new capability; each tier is named together with
  what a false positive costs; and `freeze` is recorded in the store, closes only the value-serving
  routes, keeps `/v1/health` and the audit trail open, and is cleared on the host alone.
- **Alerting deliberately means no outbound connection.** No SMTP client, no webhook, no notifier in
  the process that holds the master key. A tripwire is a field on `/v1/health`, an audit entry, and a
  marker file; the monitoring section 17 already requires is what turns it into a page. Same reasoning
  that keeps the v1 audit devices to `sqlite` and `file`.
- **Leak reports (ADR-16, plan section 23).** One unauthenticated endpoint, `POST /v1/report`, that
  accepts a candidate secret value and marks the version it matches as leaked. **It never says whether
  the value matched** — `202` with an empty body for a match and a miss alike, `429` at a limit. An
  endpoint that confirms a guess is a guessing machine for any value with little entropy, and section
  10 already draws the line it would cross: an unauthenticated endpoint may report what the process
  enforces and never what is stored.
- **Matching goes through a blind index**, `HMAC-SHA256` under a key derived from the root key by the
  pattern `TokenPepper::derive` already uses, so a report is one indexed lookup instead of a
  full-corpus decryption. What it adds to the database is stated rather than assumed away: a reader of
  the file learns which secrets hold *the same* value, and anyone who could attack the index offline
  can already decrypt every value directly. Rejected: a truncated index or a Bloom filter, because a
  false leak mark on a `breaks-data` secret invites the rotation that destroys data.
- **The leaked mark influences no authorization decision**, and here that is the security property
  rather than tidiness. It can be set by an anonymous request; if it refused reads, anyone who has
  ever seen a value could switch that secret off for everybody from outside. It sits on the version,
  so rotation ages it out — and there is deliberately no command that clears it.
- **The limits run before the audit write and before the store lock.** This is the first request path
  in the design that reaches the store without an identity, and the service is fail-closed on the
  audit trail: an anonymous request that writes an audit entry spends a resource whose exhaustion is a
  total outage. Refusals cost a counter and are summarized once per window, not once each; a
  concurrency cap keeps anonymous traffic off the mutex authorized reads queue on; and the endpoint is
  off unless a deployment enables it.
- **No unauthenticated request reaches a tier above `alert`.** A reported honeypot value is the
  strongest signal the system can produce and it still only alerts, because otherwise the report
  endpoint would be a remote off switch operated by whoever holds a leaked value. This is why the two
  features were designed together and are scheduled in this order.
- **Threat model:** adversary **A9**, the anonymous reporter, with the row marked as describing
  nothing that exists yet. **Scheduling:** phase 8 then phase 9, and neither before the external
  review — one adds behaviour to the authentication path, the other a key derivation in `ciphr-crypto`
  and the only anonymous path to the store. `docs/security-review.md` records what each would add to
  the review's scope if it lands first anyway.
- **Two open questions, added to plan section 21:** whether the value index is written unconditionally
  (recommended, because a half-indexed corpus makes a miss meaningless and the endpoint is designed
  not to admit it), and whether `POST /v1/report` needs its own listener — which is the same
  network-exposure decision as question 2 and has to be answered with it.

### Fixed — the documented server configuration could not be loaded

- The example in `crates/ciphr-server/src/config.rs` put `policies` after the `[seal]` table. In TOML
  a bare key written after a table header belongs to that table, so it parsed as `seal.policies`,
  which `deny_unknown_fields` correctly refused. Anyone configuring a server by following the
  documentation got a parse error naming a key they had put at the top level.
- The fixture in the tests had it right the whole time, which is exactly why nothing failed: the test
  named `loads_the_documented_example` was loading a *copy* of the example, and the copy stayed
  correct while the original drifted. That test now covers the fields under its real name, and a new
  one reads the TOML block out of the module documentation and loads it — an example that cannot work
  now fails the build.
- Plan section 12 had the same example without `policies` at all, and that field is required. Both
  now show it first, with the reason its position matters.

### Added — the viewer, phase 5

- **`ui/` is a read-only browser view of a deployment**: the audit trail with server-side filters,
  secret metadata with a per-value reveal, identities, policies, and health. Vue 3.5.41 and one
  runtime dependency, built with Vite, served by its own container (`ui/Dockerfile`,
  nginx-unprivileged) and released on its own tag namespace (`ui-v*`,
  `.github/workflows/release-ui.yml`). ADR-11's third argument, made concrete: an npm advisory must
  not force a new server image and therefore not a restart of the service whose restart demands the
  most care. Documented in `docs/ui.md`.
- **It cannot write anything.** No secret, no policy, no identity, no token. That keeps the reach of
  an XSS finding at "read what the signed-in human is allowed to read anyway", and it is why no
  policy-write API had to exist for the viewer to be useful (ADR-3).
- **Sign-in is a pasted token** for an identity of kind `human`, held in `sessionStorage` and gone
  when the tab closes (ADR-12). No cookie, so the CSRF class does not exist rather than being
  mitigated. The shape is checked before any request, so a truncated paste fails locally instead of
  producing an audit entry for an authentication that never had a chance; the header shows the
  token's non-secret identifier, the same one the trail records.
- **The security requirements of plan section 15 are structural where they can be.** Views are
  switched with `v-if`, so leaving one destroys its component and revealed plaintext with it. There
  is one reveal at a time and no bulk form, even though `/v1/export` exists. There is deliberately no
  copy button: the clipboard is a place a value survives the tab, the session, and the reader's
  attention, with no expiry.
- **A strict Content-Security-Policy**, sent by the container and repeated in the document so a
  bundle served by something else keeps it: `default-src 'none'`, `script-src 'self'`,
  `connect-src 'self'`, no `unsafe-inline`, no `unsafe-eval`. The build emits no inline script and no
  inline style, and CI fails if one appears. `frame-ancestors` is in the header only, because
  browsers ignore it in a meta element and log an error saying so — a page that complains about its
  own policy teaches whoever reads that console to ignore it.
- **No service worker**, and `main.ts` unregisters any it finds from an earlier deployment on the
  same origin; the container refuses to serve one. A cached response to a secret read is a secret
  without an expiry date.
- **`ci/check-ui-budget.sh`** is the viewer's own dependency budget, separate from the Rust one as
  plan section 15 requires: exactly one runtime dependency, a ceiling on the whole tree, no package
  with an install script, and every package resolved from the public registry with an integrity hash.
  CI installs with `npm ci --ignore-scripts` and runs `npm audit --audit-level=high`.
- **The chain badge says what it proves.** A page of records is checked for linkage — consecutive
  sequence numbers, each record naming its predecessor's hash — and the viewer does not recompute
  hashes: doing that in a browser means re-serializing parsed JSON and hoping the encoder agrees byte
  for byte with the server's, which is a second implementation of the hashed form and the same class
  of mistake as a second path normalizer. With a narrowing filter applied the check is skipped and
  says so, because a filtered page is a selection rather than a run. The full check is
  `ciphr audit verify`, and the one that survives a forward rewrite is `--anchor`.
- Verified in a real browser under the deployment's own policy — same origin, `/v1` proxied to a live
  service over HTTPS with a verified certificate — not only type-checked: every view renders, the
  reveal works and does not survive navigation, sign-out clears storage, no service worker is
  registered, and the console is free of errors and failed requests.

### Fixed — `/v1/audit` returns the bytes it says it returns

- The endpoint promised each record as "the exact JSON that was hashed, so a client can verify the
  chain itself". It held a `serde_json::Value`, which is a **sorted** map: the record came back with
  its fields in alphabetical order rather than the order they were written and hashed in, so any
  client that recomputed the hash got a mismatch on an untouched chain. The response now carries the
  stored text verbatim (`RawValue`, hence the `raw_value` feature on `serde_json`).
- Found by building a client against the documentation, and the reason it survived until now is in
  the old test: it read a **parsed** body, where field order is invisible. The new test
  (`the_audit_endpoint_returns_the_exact_bytes_that_were_hashed`) reads the raw response, asserts the
  stored record appears in it verbatim, and checks the reported hash against `hash_payload` of those
  bytes. It fails on the old code and passes on the new — checked, not assumed.

### Added — `ciphr audit anchor`, the head of the chain kept outside the store

- **`ciphr audit anchor [--out FILE]`** writes one JSON line — format version, timestamp, sequence
  number, hash — to standard output and appends it to `--out`. It is the half of the retention design
  in plan section 7 that closes a gap the chain cannot close itself: a hash chain detects an entry
  removed, edited, or reordered, but not a forward rewrite by someone who can write the store, because
  they recompute every hash from the point they changed and the result verifies from genesis. Evidence
  kept in the same place as the thing it is evidence about is not evidence.
- **`ciphr audit verify --anchor FILE`** checks the chain against the newest anchor in that file.
  Two shapes are accepted, and they are the two that occur: the whole chain, where the record at the
  anchored sequence must hash to the anchored hash; and a run that begins immediately after the
  anchored sequence, which is what a cut leaves behind — there the anchor is the predecessor the first
  surviving record must chain to. Anything else is refused as `AnchorUnreachable` rather than passed:
  an anchor that cannot be attached to the records in hand proves nothing about them.
- **Both commands read without the store lock and without the master key**, which is what makes them
  usable at all: verification hashes stored records, so it needs no key, and a reader is not the
  second writer the lock exists to prevent. `SqliteStore::open_read_only` is new for this, and it does
  not migrate — a reader that silently upgraded a schema would be a writer. Requiring the lock would
  have meant the trail could only be checked with the service stopped, which is the opposite of when
  a check is wanted. There is a test that holds the lock and asserts both commands still work.
- **Anchoring records no audit entry of its own.** Two reasons, and either would be enough: an entry
  would move the head the anchor just wrote down, and writing one needs the lock the running server
  holds.
- **An existing anchor is verified before a new one is appended**, and nothing is appended if it does
  not hold. An anchor written over a contradiction would give a rewrite a fresh alibi and leave the
  file looking healthy. A mismatch names both of its possible causes — the chain was rewritten, or the
  anchor file belongs to a different store — because from inside the store they are indistinguishable,
  and both are worth stopping for.
- **What an anchor covers is the chain up to its sequence number.** Everything after it rests on the
  chain alone until the next anchor, which is the argument for a schedule rather than for reaching for
  this after an incident. And the file has to live somewhere the store's writer cannot reach; next to
  the database it is decoration. `docs/operations/audit-trail.md` and `docs/operations/cli.md` say so
  where the commands are documented.
- Not built, and named as such in plan section 7: the cut itself. Nothing bounds the queryable device
  and nothing archives what a bound would remove, so `audit_log` still grows without bound.

### Changed — the review requirement says what it binds, and its scope is three crates

- **Four places said the external review is "a precondition for holding real secrets".** The project
  cannot enforce that — nothing in the software refuses to serve a value because a review is
  outstanding — so stated that way the sentence describes a gate that does not exist, and the first
  deployment to proceed without the review turns it into a false claim rather than an accepted risk.
  `README.md`, `AGENTS.md`, `docs/crypto.md` and the risk table in `docs/README.md` now say the review
  **has not happened**, that the crates deciding every access are verified by nobody but their author
  until it does, and that proceeding anyway is an accepted risk rather than a met condition.
- **`docs/security-review.md` states who the condition binds:** this project. An operator's decision
  to run without the review belongs in that deployment's documentation — dated, with what it covers
  and what reverses it — and does not reach back into this repository. The status line there changes
  when a review happens and for no other reason; neither the pre-review pass nor uneventful time in
  production moves it.
- **The mandatory scope is three crates, not two** (plan section 18, `AGENTS.md`, `docs/crypto.md`).
  `docs/security-review.md` has said so since it was written: path normalization and the glob matcher
  live in `ciphr-core`, and normalization is the one function ADR-9 names as the place where routing
  and authorization can silently disagree. The plan and the summaries quoting it still named
  `ciphr-crypto` and `ciphr-policy` alone, so a review scoped from the plan would have missed the
  ADR-9 surface entirely.
- Plan section 18 also records what operational experience is worth here: it finds defects a review
  would not — the audit-chain fix above is one — and still does not discharge the requirement, because
  it exercises the paths a deployment happens to take rather than the ones an attacker chooses.

### Changed — two limits the first migration exposed are written down

- **`docs/operations/audit-trail.md` no longer says retention is undecided.** The shape is settled
  and recorded in section 7 of the plan — queryable device bounded, file device unbounded and
  archived, and the head hash plus its sequence number written outside the store at every cut, so
  verification starts from that anchor instead of from genesis. **None of that mechanism exists.**
  The document now describes what the software does: nothing deletes, and `audit_log` grows for as
  long as the store does. Two consequences are named with it — a hand-rolled `DELETE` produces the
  same `SequenceGap` as tampering, so afterwards nothing distinguishes a retention run from a
  cover-up; and while auditing is fail-closed, the size of the audit volume is the only bound on the
  trail.
- **The plan gained "The consumer on another host" (section 13).** All three consumption routes
  assume the consumer runs where the service is reachable, and a deployment that terminates TLS at
  the service and publishes no port beyond its own host has no route for one that does not. The
  consequence is about retirement rather than convenience: a value with several consumers stops being
  duplicated only once *every* one of them can fetch it, so one consumer out of reach keeps the old
  copy authoritative — and a path prefix for shared values buys ordering, not retirement, while that
  is true. What this bounds is phase 7 rather than phase 6: a deploy that renders configuration from
  one reachable runner and copies it onward can still retire a forge secret for a host that never
  reaches the service, while runtime fetching cannot be delegated that way.
- **Three entries left the plan's open-questions list with their answers** (section 21): the source
  of the TLS certificate for ADR-8, the UI origin, and `::add-mask::` on a Forgejo runner. The first
  keeps the two consequences that belong to this repository rather than to a deployment — a leaf is
  replaceable without touching a client because the pin is the CA, and the leaf must carry the
  loopback name in its SAN because ADR-8 forbids `--insecure` and the health check speaks TLS to
  itself. The third stays half-answered on purpose: **act_runner is still unproven**, and "both are
  act derivatives" is the assumption that list refused to make about the Forgejo runner.

### Added — the changelog rule is enforced rather than trusted

- `ci/check-changelog.sh` fails a commit that changes `crates/` without changing this file, and it
  is a blocking job in `ci.yml`. The rule is not new — the header of this file has always said the
  changelog is updated in the same commit as the change it describes. What is new is that something
  checks it.
- **It was added because the rule broke.** `0f711ce` changed behaviour an operator has to know about
  and recorded it nowhere but its own commit body, and nothing noticed. Every other documentation
  discipline in this repository is a script; this was the one left to habit, and habit is what
  eroded. That is an argument the project already makes about source rules, applied to itself.
- The trigger is `crates/` and nothing else. Deployment files, CI, and documentation are outside it
  on purpose: a changelog that records every comment fix is one nobody reads, and a gate that fires
  on noise gets worked around rather than obeyed.
- A change with genuinely no observable effect opts out per commit with a `Changelog-Exempt:`
  trailer that states a reason. The gate checks that a reason exists, not that it is a good one —
  that is what a reader of the history is for. An opt-out that costs nothing to write would not be
  a gate.
- Tags are exempt from the job: a release rebuilds code that already passed this on main, and the
  range a tag push reports is not a change under review.

### Changed — the CI integration is named as a boundary, and one claim is withdrawn

- **`README.md` states the integration boundary under *Honest boundaries*.** The audit trail records
  that a runner read a value, not what it did with the value afterwards, and no forge masks a value
  fetched at runtime. That was documented — in the risk table of `docs/README.md` and in the masking
  trap section of `docs/operations/cli.md` — but not on the front page, which named runner-agnostic
  CI access only as an advantage. For a project whose name contains *CI*, having the boundary that
  affects the primary consumer sit two clicks deeper than the one that affects root was the wrong
  asymmetry.
- **`docs/threat-model.md` no longer lists reproducible builds among the countermeasures in place.**
  They are not implemented, and `docs/` describes what exists. The entry now says so and records the
  condition instead: while the repository is private every build is internal, so no third party is
  in a position to rebuild an artifact and compare it. It becomes worth the cost when the repository
  goes public, and the paragraph names itself as the thing that has to change then.
- The status line of the threat model said phase 1 while the project is at phase 3, and the same
  line claimed only the cryptographic and storage defences exist. Corrected, with the UI (A7) and
  MCP (A8) rows marked as describing components that are not built.

### Changed — base images pinned by digest

- `Dockerfile` pins `rust:1.94-bookworm` and `debian:bookworm-slim` by their multi-platform index
  digests. The workflows already pin every third-party action by commit hash on the grounds that a
  tag can be moved, and `release.yml` tells deployments to pin this image by digest for the same
  reason; the base images were the one place the argument was not applied to itself.
- The comment that justified the toolchain pin with "reproducible builds are a supply-chain
  requirement here" is gone with it. The pin is worth having because the base image must not decide
  the compiler version, which is true regardless — and the `apt-get install` in the runtime stage
  means the image is pinned rather than reproducible. The Dockerfile now says that rather than
  implying otherwise.

### Fixed — `init` records the store's own creation to every audit device

- `ciphr init` called `.with_audit(None)` and therefore ignored `--audit-file`, while every other
  command honoured it. The first record of every chain — the creation of the store itself — reached
  the SQLite device only (`0f711ce`, recorded here after the fact; the commit carried no entry).
- The damage is to the archived copy, which is the whole purpose of the file device: its first line
  is sequence 2, and that record's `prev_hash` names an entry the file does not contain. An archive
  that cannot be verified from its own beginning has lost the one property an archived hash chain
  has.
- **Stores that are already initialized keep the gap.** A chain is exactly the thing that cannot be
  amended after the fact, so nothing is backfilled and nothing attempts to be. Verification against
  the SQLite device is unaffected and remains the authoritative check; an archive from before this
  fix has to be verified from sequence 2 onwards, knowing why.
- Found on a deployed store rather than in the code — `audit.jsonl` began at sequence 2. The first
  guess was a forgotten flag, and measuring against a throwaway store with the flag set disproved
  it. The test drives the built binary, because `init` is private to a binary crate and the
  observable behaviour is a flag's effect on a file.

### Added — a second, temporary publisher for the private phase

- `.forgejo/workflows/build-images.yml` builds the image and pushes it to the internal registry the
  deployment host already authenticates to. `release.yml` and GHCR remain the intended home; this
  exists only because a private repository has a private GHCR package and the host has no
  credentials for it.
- Making the GHCR package public instead was considered and rejected. Nothing in the image is
  secret — no configuration, no keys, and the release binaries embed no paths from this
  workspace — but publishing the artefact of an unreviewed cryptographic implementation invites
  someone to run it, and plan section 18 makes the review a precondition for production use, which
  is a property of the software rather than of one deployment. A public image from a private
  repository is also unauditable.
- **The file carries its own deletion condition**: once the repository is public, the GHCR package
  can be public, `release.yml` is the single publisher again, and this goes.
- It pushes **one tag and no `latest`**. This is the one service that can read every secret in a
  deployment; an image reference that can move underneath it is exactly what it must not have.
- It also states what it cannot do: the gates run on GitHub, so a tag produces an image here whether
  or not that run was green. The GitHub run is the gate, and the deployment must not bump its pin
  until it has passed.

## [0.1.0] — 2026-08-19

The first tagged version. It is the artifact the external review is performed against, **not** a
release for production use: the review of `ciphr-crypto`, `ciphr-policy`, and the reviewed parts of
`ciphr-core` is a precondition for holding real secrets (plan section 18, `docs/security-review.md`).

Phases 0 to 3 of the plan are complete — the cryptographic layer, the store, the policy evaluator,
the audit trail, the HTTPS API with token authentication, and the CLI. 255 tests, three fuzz targets,
and a pre-review pass whose ten findings are recorded in `docs/review-2026-08-18.md`.

### Added — the master key may come from a file

- `[seal] type = "static_file"` with a `path`, and `--master-key-file` on the CLI. Recorded as an
  extension of ADR-5 rather than a new decision: what ADR-5 decides is a *static* key behind a trait,
  and where that key is read is a property of one implementation. The key bytes are identical either
  way, and a store sealed through one source opens through the other — there is a test for exactly
  that.
- The reason is not only that it is smaller: section 13 of the plan tells consumers not to pass
  secrets through `environment:`, because the value is baked into the container configuration and is
  readable through the runtime's inspect API by everyone with socket access — a broader set than root.
  ciphr was doing that with its own master key. A secret manager whose deployment contradicts its own
  guidance is hard to argue for.
- What it removes: the key is no longer in the container configuration or in `/proc/<pid>/environ`.
  What it does not change, stated in ADR-5 and in the operations guide: root on the host reads the
  file just as it read the variable, the key is in process memory either way, and it is still one
  bootstrap secret per host. Whether the key is at rest on a disk depends on the runtime — Swarm and
  Kubernetes secrets are memory-backed, plain Compose bind-mounts a real file.
- **Both sources cannot be active at once.** The configuration is one tagged variant and the CLI
  refuses the two flags together, so there is deliberately no precedence rule: a rule about which
  source wins is a rule that lets a deployment use the key nobody thought was active.
- **A world-readable key file stops the process**, rather than producing a warning nobody reads.
  Group-readable is accepted: root-owned and read by a service group is legitimate, and refusing it
  would push deployments towards running as root. Windows has no equivalent bit and no check runs
  there, which is documented rather than silently skipped.
- Surrounding whitespace is trimmed, so a file written with `echo` is not a different key from one
  written with `printf %s`.
- No URL-style `file://` prefix: parsing a source out of a string is the hand-written parsing ADR-2
  rejected for policies, and the argument applies to configuration too.

### Changed

- `StaticEnvSeal` is now `StaticSeal`, since the name would otherwise describe only one of its two
  sources. The identifier recorded in a store is `static` rather than `static_env` for the same
  reason — it names the mechanism, not where the key was read. `static_env` is accepted as equivalent
  when opening an existing store and is replaced on the next re-wrap.
- `/v1/health` reports `key_source` (`env`, `file`, or `supplied`) alongside `seal`. The two
  legitimately differ while a deployment moves between sources, which is exactly when an operator
  needs to see which one is in effect.
- `docs/operations/master-key.md` was still describing phase 1, including a rotation procedure that
  said no CLI command existed for it. Both are corrected.

Phases 0 to 3 are complete. The external review has not taken place; it remains a precondition for
first production use.

### Fixed — one writer per store

- Finding 10. `StoreLock` in `ciphr-store`, taken before the store is opened: by the server for the
  life of the process, by the CLI for the duration of a command. A second writer is refused with a
  message that says what to do instead of a permanent `503` afterwards.
- It adds no constraint that was not already there. A restart was required after any such write
  anyway, because only a restart re-reads the chain head; the lock moves the discovery earlier.
- No new dependency: `create_new` for atomicity, `/proc` for liveness.
- **Two errors only the container caught.** Probing for `/proc` at runtime looked portable and was
  not — on Windows the path resolved against the drive root and reported a directory, so every
  holder looked dead and the lock was taken from a live process. And a process id alone is useless in
  a container, where the server is always process 1: a lock left by a killed container looked alive
  forever, so nothing could start after an unclean stop. The lock now records the holder's start
  time from `/proc/<pid>/stat`, verified by killing a container and starting another.
- Transition cost: a lock file written by an earlier build records only a process id, cannot be
  verified, and has to be removed by hand once.

### Found — a CLI write while the server runs takes the service down

- Finding 10, reproduced against a running instance: one `ciphr put` from the CLI while the server
  is up turns every subsequent request into `503`, and it does not recover until the process is
  restarted.
- The chain lives in memory and both processes hold one. The server resumes from the store's head at
  startup; a CLI write moves that head without telling it; the server's next record collides on a
  sequence number, no device accepts it, and fail-closed refuses the request. The chain only advances
  on a committed record, so the collision repeats forever.
- Every component behaves as designed. The assumption underneath them — that one process at a time
  writes to a store — is stated nowhere and enforced nowhere.
- It matters because the CLI is the documented way to do `token issue`, `import`, `destroy` and
  `rotate-master-key`, two of which are routine. `import` is the migration tool for an existing
  corpus; run against a live server it takes the service down on its first write.
- Fixed in the entry above, after the options were weighed: a lock is the only one that states the
  assumption rather than working around it.

### Added — a container image and a release workflow

- `Dockerfile`, `docker-entrypoint.sh` and `.github/workflows/release.yml`. Single architecture on
  purpose: this runs on one amd64 host, and a multi-arch manifest would mean a second build, a
  digest merge and a cache scope per architecture to produce an artifact nothing pulls.
- Both binaries ship in the image. The CLI is not a convenience: `init`, `token issue`, `destroy`,
  `audit verify` and `rotate-master-key` need the master key and the store and have no endpoint by
  design (ADR-3), so they run as `docker exec` against this container. A separate CLI image would
  need the same volume, the same master key and therefore the same trust.
- The health check speaks HTTPS and **verifies**, using the CA that signed the listener's own leaf.
  ADR-8 rules out `--insecure` everywhere, and a health check that skipped verification would be the
  one place that rule was quietly broken.
- The entrypoint disables core dumps before dropping privileges — a dump of this process contains
  the master key, the root key, and whatever was in flight, and `ZeroizeOnDrop` cannot help with a
  snapshot of a live process. It belongs with the process rather than in a container definition that
  a deployment can forget.
- **Built and run before being committed**, which is the only reason three of these are right. The
  `CMD` invoked a `--config` flag that does not exist; the config path is positional. The entrypoint
  accepted a key that is mode 600 *and owned by root*, which the service then cannot read — the
  likelier mistake by far, since `install -o root -g root -m 0600` is the reflex for a private key,
  and it surfaced as "Permission denied" from the TLS loader, reading like a broken certificate. And
  `docker commit` does not carry volume contents, so a store initialized that way disappears.
- Verified end to end: the container reports healthy, an authenticated request over TLS succeeds, and
  `/v1/health` shows `accepting` moving from `null` to `true` — finding 6's fix, in a running system.

### Changed — `security-review.md` brought in line with what the code now does

- **B9 is struck from the known imperfections.** The known-answer tests were reproduced against an
  independent AES-256-GCM implementation, so they validate the primitive and its plumbing rather than
  only the stored format.
- **E1 corrected.** It claimed reads work first and record afterwards. They never did — the
  authorization decision is recorded before the read, which is the stronger property. The claim was
  weaker than the implementation, and a reviewer checking the claim would have found the code
  "wrong" in the safe direction.
- **A3 rewritten** for the allowlist, with a pointer to why it changed, and **A4** now states that
  invisible characters are refused while confusables across scripts are not, and that the second half
  is a decision rather than an omission.
- The document now says a pre-review pass exists, what it closed, and — the part that matters — that
  it came from the same model that co-authored the code, so every claim it looked at was looked at
  with the wrong eyes.

### Changed — the audit record shape, for listings and for device failures

- **Findings 4 and 8.** Two additions to the stored record, both deliberate and both changing the
  known-answer test in `chain.rs` — which is what that test is for.
- `results`: how many items an operation returned, set by listing and null elsewhere. `/v1/list`
  used to write a plain allow with no rule attached, which is the falsifier D4 names for itself: an
  allow the evaluator never produced. Listings authorize per returned path, so there is no single
  decision to record; the count is what the trail can honestly carry, and its presence is what marks
  the entry as not being a decision. The listing is now produced before it is recorded, so the number
  is true — and still before anything is serialized, so a failure to record reveals nothing.
- Authorizing the prefix instead was rejected for the reason the plan already gives: `infra/**` does
  not match `infra`, so a prefix check refuses the listing to exactly the identity allowed to read
  everything beneath it. The path names are not recorded either: an entry that grows with the size of
  a listing is a way to make records unbounded.
- `Action::AuditDeviceFailed`: the devices that accepted a record now record that another one
  refused it, naming the device. The chain advances when any device accepts, so the refusing one is
  missing that sequence number for good — and a gap found later is indistinguishable from a deleted
  entry, which commits whoever finds it to treating the surrounding accesses as unlogged. The trail
  now explains its own gaps. The write is infallible and non-recursive by design.
- The `chain.rs` known-answer test carried a comment claiming a change to the stored form makes every
  existing chain fail to verify. **It does not**, and the reason is the design the module already
  documents: verification hashes the stored bytes and re-serializes nothing, so older records keep
  verifying exactly as they did. The comment is corrected.

### Documented — the sharp edge in specificity

- **Finding 5.** `docs/authorization.md` gains a worked example: `infra/**` and `*/*/*/DB_PASSWORD`
  are both specificity 1, so a broad grant and a cross-cutting exception tie, and a tie denies with
  the reason `tie` rather than the override the author meant. Writing the exception as
  `infra/*/*/DB_PASSWORD` makes it specificity 2 and it wins outright.
- Both spellings deny; what differs is the recorded reason, and the documentation says so rather than
  implying a behaviour change. A tie is also fragile — it holds only while no third rule of the same
  specificity appears. Pinned in `decision_table.rs`, because a worked example is only worth having
  while it stays true.
- The semantics are unchanged on purpose. Counting positions instead of segments would match
  intuition in this case and would have to justify itself in every other, and any such change alters
  authorization outcomes in the crate still waiting for the external review.

### Changed — path segments are drawn from an allowlist

- Finding 1. The segment rules rejected control characters and whitespace, which let every Unicode
  *format* character through: U+200B, U+00AD, U+FEFF, U+2060 and U+202E were all accepted, and each
  one produces a path that renders identically to another — or, for the bidirectional override, as a
  different one entirely. That contradicted the rule's own stated reason for refusing whitespace.
- Segments now allow letters and digits of any script plus `-`, `_` and `.`, and refuse the rest.
  **An allowlist rather than a longer denylist**, because a denylist grows with every Unicode
  revision and a gap in it stays invisible until someone finds it. Not an ASCII rule: `日本/x` is a
  valid path.
- Control characters and whitespace keep their own errors; the new one names the offending code
  point as `U+XXXX` rather than printing a character nobody can see.
- **Confusables are unchanged and are now a stated boundary.** A Cyrillic `а` and the `ﬁ` ligature
  are letters, so any rule admitting non-ASCII names admits them. A test pins that they remain
  distinct paths.
- One deliberate cost: `%` and `[` are no longer legal in paths, and a store test used them to show
  the prefix listing is a range scan rather than `LIKE`/`GLOB`. `_` is also a `LIKE` wildcard and
  still legal, so that guard survives; the `GLOB` half does not, and the test now says so.

### Fixed — three review findings that needed no decision

- **Finding 3, the one with a trap in it.** `state.rs` and the doc comment on `read_secret` both
  said reads do the work first and audit afterwards. They never did — the authorization decision is
  recorded before the read. The wording is corrected and the code left alone, because recording
  first is the stronger property and the risk was someone aligning the code to the sentence. The
  decryption-failure and non-UTF-8 paths now write the second audit entry the not-found path always
  wrote, so no outcome other than a served value is recorded as if a value had been served.
- **Finding 7, a torn line in the file device.** `write_all` is not atomic; a failure part-way
  through left bytes on disk that the next record was appended to, producing a line the chain could
  never verify again — indistinguishable from an edit, and triggered by exactly the failure this
  device is designed around. The line is now built once and the file truncated back on any error.
  Two tests assert the tracked size never drifts from the file; the `ENOSPC` path itself is stated
  as untested, because faking the error would only test the fake.
- **Finding 2, a timing difference on unknown token identifiers.** Both paths now derive the
  verifier and run the same constant-time comparison. This narrows rather than closes it — the known
  path still performs one extra query — and the code says so instead of claiming more than it does.

### Fixed — the server no longer discards partial audit-device failures

- Finding 6. `AuditSink::record` has always reported which devices refused a record; `AppState`
  dropped that on the floor, so a device failing every write stayed invisible in the API, on the
  health endpoint and in the logs — the exact state `device.rs` names as the thing to prevent.
- `/v1/health` now reports each audit device as `{ name, accepting }`. `accepting` is `null` until
  the first record: "nothing written yet" is a third state, and a monitor that reads it as healthy
  reports a working second device on a service that has never written to it.
- **The reason a device gave is not reported.** The route is unauthenticated and a device failure
  message names a path or a database. A test asserts the reason stays out of the response.
- Covered by two tests, one driving a sink with two devices where one refuses everything. Finding 8
  is unaffected: a gap on the lagging device remains indistinguishable from a deletion afterwards.

### Added — `/v1/health` states what the process enforces

- Plan sections 10 and 17. The design has no switch that turns a security property off: TLS is a
  non-optional config field, the workspace has no feature flag at all, and the single relaxation that
  exists (`--force` on secret output) suspends a heuristic for one invocation rather than disabling a
  property. The constructive counterpart is a service that says what it enforces, so an operator can
  check it from outside instead of trusting a claim in a README.
- Named for the endpoint: seal state (already returned), **per-device** audit state (missing, and the
  reason the third monitoring check in section 17 cannot currently be built — see finding 6), and the
  transport including certificate expiry, so a renewal deadline is monitorable rather than a surprise.
- The existing constraint still binds and is restated: the endpoint is unauthenticated, so it may
  report *what is enforced* and never *what is stored*. A device name, a boolean and an expiry date
  are properties of the process; a count of secrets, a path or an identity are not.

### Added — masking measured on a real runner, and its limit

- Finding 9 in `docs/review-2026-08-18.md`, from a run on a real Forgejo runner in the same
  host-execution mode a deployment uses. The premise behind `export --format actions-env` is
  confirmed: a runtime-fetched value with no mask registered appears in the job log in full, so the
  masking really is the product's job and not the forge's.
- Every case the format was built for holds — same step, across steps through `$GITHUB_ENV`,
  multi-line values through the heredoc form, a value inside a composed URL, and a value in the
  stderr of a failing command are all redacted. The heredoc round-trip was checked by comparing
  SHA-256 digests rather than by printing anything.
- **The limit: masks match literal substrings, and `set -x` re-quotes.** A value containing a single
  quote is rendered `'part'\''part'` and a value containing a tab is rendered `$'a\tb'`; neither
  matches, and both are printed in full. Measured across eight values differing only in which
  character they contained — exactly those two leaked. Spaces, `$`, backticks, double quotes and
  backslashes are safe, because bash leaves the content unchanged inside the quotes.
- The multi-line case is safe **because** masks are emitted per line: the same property that
  `render_actions_env` justifies with "runners match literal strings" also defeats bash's `$'…\n…'`
  form, since each line's bytes still appear verbatim between the escapes.
- The module documentation in `crates/ciphr-cli/src/formats.rs` names `set -x` as the motivation for
  the feature and does not state where the protection stops. That is the minimum to change; whether
  to additionally register the shell-quoted renderings is a judgement recorded with the finding.

### Added — developer experience as a stated goal, and ADR-14

- Plan section 1 gains a **Developer experience** subsection. Until now usability was not a criterion
  anywhere in the plan: "convenience" appeared exactly once, as a reason to reject something. That is
  the `AGENTS.md` rule working as intended, and it is also why the gap ADR-14 records went unnoticed
  — an unstated goal produces no findings.
- The section is as much a set of non-goals as goals. Managing secrets, policies, identities, or
  tokens through a web form stays ruled out by ADR-3 and section 15; environments and folders stay
  ruled out by the multi-tenancy non-goal; sharing links remain a password manager's job. Asking for
  any of them is a request to revisit an ADR, not to schedule work.
- **ADR-14 — `ciphr run` injects secrets into a child process. Proposed, not accepted**, decision
  required before phase 7. Section 13's route B currently costs one derived image per third-party
  service, which is why it is the least likely route to be carried out despite applying to the most
  images. A `run` subcommand that fetches under a prefix and `exec`s the real entrypoint reduces that
  to a bind-mounted static binary and an overridden `entrypoint:`.
- The record states four conditions that must hold before it can be accepted — a static musl build,
  a written-down original entrypoint (which trades a rebuild for a pin, and says so), settled
  fail-closed behaviour on a failed fetch, and prefix-to-variable-name semantics shared with route
  C — and three rejected alternatives, including keeping the plan as it stands.

### Added — a pre-review pass over every claim

- `docs/review-2026-08-18.md`: findings, coverage, and a fitness statement in the form
  `docs/security-review.md` asks for. It is **not** the external review and says so in its first
  section: it was produced by the same model that co-authored the code, so it carries the same blind
  spots and does not discharge plan section 18.
- **B9 is closed.** All three pinned known-answer vectors were reproduced byte-for-byte by OpenSSL's
  AES-256-GCM, with the value AAD rebuilt from the prose in `envelope.rs` rather than copied from
  `AAD_HEX`, plus two negative controls. The known-answer tests now validate the primitive and its
  plumbing, not only the stored format. This should be struck from the list of known imperfections in
  `docs/security-review.md` once that document is revised.
- Eight findings, none of them a break of the envelope scheme or the evaluator. Three are fixes
  (invisible and confusable characters accepted in paths; partial audit-device failures discarded by
  the server; a torn line left behind by a failed file-device write), three are decisions
  (`/v1/list` records an allow no rule produced; specificity ignores pattern breadth; a benign device
  gap is indistinguishable from a deletion), and two are documentation that describes an ordering the
  code does not implement.
- Claims confirmed as stated: A1–A3, A5, A6, B1–B8, B10, C1, C3–C6, D1–D3, D5–D7, E2–E6. The one
  claim that holds while its surrounding module documentation overstates it is C2.

### Added — preparation for the external review

- `docs/security-review.md`: the scope, every claim the code makes, and what would falsify each. It
  states plainly that it was written by the author and cannot substitute for the review, that a
  checklist narrows attention, and that design disagreements are findings rather than
  misunderstandings.
- It corrects the plan's review scope: section 18 names `ciphr-crypto` and `ciphr-policy`, but path
  normalization and the glob matcher live in `ciphr-core` — the ADR-9 surface — so that crate is in
  scope too. About 1500 lines of code in total.
- The known imperfections are listed up front rather than left to be rediscovered: the known-answer
  tests are self-generated and validate the format rather than AES-GCM, constant-time behaviour is
  exercised but not proven, and the hash chain cannot detect a forward rewrite.

### Added — phase 3: the CLI

- `ciphr`, working on the local store with the master key from the environment: `init`, `put`, `get`,
  `list`, `versions`, `delete`, `undelete`, `destroy`, `rotation`, `export`, `import`, `token`,
  `audit`, `rotate-master-key`, and `dump`.
- **No value is ever an argument.** There is no `--value` flag; values come from standard input.
  There is no interactive prompt either, because prompting with echo writes the secret into the
  operator's scrollback and disabling echo would need another dependency.
- **No secret goes to a pipe unasked.** `get`, `export`, `dump`, and `token issue` refuse when output
  is not a terminal unless `--force` is given. `export --format actions-env` is exempt, because
  writing into the runner's environment file is its purpose.
- `export --format actions-env` emits `::add-mask::` for every value *before* the assignments, one
  mask per line for multi-line values, and assigns those with a heredoc whose delimiter includes the
  variable name so a value containing `EOF` cannot end its own block. No forge masks a value fetched
  at runtime, so masking is part of the product rather than of the documentation.
- `import --from-dotenv` with `--dry-run` that prints paths and value *lengths*, never values. A line
  the parser cannot read stops the import rather than being skipped, and `$VAR` references are not
  expanded — storing the expansion would store something the file does not say.
- `token issue` checks the identity exists in the policy file, prints the token exactly once, and
  requires a unit on a TTL: `90` meaning seconds when days were intended is a token that expires
  mid-deploy.
- `dump --format portable` ships in v1 deliberately: it is the insurance against the scenario in the
  plan, and insurance bought after the fire is worthless.
- CLI actions are audited, metadata reads included, so the trail says the same thing whether an
  access came through the API or from the host.
- `docs/operations/cli.md` documents every command and the reasoning behind the two rules.

### Changed

- The CLI works on the local store rather than through the SDK, which the plan had assumed. Most of
  what it does needs the master key and has no endpoint by design (ADR-3); a CLI that spoke HTTP
  would need the privileged API this project deliberately does not have. `ciphr-sdk` therefore stays
  a skeleton until phase 7, where applications fetching their own secrets is the requirement.
- `SecretPath::segments` is now double-ended, so the last segment — the conventional environment
  variable name — can be taken without collecting.

### Added — phase 3: the HTTP server

- `ciphr-server`: all ten v1 endpoints on axum, with TLS terminating at the listener
  (ADR-8) — there is no option to disable it and no insecure mode, because a flag that turns off
  transport encryption is a flag that ends up set in production.
- Configuration in one strict TOML file: an unknown key is an error, and the server **refuses to
  start** without an audit device. Policies live in a separate file, named by the configuration.
- Startup refuses rather than degrading: an unreadable policy file, an uninitialized store, a
  missing or wrong master key, an audit device that cannot be opened, or unusable TLS material each
  stop the process. A certificate and key swapped by mistake is reported by name at startup instead
  of surfacing as a handshake failure for the first client.
- Audit ordering, deliberately different for reads and writes: a read does the work, records the
  real outcome, then answers — so a failed audit drops the value before it leaves the process. A
  write records the authorized intent *first*, so a failed audit leaves the store untouched. Both
  are tested, including that no value is served and no secret is written when the trail is down.
- `every_endpoint_writes_an_audit_entry` walks every route and asserts an entry appeared, which
  turns "nothing is answered before it is recorded" into a checked property rather than a
  convention a future handler can quietly break.
- Listings authorize **per returned path** rather than on the prefix, because `infra/**`
  deliberately does not match `infra`. The alternative — a special case in the evaluator so a
  subtree grant also covers its prefix — was rejected: path-based authorization is worth having
  only if there is one rule for how a decision is made.
- `/v1/export` authorizes and records path by path, so a bulk read produces one entry per secret;
  a single refusal fails the whole export rather than revealing which paths are readable.
- `/v1/audit` returns each record as the exact stored bytes plus its hash, so a client can verify
  the chain instead of trusting the endpoint, with server-side filters on identity, path, decision,
  time, and sequence.
- Values are UTF-8 text on the wire and in the store — a stated limitation rather than two
  representations that every client would have to handle.
- `openapi.yaml`, covering all ten endpoints plus the reserved `POST /v1/auth/oidc/login`, which
  returns 404 in v1 and is listed so the path is not claimed by accident.

### Changed

- `rustls-pemfile` removed: it was unused, and `cargo deny` flagged it as unmaintained. The gate
  caught a dependency that should not have been added.
- `deny.toml` records two `getrandom` duplicates with the reason for each — one from `ring`, one
  from `proptest` — rather than relaxing the duplicate rule.
- `AuditDevice` now requires `Send`, since a device is written to from whichever worker thread
  handles a request. It is deliberately not `Sync`: two threads writing one file device would
  interleave lines, which for a hash chain means a chain that does not verify.

### Added — phase 3: authentication

- `ciphr-core`: unpadded base64url, hand-written and checked against the RFC 4648 vectors. Decoding
  is strict about trailing bits and rejects the padded form, so one token cannot have two spellings
  that both authenticate.
- `ciphr-crypto`: tokens shaped `cph_<8 chars id><43 chars secret>` — 256 bits of entropy in the
  secret half, a non-secret identifier so authentication is an indexed lookup rather than a scan, and
  a `cph_` prefix that secret scanners recognize. `Token` implements neither `Debug`, `Display` nor
  `Serialize`; its text form is available once, through a wrapper that wipes itself.
- Verifiers are `HMAC-SHA256(pepper, secret)` with the pepper derived from the root key under a
  domain-separating label, so a database-only leak does not permit offline verification of guessed
  tokens. Password hashing is deliberately absent: there is no dictionary to attack, so Argon2id would
  cost CPU on every request and buy nothing.
- Comparison is constant-time through `subtle`, with a test that a difference is detected at every
  byte position — and a comment saying plainly why that is a behavioural stand-in rather than proof,
  since a timing assertion in a unit test produces flakiness rather than evidence.
- `ciphr-store`: migration 003 adds `tokens`, and there is deliberately **no identities table** — the
  policy file is authoritative for identities (ADR-3), and a second copy would drift. Authentication,
  issuing, listing, revoking one token, and revoking every token of an identity at once.
- Every kind of invalid token is indistinguishable to the caller: unknown identifier, wrong secret,
  expired, revoked. The verifier is compared before expiry and revocation are considered, so timing
  cannot separate those cases either.

### Added — phase 2: policy evaluation and the audit trail

- `ciphr-core`: the five capabilities, with no `admin` among them — a test asserts that, because an
  `admin` capability would undo ADR-3. `PathPattern`, the glob language for policies, built on the
  **same** normalization function as `SecretPath` so a pattern and a path cannot disagree (ADR-9).
- Pattern language restrictions tighter than the plan required, each for a stated reason: `**` only
  as the last segment, so matching is a linear scan with no backtracking; no partial wildcards, so
  `db*` cannot quietly mean more than its author read into it; and `**` matches one or more segments
  rather than zero, so a rule about a subtree is not also a rule about its parent.
- `ciphr-policy`: TOML policy files loaded strictly — an unknown key, an unknown capability, a
  dangling policy reference, a duplicate name, or two rules for one pattern refuse the whole file. A
  policy set that loads partially would be a set of permissions nobody wrote. `capabilities` is
  required even when empty, so an explicit denial is explicit.
- The evaluator: deny by default, most specific match wins, denial wins a tie, and an empty
  capability set is an explicit denial. Every decision carries the rule that produced it and every
  denial a reason, so the audit trail can say *why*.
- A 22-row decision table (`tests/decision_table.rs`) with a test asserting it still covers every
  capability and every deny reason, plus property tests for `**` subsuming `*` and for specificity.
- `ciphr-audit`: entries that record who, what, where, which version, the decision, the deciding
  rule, and the request context — and never a value, key material, or a token, only a token's
  non-secret identifier.
- The hash chain: each record's hash is the SHA-256 of exactly the bytes stored, so verification
  re-serializes nothing and a JSON Lines file can be checked line by line with `sha256sum`. A test
  asserts the known limitation too: a forward rewrite by someone with write access still verifies.
- Fail-closed sink: if no device accepts a record the caller must refuse the request, and the
  sequence number is **not** consumed — a gap is indistinguishable from a deleted entry, and an
  audit trail that cries tampering after a disk error is one nobody reads twice. A sink with no
  devices is refused at construction.
- The file device (JSON Lines, size-based rotation, `reopen` for `SIGHUP`, each write synced) and the
  SQLite device in `ciphr-store` with migration 002, which refuses to overwrite an existing sequence
  number because two records claiming one position is evidence.
- RFC 3339 UTC timestamps without a date dependency, checked against independently computed values
  including two leap days and a century boundary.
- `fuzz/`: three cargo-fuzz targets — path normalization, pattern matching, policy loading — that
  assert invariants rather than only checking for panics, run as a blocking CI job on a nightly
  pinned by date, with `cargo-fuzz` installed from a checksum-pinned release binary.
- Documentation: `docs/authorization.md`, `docs/operations/audit-trail.md` (including what to do when
  verification fails, and why the head hash belongs outside the store), and `docs/fuzzing.md` — which
  states plainly that a 45-second smoke run is not a fuzzing campaign.

### Changed

- `AGENTS.md` no longer claims `ciphr-policy` takes no dependencies. It takes a TOML parser and
  `serde`, which is the substance of ADR-2 rather than an exception to the dependency budget.

### Added — phase 1: cryptography, storage, seal

- `ciphr-core`: normalized secret paths (NFC, no relative or empty segments, no wildcards, length
  limits) as the single normalization in the system; version numbers starting at one; the `Plaintext`
  wrapper, which implements neither `Debug`, `Display`, `Serialize` nor `PartialEq`; the five rotation
  classes, each carrying the advice for its own failure mode.
- `ciphr-crypto`: envelope encryption — master key wraps root key, root key wraps one data key per
  secret version — with path and version bound as additional authenticated data, so a ciphertext
  cannot be relocated. Known-answer tests pin the wire format; property tests cover round-tripping,
  relocation, and single-bit tampering. Every authentication failure returns one indistinguishable
  error rather than an oracle. Randomness comes from the OS CSPRNG only; `rand` is not a dependency,
  so no seeded generator exists in the graph.
- `ciphr-crypto`: the `Seal` trait and `StaticEnvSeal`, reading a 64-hexadecimal-character master key
  from the environment. The trait's `unseal` takes the wrapped record as an argument, unlike the
  sketch in the plan, which could not work — a seal must not reach into the store.
- `ciphr-store`: SQLite behind the `Store` trait, with STRICT tables, WAL, foreign keys enforced, and
  numbered migrations applied transactionally with their version marker. Secrets, versions, soft
  delete, undelete, crypto-shredding, rotation class, metadata and version listings that need no key,
  and prefix listing by range scan rather than `LIKE` — so a path containing `%` or `_` cannot be
  mistaken for a wildcard.
- `ciphr-store`: encryption is passed into `put` as a callback and runs inside the allocating
  transaction, so the version bound into a ciphertext is by construction the version it is stored
  under.
- Master key rotation, demonstrated end to end: one record is rewritten, every ciphertext is unchanged
  byte for byte, the old key stops working, and a replacement record for a different root key is
  refused.
- Documentation: `docs/README.md` (the index, the rules documentation is held to, and a table of risk
  areas), `docs/crypto.md` (the implemented design and what the tests do and do not establish), and
  `docs/operations/` for master key handling and for rotating secrets that cannot safely be rotated.
- CI gate `ci/check-docs.sh`: every document under `docs/` carries a date, and no date lies in the
  future.

### Added — phase 0: repository skeleton

- Cargo workspace with the eight v1 crates: `ciphr-core`, `ciphr-crypto`, `ciphr-store`,
  `ciphr-policy`, `ciphr-audit`, `ciphr-sdk`, `ciphr-server`, and `ciphr-cli`. The CLI binary is
  named `ciphr`.
- `#![forbid(unsafe_code)]` in every crate root, plus a denial of `print!`, `eprint!`, and `dbg!` in
  library crates.
- Workspace lint policy: `missing_docs`, `unreachable_pub`, `unused_qualifications`, and clippy's
  `all` and `pedantic` groups, all blocking through `-D warnings` in CI.
- Toolchain pinned in `rust-toolchain.toml`, formatting settings in `rustfmt.toml`.
- `deny.toml`: permissive-only licence allowlist, advisory database with a staleness limit, denial of
  duplicate crates, wildcard requirements, unknown registries, and any transitive OpenSSL binding.
- CI workflow with blocking gates — `cargo fmt`, `cargo clippy -D warnings`, `cargo test`,
  `cargo deny check`, `cargo audit --deny warnings` — and three source-rule gates in `ci/`: no output
  from library crates, `forbid(unsafe_code)` present in every crate root, and no `v-html` in the
  future UI. Third-party actions are pinned by commit hash, and `cargo-deny` and `cargo-audit` are
  installed from release binaries pinned by version and SHA-256 rather than compiled in CI.
- Decision records ADR-1 through ADR-13 in `docs/adr/`, one file each, with an index.
- `docs/threat-model.md` — adversaries A1 to A8, the boundaries that are deliberately not defended,
  and the availability trade written down as part of the model.
- `docs/why-build-this.md` — the evaluation of existing tools, the finding that OpenBao meets the
  requirement for free, and the condition under which abandoning this project is the correct
  decision.
- `AGENTS.md` with the working rules, and `SECURITY.md` with the disclosure process and scope.

[Unreleased]: https://github.com/nuetzliches/ciphr/compare/v0.10.0...main
[0.10.0]: https://github.com/nuetzliches/ciphr/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/nuetzliches/ciphr/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/nuetzliches/ciphr/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/nuetzliches/ciphr/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/nuetzliches/ciphr/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/nuetzliches/ciphr/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/nuetzliches/ciphr/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/nuetzliches/ciphr/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/nuetzliches/ciphr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nuetzliches/ciphr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nuetzliches/ciphr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nuetzliches/ciphr/releases/tag/v0.1.0
