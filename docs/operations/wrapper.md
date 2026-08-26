# `ciphr-run`: getting the wrapper, and mounting it

**Status:** implemented and tested as of 2026-08-26. Built 2026-08-20, scope guidance added
2026-08-21, release asset renamed to carry its target triple 2026-08-21, the token file's trust
requirement written down 2026-08-23, the `bulk_export` dependency removed 2026-08-24, and the
availability requirement behind a `125` at boot written down 2026-08-26 (phase 7,
[ADR-14](../adr/0014-ciphr-run-injects-into-a-child-process.md)).
The wrapper works and ships; where a deployment keeps the token file and which entrypoint it pins
are decisions this document does not make for it.

`ciphr-run` fetches a service's secrets over the API and `exec`s the real entrypoint with them in
its environment. It exists so an image that only understands environment variables needs no
Dockerfile of its own: mount one file, override `entrypoint:`, leave the image alone.

```
ciphr-run --url https://host:4400 --token-file /run/secrets/token --ca /etc/ciphr/ca.crt \
          --prefix infra/host/service -- /original/entrypoint --flags
```

`--prefix` needs `list` **and** `read`. `--path`, repeatable, needs only `read` and is the narrower
grant — prefer it where the set of secrets is known. The two are mutually exclusive.

## The shape a deployment actually writes

The command line above is what runs; what somebody edits is a compose file. The whole change to a
third-party service is an `entrypoint:` override and two read-only mounts:

```yaml
services:
  app:
    image: someone-elses/app@sha256:<digest>   # unchanged, and no derived Dockerfile
    entrypoint:
      - /ciphr-run
      - --url
      - https://ciphr.internal:4400
      - --token-file
      - /run/secrets/ciphr-token
      - --ca
      - /etc/ciphr/ca.crt
      - --path
      - infra/host/app/DB_PASSWORD
      - --path
      - infra/host/app/API_KEY
      - --report
      - --
      # Everything after `--` is what the image's own entrypoint was. Record it
      # from `docker inspect`, because overriding it means owning it: a base image
      # that moves its entrypoint moves it silently, and `--report` prints what was
      # invoked so the drift shows up in the container log rather than in an outage.
      - /original/entrypoint
      - --config
      - /etc/app.conf
    volumes:
      - ./ciphr-run:/ciphr-run:ro
      - ciphr-token:/run/secrets:ro            # not a directory this service can write
      - ./ca.crt:/etc/ciphr/ca.crt:ro
```

Three things in that file are decisions rather than syntax, and each has its own paragraph below:
the token lives in a **named volume** and not in the working directory (*Who has to be trusted*), the
image is pinned by digest for the same reason the wrapper is (*Where the file comes from*), and the
list form of `entrypoint:` is required — the string form goes through a shell, which would put the
flags back into a place that re-splits them.

The exec form also means `--report` output and the service's own output land on the same stream,
which is intended: one container log shows which variables were delivered and which program was
started, and never a value.

## Where the file comes from

Two channels carry the same binary. Which one applies depends on what the host can authenticate to,
not on preference.

**Two architectures since 2026-08-24**, and the file is not interchangeable between them: mounting an
amd64 binary into a container on an arm64 host produces `exec format error` at the moment a service is
starting without its secrets. Take the one that matches the host, not the one that matches the machine
you are fetching from.

**As a release asset**, named after its target triple — `ciphr-run-x86_64-unknown-linux-musl` or
`ciphr-run-aarch64-unknown-linux-musl` — each attached to the tag beside its own `.sha256`. This is
the direct route for anything that can authenticate to the source forge.

The name carried that triple before there was a second target, which is what made the second one an
addition rather than a rename: an asset name is the thing a fetch script is written against, and
qualifying it afterwards would have meant breaking every such script or publishing a qualified binary
beside an unqualified checksum (issue #4).

**As an image whose whole filesystem is that one file**, pushed under `<image>/run:<version>` next to
the service image. This is the route for a host that authenticates to a registry rather than to the
forge. The tag is a manifest list over both architectures, so a host pulls its own without asking; the
file comes out without the container ever being started:

```sh
docker create --platform linux/arm64 --name ciphr-run-export <image>/run@sha256:<digest>
docker cp ciphr-run-export:/ciphr-run ./ciphr-run
docker rm ciphr-run-export
```

`--platform` is what picks the variant out of the manifest list, and it is needed even when it matches
the host: `docker create` would otherwise resolve to the host's architecture, which is right until
somebody fetches on a laptop for a server. `docker cp` reads the filesystem of a *created* container,
so an image with no shell in it is no obstacle, and nothing is executed — pulling a foreign
architecture to copy one file out of it needs no emulation.

The file inside the image is plain `/ciphr-run` and stays that way: an image states its architecture
in its own manifest, so the digest already answers the question the triple answers for the release
asset. Pin the digest, not the tag: this file is mounted into containers built by other people, and
there is deliberately no `:latest` to follow.

**Verify the checksum, and expect the two channels to agree — per architecture.** They carry the same
bytes: each release asset is extracted from the image that was just pushed, with `docker create
--platform` and `docker cp` against its digest, and the published number is computed from what came
out. The two *architectures* have different checksums, and that is not a disagreement between
channels. So a mismatch between the asset
and the file inside the image is not an expected difference between two builds — it is something to
stop for.

That was not true until 2026-08-24. A second build ran on another runner and pushed to an internal
registry, so each channel published the checksum of the bytes *it* produced and a mismatch between
them meant nothing. That build was removed when the images became something this repository publishes
once; the checksums it published belong to tags from before that date.

## What breaks, what it looks like, and what to do

**The wrapper refuses and nothing starts.** Exit code **125**, and a message on standard error. This
is the designed outcome for every failure before `exec`: no command, unreadable token file,
unreachable service, a certificate the CA does not sign, an empty listing, a secret whose path
cannot become a variable name. The service did not start and did not crash, and a restart policy
can tell the difference — that is what 125 is for. **126** is a command that exists and cannot be
executed, **127** one that was not found; anything else is the child's own exit code.

**The most common cause of a `125` is not a misconfiguration — it is a boot order.** The wrapper
fetches at exec time, so a host that brings its services up before the vault is ready produces a
`125` from every wrapped container at once, and a restart policy then makes it look intermittent.
There is deliberately no client-side cache ([ADR-27](../adr/0027-the-vault-is-a-startup-dependency.md));
what to express instead, and what must not be co-located or restarted together, is
[availability.md](availability.md).

**The service starts with no secrets and fails later, obscurely.** This should not happen and is
worth recognizing if it does: an empty listing is treated as a refusal, not as an empty
environment. A token without the `list` capability produces the same empty array as a prefix with
nothing under it, so the wrapper refuses rather than starting a service that quietly has nothing.
If a service legitimately has no secrets, it does not need the wrapper.

**The token file is readable, or writable, by everyone and the process stops.** Same rule as the
master key, and since 2026-08-21 literally the same rule rather than a second copy of it: group bits
are allowed, world bits are not. Writable counts for a reason worth stating — whoever can replace
this file does not have to learn the token in it, they can substitute one of their own and have the
wrapper fetch under an identity they control. On a Windows host the refusal can be a false positive
— a bind-mounted file reports mode 0777 regardless of what it is on the host — so on that platform
put the token in a named volume rather than relaxing anything.

**Who has to be trusted for that check to mean anything: the file's owner and the directory it sits
in.** The wrapper opens the token file once and inspects *that descriptor* — the permission bits and
the content come from one open file, so a file swapped in after the check is not the file that was
read (F10, [issue #13](https://github.com/nuetzliches/ciphr/issues/13)). What no check can settle is
who could have written the file before it was opened: whoever can create entries in the directory the
token lives in can put their own token there at mode `0600`, and it will pass every rule on this page.
So mount the token from a directory the service account cannot write — a secrets mount, or a
root-owned directory — and not from a working directory shared with the application. This is the
requirement to write into the mount, because `ciphr-run` is bind-mounted into images this project does
not own and nothing in the image enforces it.

**The service reads the token file itself.** Not a failure — a property. `exec` replaces the
process image, not the filesystem view, so whatever the wrapper could read, the service can read.
Scope the token to the service's own prefix and this gives away nothing it did not already receive.
A host-wide token covering several services means one compromised service can read the others'.

**The pinned entrypoint drifts.** Overriding `entrypoint:` means recording what the image had, and
that recorded value changes silently when the base image moves. `--report` prints the delivered
variable *names* and the program about to be executed to standard error — never a value, and there
is no verbosity level that would. A container log then shows which entrypoint was actually invoked,
so drift is visible in the record instead of only in the outage.

**The platform has no `exec`.** The wrapper refuses, before it reads the token. There is no
spawn-and-wait fallback: a supervisor that stayed alive would hold every value for the lifetime of
the service and swallow its signals, which is the opposite of the point.

## It no longer needs an optional route to be on

Until 2026-08-24 both forms read through `POST /v1/export`, which is a surface entry
([ADR-20](../adr/0020-optional-surface.md)) and therefore **off unless a deployment names it**. A
deployment that had made no decision about that entry had a wrapper that could not fetch at all: exit
`125`, with a `404` behind it — the same status a missing secret produces.

The SDK reads through the bulk route where it exists and falls back to one `GET /v1/secrets/{path}`
per path where it does not, so route B now works on a default deployment. Two things do not change
with the route: the audit trail records one entry per secret served either way, and the capabilities
are the same (`read` per path, plus `list` for `--prefix`). One thing does — a refusal. The bulk route
refuses whole; read one at a time, the paths before the refused one have been served and audited, and
the error names the path that was refused. The wrapper still `exec`s nothing in either case.

Naming the entry is still worth doing where a service has many secrets: it is one request instead of
one per path, at container start, which is when a service is waiting.

## A name can decide how the service starts, and those names are refused

Since 2026-08-24, F4 of [the full-repository review](../assurance/reviews/review-2026-08-24-full-repository.md).

The variable name is the last path segment, and with `--prefix` the set of names is whatever the store
holds when the fetch runs. So an identity holding `write` on that prefix does not only choose what the
service reads — it chooses **variable names**, and a few names are read by the loader or by a language
runtime *before* the program's own code runs. `LD_PRELOAD` and the rest of `LD_*`, `DYLD_*`,
`NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `BASH_ENV`, `JAVA_TOOL_OPTIONS`,
`PATH`, `IFS`.

The wrapper refuses those names now: **exit 125, nothing executed**, and the message names the
variable and says why it is different from a password. If a deployment genuinely needs such a variable,
it belongs in the container definition — where it is a line somebody reviewed — rather than in the
store.

**What that is worth, and what it is not.** Most of those names need a file inside the image to be
useful, so the practical case is narrower than it sounds. `NODE_OPTIONS` is the exception worth
knowing: `--inspect=0.0.0.0:9229` opens a debugger port and needs no file at all, which is the same
mechanism that made GitHub Actions stop letting a workflow set environment variables through a log
directive.

**And a denylist is incomplete.** Every runtime has an option variable and this list cannot keep up
with images this project does not own. It removes the names an attacker reaches for first; what
actually bounds the problem is the next section.

## `--path` or `--prefix`

`--prefix` needs `list` as well as `read` and takes whatever exists under the prefix at that moment;
`--path` needs only `read` and takes what the container definition names. Prefer `--path` wherever the
set of secrets is known when the deployment is written, for two reasons that belong to the prefix form
alone:

- **A listing that shrinks does so silently.** `GET /v1/list` authorizes every path it returns, so
  removing one path's `list` capability makes the set one shorter. This wrapper refuses an *empty*
  result, not an incomplete one, and the service then starts with a variable missing. A named path the
  identity may not read fails the whole fetch instead, because `POST /v1/export` refuses on a single
  denial rather than answering partially — and the wrapper exits `125` without starting anything.
- **Somebody else's new secret can stop this service.** The variable name is the last path segment,
  and a set in which two paths want the same name is refused whole ([ADR-18](../adr/0018-one-rule-for-the-variable-name.md)).
  Under `--prefix` the set is whatever the store holds, so a secret added for a neighbouring service
  can refuse this container's next start.

The scope question behind this — an exact grant against a sub-path grant — is in
[`../authorization.md`](../authorization.md).

## What it does not solve

The secrets are in the service's environment, which is where that image wanted them — so they are
in `/proc/<pid>/environ` of the service, readable by root and by anything that can enter the
namespace. Route B removes the plaintext copy on disk and in the container configuration. It does
not remove the environment; only an application that fetches its own secrets does that, which is
route C and the SDK.
