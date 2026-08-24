# `ciphr-run`: getting the wrapper, and mounting it

**Status:** implemented and tested as of 2026-08-24. Built 2026-08-20, scope guidance added
2026-08-21, release asset renamed to carry its target triple 2026-08-21, the token file's trust
requirement written down 2026-08-23, and the `bulk_export` dependency removed 2026-08-24 (phase 7,
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

**As a release asset**, named `ciphr-run-x86_64-unknown-linux-musl` and attached to the tag beside
`ciphr-run-x86_64-unknown-linux-musl.sha256`. This is the direct route for anything that can
authenticate to the source forge.

The name carries the target triple although only one target is built. That is deliberate rather than
pedantic: an asset name is the thing a fetch script is written against, so qualifying it later would
mean either breaking every such script or publishing a qualified binary beside an unqualified
checksum. The suffix costs nothing now and buys the choice later.

**As an image whose whole filesystem is that one file**, pushed under `<image>/run:<version>` next
to the service image. This is the route for a host that authenticates to a registry and not to the
forge — which, while the repository is private, is the normal case. The file comes out without the
container ever being started:

```sh
docker create --name ciphr-run-export <image>/run@sha256:<digest>
docker cp ciphr-run-export:/ciphr-run ./ciphr-run
docker rm ciphr-run-export
```

`docker cp` reads the filesystem of a *created* container, so an image with no shell in it is no
obstacle. The file inside the image is plain `/ciphr-run` and stays that way: an image states its
architecture in its own manifest, so the digest already answers the question the suffix answers for
the release asset -- a file pulled from a tag arrives carrying nothing but its name. Pin the digest,
not the tag: this file is mounted into containers built by other people,
and there is deliberately no `:latest` to follow.

**Verify the checksum against the channel you pulled from.** The two images are built independently
— GitHub's from its own runner, the registry copy from another — and neither build is claimed to be
reproducible. The checksums are published in each build's job summary. A mismatch between the two
channels is expected; a mismatch against the channel's own published number is not.

## What breaks, what it looks like, and what to do

**The wrapper refuses and nothing starts.** Exit code **125**, and a message on standard error. This
is the designed outcome for every failure before `exec`: no command, unreadable token file,
unreachable service, a certificate the CA does not sign, an empty listing, a secret whose path
cannot become a variable name. The service did not start and did not crash, and a restart policy
can tell the difference — that is what 125 is for. **126** is a command that exists and cannot be
executed, **127** one that was not found; anything else is the child's own exit code.

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
