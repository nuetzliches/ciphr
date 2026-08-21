# `ciphr-run`: getting the wrapper, and mounting it

**Status:** implemented and tested as of 2026-08-20, scope guidance added 2026-08-21, release
asset renamed to carry its target triple 2026-08-21 (phase 7,
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
