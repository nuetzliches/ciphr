# `ciphr-run`: getting the wrapper, and mounting it

**Status:** implemented and tested as of 2026-08-20 (phase 7, [ADR-14](../adr/0014-ciphr-run-injects-into-a-child-process.md)).
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

**As a release asset**, attached to the tag along with `ciphr-run.sha256`. This is the direct route
for anything that can authenticate to the source forge.

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
obstacle. Pin the digest, not the tag: this file is mounted into containers built by other people,
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

**The token file is world-readable and the process stops.** Same rule as the master key: group bits
are allowed, world bits are not. On a Windows host this can be a false positive — a bind-mounted
file reports mode 0777 regardless of what it is on the host — so on that platform put the token in
a named volume rather than relaxing anything.

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

## What it does not solve

The secrets are in the service's environment, which is where that image wanted them — so they are
in `/proc/<pid>/environ` of the service, readable by root and by anything that can enter the
namespace. Route B removes the plaintext copy on disk and in the container configuration. It does
not remove the environment; only an application that fetches its own secrets does that, which is
route C and the SDK.
