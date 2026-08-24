# ── Stage 1: build ───────────────────────────────────────────────────────────
# The toolchain is pinned in rust-toolchain.toml and that pin is the point: the
# base image must not be the thing that decides the compiler version.
#
# Both base images are pinned by digest, for the reason release.yml gives about
# its own action pins and about the tag it tells deployments not to follow: a
# tag is a name that can be moved, and this is the one service that reads every
# secret in a deployment. The tag stays in the reference because a bare digest
# says nothing about what it is; Docker uses the digest when both are present.
# Each is the multi-platform index digest, so this stays platform-agnostic.
#
# This pins the base layer. Since 2026-08-24 it also pins what `apt-get` adds to
# the runtime stage: exact versions, resolved from a Debian snapshot rather than
# from whatever the archive offers today — see the block above that stage. What
# is still not pinned is the toolchain image's own contents and the `musl-tools`
# the wrapper's builder installs, so this image is closer to reproducible and is
# not yet reproducible. `docs/threat-model.md` says what that gap costs.
FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS builder

WORKDIR /build

# Manifests first, so a change to source does not invalidate the dependency
# layer. `--locked` refuses to update Cargo.lock: a build that silently resolves
# a different dependency graph than the one that was reviewed is not the build
# that was reviewed.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN cargo build --release --locked --bin ciphr-server --bin ciphr

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

# Three packages, and each is here for one reason.
#
# `curl` is for the health check and nothing else. It is what lets the check
# speak HTTPS to the service and *verify* the certificate — ADR-8 rules out
# `--insecure` everywhere, including in a HEALTHCHECK, and a check that skipped
# verification would be the one place the rule was quietly broken. `gosu` is what
# the entrypoint drops privileges with, and `ca-certificates` is what anything
# speaking TLS from inside this container would expect to find.
#
# ── Why a snapshot and exact versions ────────────────────────────────────────
#
# `apt-get install curl` resolves to whatever the archive offers on the day of
# the build, so two builds of the same commit produced two different images and
# nothing recorded which one a deployment was running. The base layer was pinned
# by digest and this was not, which made "pinned" true of one half.
#
# The three versions below were read out of the snapshot named in
# `DEBIAN_SNAPSHOT` on 2026-08-24, on amd64 **and** on arm64 — identical on both,
# including the `+b10` binNMU on gosu. That is the detail that decides whether one
# set of pins can serve a multi-architecture build at all, and it was measured
# rather than assumed.
#
# Bumping them is a deliberate commit: move the snapshot, read the three versions
# out of it, and say in the changelog what the bump carries. What this gives up is
# a security update arriving on its own; what it buys is that an image built from
# this commit next year is the image built from it today.
#
# The snapshot list is handed to apt rather than written into the image: with
# `Dir::Etc::SourceList` and an empty `SourceParts`, the base image's own
# `debian.sources` is neither replaced nor deleted, so a container somebody
# debugs later still has ordinary apt sources.
ARG DEBIAN_SNAPSHOT=20260824T000000Z
ARG CA_CERTIFICATES_VERSION=20250419~deb12u1
ARG CURL_VERSION=7.88.1-10+deb12u15
ARG GOSU_VERSION=1.14-1+b10

RUN set -eu; \
    printf 'deb http://snapshot.debian.org/archive/debian/%s bookworm main\n' "$DEBIAN_SNAPSHOT" > /tmp/snapshot.list; \
    printf 'deb http://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' "$DEBIAN_SNAPSHOT" >> /tmp/snapshot.list; \
    apt_opts="-o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/dev/null -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3"; \
    apt-get $apt_opts update; \
    apt-get $apt_opts install -y --no-install-recommends \
      ca-certificates="$CA_CERTIFICATES_VERSION" \
      curl="$CURL_VERSION" \
      gosu="$GOSU_VERSION"; \
    rm -f /tmp/snapshot.list; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd -r ciphr; \
    useradd -r -g ciphr -s /sbin/nologin ciphr

# Both binaries, deliberately. The CLI is not a convenience here: `init`,
# `token issue`, `destroy`, `audit verify` and `rotate-master-key` need the
# master key and the store, and have no endpoint on purpose (ADR-3). They are
# run as `docker exec ciphr ciphr …` against this container. A separate CLI
# image would need the same volume, the same master key and therefore the same
# trust, and would buy nothing but a second artifact to keep in step.
COPY --from=builder /build/target/release/ciphr-server /usr/local/bin/ciphr-server
COPY --from=builder /build/target/release/ciphr /usr/local/bin/ciphr

# Owned before VOLUME, so a named volume inherits the ownership rather than
# arriving as root and forcing the entrypoint to chown a database it should not
# be touching.
RUN mkdir -p /var/lib/ciphr /etc/ciphr/tls && chown -R ciphr:ciphr /var/lib/ciphr
VOLUME /var/lib/ciphr

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV RUST_LOG=info
EXPOSE 4400

# Speaks HTTPS and verifies, using the CA that signed the listener's own leaf.
# `localhost` is in that certificate's SAN precisely so this check needs no
# exception. If the CA is not mounted the check fails — which is correct: a
# service whose clients cannot verify it is not healthy for its purpose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS --cacert /etc/ciphr/tls/ca.crt https://localhost:4400/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# The config path is positional -- there is no `--config` flag, because the
# server takes exactly two arguments and everything else lives in the file.
# `ciphr-server --check-config <path>` validates without starting, which is what
# a deployment should run before it restarts anything.
CMD ["ciphr-server", "/etc/ciphr/ciphr.toml"]
