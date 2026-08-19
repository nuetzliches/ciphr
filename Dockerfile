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
# This pins the base layer, not the build. `apt-get install` below still
# resolves whatever the archive currently offers, so the image is *pinned* and
# not yet *reproducible* — see docs/threat-model.md for why that gap is left
# open while the repository is private.
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

# `curl` is here for the health check and nothing else. It is what lets the
# check speak HTTPS to the service and *verify* the certificate — ADR-8 rules
# out `--insecure` everywhere, including in a HEALTHCHECK, and a check that
# skipped verification would be the one place the rule was quietly broken.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gosu && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r ciphr && useradd -r -g ciphr -s /sbin/nologin ciphr

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
