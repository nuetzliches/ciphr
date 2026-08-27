# ── Stage 1: build the bundle ────────────────────────────────────────────────
# Both base images are pinned by their multi-platform index digest, for the same
# reason the server's Dockerfile gives: a tag is a name that can be moved. The
# tag stays in the reference because a bare digest says nothing about what it is.
#
# Node is pinned to a major here rather than to an exact patch: this stage
# produces static files whose content the Node patch level does not decide, and
# the digest already fixes the image. The Rust side pins the compiler exactly
# because the compiler is part of the artifact; a bundler is not the same case.
FROM node:24-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS builder

WORKDIR /build

# Manifests first, so editing a component does not re-resolve the dependency
# tree. `npm ci` refuses to update the lockfile, which is the same argument
# `cargo build --locked` makes: a build that quietly resolves a different graph
# than the one that was reviewed is not the build that was reviewed.
#
# `--ignore-scripts` is deliberate. The only package in this tree with an install
# script is `fsevents`, which is macOS-only and optional, so nothing here needs
# one — and an install script is arbitrary code from a dependency running with
# the network and the filesystem of the build. See ci/check-ui-budget.sh, which
# fails if a package with an install script ever enters the tree.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

# The attribution, before anything that changes often, because it depends on the
# lockfile and on nothing else — so editing a component does not regenerate it.
#
# It is generated inside the image build rather than handed in, for the reason
# the whole context is `ui/`: a file produced outside and copied in is a file
# nobody can check against the tree it claims to describe. What it produces is
# the license text of every package whose code is in the bundle, which until
# 2026-08-26 this image shipped none of. `ci/check-npm-licenses.sh` is the
# separate gate on *which* licenses may be here at all.
COPY scripts/ scripts/
RUN npm run notices

COPY tsconfig.json vite.config.ts index.html ./

# The files the document references by path instead of importing — the favicon,
# and anything else that ever joins it. This directory was missing from the list
# until 2026-08-21, and nothing noticed: Vite skips a public directory it cannot
# find without a word, so every image built before then served a 404 for the icon
# `index.html` asks for. `ci/check-ui-image-files.sh` now fails if a tracked path
# under ui/ is named by no COPY here.
#
# Before src/, because a component changes far more often than an icon does.
COPY public/ public/
COPY src/ src/

# Type check and build. `vue-tsc` is part of the build script rather than a
# separate CI step so that the image cannot be produced from code that does not
# type check.
RUN npm run build

# ── Stage 2: serve it ────────────────────────────────────────────────────────
# nginx-unprivileged rather than the official nginx image: this container serves
# static files to a browser and should not start as root to do it. The upstream
# unprivileged image runs as UID 101 and listens on 8080, so there is no
# capability to drop and no port below 1024 to justify.
FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6

# The default site is replaced, not extended: a leftover server block that serves
# the same files without the security headers would be the kind of second path
# nobody notices until it matters.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /build/dist/ /usr/share/nginx/html/

# Beside the bundle rather than inside it. MIT requires the notice to travel with
# the distribution, and the image is the distribution; serving it would be a
# second thing — a `.md` under the web root arrives at a browser as a download,
# under a policy that names every fetch type, for no gain. `docker cp` reaches it,
# which is the same way the service image's copy is read.
COPY --from=builder /build/THIRD-PARTY-NOTICES.md /usr/share/doc/ciphr-ui/THIRD-PARTY-NOTICES.md

# And this project's own terms, beside them, for the reason the service image
# gives: a recipient of the image needs the text, not a pointer to a repository.
# These two files exist under `ui/` because this build sees nothing else --
# `ci/check-license-copies.sh` is what keeps them equal to the ones at the root.
COPY --chmod=0644 LICENSE-MIT LICENSE-APACHE /usr/share/doc/ciphr-ui/

# The configuration is checked where it is assembled, for the same reason
# `vue-tsc` runs in the stage above: an image that cannot be produced from a file
# nginx refuses is better than a container that discovers it at deploy time, in
# front of the reverse proxy, with nothing serving the viewer. Nothing else in
# this repository can catch it -- `nginx -t` needs nginx, and the gate scripts run
# on a developer machine and on a runner that has neither.
RUN nginx -t

# This container holds nothing: no volume, no configuration file to mount, no
# access to the database or the master key (plan section 15). Not deploying it
# costs nothing but the viewer.
EXPOSE 8080

# busybox wget, already in the image. A container that answers for its own root
# document is the whole health question here — there is no upstream to check,
# because this container does not proxy the API. The reverse proxy in front does
# that routing, which is what keeps the viewer same-origin with the service and
# CORS out of the picture entirely.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
