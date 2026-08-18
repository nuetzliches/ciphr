#!/bin/sh
# Install the pinned supply-chain tools from their upstream release archives.
#
# Why not `cargo install`: compiling both tools from source took 8m47s on a cold
# cache, which was the entire runtime of the supply-chain job. Downloading the
# release binaries takes seconds, and it removes a cache whose only purpose was
# to hide a compile.
#
# Why this is not a weaker supply chain: the version **and** the SHA-256 of each
# archive are pinned below, so a substituted or re-uploaded artifact fails the
# check. `cargo install` verifies nothing beyond whatever crates.io serves at the
# moment it runs.
#
# On the two hashes: cargo-deny publishes a `.sha256` next to each archive, and
# the value below matches it. rustsec publishes no checksums for cargo-audit, so
# that hash was recorded from the artifact as fetched on 2026-08-18. The first
# fetch is trust; every fetch after it is verification.
#
# Bumping a version means replacing the version and its hash in the same commit,
# with the hash taken from the upstream artifact.
#
# Linux x86_64 only, because that is the CI target. On a development machine use
# `cargo install --locked cargo-deny@0.20.2 cargo-audit@0.22.2`.
set -eu

DENY_VERSION='0.20.2'
DENY_SHA256='9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f'

AUDIT_VERSION='0.22.2'
AUDIT_SHA256='7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428'

bin_dir="${1:-$HOME/.cargo/bin}"
mkdir -p "$bin_dir"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# fetch <url> <expected sha256> <destination>
fetch() {
    curl --fail --silent --show-error --location --retry 3 --output "$3" "$1"
    if ! printf '%s  %s\n' "$2" "$3" | sha256sum --check --status; then
        echo "install-supply-chain-tools: checksum mismatch for $1" >&2
        echo "  expected $2" >&2
        echo "  actual   $(sha256sum "$3" | cut -d' ' -f1)" >&2
        exit 1
    fi
}

deny_dir="cargo-deny-${DENY_VERSION}-x86_64-unknown-linux-musl"
fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/${DENY_VERSION}/${deny_dir}.tar.gz" \
    "$DENY_SHA256" "$tmp/deny.tar.gz"
tar -xzf "$tmp/deny.tar.gz" -C "$tmp" "${deny_dir}/cargo-deny"
mv "$tmp/${deny_dir}/cargo-deny" "$bin_dir/cargo-deny"

audit_dir="cargo-audit-x86_64-unknown-linux-musl-v${AUDIT_VERSION}"
fetch "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv${AUDIT_VERSION}/${audit_dir}.tgz" \
    "$AUDIT_SHA256" "$tmp/audit.tgz"
tar -xzf "$tmp/audit.tgz" -C "$tmp" "${audit_dir}/cargo-audit"
mv "$tmp/${audit_dir}/cargo-audit" "$bin_dir/cargo-audit"

chmod 0755 "$bin_dir/cargo-deny" "$bin_dir/cargo-audit"

echo "install-supply-chain-tools: cargo-deny ${DENY_VERSION}, cargo-audit ${AUDIT_VERSION} in $bin_dir"
