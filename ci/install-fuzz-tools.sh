#!/bin/sh
# Install the pinned cargo-fuzz binary.
#
# Same discipline as ci/install-supply-chain-tools.sh: the version and the SHA-256
# of the release archive are pinned here, so a substituted artifact fails the check
# and a version bump is a commit that changes both together. `cargo install
# cargo-fuzz` would compile it from source on every cold run, which is the cost
# that was just removed from the supply-chain job.
#
# rust-fuzz publishes no checksums, so the hash below was recorded from the
# artifact as fetched on 2026-08-18: the first fetch is trust, every fetch after it
# is verification.
#
# Linux x86_64 only. On a development machine, fuzzing needs a nightly toolchain
# and libFuzzer, neither of which works on Windows — see docs/fuzzing.md.
set -eu

CARGO_FUZZ_VERSION='0.13.2'
CARGO_FUZZ_SHA256='b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c'

bin_dir="${1:-$HOME/.cargo/bin}"
mkdir -p "$bin_dir"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

url="https://github.com/rust-fuzz/cargo-fuzz/releases/download/${CARGO_FUZZ_VERSION}/cargo-fuzz-${CARGO_FUZZ_VERSION}-x86_64-unknown-linux-musl.tar.gz"
curl --fail --silent --show-error --location --retry 3 --output "$tmp/cargo-fuzz.tar.gz" "$url"

if ! printf '%s  %s\n' "$CARGO_FUZZ_SHA256" "$tmp/cargo-fuzz.tar.gz" | sha256sum --check --status; then
    echo "install-fuzz-tools: checksum mismatch for $url" >&2
    echo "  expected $CARGO_FUZZ_SHA256" >&2
    echo "  actual   $(sha256sum "$tmp/cargo-fuzz.tar.gz" | cut -d' ' -f1)" >&2
    exit 1
fi

tar -xzf "$tmp/cargo-fuzz.tar.gz" -C "$tmp" cargo-fuzz
mv "$tmp/cargo-fuzz" "$bin_dir/cargo-fuzz"
chmod 0755 "$bin_dir/cargo-fuzz"

echo "install-fuzz-tools: cargo-fuzz ${CARGO_FUZZ_VERSION} in $bin_dir"
