#!/bin/sh
# Print the third-party crates that are inside a published artefact, one
# "name version" per line, sorted and deduplicated.
#
# This exists so that the generator and the gate cannot disagree about what
# "shipped" means. `ci/generate-attribution.sh` reads it to know whose notice it
# owes, and `ci/check-attribution.sh` reads it to know whether the committed file
# is still complete. A list of triples written out twice is a list that drifts,
# and the direction it drifts in here is a missing notice.
#
# ── The triples, and why these ───────────────────────────────────────────────
# Every triple this project publishes an artefact for, and no others:
#
#   linux-gnu   x86_64, aarch64   the server image (server + CLI)
#   linux-musl  x86_64, aarch64   `ciphr-run` and `ciphr-ci`
#
# `x86_64-pc-windows-msvc` is in `deny.toml`'s `[graph] targets` and is
# deliberately not here. That entry makes the supply-chain gate cover what
# developers build on; no Windows artefact is published, so no Windows notice is
# owed. If that changes, this list changes with it and the gate then demands the
# notices that came with it.
#
# ── The edges, and why not dev ───────────────────────────────────────────────
# `--edges normal,build`: a build-dependency's code can end up in the artefact
# through codegen, so it counts. A dev-dependency cannot -- `cargo` does not build
# them for a consumer and nothing a deployment receives contains them -- and
# listing one would assert an obligation this project does not have.
set -eu

cd "$(dirname "$0")/.."

targets='x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl'

if ! command -v cargo >/dev/null 2>&1; then
    echo >&2 "shipped-crates: cargo is needed and is not on PATH"
    exit 1
fi

# Our own crates are covered by LICENSE-MIT and LICENSE-APACHE, not by an
# attribution entry. A glob rather than `ls`, so the list is the directories that
# exist rather than a parse of somebody's output.
members=' '
for directory in crates/*/; do
    members="$members$(basename "$directory") "
done

# `{p}` prints "name vX.Y.Z", so the leading `v` comes off to make the string
# match the crate directory in the registry.
for target in $targets; do
    cargo tree --workspace --edges normal,build --target "$target" \
        --prefix none --format '{p}' --locked
done |
    awk 'NF >= 2 { version = $2; sub(/^v/, "", version); print $1 " " version }' |
    sort -u |
    while read -r name version; do
        case "$members" in
            *" $name "*) continue ;;
        esac
        printf '%s %s\n' "$name" "$version"
    done
