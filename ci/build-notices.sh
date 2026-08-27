#!/bin/sh
# Generate the third-party notice file that ships with every binary artefact.
#
# ── Why this exists ──────────────────────────────────────────────────────────
#
# `deny.toml` decides which licenses may enter the graph, and `cargo deny` fails
# a pull request that widens that set. That answers "may we use this". It does
# not answer the other half: MIT, BSD-2, BSD-3, ISC and Zlib each require the
# copyright notice to travel *with the binary*, not merely with the source. This
# project distributes binaries — the static `ciphr-run` wrapper mounted into
# foreign containers (ADR-14), the `ciphr-ci` binary a runner downloads (ADR-25),
# and the service image — and until this script existed, none of them carried a
# single upstream copyright line. That is the one licensing obligation the
# repository was not meeting, and it is met by shipping a file rather than by
# writing a policy.
#
# ── Why not cargo-about ──────────────────────────────────────────────────────
#
# It would be a fourth pinned upstream binary next to cargo-deny, cargo-audit and
# cargo-fuzz, it needs a template and a configuration file of its own, and for a
# crate whose text it cannot find locally it reaches out to the network from
# inside a release job. What it would buy is a license text *reconstructed* from
# an SPDX identifier. This script does the opposite and the stronger thing: it
# copies the license files the crates themselves ship, byte for byte. An
# attribution assembled from the actual artefact cannot attribute the wrong
# thing, and there is nothing to keep in step with upstream.
#
# The cost of that choice is the rule in the next paragraph, and it is the reason
# this script is a gate and not only a generator.
#
# **A crate that ships no license file fails this.** There is no fallback that
# invents a text from the SPDX expression, because a notice nobody verified is
# worse than a missing one — it looks like attribution. All 122 crates in the
# shipped graph carry a file today; the first one that does not is a decision to
# make in a pull request, not a case to handle in a loop. The failure message
# says as much.
#
# **This checks no license against a policy.** `cargo deny check licenses` is
# that gate and stays the only one; two tools with two copies of the allow list
# is how the copies drift apart.
#
# ── What goes in ─────────────────────────────────────────────────────────────
#
# Normal and build edges, all features, and **the targets from `[graph] targets`
# in deny.toml** — read from that file rather than repeated here, because "the
# platforms this project ships" is one fact and cargo-deny already owns it.
#
# The targets are the interesting half. `--target all` was the obvious choice and
# is the wrong one: it pulls in `r-efi` for UEFI and `rsqlite-vfs` through
# `sqlite-wasm-rs` for `wasm32`, neither of which is in any artefact anybody
# receives, and both of which ship no license text — so the first run of this
# script failed on two crates that are not distributed. Attribution follows what
# is distributed. Across the five triples in deny.toml the graph is 133 crates
# and the two arm64 legs resolve to exactly what their amd64 counterparts do.
#
# Everything else stays over-inclusive on purpose: all features rather than the
# ones a given binary enables, and one list for every artefact rather than one
# per binary. Over-attribution is a longer file; under-attribution is the breach.
# Dev-dependencies are excluded because they are not distributed: `proptest` is
# in no binary anyone receives.
#
# No node, no jq: this runs inside the `rust:1.94-bookworm` builder stage of
# `Dockerfile`, which has neither.
#
# Usage:
#   sh ci/build-notices.sh [output path]      default: target/THIRD-PARTY-NOTICES.md
set -eu

cd "$(dirname "$0")/.."

out="${1:-target/THIRD-PARTY-NOTICES.md}"

if ! command -v cargo >/dev/null 2>&1; then
    echo >&2 "build-notices: cargo is needed to resolve the graph, and it is not on PATH"
    exit 1
fi

cargo_home="${CARGO_HOME:-$HOME/.cargo}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# The texts are read out of the unpacked crate sources, so they have to be
# unpacked. `cargo fetch --locked` does both halves and does them for every
# platform in the lockfile rather than for the host -- which is the reason it is
# here and not assumed: a `cargo build` in the builder stage of `Dockerfile`
# fetches what Linux needs and nothing Windows does, and the windows-only crates
# would then be missing from a file that claims to cover every platform. It costs
# eleven seconds from an empty cache and nothing at all from a warm one.
cargo fetch --locked

# The targets, out of deny.toml's `[graph]` block. One list, one file, and a
# platform added there is a platform attributed here without anybody remembering
# to do it twice.
targets=$(awk '
    /^targets[[:space:]]*=[[:space:]]*\[/ { inside = 1 }
    inside {
        while (match($0, /"[^"]+"/)) {
            print substr($0, RSTART + 1, RLENGTH - 2)
            $0 = substr($0, RSTART + RLENGTH)
        }
        if ($0 ~ /\]/) { inside = 0 }
    }
' deny.toml)

if [ -z "$targets" ]; then
    echo >&2 "build-notices: no \`targets\` list found in deny.toml's [graph] block"
    echo >&2 "That list decides what this file attributes, so an empty one is a stop."
    exit 1
fi

# The graph, one `name version` pair per line.
#
# `--prefix none --no-dedupe` turns the tree into a flat list, which is what a
# notice file wants: the shape of the graph says nothing about who holds a
# copyright. The `grep -v` drops our own crates -- a path dependency prints its
# directory in parentheses, and on Windows that directory starts with a drive
# letter -- and they are dropped because they are covered by LICENSE-MIT and
# LICENSE-APACHE at the root of this repository rather than by this file.
printf '%s\n' "$targets" | while read -r target; do
    cargo tree \
        --locked \
        --all-features \
        --target "$target" \
        --edges normal,build \
        --workspace \
        --prefix none \
        --no-dedupe
done |
    grep -v -E '\((/|[A-Za-z]:[\\/])' |
    awk '$2 ~ /^v/ { print $1 " " substr($2, 2) }' |
    sort -u > "$tmp/crates"

count=$(wc -l < "$tmp/crates" | tr -d ' ')
if [ "$count" -eq 0 ]; then
    echo >&2 "build-notices: the dependency graph came back empty, which cannot be right"
    exit 1
fi

# Locate a crate's unpacked source. The directory name is `name-version`, under
# some registry beneath $CARGO_HOME/registry/src -- more than one exists when a
# machine has talked to both the git index and the sparse one, so all of them are
# tried rather than the first one guessed.
crate_dir() {
    for base in "$cargo_home"/registry/src/*/; do
        if [ -d "$base$1-$2" ]; then
            printf '%s' "$base$1-$2"
            return 0
        fi
    done
    return 1
}

# The license files a crate ships, as paths relative to its root.
#
# The whole tree rather than the top level, because the top level is not where
# the interesting ones are. Four crates in this graph vendor third-party code and
# carry its license beside it: `ring` has the fiat-crypto license under
# `third_party/` and the once_cell polyfill's two under `src/`, `tracing-core`
# has spin's, and `libsqlite3-sys` has sqlcipher's. A top-level scan finds none of
# them and no reader would notice, which is what makes it the wrong scan. It adds
# five files to the graph in total, so this is precision rather than volume.
#
# Regular files only, so a crate with a `LICENSES/` directory is not listed as if
# the directory were a text.
license_files() {
    (
        cd "$1" && find . -type f |
            sed 's|^\./||' |
            grep -E -i '(^|/)(licen[cs]e|copying|notice|unlicense)[^/]*$' |
            sort
    )
}

# The SPDX expression out of the packaged manifest. A published crate carries a
# resolved `license` field -- `cargo publish` writes inherited workspace values
# into the packaged manifest -- so this needs no TOML parser. A crate that names
# only a `license-file` says so in the output rather than being called unlicensed.
license_expression() {
    expression=$(grep -m1 -E '^license[[:space:]]*=' "$1/Cargo.toml" 2>/dev/null |
        sed 's/^[^=]*=[[:space:]]*//; s/^"//; s/"[[:space:]]*$//' || true)
    if [ -n "$expression" ]; then
        printf '%s' "$expression"
        return 0
    fi
    if grep -q -E '^license-file[[:space:]]*=' "$1/Cargo.toml" 2>/dev/null; then
        printf 'stated in the license file below'
        return 0
    fi
    return 1
}

# ── Pass one: resolve everything, and fail before writing anything ───────────
#
# The file is written only once every crate has been located, has an expression
# and has at least one text. A half-written notice file that a release job then
# attaches is the failure mode worth designing out.
missing_dir=''
missing_license=''
missing_text=''

while read -r name version; do
    dir=$(crate_dir "$name" "$version") || {
        missing_dir="$missing_dir  $name $version
"
        continue
    }

    expression=$(license_expression "$dir") || {
        missing_license="$missing_license  $name $version
"
        continue
    }

    files=$(license_files "$dir")
    if [ -z "$files" ]; then
        missing_text="$missing_text  $name $version ($expression)
"
        continue
    fi

    printf '%s\t%s\t%s\t%s\n' "$name" "$version" "$expression" "$dir" >> "$tmp/resolved"
done < "$tmp/crates"

if [ -n "$missing_dir" ]; then
    echo >&2 "build-notices: no unpacked source for:"
    printf >&2 '%s' "$missing_dir"
    echo >&2 ""
    echo >&2 "The sources are read from \$CARGO_HOME/registry/src, so they have to be"
    echo >&2 "there. Run \`cargo fetch --locked\` and try again."
    exit 1
fi

if [ -n "$missing_license" ]; then
    echo >&2 "build-notices: no license field in the packaged manifest of:"
    printf >&2 '%s' "$missing_license"
    exit 1
fi

if [ -n "$missing_text" ]; then
    echo >&2 "build-notices: these crates state a license and ship no text for it:"
    printf >&2 '%s' "$missing_text"
    echo >&2 ""
    echo >&2 "Nothing here will invent one from the SPDX expression: a notice nobody"
    echo >&2 "verified reads like attribution while being none. Get the text from the"
    echo >&2 "crate's repository, add it under ci/notices/<crate>/ and name it here, or"
    echo >&2 "replace the dependency. Either way it is a decision in a pull request."
    exit 1
fi

# ── Pass two: write it ───────────────────────────────────────────────────────
mkdir -p "$(dirname "$out")"

{
    # A quoted heredoc rather than a run of `echo`s: the prose contains backticks
    # and markdown emphasis, and none of it should be read by the shell.
    cat <<'MD'
# Third-party notices

ciphr itself is licensed under **MIT OR Apache-2.0**, at your option; those two
texts are `LICENSE-MIT` and `LICENSE-APACHE` in the source repository and are
not repeated here.

This file covers everything else that is compiled into the binaries and images
this project publishes. Each entry reproduces the license files the crate itself
ships, verbatim; nothing below was reconstructed from an SPDX identifier. It is
generated by `ci/build-notices.sh` and is not edited by hand.

The list is deliberately wider than any single artefact links: it covers every
platform this project publishes for and every feature, so a notice is never
missing from the one build that needed it. Dev-dependencies are excluded — they
are not distributed.

MD
    echo "**$count crates.** By license expression:"
    echo ''

    cut -f3 "$tmp/resolved" | sort | uniq -c | sort -rn |
        while read -r n expression; do
            echo "- $n × $expression"
        done

    echo ''
    echo '---'
    echo ''

    while IFS='	' read -r name version expression dir; do
        echo "## $name $version"
        echo ''
        echo "License: **$expression**"
        echo ''

        license_files "$dir" | while read -r file; do
            echo "### $file"
            echo ''
            # A fence long enough that the text cannot close it. License texts do
            # not contain code fences, and a guard that costs one grep is cheaper
            # than the day one does.
            fence='```'
            if grep -q '^```' "$dir/$file"; then
                fence='``````'
            fi
            echo "$fence"
            cat "$dir/$file"
            echo "$fence"
            echo ''
        done
    done < "$tmp/resolved"
} > "$out"

echo "build-notices: ok — $count crates, $out"
