#!/bin/sh
# Generate THIRD-PARTY-LICENSES.md: the notices the published artefacts owe.
#
# ── Why this file has to exist ───────────────────────────────────────────────
# Almost every dependency in this tree is under MIT, BSD-2-Clause, BSD-3-Clause,
# ISC or Unicode-3.0, and every one of those licences requires its copyright
# notice and permission text to travel with a *copy* of the software. A compiled
# binary is a copy, and so is a container image that contains one. Apache-2.0
# §4 says the same for its own text. `deny.toml` decides which licences may enter
# the tree; nothing decided that their conditions were met on the way out, and
# until this file existed the answer was that they were not: the images and the
# release binaries carried two OCI labels naming a licence and not one line of
# anybody's notice.
#
# A label is not a notice. It names a licence to a registry; it does not give the
# person who pulled the image the text the licence says they must receive.
#
# ── What "shipped" means here ────────────────────────────────────────────────
# The crate list is the union over the four triples this project actually
# publishes an artefact for, with `--edges normal,build` and dev-dependencies
# excluded: a test-only crate is never in anything a deployment receives, and
# listing it would claim an obligation that does not exist.
#
# `x86_64-pc-windows-msvc` is deliberately absent even though `deny.toml` lists
# it under `[graph] targets`. That entry is there so the supply-chain gate covers
# what developers build on. No Windows artefact is published, so no Windows
# notice is owed.
#
# ── Why the texts are deduplicated ──────────────────────────────────────────
# Most crates ship the same 202-line Apache-2.0 text. Emitting it once per crate
# would produce a file of some 27,000 lines that nobody would ever read, and a
# notice nobody reads is the failure this is meant to fix rather than a stricter
# form of compliance. Each distinct text therefore appears once, followed by
# every crate that ships it. The copyright lines differ between crates and are
# part of the text, so two crates share a block only when their notice is
# byte-identical.
#
# ── Why a crate with no text of its own is an error ─────────────────────────
# 131 of 131 shipped crates carry their own licence file, so the fallback that
# would otherwise be needed here -- a canonical text per SPDX identifier, chosen
# by this script on the crate's behalf -- does not exist, and is not written
# speculatively. If that ever stops being true the run fails and names the crate,
# because deciding which text stands in for a missing one is a judgement about
# somebody else's licence and belongs in a commit, not in a default.
#
# Regenerate after any dependency change:
#
#     sh ci/generate-attribution.sh
#
# `ci/check-attribution.sh` is the blocking gate that fails if this was not done.
# It needs no unpacked sources and so runs anywhere; this script needs them, and
# therefore needs a `cargo build` or `cargo fetch` to have happened first.
set -eu

cd "$(dirname "$0")/.."

out="${1:-THIRD-PARTY-LICENSES.md}"

for tool in cargo sha256sum find sort; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo >&2 "generate-attribution: $tool is needed and is not on PATH"
        exit 1
    fi
done

src_root="${CARGO_HOME:-$HOME/.cargo}/registry/src"
if [ ! -d "$src_root" ]; then
    echo >&2 "generate-attribution: no unpacked registry at $src_root"
    echo >&2 "  run 'cargo build --locked' first -- this script reads the crates' own licence files"
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# What ships, from the one place that decides it. `ci/check-attribution.sh` reads
# the same script, which is why the two cannot disagree about the crate set.
sh ci/shipped-crates.sh > "$tmp/crates"

count="$(wc -l < "$tmp/crates" | tr -d ' ')"
if [ "$count" -eq 0 ]; then
    echo >&2 "generate-attribution: no third-party crates found -- has the workspace changed shape?"
    exit 1
fi

mkdir -p "$tmp/texts" "$tmp/covers"
: > "$tmp/table"
: > "$tmp/textless"

while read -r name version; do
    # The registry unpacks into one directory per index, so the crate is under a
    # path this cannot name exactly. A glob rather than `ls`, for the reason
    # `ci/shipped-crates.sh` gives.
    dir=''
    for candidate in "$src_root"/*/"$name-$version"; do
        if [ -d "$candidate" ]; then
            dir="$candidate"
            break
        fi
    done

    if [ -z "$dir" ]; then
        echo >&2 "generate-attribution: no unpacked source for $name $version"
        echo >&2 "  run 'cargo build --locked' so the crate is unpacked, then try again"
        exit 1
    fi

    # The declared expression, for the index. `license-file` must not match, so
    # the pattern requires the `=` to follow the word.
    expression="$(
        awk '/^license[[:space:]]*=/ {
                sub(/^license[[:space:]]*=[[:space:]]*/, "")
                gsub(/"/, "")
                print
                exit
            }' "$dir/Cargo.toml"
    )"
    [ -n "$expression" ] || expression='(declared in a licence file rather than an expression)'

    printf '| %s | %s | %s |\n' "$name" "$version" "$expression" >> "$tmp/table"

    files="$(
        find "$dir" -maxdepth 1 -type f \
            \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) |
            sort
    )"

    if [ -z "$files" ]; then
        printf '%s %s (%s)\n' "$name" "$version" "$expression" >> "$tmp/textless"
        continue
    fi

    for file in $files; do
        # Carriage returns come off before anything else. Some crates ship CRLF
        # licence files, and `.gitattributes` normalises this repository to LF --
        # so without this the file is rewritten on every regeneration under
        # Windows and shows as modified when nothing changed. It also groups two
        # texts that differ only in line ending, which are the same notice.
        tr -d '\r' < "$file" > "$tmp/text"

        # Short hash: enough to group identical texts, and it never reaches the
        # output, so a collision would have to be engineered rather than met.
        hash="$(sha256sum "$tmp/text" | cut -c1-16)"
        [ -f "$tmp/texts/$hash" ] || cp "$tmp/text" "$tmp/texts/$hash"
        printf '%s %s (%s)\n' "$name" "$version" "$(basename "$file")" >> "$tmp/covers/$hash"
    done
done < "$tmp/crates"

if [ -s "$tmp/textless" ]; then
    cat >&2 <<'MSG'
generate-attribution: a shipped crate carries no licence text of its own.

Every crate below is distributed inside an artefact of this project and ships no
LICENSE, LICENCE, COPYING or NOTICE file, so this script has no notice to pass
on. It will not choose a canonical text on the crate's behalf: which text stands
in for a missing one is a reading of somebody else's licence and belongs in a
commit with a reason.

Either take the notice from the crate's repository and add it to this script as a
recorded exception, or drop the dependency.

MSG
    sed 's/^/  /' "$tmp/textless" >&2
    exit 1
fi

# `sed` rather than `find -printf`, which is a GNU extension.
texts="$(find "$tmp/texts" -maxdepth 1 -type f | sed 's|.*/||' | sort)"
text_count="$(printf '%s\n' "$texts" | grep -c . || true)"

{
    cat <<MSG
# Third-party licences

The notices that travel with every published artefact. **Generated — do not edit
by hand:** run \`sh ci/generate-attribution.sh\` and commit the result.
\`ci/check-attribution.sh\` fails the build if the two disagree.

This covers the $count third-party crates linked into the binaries this project
publishes: the union over \`x86_64\`/\`aarch64\` \`linux-gnu\` (the server image)
and \`linux-musl\` (\`ciphr-run\` and \`ciphr-ci\`), following normal and build
dependencies only. Test-only dependencies are excluded because no artefact
contains them, and \`x86_64-pc-windows-msvc\` — which \`deny.toml\` does cover —
is excluded because no Windows artefact is published.

ciphr's own code is not listed here. It is under \`MIT OR Apache-2.0\`; see
[\`LICENSE-MIT\`](LICENSE-MIT) and [\`LICENSE-APACHE\`](LICENSE-APACHE), which ship
beside this file in every image and beside every release binary.

The viewer's own dependencies are a separate package and a separate artefact:
see [\`ui/THIRD-PARTY-LICENSES.md\`](ui/THIRD-PARTY-LICENSES.md).

## The crates

| Crate | Version | Licence |
|---|---|---|
MSG
    sort "$tmp/table"

    cat <<MSG

## The notices

$text_count distinct texts. Each appears once and is followed by every crate that
ships it; a crate appears under more than one when it ships more than one, which
is what a dual-licensed crate does.
MSG

    for hash in $texts; do
        covered="$(sort "$tmp/covers/$hash")"
        n="$(printf '%s\n' "$covered" | grep -c . || true)"
        names="$(
            printf '%s\n' "$covered" |
                sed 's/.*(\(.*\))/\1/' | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g'
        )"

        if [ "$n" -eq 1 ]; then noun=crate; else noun=crates; fi
        printf '\n### Shipped by %s %s as %s\n\n' "$n" "$noun" "$names"
        printf 'Covers:\n\n'
        printf '%s\n' "$covered" | sed 's/^/- /'
        printf '\n````text\n'
        cat "$tmp/texts/$hash"
        printf '\n````\n'
    done
} > "$out"

echo "generate-attribution: $out written -- $count crates, $text_count distinct notices"
