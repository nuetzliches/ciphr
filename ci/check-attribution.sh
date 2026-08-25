#!/bin/sh
# Gate: the notices in THIRD-PARTY-LICENSES.md cover exactly what ships.
#
# The failure this exists for is silent and legal rather than technical. A
# dependency is added, every other gate passes, the release goes out -- and the
# images and binaries now contain code whose licence requires its notice to
# travel with them, with no notice in the artefact. Nothing about the build looks
# wrong, because nothing about the build is wrong.
#
# So the rule is the cheap half of the work: the crate set in the committed file
# must equal the crate set that is actually shipped. `ci/shipped-crates.sh`
# answers the second half and the generator reads the same script, so this
# compares two views of one list rather than two lists.
#
# ── Why this does not regenerate and diff ────────────────────────────────────
# Regenerating needs every shipped crate unpacked in the registry, including the
# ones that only a musl or an aarch64 resolution pulls in, and a `cargo build` on
# one host does not unpack those. A gate that needs a full cross-target fetch to
# say yes is a gate that gets skipped. Reading the crate set needs `Cargo.lock`
# and the index and nothing else.
#
# What that leaves uncovered is a crate changing its licence text within one
# published version, which crates.io does not permit: a version is immutable once
# published. The version is in the table, so any change to a crate's terms
# arrives as a version bump and this gate sees it.
set -eu

cd "$(dirname "$0")/.."

file=THIRD-PARTY-LICENSES.md

if [ ! -f "$file" ]; then
    echo >&2 "check-attribution: $file does not exist"
    echo >&2 "  run 'sh ci/generate-attribution.sh' and commit the result"
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

sh ci/shipped-crates.sh > "$tmp/shipped"

# The table rows between the two headings, as "name version". Restricting to the
# section keeps a crate named in the prose or inside a licence text from counting
# as an entry.
awk '
    /^## The crates$/  { in_table = 1; next }
    /^## The notices$/ { in_table = 0 }
    in_table && /^\| / {
        # | name | version | expression |
        split($0, field, /[[:space:]]*\|[[:space:]]*/)
        if (field[2] == "Crate" || field[2] ~ /^-+$/ || field[2] == "") next
        print field[2] " " field[3]
    }
' "$file" | sort -u > "$tmp/listed"

if [ ! -s "$tmp/listed" ]; then
    echo >&2 "check-attribution: $file lists no crates -- has its shape changed?"
    exit 1
fi

status=0

missing="$(comm -23 "$tmp/shipped" "$tmp/listed")"
extra="$(comm -13 "$tmp/shipped" "$tmp/listed")"

if [ -n "$missing" ]; then
    echo >&2 "check-attribution: shipped and carrying no notice:"
    printf '%s\n' "$missing" | sed 's/^/  + /' >&2
    status=1
fi

if [ -n "$extra" ]; then
    echo >&2 "check-attribution: listed but no longer shipped:"
    printf '%s\n' "$extra" | sed 's/^/  - /' >&2
    status=1
fi

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-attribution: THIRD-PARTY-LICENSES.md no longer matches what is published.

Almost every dependency here is under MIT, BSD or ISC, and each of those requires
its copyright notice to travel with a copy of the software. A binary is a copy and
so is an image containing one, so a crate in the artefact and not in that file is
a condition this project has not met -- and an OCI label naming the licence is not
the notice the licence asks for.

    sh ci/generate-attribution.sh

Then commit the result together with the dependency change that caused it.

MSG
    exit 1
fi

echo "check-attribution: ok -- $(wc -l < "$tmp/listed" | tr -d ' ') crates carry their notice"
