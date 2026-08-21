#!/bin/sh
# Gate: the CLI's copy of the surface entry list agrees with the server's.
#
# The closed list of ADR-20 entries lives in `crates/ciphr-server/src/surface.rs`,
# and `crates/ciphr-cli/src/main.rs` carries a copy. The copy is deliberate: the
# CLI does not depend on the server crate, because that crate pulls in axum,
# rustls and a tokio runtime and none of those belong in a host tool.
#
# **Why a gate rather than the move the old comment planned.** That comment said
# "if it grows, move the list into `ciphr-core` as data rather than copy it
# twice". The list grew, and the move is no longer available:
# `ci/check-core-no-features.sh` fails on any `surface::`, `mod surface` or
# `use …surface…` in `ciphr-crypto`, `ciphr-policy` or `ciphr-core`, and ADR-20
# property 1 means it in spirit as well as in regex -- the reviewed core is not
# supposed to know that entries exist. The old plan was already illegal by the
# time its trigger fired. If three rows ever earn more than a gate, the shapes
# that stay legal are a data-only crate outside the reviewed core, or one shared
# source file `include!`d by both: no dependency edge, one text, and
# `compiled_in: cfg!(feature = …)` staying in the crate that has the feature.
#
# ── What is checked ──────────────────────────────────────────────────────────
#
# Name, kind and cost text, for every entry, in both files.
#
# **Name**, because it is a contract: it appears in a deployment's configuration
# file. A name missing from the CLI's copy is an entry `ciphr surface show`
# silently leaves out of its "off" list -- and that list is the only place an
# operator can read what a deployment chose *not* to turn on, because an entry
# that is off is absent from the router and so byte-identical on the wire to a
# path that never existed.
#
# **Kind**, because it decides whether a stanza can turn the entry on at all. A
# runtime entry that is off can be switched on by editing the file; a build entry
# cannot, and needs a different artefact. A `kind` that drifts -- an entry that
# becomes a build entry upstream, or a new row typed `runtime` because the row
# above says so -- makes `surface show` print "(runtime, not named by this file)"
# for something no file can name into existence. That is exactly the distinction
# the server's report is careful to draw ("not named by this configuration, *and
# not in this binary*"), and losing it in the interface an operator reaches first
# is worse than losing it on the wire, because the host is where a configuration
# gets edited.
#
# **Cost**, with whitespace normalized, because that sentence is now a decision
# input in both implementations. `ciphr surface show` prints it for entries that
# are *off*, which is the state somebody is still deciding about. Each copy is
# pinned by a test, but each test asserts a fragment -- a half-edited sentence
# passes both. `GET /v1/surface` is the authority and cannot drift from the
# binary, but reaching it needs a running service, a token and a network hop,
# which is not the situation of somebody reading `surface show` on a host with
# the service stopped.
#
# The two files wrap the sentence differently, which is why comparing the text
# needs the normalization and not why it should be skipped.
set -eu

cd "$(dirname "$0")/.."

server='crates/ciphr-server/src/surface.rs'
cli='crates/ciphr-cli/src/main.rs'

for file in "$server" "$cli"; do
    if [ ! -f "$file" ]; then
        echo "check-surface-entries: $file is missing -- has the layout changed?" >&2
        exit 1
    fi
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# One `name<TAB>kind<TAB>cost` line per entry, from either file.
#
# Anchored on the `name:` line and reading forward, rather than grepping the file
# for each field: an unrelated `name: "…"` literal elsewhere would otherwise be
# read as an entry, and the failure would name a line that has nothing to do with
# surface. `Kind::Runtime` and `"runtime"` normalize to the same word, and a cost
# string's `\` line continuations and indentation collapse to single spaces --
# which is what the compiler does to the literal anyway.
extract() {
    awk '
        /^[[:space:]]+name:[[:space:]]*"[a-z_]+"[[:space:]]*,/ {
            name = $0
            sub(/^[^"]*"/, "", name)
            sub(/".*$/, "", name)
            kind = ""
            cost = ""
            next
        }
        name != "" && /^[[:space:]]+kind:/ {
            kind = $0
            sub(/^[[:space:]]*kind:[[:space:]]*/, "", kind)
            gsub(/[",]|Kind::/, "", kind)
            gsub(/[[:space:]]/, "", kind)
            kind = tolower(kind)
            next
        }
        name != "" && /^[[:space:]]+cost:/ {
            collecting = 1
            line = $0
            sub(/^[[:space:]]*cost:[[:space:]]*"/, "", line)
        }
        collecting {
            if (line == "") { line = $0 }
            chunk = line
            if (chunk ~ /",[[:space:]]*$/) {
                sub(/",[[:space:]]*$/, "", chunk)
                collecting = 0
            }
            cost = cost " " chunk
            line = ""
            if (collecting == 0) {
                gsub(/[[:space:]]+/, " ", cost)
                sub(/^ /, "", cost)
                sub(/ $/, "", cost)
                print name "\t" kind "\t" cost
                name = ""
            }
            next
        }
    ' "$1" |
        # A `\` at end of line inside a Rust string literal eats the newline and
        # the next line's indentation, so the value the compiler produces is
        # single spaced. No cost sentence contains a literal backslash, so
        # dropping them -- as \, to keep the shell out of it -- and squeezing
        # the spaces they leave behind reproduces that value from either file's
        # wrapping. Tabs separate the fields and `tr -s ' '` leaves them alone.
        tr -d '\134' |
        tr -s ' ' |
        sort
}

extract "$server" > "$work/server"
extract "$cli" > "$work/cli"

if [ ! -s "$work/server" ]; then
    echo "check-surface-entries: no entries found in $server -- has the list moved?" >&2
    exit 1
fi

if cmp -s "$work/server" "$work/cli"; then
    echo "check-surface-entries: ok ($(wc -l < "$work/server" | tr -d ' ') entries)"
    exit 0
fi

echo "check-surface-entries: the two entry lists disagree." >&2
echo >&2
diff -u "$work/server" "$work/cli" |
    sed "s@^---.*@--- $server@; s@^+++.*@+++ $cli@" >&2
cat >&2 <<'MSG'

Each line above is name, kind and cost sentence, tab separated, with whitespace
normalized. Fix the row in `KNOWN` in crates/ciphr-cli/src/main.rs, or in
`ENTRIES` in crates/ciphr-server/src/surface.rs -- whichever is behind.

A missing name is an entry `ciphr surface show` leaves out of its "off" list. A
wrong kind tells an operator a stanza can turn on something only a different
build can. A drifted cost sentence is a decision input that says two things.
MSG
exit 1
