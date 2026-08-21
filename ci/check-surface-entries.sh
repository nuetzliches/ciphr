#!/bin/sh
# Gate: the CLI knows every surface entry the server does.
#
# The closed list of ADR-20 entries lives in `crates/ciphr-server/src/surface.rs`,
# and `crates/ciphr-cli/src/main.rs` carries a copy. The copy is deliberate: the
# CLI does not depend on the server crate, because that crate pulls in axum,
# rustls and a tokio runtime and none of those belong in a host tool.
#
# What makes the copy worth a gate rather than a comment is what `ciphr surface
# show` does with it. It prints the entries a configuration named *and the ones it
# did not*, because an entry that is off is absent from the router and therefore
# byte-identical on the wire to a path that never existed -- so the list of names
# on this side is the only answer to "was this route never built, or merely never
# named?". An entry missing from the CLI's copy is silently missing from that list,
# which is exactly the gap this output was added to close.
#
# ── What is checked ──────────────────────────────────────────────────────────
#
# The set of entry names in both files is the same. Names only: the cost sentences
# are prose and are wrapped differently in the two files, and the artefact that
# cannot drift from the binary is `GET /v1/surface`, which serves the sentence the
# server was built with. A name is a contract -- it appears in a deployment's
# configuration file -- and a missing one is a behaviour bug.
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

# `name: "…"` inside an entry literal, in both files. The two lists are written the
# same way on purpose, so one extraction serves both.
names() {
    grep -oE '^[[:space:]]+name:[[:space:]]*"[a-z_]+"' "$1" |
        grep -oE '"[a-z_]+"' | tr -d '"' | sort -u
}

server_names=$(names "$server")
cli_names=$(names "$cli")

if [ -z "$server_names" ]; then
    echo "check-surface-entries: no entry names found in $server -- has the list moved?" >&2
    exit 1
fi

if [ "$server_names" = "$cli_names" ]; then
    echo "check-surface-entries: ok"
    exit 0
fi

echo "check-surface-entries: the two entry lists disagree." >&2
echo >&2
echo "  $server:" >&2
echo "$server_names" | sed 's/^/    /' >&2
echo "  $cli:" >&2
echo "$cli_names" | sed 's/^/    /' >&2
cat >&2 <<'MSG'

An entry the CLI does not know is one `ciphr surface show` leaves out of its "off"
list, and that list is the only place an operator can read what a configuration
chose *not* to turn on. Add the row to `KNOWN` in crates/ciphr-cli/src/main.rs,
with the same name, its kind, and its cost sentence.
MSG
exit 1
