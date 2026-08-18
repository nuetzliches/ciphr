#!/bin/sh
# Gate: every crate root carries `#![forbid(unsafe_code)]`.
#
# Workspace-level lint configuration would be easier to bypass and easier to
# lose in a merge. The attribute sits in the source of every crate so that
# reading the first line of any crate root tells you the guarantee holds. An
# exception would need a written justification and review; none is anticipated.
set -eu

cd "$(dirname "$0")/.."

status=0
for root in crates/*/src/lib.rs crates/*/src/main.rs; do
    [ -e "$root" ] || continue
    if ! grep -q '^#!\[forbid(unsafe_code)\]$' "$root"; then
        echo "check-forbid-unsafe: missing #![forbid(unsafe_code)] in $root" >&2
        status=1
    fi
done

[ "$status" -eq 0 ] && echo "check-forbid-unsafe: ok"
exit "$status"
