#!/bin/sh
# Gate: no direct process output from library crates.
#
# A library that prints has no idea what it is printing into. In this project the
# next step from there is a secret in a log file, which is the leak class the
# whole design is built to prevent. Library crates return values and errors; the
# binaries decide what a human gets to see.
#
# The same rule is enforced at compile time by `#![deny(clippy::print_stdout,
# clippy::print_stderr, clippy::dbg_macro)]` in every library crate root. This
# gate exists because a new crate can forget the attribute, and because `dbg!`
# left in a commit should fail the build regardless of lint configuration.
set -eu

cd "$(dirname "$0")/.."

# Binary crates are exempt: producing output is their job. The list is explicit
# rather than derived from Cargo.toml, so that adding a crate that prints is a
# visible edit to this gate instead of a side effect of how it was declared.
#
# `ciphr-run` is the whole of a binary crate, not a `main.rs` beside a library,
# which is why the exemption covers its directory. What it prints is its own
# error message and, with `--report`, variable *names* — never a value. The
# compile-time half of the rule still applies to everything it depends on:
# `ciphr-sdk` and `ciphr-core` carry the lint attribute.
libs=$(find crates -name '*.rs' -path '*/src/*' \
    ! -path 'crates/ciphr-cli/*' \
    ! -path 'crates/ciphr-run/*' \
    ! -path 'crates/ciphr-server/src/main.rs')

if [ -z "$libs" ]; then
    echo "check-no-print: no library sources found — is the layout still crates/*/src?" >&2
    exit 1
fi

# shellcheck disable=SC2086
if grep -nE '\b(print|println|eprint|eprintln|dbg)!' $libs; then
    cat >&2 <<'MSG'

check-no-print: direct output found in a library crate (see the lines above).

Return the value or an error instead. If a binary needs to show something, it
belongs in crates/ciphr-cli, crates/ciphr-run, or crates/ciphr-server/src/main.rs.
MSG
    exit 1
fi

echo "check-no-print: ok"
