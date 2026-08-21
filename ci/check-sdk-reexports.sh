#!/bin/sh
# Gate: a consumer of `ciphr-sdk` never has to name `ciphr-core` in its manifest.
#
# `ciphr-sdk` is the client half of route C: an application fetching its own
# secrets at startup. Its signatures are built from `ciphr-core` types --
# `SecretPath` is an argument to every call, `Plaintext` is what a value is,
# `EnvVarName` is what `Environment` hands back, `PathError` and `EnvNameError`
# sit inside `SdkError`. A type that appears in a public signature and is not
# reachable through this crate forces a second dependency on every consumer, and
# forces that consumer to keep the two versions in step by hand. That is a
# versioning trap rather than an inconvenience, and it is invisible from inside
# the workspace: every crate here can already reach `ciphr-core`, so nothing
# fails to compile.
#
# ── What is checked ──────────────────────────────────────────────────────────
#
# Every `ciphr_core` item this crate imports is re-exported from its root, and no
# documentation example reaches for `ciphr_core` directly. The first is the API
# property; the second is the one a reader copies.
#
# Imports rather than signatures, deliberately. Parsing Rust in shell to find
# which types are public is not worth the fragility, and the over-approximation
# is nearly free: a `ciphr-core` type worth importing into this crate at all is
# almost always in its API. Where one genuinely is not, list it in
# `internal_only` below with the reason -- an explicit line somebody has to write
# is the point.
set -eu

cd "$(dirname "$0")/.."

crate='crates/ciphr-sdk'
root="$crate/src/lib.rs"

if [ ! -f "$root" ]; then
    echo "check-sdk-reexports: $root is missing -- has the layout changed?" >&2
    exit 1
fi

# Core types imported by this crate but deliberately not part of its API.
# One name per line, each with a reason.
internal_only=''

status=0

# Every `use ciphr_core::{…}` and `use ciphr_core::X;` in the crate's sources,
# flattened to one name per line. Test modules count: a type a test names is a
# type the crate exposes to something, and the exemption list is the place to say
# otherwise.
imported=$(grep -rhoE '^[[:space:]]*use ciphr_core::\{[^}]*\}|^[[:space:]]*use ciphr_core::[A-Za-z0-9_]+' \
    "$crate/src" |
    sed -E 's@^[[:space:]]*use ciphr_core::@@; s@[{};]@@g' |
    tr ',' '\n' |
    sed -E 's@^[[:space:]]*@@; s@[[:space:]]*$@@' |
    grep -E '^[A-Z][A-Za-z0-9_]*$' |
    sort -u)

# What the root actually re-exports, from every `pub use ciphr_core::…` in it.
exported=$(sed -n '/pub use ciphr_core::/,/;/p' "$root" |
    sed -E 's@pub use ciphr_core::@@; s@[{};]@@g' |
    tr ',' '\n' |
    sed -E 's@^[[:space:]]*@@; s@[[:space:]]*$@@' |
    grep -E '^[A-Z][A-Za-z0-9_]*$' |
    sort -u)

if [ -z "$imported" ]; then
    echo "check-sdk-reexports: no ciphr_core imports found -- has the crate changed shape?" >&2
    exit 1
fi

for name in $imported; do
    if echo "$exported" | grep -qx "$name"; then
        continue
    fi
    if echo "$internal_only" | grep -qx "$name"; then
        continue
    fi
    echo "check-sdk-reexports: ciphr_core::$name is used but not re-exported from $root" >&2
    status=1
done

# The example a reader copies, in a crate-level (`//!`) or item-level (`///`) doc
# comment alike. `ciphr_core::` in prose is fine -- an intra-doc link to a
# re-exported type is written as [`Plaintext`] -- so it is a `use` line inside a
# fenced block that this catches. An example that names the second crate teaches
# the dependency even when the re-export is there.
if grep -nE '^[[:space:]]*//[/!][[:space:]]*use ciphr_core' "$crate/src"/*.rs >&2; then
    echo "check-sdk-reexports: the doc examples above import ciphr_core directly" >&2
    status=1
fi

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-sdk-reexports: a consumer of ciphr-sdk would need ciphr-core too.

Add the name to the `pub use ciphr_core::{…}` block in crates/ciphr-sdk/src/lib.rs.
If the type genuinely does not appear in this crate's public API, add it to
`internal_only` in this script with the reason.

MSG
    exit 1
fi

echo "check-sdk-reexports: ok"
