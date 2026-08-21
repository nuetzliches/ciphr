#!/bin/sh
# Gate: the reviewed core declares no Cargo features and reaches no optional surface.
#
# ADR-20 property 1: nothing optional is reachable from `ciphr-crypto`,
# `ciphr-policy`, or the path, pattern and secret code in `ciphr-core`. The reason
# is the external review. Three crates, about 1500 lines, read end to end -- and if
# optionality reaches them, "the reviewer read the code that decides every access"
# becomes "the reviewer read it in one configuration". A review that has to be
# repeated per configuration is a promise to do one later.
#
# ADR-20 says the gate arrives with the first entry and not before, because a gate
# with nothing to catch is a gate nobody trusts. `honeypot_alert` is that entry,
# so this exists now.
#
# ── What is checked ──────────────────────────────────────────────────────────
#
# Three claims, each with its own message, because they fail for different
# reasons and the fix differs:
#
#   1. No `[features]` table in the crate's own manifest.
#   2. No `cfg(feature = ...)` in its sources.
#   3. No code reference to a surface module.
#
# And one from the other side: the workspace dependency entries for these crates
# must not hand them features either. A crate that declares none can still be
# built with some if a dependent asks, and the claim is about what the reviewer
# read rather than about where the request came from.
#
# ── What deliberately is not checked ─────────────────────────────────────────
#
# **Prose.** All three crates discuss attack surface in their doc comments, and
# they should. Comment lines are stripped before the third check, so a gate that
# reads "new surface here needs its own pass" as a code reference does not exist.
# The cost is that a `surface::` call hidden after `//` on the same line as code
# is missed; that is not a way anybody writes Rust, and the alternative is a gate
# that fires on the sentences most worth writing.
#
# **Whether the core is small.** Size is the review's business and cannot be a
# number here. This checks the one property that makes a size claim mean
# anything: that the code the number covers is the code every build runs.
set -eu

cd "$(dirname "$0")/.."

# Explicit rather than derived, the same way `check-no-print.sh` lists its
# exemptions: adding a crate to the reviewed core should be a visible edit here,
# not a side effect of where somebody put a directory.
core='ciphr-crypto ciphr-policy ciphr-core'

status=0

for crate in $core; do
    manifest="crates/$crate/Cargo.toml"

    if [ ! -f "$manifest" ]; then
        echo "check-core-no-features: $manifest is missing -- has the layout changed?" >&2
        status=1
        continue
    fi

    if grep -qE '^\[features\]' "$manifest"; then
        echo "check-core-no-features: $manifest declares [features]" >&2
        status=1
    fi

    sources=$(find "crates/$crate/src" -name '*.rs')
    if [ -z "$sources" ]; then
        echo "check-core-no-features: no sources under crates/$crate/src" >&2
        status=1
        continue
    fi

    # shellcheck disable=SC2086
    if grep -nE 'cfg\([[:space:]]*(not\([[:space:]]*)?feature[[:space:]]*=' $sources >&2; then
        echo "check-core-no-features: the lines above gate core code on a feature" >&2
        status=1
    fi

    # Comment lines are dropped first; see the header for why. `mod surface`,
    # `use …surface…` and `surface::` are the three ways a module gets reached.
    # shellcheck disable=SC2086
    if sed -E 's@^[[:space:]]*//.*$@@' $sources |
        grep -nE '(^|[^[:alnum:]_])(mod|use)[[:space:]]+[A-Za-z0-9_:]*surface|surface::' >&2; then
        echo "check-core-no-features: the lines above reference a surface module" >&2
        status=1
    fi
done

# The other side of claim 1. A `features = [...]` on one of these in
# `[workspace.dependencies]` would enable something the crate does not declare
# today but might tomorrow, and the dependent asking for it is not the thing that
# makes the claim false.
for crate in $core; do
    if grep -E "^$crate[[:space:]]*=" Cargo.toml | grep -q 'features'; then
        echo "check-core-no-features: Cargo.toml gives $crate features in [workspace.dependencies]" >&2
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-core-no-features: optionality reached the reviewed core.

ADR-20 property 1: `ciphr-crypto`, `ciphr-policy` and the path, pattern and secret
code in `ciphr-core` know nothing about any surface entry -- no flag, no
`cfg(feature)`, no trait object one configuration installs.

Where an optional feature needs something from the core, the core gains it
**unconditionally**: a general function, present in every build, reviewed once,
with the optional part composed on top of it in `ciphr-server`, `ciphr-store` or
`ciphr-cli`. ADR-16's blind index is the worked example.

MSG
    exit 1
fi

echo "check-core-no-features: ok"
