#!/bin/sh
# Build `ciphr-ci` as a static binary and hold it to a size budget.
#
# This is the artefact a workflow step downloads (ADR-25). Two properties have to
# hold, and neither is checked by `cargo build` succeeding:
#
#   * It has to be *statically* linked. A runner is whatever the job's image is:
#     a glibc runner image, an Alpine container job, a self-hosted machine
#     somebody set up years ago. A binary that needs a particular libc works on
#     the runner it was tried on and fails on the next one, which is the failure
#     that happens in somebody else's repository rather than in this one.
#
#   * It has to stay small enough that fetching it per job is uncontroversial.
#     The budget is a review trigger rather than a transfer cost: this binary
#     holds a token and renders secrets, and a jump in size means a dependency
#     arrived in it.
#
# ── Why this is not `ci/build-wrapper.sh` with an argument ────────────────────
#
# The two scripts check the same two properties for different reasons, and the
# numbers they check against are not the same number. The wrapper's budget is
# about a file mounted into images this project does not own; this one is about
# a file downloaded onto a runner beside a credential. Folding them together
# would mean one budget for both, and one budget for both is the weaker of the
# two checks applied to whichever binary is smaller -- the argument
# `build-wrapper.sh` already makes about a second architecture, applied to a
# second binary. The duplication is nineteen lines of `case` and `if`; the
# alternative is a gate that stops meaning what it says.
#
# **This budget is derived rather than measured, and that is a difference worth
# stating.** The wrapper measured 3,347,368 bytes stripped on 2026-08-20, and
# this binary is that dependency set plus `ciphr-export` -- a renderer, a hex
# encoder and `serde_json`, which is already in the graph through `ciphr-sdk`.
# The number below is the wrapper's budget plus half a mebibyte. The first CI run
# prints what it actually is; replace this paragraph with that measurement and
# its date, and set the budget from it, rather than leaving a number nobody has
# seen a binary next to.
set -eu

cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
# Per target, not per project: an aarch64 static binary is a different size for
# reasons that have nothing to do with dependencies, so a second target gets its
# own number here rather than raising this one to fit both.
BUDGET=5767168 # 5.5 MiB
OUT=${1:-target/ci}

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "build-ci-binary: adding the $TARGET target" >&2
    rustup target add "$TARGET"
fi

cargo build --release --locked -p ciphr-ci --target "$TARGET"

built="target/$TARGET/release/ciphr-ci"
mkdir -p "$OUT"

# The name carries the target triple, for the reason `build-wrapper.sh` gives:
# an asset name is what a fetch script is written against, so qualifying it
# later would mean breaking every such script or publishing a qualified binary
# beside an unqualified checksum. Derived from $TARGET rather than written out,
# so a second target cannot inherit the first one's name.
binary="$OUT/ciphr-ci-$TARGET"

# Stripped. This one runs on a machine whose logs and cores are readable by
# whoever administers the runner, which is not necessarily whoever owns the
# secrets it fetched.
strip "$built" -o "$binary"

size=$(wc -c < "$binary" | tr -d ' ')

# `ldd` on a static binary reports it as such rather than failing, so the string
# is the check. `file` is not used: its wording varies between versions.
linkage=$(ldd "$binary" 2>&1 || true)
case "$linkage" in
*"statically linked"* | *"not a dynamic executable"*) ;;
*)
    echo "build-ci-binary: $binary is not statically linked:" >&2
    echo "$linkage" >&2
    exit 1
    ;;
esac

if [ "$size" -gt "$BUDGET" ]; then
    echo "build-ci-binary: $binary is $size bytes, over the budget of $BUDGET" >&2
    echo "build-ci-binary: a jump this size is a new dependency; decide on it rather than raising the number" >&2
    exit 1
fi

# The checksum belongs next to the binary: a workflow that fetches one file has
# no other way to know it got the right one, and `action.yml` verifies it.
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && sha256sum "ciphr-ci-$TARGET" > "ciphr-ci-$TARGET.sha256")
fi

echo "build-ci-binary: ok -- $size bytes, statically linked, budget $BUDGET"
