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
# **Both budgets are derived rather than measured, and that is a difference worth
# stating.** The wrapper was measured -- 3,347,368 bytes on x86_64 (2026-08-20) and
# 2,888,088 on aarch64 (2026-08-24) -- and this binary is that dependency set plus
# `ciphr-export`: a renderer, a hex encoder and `serde_json`, which is already in
# the graph through `ciphr-sdk`. Each number below is the wrapper's budget for that
# target plus half a mebibyte. Note what the wrapper's two measurements say about
# guessing: the aarch64 binary is *smaller* than the amd64 one, so a single number
# for both would have been the weaker check for one of them. The first CI run per
# target prints what these actually are; replace this paragraph with those
# measurements and set the budgets from them.
set -eu

cd "$(dirname "$0")/.."

# The target this run builds, named from outside, because the budget and the
# asset name both follow from it and have to follow from the same word.
TARGET=${TARGET:-x86_64-unknown-linux-musl}
OUT=${1:-target/ci}

# Per target, not per project: an aarch64 static binary is a different size for
# reasons that have nothing to do with dependencies, so each target gets its own
# number rather than one raised to fit both. An unknown target is refused rather
# than defaulted -- a target with no budget is a gate that checks nothing while
# reporting that it ran.
case "$TARGET" in
x86_64-unknown-linux-musl)
    BUDGET=5767168 # 5.5 MiB
    ;;
aarch64-unknown-linux-musl)
    BUDGET=5242880 # 5 MiB
    ;;
*)
    echo "build-ci-binary: no size budget for $TARGET" >&2
    echo "build-ci-binary: add one to the case above rather than passing this target through" >&2
    exit 1
    ;;
esac

# **Run this on a machine of the target architecture**, for the reason
# `build-wrapper.sh` gives at the same place: `strip` and `ldd` below are the
# host's and neither reads a foreign ELF.

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "build-ci-binary: adding the $TARGET target" >&2
    rustup target add "$TARGET"
fi

cargo build --release --locked -p ciphr-ci --target "$TARGET"

built="target/$TARGET/release/ciphr-ci"
mkdir -p "$OUT"

# The name carries the target triple, for the reason `build-wrapper.sh` gives:
# an asset name is what a fetch script is written against, and a second
# architecture has to be able to arrive beside the first rather than renaming it.
# Derived from $TARGET rather than written out, so one target cannot inherit the
# other one's name -- and `action.yml` picks between them by what the runner is.
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
