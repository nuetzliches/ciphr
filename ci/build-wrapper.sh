#!/bin/sh
# Build `ciphr-run` as a static binary and hold it to a size budget.
#
# This is the artefact route B mounts (ADR-14): one file, bind-mounted into an
# image this project does not own, with `entrypoint:` overridden. Two properties
# have to hold for that to work at all, and neither is checked by `cargo build`
# succeeding:
#
#   * It has to be *statically* linked. Bind-mounting a binary into a foreign
#     image only works if it needs nothing from that image -- no libc, no
#     loader. `ldd` saying "statically linked" is the check; the musl target
#     gives it, and this script verifies rather than assumes.
#
#   * It has to stay small enough that mounting it is uncontroversial. The
#     budget is not a performance concern. It is a review trigger: a binary that
#     doubles has acquired a dependency, and this is where that gets noticed
#     instead of during a deploy.
#
# Each budget is set at roughly 1.5x a measurement, so ordinary growth passes and
# a new dependency of any size does not. The measurements are in the `case`
# below, beside the number they produced.
set -eu

cd "$(dirname "$0")/.."

# The target this run builds. One per invocation, and named from outside, because
# the two things that follow from it -- the budget and the asset name -- have to
# follow from the same word.
TARGET=${TARGET:-x86_64-unknown-linux-musl}
OUT=${1:-target/wrapper}

# The budget is per target, not per project. An aarch64 static binary is a
# different size for reasons that have nothing to do with dependencies, so each
# target gets its own number rather than one raised to fit both -- raising it to
# whichever is larger quietly weakens the check for the smaller one, which is the
# check this exists to be.
#
# An unknown target is refused rather than given a default. A target with no
# budget is a gate that checks nothing while reporting that it ran.
case "$TARGET" in
x86_64-unknown-linux-musl)
    # Measured 2026-08-20 with the pinned toolchain: 3,347,368 bytes stripped.
    BUDGET=5242880 # 5 MiB
    ;;
aarch64-unknown-linux-musl)
    # Measured 2026-08-24 with the pinned toolchain: 2,888,088 bytes stripped --
    # *smaller* than x86_64, which is the reason this is a `case` and not one
    # number raised to fit both. A budget of 6 MiB, picked to be safely above the
    # amd64 measurement, would have let this binary grow by more than half again
    # before anything noticed.
    #
    # Built in an emulated arm64 container rather than on an arm64 machine. That
    # affects how long it took and not what came out: same toolchain version, same
    # target, same locked dependency graph. The first CI run on a native runner
    # prints the number this budget should be checked against.
    BUDGET=4718592 # 4.5 MiB
    ;;
*)
    echo "build-wrapper: no size budget for $TARGET" >&2
    echo "build-wrapper: add one to the case above rather than passing this target through" >&2
    exit 1
    ;;
esac

# **Run this on a machine of the target architecture.** `strip` and `ldd` below
# are the host's, and neither reads a foreign ELF: a cross-build would fail at
# the strip or, worse, report a linkage it did not look at. `ci.yml` runs one
# matrix leg per architecture on a native runner for this reason, which is also
# what lets the tests run *as* static binaries rather than merely be built.

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "build-wrapper: adding the $TARGET target" >&2
    rustup target add "$TARGET"
fi

cargo build --release --locked -p ciphr-run --target "$TARGET"

built="target/$TARGET/release/ciphr-run"
mkdir -p "$OUT"

# The name carries the target triple, which is what makes a second architecture
# an addition rather than a rename. It was qualified on 2026-08-21 while amd64
# was still the only one, precisely so that today's arm64 asset could arrive
# beside it instead of forcing a choice between breaking every fetch script
# written against the documented name and shipping a qualified binary next to an
# unqualified checksum (issue #4). Derived from $TARGET rather than written out,
# so one target cannot inherit the other one's name.
binary="$OUT/ciphr-run-$TARGET"

# Stripped, because this is the file a deployment mounts and the symbols buy a
# reader of a core dump nothing that the debug build does not.
strip "$built" -o "$binary"

size=$(wc -c < "$binary" | tr -d ' ')

# `ldd` on a static binary reports it as such rather than failing, so the string
# is the check. `file` is not used: its wording varies between versions.
linkage=$(ldd "$binary" 2>&1 || true)
case "$linkage" in
*"statically linked"* | *"not a dynamic executable"*) ;;
*)
    echo "build-wrapper: $binary is not statically linked:" >&2
    echo "$linkage" >&2
    exit 1
    ;;
esac

if [ "$size" -gt "$BUDGET" ]; then
    echo "build-wrapper: $binary is $size bytes, over the budget of $BUDGET" >&2
    echo "build-wrapper: a jump this size is a new dependency; decide on it rather than raising the number" >&2
    exit 1
fi

# The checksum belongs next to the binary, because a deployment that fetches one
# file has no other way to know it got the right one.
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && sha256sum "ciphr-run-$TARGET" > "ciphr-run-$TARGET.sha256")
fi

echo "build-wrapper: ok -- $size bytes, statically linked, budget $BUDGET"
