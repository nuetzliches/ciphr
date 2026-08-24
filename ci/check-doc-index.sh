#!/bin/sh
# Gate: every document is reachable from an index, and the ADR index matches the
# ADR directory.
#
# `docs/README.md` is the page that tells a reader what exists and what each
# thing is for. That job is only done if the page is *complete*, and nothing was
# checking that it was. It is the last documentation discipline here that was
# left to habit, and -- exactly like the changelog rule before
# `check-changelog.sh` -- it is the one that eroded.
#
# ── The measurement ──────────────────────────────────────────────────────────
#
# Taken at `6feceb5`, before this gate:
#
#   * **Ten tracked documents were linked from no index at all.** All five field
#     reports, four of the six review records, and `operations/freeze.md` -- the
#     one page in the repository that describes an unimplemented procedure, which
#     is the worst possible document to leave undiscoverable.
#   * **Three sources disagreed about how many ADRs exist.** `docs/README.md`
#     said twenty-one, `docs/adr/README.md` said twenty-four, the root
#     `README.md` said 25, and the directory held 25. The index whose purpose is
#     to establish status was the least reliable of the three.
#   * **Two ADR rows described shipped work as unbuilt.** ADR-15 read "not built,
#     phase 8 still waits on the review" and ADR-20 read "nothing implemented",
#     four releases after both shipped and months after the review happened.
#
# None of that is a typo. It is what an index does when the tree moves and the
# prose does not, and no amount of care prevents it -- which is the argument for
# a script rather than a rule.
#
# ── What is checked, and what deliberately is not ────────────────────────────
#
# **Reachability, not correctness.** This asks whether a document is linked from
# an index. It cannot ask whether the sentence describing it is true. A row
# saying an ADR is unbuilt when it shipped passes this gate, and only a human
# catches it -- but a *missing* row is mechanical, and it is the one that hides a
# document completely.
#
# **One hop, from a known set of indexes.** A document linked only from another
# ordinary document is not reachable for this purpose. The point is that a reader
# who opens the index sees everything; a chain of cross-references is not an
# index.
#
# **The ADR table is one row per file, both ways.** A file with no row is a
# decision nobody can find. A row with no file is a link to nothing. Both are
# checked, because the second is what happens when a record is renamed.
#
# **Written-out counts are checked; digits are not.** `docs/README.md` says
# "twenty-one records" and the root `README.md` says "the 25 architecture
# records". Both forms are found and both must match the file count. The number
# words are spelled out to thirty, which is enough for a project that has
# twenty-five and adds a few a year, and past that the gate says so rather than
# passing quietly.
#
# **Nothing about `.claude/plans/` or the site.** The plan is a specification,
# not an index, and `site/` is a curated ordering that deliberately does not
# carry everything.
#
# ── The allowlist ────────────────────────────────────────────────────────────
#
# A document may be deliberately unindexed. The list below is how it says so,
# with a reason, per file -- the same shape as the `Changelog-Exempt:` and
# `Docs-Date-Exempt:` trailers and the `check-doc-commands.sh` allowlist, and for
# the same reason: an opt-out that costs nothing to write is not a gate.
set -eu

cd "$(dirname "$0")/.."

# The pages that count as an index. A document is indexed if one of these links
# to it.
indexes='docs/README.md docs/adr/README.md docs/operations/README.md docs/assurance/README.md'

adr_index='docs/adr/README.md'

# Documents deliberately reachable from no index. One line per file,
# `<file> # <reason>`.
allowed=$(cat <<'LIST'
LIST
)

status=0

# ── Every document is linked from an index ───────────────────────────────────
#
# The indexes themselves are excluded: an index that had to link to itself would
# be satisfying the gate rather than serving a reader. `docs/README.md` does link
# to the other three, which is checked below as an ordinary document would be.

for doc in $(find docs -name '*.md' | sort); do
    case " $indexes " in
        *" $doc "*) continue ;;
    esac

    if echo "$allowed" | grep -q "^$doc "; then
        continue
    fi

    # The link as it would be written *from* each index: a path relative to the
    # index's own directory. `docs/operations/cli.md` is `operations/cli.md` from
    # `docs/README.md` and `cli.md` from `docs/operations/README.md`, and both
    # are correct -- so the target is matched by its path suffix rather than by
    # one canonical spelling.
    found=''
    for index in $indexes; do
        [ -f "$index" ] || continue

        # The link as this index would spell it: the document's path with the
        # index's own directory removed. `docs/operations/cli.md` is
        # `operations/cli.md` from `docs/README.md` and `cli.md` from
        # `docs/operations/README.md`, and both are correct.
        #
        # Done with parameter expansion rather than `realpath --relative-to`,
        # which is GNU coreutils and would be this repository's first dependency
        # on it -- a gate that only runs on one distribution's userland is a gate
        # somebody cannot reproduce locally. Every index lives at or above the
        # documents it lists, so stripping a prefix is all that is needed; an
        # index that does not sit above a document simply does not match here,
        # and `docs/README.md` sits above all of them.
        dir="${index%/*}/"
        case "$doc" in
            "$dir"*) relative="${doc#"$dir"}" ;;
            *) continue ;;
        esac

        # Only inside a Markdown link target, so a document merely *named* in
        # prose does not count. A reader cannot click a filename.
        if grep -oE '\]\([^)]+\)' "$index" |
            tr -d ')' |
            sed 's/^](//' |
            sed 's/#.*$//' |
            grep -qxF "$relative"; then
            found='yes'
            break
        fi
    done

    if [ -z "$found" ]; then
        echo "check-doc-index: $doc is linked from no index" >&2
        status=1
    fi
done

# ── The ADR table has exactly one row per record ─────────────────────────────

for adr in $(find docs/adr -name '0*.md' | sort); do
    name=$(basename "$adr")
    if ! grep -qF "($name)" "$adr_index"; then
        echo "check-doc-index: $adr has no row in $adr_index" >&2
        status=1
    fi
done

# The other direction: a row pointing at a file that is not there. This is what a
# rename leaves behind.
for target in $(grep -oE '\]\(0[^)]+\.md\)' "$adr_index" | tr -d '()' | sed 's/^]//' | sort -u); do
    if [ ! -f "docs/adr/$target" ]; then
        echo "check-doc-index: $adr_index links to docs/adr/$target, which does not exist" >&2
        status=1
    fi
done

# ── A written-out count of the records matches the directory ─────────────────

adr_count=$(find docs/adr -name '0*.md' | wc -l | tr -d ' ')

# Only as far as thirty. Past that the gate says so rather than passing quietly,
# because a silently unchecked claim is worse than a missing check somebody knows
# about.
word_for() {
    case "$1" in
        20) echo 'twenty' ;;      21) echo 'twenty-one' ;;
        22) echo 'twenty-two' ;;  23) echo 'twenty-three' ;;
        24) echo 'twenty-four' ;; 25) echo 'twenty-five' ;;
        26) echo 'twenty-six' ;;  27) echo 'twenty-seven' ;;
        28) echo 'twenty-eight' ;; 29) echo 'twenty-nine' ;;
        30) echo 'thirty' ;;
        *)  echo '' ;;
    esac
}

expected_word=$(word_for "$adr_count")
if [ -z "$expected_word" ]; then
    echo "check-doc-index: $adr_count records is outside the range this gate spells" >&2
    echo "    extend word_for() in $0 -- an unchecked count is how the last one drifted" >&2
    status=1
else
    # Every count claim about the records, in either form, in any document that
    # makes one.
    for doc in README.md $(find docs -name '*.md' | sort); do
        # A claim is a number or number word immediately before "record" or
        # "architecture record", which is how every one of them is phrased.
        # Lower-cased before comparison: `docs/adr/README.md` opens a sentence
        # with "Twenty-four records", and a gate that missed a claim because it
        # began a sentence would be checking punctuation rather than the number.
        for claim in $(grep -oiE '[a-z0-9-]+ (architecture )?(decision )?records?' "$doc" |
                           awk '{ print tolower($1) }' | sort -u); do
            case "$claim" in
                # Not a count: "the records", "these records", "ADR records".
                [0-9]*|twenty*|thirty*) ;;
                *) continue ;;
            esac

            if [ "$claim" != "$adr_count" ] && [ "$claim" != "$expected_word" ]; then
                echo "check-doc-index: $doc says \"$claim\" records; there are $adr_count" >&2
                status=1
            fi
        done
    done
fi

if [ "$status" -ne 0 ]; then
    cat >&2 <<'MSG'

check-doc-index: an index no longer matches the tree.

An index is the page that tells a reader what exists. A document it does not
mention is one a reader has to already know about to find, and a count it gets
wrong makes the page that establishes status less reliable than listing the
directory.

Add the document to one of the indexes, or -- if it is deliberately unindexed --
to the allowlist in this script with a reason. The reason is what a later reader
needs, and it is the only thing that distinguishes a decision from an oversight.

MSG
    exit 1
fi

echo "check-doc-index: ok ($adr_count records, every document indexed)"
