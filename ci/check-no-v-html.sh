#!/bin/sh
# Gate: no `v-html` anywhere in the admin UI.
#
# The UI renders paths, identities, and audit entries that come from the server.
# `v-html` on any of them turns stored data into executed markup, in a tab that
# is allowed to reveal plaintext secrets. There is no case in a read-only viewer
# that needs it.
#
# The UI arrives in phase 5; until then this gate passes by having nothing to
# check, which is deliberate — the rule is in place before the code is.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ui ]; then
    echo "check-no-v-html: no ui/ directory yet — nothing to check"
    exit 0
fi

if grep -rnE 'v-html|innerHTML' ui \
    --include='*.vue' --include='*.ts' --include='*.js' --include='*.html' \
    --exclude-dir=node_modules --exclude-dir=dist; then
    echo >&2
    echo "check-no-v-html: raw HTML injection found in ui/ (see above). Render text, not markup." >&2
    exit 1
fi

echo "check-no-v-html: ok"
