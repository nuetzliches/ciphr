#!/bin/sh
# Gate: the notices in ui/THIRD-PARTY-LICENSES.md cover the viewer's closure.
#
# The Rust counterpart is `ci/check-attribution.sh` and the argument is the same:
# a dependency arrives, every other gate passes, and the image now serves code
# whose licence asks for a notice that is not in the image. Nothing looks broken,
# because nothing is broken -- it is a condition nobody checked.
#
# Reads the lockfile only, so it needs neither `npm ci` nor node_modules and can
# run beside the other static gates. Regenerating the texts needs the installed
# packages and is a developer step.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ui ]; then
    echo "check-ui-attribution: no ui/ directory yet — nothing to check"
    exit 0
fi

file=ui/THIRD-PARTY-LICENSES.md

if [ ! -f "$file" ]; then
    echo >&2 "check-ui-attribution: $file does not exist"
    echo >&2 "  run 'sh ci/generate-ui-attribution.sh' and commit the result"
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo >&2 "check-ui-attribution: node is needed to read the lockfile, and it is not on PATH"
    exit 1
fi

# The viewer image's build context is `ui/`, so a COPY there cannot reach the
# licence texts at the repository root and the package carries its own copies. A
# copy is a thing that drifts -- the copyright line is the part most likely to
# change, and a stale notice is worse than an absent one because it looks
# authoritative.
for licence in LICENSE-MIT LICENSE-APACHE; do
    if [ ! -f "ui/$licence" ]; then
        echo >&2 "check-ui-attribution: ui/$licence is missing"
        echo >&2 "  the viewer image ships its own copy: cp $licence ui/$licence"
        exit 1
    fi
    if ! cmp -s "$licence" "ui/$licence"; then
        echo >&2 "check-ui-attribution: ui/$licence has drifted from $licence"
        echo >&2 "  cp $licence ui/$licence"
        exit 1
    fi
done

node - <<'JS'
const fs = require("node:fs");

const lock = JSON.parse(fs.readFileSync("ui/package-lock.json", "utf8"));
const packages = lock.packages;

// The runtime closure, exactly as ci/generate-ui-attribution.sh computes it.
const closure = new Set();
const queue = Object.keys(packages[""].dependencies || {});
while (queue.length > 0) {
  const name = queue.shift();
  if (closure.has(name)) continue;
  closure.add(name);
  const entry = packages["node_modules/" + name];
  if (!entry) {
    console.error(`check-ui-attribution: ${name} is a dependency with no lockfile entry`);
    process.exit(1);
  }
  for (const dependency of Object.keys(entry.dependencies || {})) queue.push(dependency);
}

const shipped = new Set(
  [...closure].map((name) => `${name} ${packages["node_modules/" + name].version}`),
);

// The table rows between the two headings. Restricting to that section keeps a
// package named in the prose or inside a licence text from counting as an entry.
const lines = fs.readFileSync("ui/THIRD-PARTY-LICENSES.md", "utf8").split(/\r?\n/);
const listed = new Set();
let inTable = false;

for (const line of lines) {
  if (line === "## The packages") { inTable = true; continue; }
  if (line === "## The notices") { inTable = false; continue; }
  if (!inTable || !line.startsWith("| ")) continue;
  const field = line.split("|").map((cell) => cell.trim());
  if (field[1] === "Package" || /^-+$/.test(field[1]) || !field[1]) continue;
  listed.add(`${field[1]} ${field[2]}`);
}

if (listed.size === 0) {
  console.error("check-ui-attribution: the file lists no packages — has its shape changed?");
  process.exit(1);
}

const missing = [...shipped].filter((entry) => !listed.has(entry)).sort();
const extra = [...listed].filter((entry) => !shipped.has(entry)).sort();

if (missing.length > 0) {
  console.error("check-ui-attribution: in the viewer and carrying no notice:");
  for (const entry of missing) console.error(`  + ${entry}`);
}
if (extra.length > 0) {
  console.error("check-ui-attribution: listed but no longer in the viewer:");
  for (const entry of extra) console.error(`  - ${entry}`);
}

if (missing.length > 0 || extra.length > 0) {
  console.error(`
check-ui-attribution: ui/THIRD-PARTY-LICENSES.md no longer matches the package.

Every package here is under MIT, BSD-2-Clause, BSD-3-Clause or ISC, and each of
those requires its copyright notice to accompany a copy of the software. A bundle
served to a browser is a copy, and the image that serves it is a copy of that.

    sh ci/generate-ui-attribution.sh

Then commit the result together with the dependency change that caused it.
`);
  process.exit(1);
}

console.log(`check-ui-attribution: ok — ${listed.size} packages carry their notice`);
JS
