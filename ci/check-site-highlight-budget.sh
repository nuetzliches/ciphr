#!/bin/sh
# Gate: the site highlighter's dependency budget.
#
# This is `check-ui-budget.sh` applied to the second npm tree in the repository,
# for the reason that file gives: a build toolchain runs with the network and the
# filesystem of the build, so an unpoliced tree here would quietly undercut the
# supply-chain discipline the Rust side spends real effort on (plan section 19).
# A tool that colours seven code blocks does not get to arrive with a hundred
# packages, and it does not get to arrive unwatched because it is "only dev".
#
# Three rules, and one of them is stricter than the viewer's:
#
#   1. **No runtime dependency at all.** Nothing in this package is served to a
#      browser or shipped in an image. `shiki` is a devDependency and the output
#      is static markup; a `dependencies` entry appearing here means somebody has
#      changed what this package is.
#   2. A ceiling on the whole tree. 46 today, almost all of it Shiki's grammar
#      engine and the hast chain its renderer pulls in — a renderer this tool does
#      not use and cannot avoid installing.
#   3. No install scripts, and every package resolved from the public registry
#      with an integrity hash.
#
# Raising the ceiling is a deliberate commit that says why in its message.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ci/site-highlight ]; then
    echo "check-site-highlight-budget: no ci/site-highlight — nothing to check"
    exit 0
fi

if ! command -v node >/dev/null 2>&1; then
    echo >&2 "check-site-highlight-budget: node is needed to read the lockfile, and it is not on PATH"
    exit 1
fi

node - <<'JS'
const fs = require("node:fs");

// 46 today. The headroom is for a patch bump that pulls a transitive package,
// not for a second library.
const TOTAL_LIMIT = 60;
const REGISTRY = "https://registry.npmjs.org/";

const complaints = [];
const lock = JSON.parse(fs.readFileSync("ci/site-highlight/package-lock.json", "utf8"));

if (lock.lockfileVersion < 3) {
  complaints.push(
    `lockfileVersion is ${lock.lockfileVersion}; version 3 or newer is what carries integrity hashes for the whole tree`,
  );
}

const packages = lock.packages ?? {};
const root = packages[""] ?? {};

const runtime = Object.keys(root.dependencies ?? {});
if (runtime.length > 0) {
  complaints.push(
    `this package has runtime dependencies [${runtime.join(", ")}]; it produces static markup and ships nothing, so the budget allows none`,
  );
}

const total = Object.keys(packages).length;
if (total > TOTAL_LIMIT) {
  complaints.push(
    `${total} packages in the tree, and the budget is ${TOTAL_LIMIT}. Raising it is a deliberate commit that says why`,
  );
}

for (const [name, entry] of Object.entries(packages)) {
  if (name === "") {
    continue;
  }
  if (entry.hasInstallScript === true) {
    complaints.push(`${name} runs an install script`);
  }
  if (entry.link === true || entry.optional === true) {
    continue;
  }
  if (typeof entry.resolved !== "string" || !entry.resolved.startsWith(REGISTRY)) {
    complaints.push(`${name} is not resolved from ${REGISTRY}: ${entry.resolved ?? "no URL"}`);
  }
  if (typeof entry.integrity !== "string" || entry.integrity === "") {
    complaints.push(`${name} has no integrity hash`);
  }
}

if (complaints.length > 0) {
  for (const complaint of complaints) {
    process.stderr.write(`check-site-highlight-budget: ${complaint}\n`);
  }
  process.exit(1);
}

process.stdout.write(
  `check-site-highlight-budget: ok — ${total} packages, no runtime dependency\n`,
);
JS
