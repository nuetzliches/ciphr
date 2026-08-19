#!/bin/sh
# Gate: the viewer's dependency budget, separate from the Rust one.
#
# Plan section 15 requires this package to carry its own budget, because frontend
# dependency sprawl would otherwise quietly undercut the supply-chain discipline
# the Rust side spends real effort on (section 19). A viewer that renders five
# tables does not need a hundred packages to do it.
#
# Four things are checked, and each one is a rule rather than a number pulled from
# the air:
#
#   1. Exactly one runtime dependency: vue. Anything the page ships to a browser
#      is code running in a tab that may hold a plaintext secret.
#   2. A ceiling on the whole tree, dev tooling included. The build toolchain runs
#      with the network and the filesystem of the build.
#   3. No install scripts. An install script is arbitrary code from a dependency,
#      run before anyone has looked at it. The one allowed entry is fsevents,
#      which is macOS-only, optional, and never installed in CI or in the image.
#   4. Every package resolved from the public npm registry with an integrity hash.
#      A git URL or a private registry in a lockfile is a dependency nobody can
#      audit from the repository.
#
# Raising the ceiling is a deliberate commit that says why in its message, the
# same rule the pinned tool versions in ci/install-supply-chain-tools.sh follow.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ui ]; then
    echo "check-ui-budget: no ui/ directory yet — nothing to check"
    exit 0
fi

if ! command -v node >/dev/null 2>&1; then
    echo >&2 "check-ui-budget: node is needed to read the lockfile, and it is not on PATH"
    exit 1
fi

node - <<'JS'
const fs = require("node:fs");

// The ceiling on the whole tree, root package included. 70 today; the headroom is
// for a patch bump that pulls one transitive package, not for a new library.
const TOTAL_LIMIT = 90;
const RUNTIME_DEPENDENCIES = ["vue"];
const INSTALL_SCRIPTS_ALLOWED = ["node_modules/fsevents"];
const REGISTRY = "https://registry.npmjs.org/";

const complaints = [];
const lock = JSON.parse(fs.readFileSync("ui/package-lock.json", "utf8"));

if (lock.lockfileVersion < 3) {
  complaints.push(
    `lockfileVersion is ${lock.lockfileVersion}; version 3 or newer is what carries integrity hashes for the whole tree`,
  );
}

const packages = lock.packages ?? {};
const root = packages[""] ?? {};

const runtime = Object.keys(root.dependencies ?? {}).sort();
const expected = [...RUNTIME_DEPENDENCIES].sort();
if (runtime.join(",") !== expected.join(",")) {
  complaints.push(
    `runtime dependencies are [${runtime.join(", ")}]; the budget allows exactly [${expected.join(", ")}]`,
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
  if (entry.hasInstallScript === true && !INSTALL_SCRIPTS_ALLOWED.includes(name)) {
    complaints.push(`${name} runs an install script`);
  }
  // Optional platform packages for other systems carry no resolved URL on some
  // npm versions; they are never installed here, so they are not the concern.
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
    process.stderr.write(`check-ui-budget: ${complaint}\n`);
  }
  process.exit(1);
}

process.stdout.write(`check-ui-budget: ok — ${total} packages, runtime: ${runtime.join(", ")}\n`);
JS
