#!/bin/sh
# Gate: the npm trees answer to the same license policy the crates do.
#
# `deny.toml` has decided since it was written which licenses may enter this
# project, and `cargo deny` fails a pull request that widens the set. That gate
# reads 133 crates and zero npm packages. The two Node trees — the viewer and the
# site highlighter — were outside every license check in the repository, which is
# how `lightningcss` arrived under **MPL-2.0**, transitively through Vite, in a
# project whose written policy names MPL first in the list of things deliberately
# absent. Nothing was violated: it is a build-time CSS transformer, MPL is
# file-level copyleft that does not reach the CSS it emits, and it is in no
# bundle. But "nothing was violated" was luck rather than a result, because
# nothing was looking.
#
# ── The allow list is not repeated here ──────────────────────────────────────
#
# It is read out of `deny.toml`. A second copy of a policy is a copy that drifts,
# and the drift is silent in exactly the direction that matters: somebody removes
# a license from deny.toml, the npm side keeps allowing it, and the repository now
# has two answers to one question. One list, two ecosystems.
#
# ── Exceptions carry their own proof ─────────────────────────────────────────
#
# An entry in EXCEPTIONS below does not simply excuse a package. It asserts the
# package is dev-only, and this script verifies that against the lockfile: if a
# package named there ever becomes a runtime dependency, the exception fails
# instead of covering it. That is the property that makes "it never reaches a
# browser" a check rather than a sentence in a comment.
#
# `ci/check-ui-budget.sh` holds the other half — the viewer's runtime
# dependencies are exactly `[vue]` and it fails if that changes — so between the
# two, a copyleft package cannot become something a user's browser executes
# without a gate saying so first.
#
# Usage:
#   sh ci/check-npm-licenses.sh ui
#   sh ci/check-npm-licenses.sh ci/site-highlight
#
# Run after `npm ci`: package-lock.json version 3 records integrity and resolved
# URLs and no license at all, so the licenses have to be read from the installed
# packages. That is why this is a step in the jobs that install rather than in
# the supply-chain job, which installs nothing.
set -eu

cd "$(dirname "$0")/.."

package_dir="${1:-}"
if [ -z "$package_dir" ]; then
    echo >&2 "check-npm-licenses: needs a package directory, e.g. \`sh ci/check-npm-licenses.sh ui\`"
    exit 1
fi

if [ ! -d "$package_dir" ]; then
    echo "check-npm-licenses: no $package_dir directory yet — nothing to check"
    exit 0
fi

if ! command -v node >/dev/null 2>&1; then
    echo >&2 "check-npm-licenses: node is needed to read the tree, and it is not on PATH"
    exit 1
fi

if [ ! -d "$package_dir/node_modules" ]; then
    echo >&2 "check-npm-licenses: $package_dir/node_modules is not there."
    echo >&2 "A lockfile records no licenses, so this reads the installed packages."
    echo >&2 "Run \`npm ci --ignore-scripts\` in $package_dir first."
    exit 1
fi

PACKAGE_DIR="$package_dir" node - <<'JS'
const fs = require("node:fs");
const path = require("node:path");

const packageDir = process.env.PACKAGE_DIR;

// ── The allow list, out of deny.toml ─────────────────────────────────────────
//
// A regex rather than a TOML parser, because pulling a dependency into a gate
// whose subject is dependencies would be its own joke. The shape it reads is the
// one deny.toml has: `allow = [` inside `[licenses]`, one quoted identifier per
// line, closed by `]`. If that shape ever changes this fails loudly instead of
// silently allowing everything, which is the only failure mode worth designing
// for here.
const denyToml = fs.readFileSync("deny.toml", "utf8");
const licensesSection = denyToml.split(/^\[licenses\]$/m)[1];
if (licensesSection === undefined) {
  process.stderr.write("check-npm-licenses: no [licenses] section in deny.toml\n");
  process.exit(1);
}
const allowBlock = /^allow\s*=\s*\[([^\]]*)\]/m.exec(licensesSection);
if (allowBlock === null) {
  process.stderr.write("check-npm-licenses: no `allow` list in deny.toml's [licenses] section\n");
  process.exit(1);
}
const allowed = [...allowBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
if (allowed.length === 0) {
  process.stderr.write("check-npm-licenses: deny.toml's allow list came back empty\n");
  process.exit(1);
}

// ── Exceptions ───────────────────────────────────────────────────────────────
//
// A name, or a name ending in `*` for a family of platform packages, with the
// expression it is allowed to carry and why. Every entry is asserted dev-only
// against the lockfile below, so none of them can quietly start shipping.
const EXCEPTIONS = [
  {
    name: "lightningcss*",
    license: "MPL-2.0",
    reason:
      "Build-time CSS transformer reached through vite/rolldown. MPL-2.0 is " +
      "file-level copyleft over lightningcss's own sources and does not reach " +
      "the CSS it emits, and nothing of it is in the bundle. Dev-only, asserted " +
      "below. It leaves on its own the day the bundler stops depending on it.",
  },
];

const matchesException = (name) =>
  EXCEPTIONS.find((exception) =>
    exception.name.endsWith("*")
      ? name.startsWith(exception.name.slice(0, -1))
      : name === exception.name,
  );

// ── SPDX, only as far as it is used ──────────────────────────────────────────
//
// `OR` means a choice, so one allowed operand is enough. `AND` means both apply,
// so all of them have to be. Anything this cannot read — `SEE LICENSE IN …`, a
// `+` suffix, an operator it does not know — is not allowed, which is the right
// default for a gate: an expression nobody can evaluate is not an expression
// anybody has approved.
const splitTopLevel = (expression, operator) => {
  const parts = [];
  let depth = 0;
  let current = "";
  const tokens = expression.split(/(\s+|\(|\))/).filter((t) => t !== "");
  for (const token of tokens) {
    if (token === "(") depth += 1;
    if (token === ")") depth -= 1;
    if (depth === 0 && token === operator) {
      parts.push(current);
      current = "";
      continue;
    }
    current += token;
  }
  parts.push(current);
  return parts.map((p) => p.trim()).filter((p) => p !== "");
};

const isAllowed = (expression) => {
  const trimmed = expression.trim();
  if (trimmed === "") return false;

  if (trimmed.startsWith("(") && trimmed.endsWith(")")) {
    // Only strip when the opening paren is the one the closing paren matches.
    let depth = 0;
    let wraps = true;
    for (let i = 0; i < trimmed.length; i += 1) {
      if (trimmed[i] === "(") depth += 1;
      if (trimmed[i] === ")") depth -= 1;
      if (depth === 0 && i < trimmed.length - 1) {
        wraps = false;
        break;
      }
    }
    if (wraps) return isAllowed(trimmed.slice(1, -1));
  }

  const alternatives = splitTopLevel(trimmed, "OR");
  if (alternatives.length > 1) return alternatives.some(isAllowed);

  const conjuncts = splitTopLevel(trimmed, "AND");
  if (conjuncts.length > 1) return conjuncts.every(isAllowed);

  return allowed.includes(trimmed);
};

// ── The installed tree ───────────────────────────────────────────────────────
//
// Walked rather than taken from the lockfile: the lockfile lists packages for
// platforms this machine never installs, and it carries no license field for the
// ones it does.
const readLicense = (pkg) => {
  if (typeof pkg.license === "string") return pkg.license;
  // The pre-2016 shapes. Rare, and still out there in the long tail.
  if (pkg.license && typeof pkg.license.type === "string") return pkg.license.type;
  if (Array.isArray(pkg.licenses)) {
    return pkg.licenses.map((l) => (typeof l === "string" ? l : l.type)).join(" OR ");
  }
  return "";
};

const installed = [];
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    const full = path.join(dir, entry.name);
    if (entry.name.startsWith("@")) {
      walk(full);
      continue;
    }
    if (entry.name === ".bin" || entry.name.startsWith(".")) continue;
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(full, "package.json"), "utf8"));
      if (pkg.name) installed.push({ name: pkg.name, version: pkg.version, license: readLicense(pkg) });
    } catch {
      // A directory under node_modules without a readable manifest is not a
      // package; npm leaves such things behind and they carry no license.
    }
    const nested = path.join(full, "node_modules");
    if (fs.existsSync(nested)) walk(nested);
  }
};
walk(path.join(packageDir, "node_modules"));

if (installed.length === 0) {
  process.stderr.write(`check-npm-licenses: no packages found under ${packageDir}/node_modules\n`);
  process.exit(1);
}

// ── The lockfile, for the dev-only assertion on exceptions ───────────────────
const lock = JSON.parse(fs.readFileSync(path.join(packageDir, "package-lock.json"), "utf8"));
const lockEntries = Object.entries(lock.packages ?? {});

const isDevOnly = (name) => {
  const entries = lockEntries.filter(
    ([p]) => p === `node_modules/${name}` || p.endsWith(`/node_modules/${name}`),
  );
  return entries.length > 0 && entries.every(([, entry]) => entry.dev === true);
};

const complaints = [];
const seen = new Map();

for (const pkg of installed) {
  const key = `${pkg.name}@${pkg.version}`;
  if (seen.has(key)) continue;
  seen.set(key, pkg.license);

  if (isAllowed(pkg.license)) continue;

  const exception = matchesException(pkg.name);
  if (exception === undefined) {
    complaints.push(
      pkg.license === ""
        ? `${key} states no license`
        : `${key} is ${pkg.license}, which deny.toml does not allow`,
    );
    continue;
  }

  if (pkg.license !== exception.license) {
    complaints.push(
      `${key} is ${pkg.license}; its exception covers ${exception.license} and nothing else`,
    );
    continue;
  }

  if (!isDevOnly(pkg.name)) {
    complaints.push(
      `${key} has an exception that asserts it is dev-only, and the lockfile says it is not. ` +
        `The exception does not apply and this package now ships under ${pkg.license}`,
    );
  }
}

if (complaints.length > 0) {
  for (const complaint of complaints) {
    process.stderr.write(`check-npm-licenses: ${complaint}\n`);
  }
  process.stderr.write(
    "\ncheck-npm-licenses: the npm tree answers to deny.toml's allow list, which is\n" +
      "permissive licenses only. Replace the package, or — if it is build tooling that\n" +
      "reaches no artefact — add it to EXCEPTIONS in this script with the reason. An\n" +
      "exception asserts the package is dev-only and is checked against the lockfile.\n" +
      "\nWidening the allow list itself is a change to deny.toml and a decision for a\n" +
      "pull request, not a way around this message.\n",
  );
  process.exit(1);
}

const expressions = new Set([...seen.values()]);
const excepted = installed.filter((p) => !isAllowed(p.license)).map((p) => p.name);
const note = excepted.length > 0 ? `, ${new Set(excepted).size} by exception` : "";
process.stdout.write(
  `check-npm-licenses: ok — ${seen.size} packages in ${packageDir}, ` +
    `${expressions.size} license expressions${note}\n`,
);
JS
