#!/bin/sh
# Generate ui/THIRD-PARTY-LICENSES.md: the notices the viewer image owes.
#
# The Rust side of this is `ci/generate-attribution.sh`, and the reason there
# applies here without change: MIT, BSD-2-Clause, BSD-3-Clause and ISC each
# require their copyright notice to accompany a copy of the software, a bundle
# served to a browser is a copy, and the viewer image is a copy of that. What
# differs is only where the packages live.
#
# ── Why the whole runtime closure, not the bundle ────────────────────────────
# Vite tree-shakes, so the served bundle contains less than the runtime
# dependency closure -- `@vue/compiler-sfc` is resolved at build time and is not
# in the page. Working out exactly which modules survived would mean reading
# Vite's module graph, and being wrong in that direction means a missing notice.
# The closure over-attributes instead: naming a package whose code did not make it
# into the bundle costs a paragraph, and naming one fewer than shipped costs
# compliance. `--omit=dev` is still applied, because the build toolchain is not in
# the artefact at all.
#
# Regenerate after any dependency change:
#
#     sh ci/generate-ui-attribution.sh
#
# Needs `npm ci` to have run in ui/, because it reads each package's own licence
# file. `ci/check-ui-attribution.sh` is the blocking gate and needs only the
# lockfile.
set -eu

cd "$(dirname "$0")/.."

if [ ! -d ui ]; then
    echo "generate-ui-attribution: no ui/ directory yet — nothing to do"
    exit 0
fi

if ! command -v node >/dev/null 2>&1; then
    echo >&2 "generate-ui-attribution: node is needed and is not on PATH"
    exit 1
fi

if [ ! -d ui/node_modules ]; then
    echo >&2 "generate-ui-attribution: ui/node_modules is missing"
    echo >&2 "  run 'npm ci --ignore-scripts' in ui/ first -- this reads the packages' licence files"
    exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM

# Into a temporary file and moved on success. Writing straight to the destination
# leaves it truncated when the run below refuses -- and the run refuses precisely
# when a notice is missing, which is the worst moment to also have destroyed the
# last good copy.
node - <<'JS' > "$tmp"
const fs = require("node:fs");
const path = require("node:path");

const lock = JSON.parse(fs.readFileSync("ui/package-lock.json", "utf8"));
const packages = lock.packages;

// The runtime closure, from the root's own dependencies outward. Dev
// dependencies are never entered, so the build toolchain cannot reach this list
// through one of them either.
const closure = new Set();
const queue = Object.keys(packages[""].dependencies || {});
while (queue.length > 0) {
  const name = queue.shift();
  if (closure.has(name)) continue;
  closure.add(name);
  const entry = packages["node_modules/" + name];
  if (!entry) {
    console.error(`generate-ui-attribution: ${name} is a dependency with no lockfile entry`);
    process.exit(1);
  }
  for (const dependency of Object.keys(entry.dependencies || {})) queue.push(dependency);
}

const names = [...closure].sort();

// One block per distinct notice, keyed by the text itself: every package here is
// MIT, BSD or ISC, and several of the @vue ones ship the same file.
const texts = new Map();
const rows = [];
const textless = [];

for (const name of names) {
  const entry = packages["node_modules/" + name];
  const directory = path.join("ui", "node_modules", name);

  let files = [];
  try {
    files = fs
      .readdirSync(directory)
      .filter((file) => /^(licen[cs]e|copying|notice)/i.test(file))
      .sort();
  } catch {
    console.error(`generate-ui-attribution: ${name} is not installed in ui/node_modules`);
    process.exit(1);
  }

  rows.push(`| ${name} | ${entry.version} | ${entry.license ?? "(none declared)"} |`);

  if (files.length === 0) {
    textless.push(`${name}@${entry.version} (${entry.license ?? "none declared"})`);
    continue;
  }

  for (const file of files) {
    const text = fs.readFileSync(path.join(directory, file), "utf8").replace(/\s+$/, "");
    if (!texts.has(text)) texts.set(text, []);
    texts.get(text).push(`${name}@${entry.version} (${file})`);
  }
}

if (textless.length > 0) {
  console.error("generate-ui-attribution: a shipped package carries no licence text of its own:");
  for (const line of textless) console.error(`  ${line}`);
  console.error("");
  console.error("Take the notice from the package's repository and record it here with a reason,");
  console.error("or drop the dependency. Choosing a canonical text on the package's behalf is a");
  console.error("reading of somebody else's licence and does not belong in a default.");
  process.exit(1);
}

// Longest first, so the text every @vue package shares leads.
const blocks = [...texts.entries()].sort(
  (a, b) => b[1].length - a[1].length || a[1][0].localeCompare(b[1][0]),
);

const out = [];
out.push("# Third-party licences — the viewer");
out.push("");
out.push("The notices that travel with the viewer image and with anything served from");
out.push("it. **Generated — do not edit by hand:** run `sh ci/generate-ui-attribution.sh`");
out.push("and commit the result. `ci/check-ui-attribution.sh` fails the build if the two");
out.push("disagree.");
out.push("");
out.push(`This covers the ${names.length} packages in the viewer's runtime dependency closure.`);
out.push("Build-time tooling is excluded — it is not in the artefact. The closure is used");
out.push("rather than the tree-shaken bundle, which contains less: being wrong about which");
out.push("modules survived would mean a missing notice, so this over-attributes instead.");
out.push("");
out.push("The viewer's own code is under `MIT OR Apache-2.0`; `LICENSE-MIT` and");
out.push("`LICENSE-APACHE` ship beside this file in the image. The service's own");
out.push("dependencies are a separate artefact: see the repository's");
out.push("[`THIRD-PARTY-LICENSES.md`](../THIRD-PARTY-LICENSES.md).");
out.push("");
out.push("## The packages");
out.push("");
out.push("| Package | Version | Licence |");
out.push("|---|---|---|");
out.push(...rows);
out.push("");
out.push("## The notices");
out.push("");
out.push(`${blocks.length} distinct texts. Each appears once, followed by every package that`);
out.push("ships it.");

for (const [text, covered] of blocks) {
  out.push("");
  const noun = covered.length === 1 ? "package" : "packages";
  out.push(`### Shipped by ${covered.length} ${noun}`);
  out.push("");
  out.push("Covers:");
  out.push("");
  for (const line of covered.sort()) out.push(`- ${line}`);
  out.push("");
  out.push("````text");
  out.push(text);
  out.push("````");
}

process.stdout.write(out.join("\n") + "\n");
JS

mv "$tmp" ui/THIRD-PARTY-LICENSES.md

echo "generate-ui-attribution: ui/THIRD-PARTY-LICENSES.md written"
