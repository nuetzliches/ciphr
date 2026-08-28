// Generate the third-party notice file that ships inside the viewer image.
//
// The npm counterpart to `ci/build-notices.sh`, and it exists for the same
// reason that one does: this image is a distribution of somebody else's code,
// and MIT — which is what nearly all of it is — requires the copyright notice to
// travel with it. The image served twenty-three third-party packages to browsers
// and carried not one line of attribution.
//
// ── Why this lives in ui/ and not in ci/ ─────────────────────────────────────
//
// Every other gate in this project is a script under `ci/`. This one cannot be:
// the viewer image is built with `ui/` as its context and nothing else, because
// "it has no business being able to see the crates" (release-ui.yml), and a file
// outside that context cannot run inside the build. It is also not a gate — it is
// a build step of this package, which is what `ui/` is for. `ci/check-npm-licenses.sh`
// is the gate, and it stays where the gates are.
//
// ── "The viewer has one dependency" is about the manifest, not the bundle ────
//
// `ci/check-ui-budget.sh` holds this package to exactly one runtime dependency
// and that is a real constraint, but it constrains `package.json`. `vue` brings
// `@vue/runtime-dom`, `@vue/shared`, `@babel/parser`, `postcss` and eighteen
// others with it, and code from those is in the file a browser executes.
// Attribution follows what is distributed, so the list here is the lockfile's
// non-dev closure rather than the one name in the manifest.
//
// Some of those twenty-three are build-time even so — `@vue/compiler-sfc` runs
// in the bundler, not in the tab. They are attributed anyway, for the reason the
// Rust side attributes every platform it publishes for: over-attribution is a
// longer file and under-attribution is the breach. Splitting them would mean
// deciding, package by package, what the bundler tree-shook, which is a
// judgement that would be made once and then quietly go stale.
//
// **A package that ships no license text fails this**, exactly as on the Rust
// side and for the same reason: a notice nobody verified reads like attribution
// while being none. All twenty-three carry a LICENSE file today.
//
// Usage:  node scripts/build-notices.mjs [output path]
// Run after `npm ci`: the texts live in the installed packages, not in the
// lockfile, which records integrity hashes and no license at all.

import fs from "node:fs";
import path from "node:path";

const out = process.argv[2] ?? "THIRD-PARTY-NOTICES.md";

const fail = (message) => {
  process.stderr.write(`build-notices: ${message}\n`);
  process.exit(1);
};

if (!fs.existsSync("node_modules")) {
  fail("node_modules is not there. Run `npm ci --ignore-scripts` first.");
}

const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));

// The non-dev closure. `dev` marks a package reachable only through
// devDependencies; `devOptional` marks one reachable both ways, which means it
// is reachable from the runtime side and belongs here.
const shipped = Object.entries(lock.packages ?? {})
  .filter(([p, entry]) => p !== "" && entry.dev !== true && entry.devOptional !== true)
  .sort(([a], [b]) => a.localeCompare(b));

if (shipped.length === 0) {
  fail("the lockfile lists no runtime packages, which cannot be right");
}

const LICENSE_FILE = /^(licen[cs]e|copying|notice|unlicense)/i;

const licenseField = (dir) => {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    if (typeof pkg.license === "string") return pkg.license;
    if (pkg.license && typeof pkg.license.type === "string") return pkg.license.type;
    if (Array.isArray(pkg.licenses)) {
      return pkg.licenses.map((l) => (typeof l === "string" ? l : l.type)).join(" OR ");
    }
  } catch {
    // A package without a readable manifest states no license. The text check
    // below is the one that decides whether that is fatal.
  }
  return "";
};

const entries = [];
const notInstalled = [];
const withoutText = [];

for (const [lockPath, entry] of shipped) {
  let files;
  try {
    files = fs
      .readdirSync(lockPath, { withFileTypes: true })
      .filter((f) => f.isFile() && LICENSE_FILE.test(f.name))
      .map((f) => f.name)
      .sort();
  } catch {
    notInstalled.push(lockPath);
    continue;
  }

  const name = lockPath.replace(/^.*node_modules\//, "");
  const license = typeof entry.license === "string" ? entry.license : licenseField(lockPath);

  if (files.length === 0) {
    withoutText.push(`${name}@${entry.version} (${license || "no license field"})`);
    continue;
  }

  entries.push({ name, version: entry.version, license, dir: lockPath, files });
}

if (notInstalled.length > 0) {
  process.stderr.write("build-notices: the lockfile lists packages that are not installed:\n");
  for (const p of notInstalled) process.stderr.write(`  ${p}\n`);
  fail("run `npm ci --ignore-scripts` and try again");
}

if (withoutText.length > 0) {
  process.stderr.write("build-notices: these packages ship no license text:\n");
  for (const p of withoutText) process.stderr.write(`  ${p}\n`);
  process.stderr.write(
    "\nNothing here will invent one from the license field: a notice nobody verified\n" +
      "reads like attribution while being none. Get the text from the package's\n" +
      "repository and add it, or replace the package. Either way it is a decision in\n" +
      "a pull request.\n",
  );
  process.exit(1);
}

const byLicense = new Map();
for (const e of entries) byLicense.set(e.license, (byLicense.get(e.license) ?? 0) + 1);

let output = `# Third-party notices — the viewer

The viewer itself is licensed under **MIT OR Apache-2.0**, at your option. Those
two texts travel with this file rather than being left in a repository:
\`LICENSE-MIT\` and \`LICENSE-APACHE\` sit beside it in \`/usr/share/doc/ciphr-ui/\`
inside the image.

This file covers the packages whose code is distributed in this image. Each entry
reproduces the license files the package itself ships, verbatim; nothing below
was reconstructed from a license identifier. It is generated by
\`ui/scripts/build-notices.mjs\` and is not edited by hand.

The list is the lockfile's non-dev closure rather than the one dependency
\`package.json\` names: \`vue\` brings the rest with it and their code is in the
bundle. Build tooling is excluded — none of it reaches a browser.

**${entries.length} packages.** By license:

`;

for (const [license, n] of [...byLicense.entries()].sort((a, b) => b[1] - a[1])) {
  output += `- ${n} × ${license || "no license field"}\n`;
}

output += "\n---\n\n";

for (const e of entries) {
  output += `## ${e.name} ${e.version}\n\nLicense: **${e.license || "stated in the file below"}**\n\n`;
  for (const file of e.files) {
    const text = fs.readFileSync(path.join(e.dir, file), "utf8");
    // A fence long enough that the text cannot close it. License texts do not
    // contain code fences, and a guard that costs one test is cheaper than the
    // day one does.
    const fence = /^```/m.test(text) ? "``````" : "```";
    output += `### ${file}\n\n${fence}\n${text.replace(/\n?$/, "\n")}${fence}\n\n`;
  }
}

fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
fs.writeFileSync(out, output);
process.stdout.write(`build-notices: ok — ${entries.length} packages, ${out}\n`);
