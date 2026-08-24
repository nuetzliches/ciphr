/**
 * Marks up the code blocks in `site/` — and ships nothing to a browser.
 *
 * ── Why a tool rather than a highlighter on the page ─────────────────────────
 *
 * Three of the four pages in `site/` carry `default-src 'none'` with no
 * `script-src`, and `site/README.md` makes that a claim rather than a default: a
 * documentation page that cannot hold the policy it describes is a poor
 * advertisement for the argument it makes. Prism and highlight.js are therefore
 * out — they would colour text that never changes, at every page load, in
 * exchange for the one property those pages are built to demonstrate.
 *
 * So the colouring happens here, once, and what reaches a reader is static
 * `<span>` elements. `pages.yml` keeps uploading `site/` exactly as it is in the
 * tree, and the sentence in that workflow — *there is no build step and there is
 * not supposed to be one* — stays true: this is a maintenance tool, not a stage
 * in the publish path. `ci/check-site-highlighting.sh` runs it with `--check` so
 * the markup in the tree cannot drift from what it produces.
 *
 * ── Why Shiki as a tokenizer and not as a renderer ───────────────────────────
 *
 * Shiki's own HTML output carries a `style` attribute per token, which
 * `style-src 'self'` refuses — the same policy the pages hold. It also bakes a
 * VS Code theme's palette into the document, which would give these pages a
 * second colour scheme next to the one in `site.css` and no light mode at all.
 *
 * What is taken from Shiki is only the part worth borrowing: four TextMate
 * grammars. Every token's scopes are mapped onto **six** classes, and the six
 * colours live in `site.css` next to the rest of the palette, so both colour
 * schemes keep working. The theme named below is required by the API; its
 * colours are read and discarded.
 *
 * ── The invariant that makes this safe to run over documentation ─────────────
 *
 * The rendered text must not change — a reader copies these blocks into a
 * terminal. `markUp` therefore reassembles the tokens and refuses to emit
 * anything unless the result is character-identical to its input, and the pass
 * that strips previous output refuses any element other than this tool's own
 * spans. A block is edited by hand as plain code; the spans are regenerated.
 */

import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createHighlighter } from "shiki";

const REPOSITORY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SITE = path.join(REPOSITORY, "site");

/**
 * `data-lang` on the `<pre>` names one of these. The value a page carries is the
 * short name a reader would write; the grammar is Shiki's identifier for it.
 * `text` is the deliberate opt-out: a block that is output rather than source.
 */
const GRAMMARS = {
  yaml: "yaml",
  sh: "bash",
  toml: "toml",
  rust: "rust",
};

/** Required by the API. Its palette is discarded; only the scopes are used. */
const THEME = "github-dark";

/**
 * Scope prefixes to classes, first match winning — so the order is part of the
 * mapping. A YAML key carries `string.unquoted.plain.out` *and*
 * `entity.name.tag`, and a TOML key carries `variable.other.key` where a shell
 * variable carries `variable.other.normal`; both would land in the wrong class
 * under a different order.
 *
 * Six classes, and the restraint is the point: these blocks are read as prose
 * about which flag matters, not skimmed for syntax. Plain YAML scalars, shell
 * command names and Rust identifiers stay in the body colour, which is what
 * keeps a twenty-line compose block from becoming a rainbow.
 */
const CLASSES = [
  // A comment on this site usually carries the reason for the line above it.
  ["t-com", ["comment"]],
  // What a reader is looking for: the key, the flag, the table.
  ["t-key", ["constant.other.option", "entity.name.tag", "variable.other.key", "entity.name.section"]],
  // Shell only. Rust's `variable.other` is a local binding and stays plain.
  ["t-var", ["variable.other.normal", "variable.other.assignment", "variable.other.special", "punctuation.definition.variable"]],
  // Quoted strings only. An unquoted YAML scalar is most of a compose file.
  ["t-str", ["string.quoted"]],
  ["t-kw", ["keyword.other", "storage.type", "storage.modifier", "entity.name.type", "support.function.builtin"]],
];

/**
 * Two things no grammar can know, and the two that carry the most meaning on
 * `integrate.html`: a GitHub Actions expression, and a placeholder a reader must
 * replace. Route A names a tag and two checksums that do not exist until
 * `ciphr-ci` is released, and until then the only thing marking them is a pair
 * of angle brackets. Marked, the convention becomes visible.
 *
 * Applied only to tokens the grammar left plain, so it cannot recolour a string
 * or a comment — and the placeholder half is skipped for Rust, where `<` opens a
 * generic parameter rather than a blank to fill in.
 */
const EXPRESSION = /\$\{\{[^{}]*\}\}/;
const PLACEHOLDER = /<[^<>]{1,60}>/;

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", "#39": "'" };

/** The entities the pages actually use. Anything else is a mistake, loudly. */
function decode(html, where) {
  return html.replace(/&(#?[0-9a-zA-Z]+);/g, (whole, name) => {
    if (Object.hasOwn(ENTITIES, name)) {
      return ENTITIES[name];
    }
    throw new Error(`${where}: the entity ${whole} is not one this tool knows how to round-trip`);
  });
}

/** `&`, `<` and `>`, which is what the hand-written blocks already escape. */
function encode(text) {
  return text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/**
 * Back to the plain code a person edits. Only this tool's spans are removed;
 * anything else inside a code block is refused rather than silently discarded,
 * because a link or an `<em>` in there is a decision this tool must not make.
 */
function stripPreviousOutput(inner, where) {
  const stripped = inner.replace(/<span class="t-[a-z]+">/g, "").replaceAll("</span>", "");
  const leftover = stripped.match(/<[a-zA-Z/][^>]*>/);
  if (leftover) {
    throw new Error(
      `${where}: a code block may hold text and this tool's spans, and this one holds ${leftover[0]}`,
    );
  }
  return stripped;
}

function classFor(scopes) {
  for (const [name, prefixes] of CLASSES) {
    if (prefixes.some((prefix) => scopes.some((scope) => scope.startsWith(prefix)))) {
      return name;
    }
  }
  return null;
}

/** Splits a plain run on the markers above, so each piece carries its own class. */
function splitMarkers(content, allowPlaceholder) {
  const pattern = new RegExp(
    allowPlaceholder ? `(${EXPRESSION.source}|${PLACEHOLDER.source})` : `(${EXPRESSION.source})`,
    "g",
  );
  const pieces = [];
  for (const piece of content.split(pattern)) {
    if (piece === "" || piece === undefined) {
      continue;
    }
    const marked = new RegExp(`^(?:${pattern.source})$`).test(piece);
    pieces.push({
      content: piece,
      className: marked ? (EXPRESSION.test(piece) ? "t-var" : "t-ph") : null,
    });
  }
  return pieces;
}

async function markUp(highlighter, code, lang, where) {
  const grammar = GRAMMARS[lang];
  const { tokens } = highlighter.codeToTokens(code, {
    lang: grammar,
    theme: THEME,
    includeExplanation: "scopeName",
  });

  const lines = tokens.map((line) => {
    const pieces = [];
    for (const token of line) {
      const scopes = (token.explanation ?? []).flatMap((part) =>
        (part.scopes ?? []).map((scope) => scope.scopeName),
      );
      const className = classFor(scopes);
      if (className === null) {
        pieces.push(...splitMarkers(token.content, grammar !== "rust"));
      } else {
        pieces.push({ content: token.content, className });
      }
    }

    // Adjacent pieces in one class become one span. Purely so that the diff of a
    // regenerated page is readable by whoever has to review it.
    const merged = [];
    for (const piece of pieces) {
      const last = merged[merged.length - 1];
      if (last && last.className === piece.className) {
        last.content += piece.content;
      } else {
        merged.push({ ...piece });
      }
    }
    return merged;
  });

  const reassembled = lines.map((line) => line.map((piece) => piece.content).join("")).join("\n");
  if (reassembled !== code) {
    throw new Error(
      `${where}: the tokens do not reassemble into the block they came from, so nothing was written`,
    );
  }

  return lines
    .map((line) =>
      line
        .map((piece) =>
          piece.className === null
            ? encode(piece.content)
            : `<span class="${piece.className}">${encode(piece.content)}</span>`,
        )
        .join(""),
    )
    .join("\n");
}

const BLOCK = /<pre\b([^>]*)><code>([\s\S]*?)<\/code><\/pre>/g;

async function processPage(highlighter, file) {
  const original = await readFile(path.join(SITE, file), "utf8");
  const problems = [];
  let blocks = 0;

  const replacements = [];
  for (const match of original.matchAll(BLOCK)) {
    const [whole, attributes, inner] = match;
    const line = original.slice(0, match.index).split("\n").length;
    const where = `${file}:${line}`;

    const declared = attributes.match(/\bdata-lang="([^"]*)"/);
    if (!declared) {
      problems.push(
        `${where}: this <pre> names no language. Add data-lang="${Object.keys(GRAMMARS).join('", "')}" — or data-lang="text" for a block that is output rather than source`,
      );
      continue;
    }

    const lang = declared[1];
    if (lang === "text") {
      continue;
    }
    if (!Object.hasOwn(GRAMMARS, lang)) {
      problems.push(`${where}: data-lang="${lang}" is not one of ${Object.keys(GRAMMARS).join(", ")}, text`);
      continue;
    }

    try {
      const code = decode(stripPreviousOutput(inner, where), where);
      const marked = await markUp(highlighter, code, lang, where);
      replacements.push([whole, `<pre${attributes}><code>${marked}</code></pre>`]);
      blocks += 1;
    } catch (error) {
      problems.push(error.message);
    }
  }

  let updated = original;
  for (const [from, to] of replacements) {
    updated = updated.replace(from, () => to);
  }

  return { file, original, updated, blocks, problems };
}

async function main() {
  const check = process.argv.includes("--check");
  const pages = (await readdir(SITE)).filter((name) => name.endsWith(".html")).sort();

  const highlighter = await createHighlighter({
    langs: [...new Set(Object.values(GRAMMARS))],
    themes: [THEME],
  });

  const results = [];
  for (const page of pages) {
    results.push(await processPage(highlighter, page));
  }

  const problems = results.flatMap((result) => result.problems);
  if (problems.length > 0) {
    for (const problem of problems) {
      process.stderr.write(`site-highlight: ${problem}\n`);
    }
    process.exitCode = 1;
    return;
  }

  const stale = results.filter((result) => result.original !== result.updated);
  const blocks = results.reduce((total, result) => total + result.blocks, 0);

  if (check) {
    if (stale.length > 0) {
      for (const result of stale) {
        process.stderr.write(
          `site-highlight: site/${result.file} is not what the highlighter produces\n`,
        );
      }
      process.stderr.write(
        "site-highlight: run `npm run highlight` in ci/site-highlight and commit the result\n",
      );
      process.exitCode = 1;
      return;
    }
    process.stdout.write(`site-highlight: ok — ${blocks} blocks in ${pages.length} pages, all current\n`);
    return;
  }

  for (const result of stale) {
    await writeFile(path.join(SITE, result.file), result.updated);
  }
  process.stdout.write(
    `site-highlight: ${blocks} blocks marked up; ${stale.length} of ${pages.length} pages rewritten\n`,
  );
}

await main();
