# site/ — the pages that go online with the repository

**Status:** current as of 2026-08-24. Four pages, three of them written on that date; the fourth is
the security-layers diagram, which is drawn against `v0.5.1`, carries the complete surface list, and
says both on itself. **It is live at <https://nuetzliches.github.io/ciphr/>** since 2026-08-24,
deployed by [`../.github/workflows/pages.yml`](../.github/workflows/pages.yml) on every push that
touches this directory — see *Publishing* below for the guard that kept it offline until then.

Everything here is English, like the rest of the repository. The three new pages were written that
way; the diagram was translated from German on 2026-08-24, when the site grew a navigation that would
otherwise have led from English pages into a German one.

## The pages

| File | What it is |
|---|---|
| `index.html` | The landing page: what the project is, the three questions it answers, the design in one screen, and what it is not. |
| `integrate.html` | The four consumer routes — a CI job, a container, an application, plain `curl` — with the code for each, the capabilities it needs, and a link to the document that owns the example. |
| `security.html` | What an integration has to get right: the token, least privilege, masking and where it stops, the transport, the trail, and the three things this design does not defend. |
| `layers.html` | The interactive diagram of the security layers. `layers.css` and `layers.js` belong to it. |
| `site.css` | The shell every page shares: the navigation bar, the prose and code styles the reading pages use, and the six classes a highlighted code block is built from. |
| `favicon.svg` | The tab icon: one centre with boundaries around it — the diagram at 16 pixels. |

Nothing here is served from anywhere else, and nothing is fetched at load: no dependency reaches a
reader, and no page makes an external request. `layers.html` is the only one that runs a script at
all; the other three carry `default-src 'none'` with no `script-src`, so nothing on them can run.

**The publish path still has no build step**, and [`../.github/workflows/pages.yml`](../.github/workflows/pages.yml)
still uploads this directory exactly as it stands. The one generated thing in it is the colouring of
the code blocks — see below.

## The code blocks are coloured by a tool, not by the page

`integrate.html` carries seven code blocks in four languages, and what marks them up is
[`../ci/site-highlight/`](../ci/site-highlight/): Shiki, used as a tokenizer, run by hand and its
output committed. A reader receives static `<span>` elements.

**Why not a highlighter on the page.** Prism and highlight.js would need `script-src` on documents
that are built to demonstrate the absence of it, in exchange for colouring text that never changes,
at every load. Shiki's own HTML output is out for a second reason: it puts a `style` attribute on
every token, which `style-src 'self'` refuses, and it would bake a VS Code palette into pages that
already have a palette and a light mode.

So only the grammars are borrowed. Every token's scopes map onto **six** classes — comment, key,
string, keyword, variable, placeholder — and those six colours live in `site.css` next to the rest,
which is why the light scheme needed two new values rather than a second theme. Six is a decision:
plain YAML scalars and Rust identifiers stay in the body colour, because a twenty-line compose file
in eleven colours reads as decoration rather than as the argument about which flag matters.

`<pre data-lang="…">` names the language — `yaml`, `sh`, `toml`, `rust`, or `text` to opt out. Edit a
block as plain code; the spans are regenerated:

```sh
cd ci/site-highlight && npm ci --ignore-scripts && npm run highlight
```

**What holds it.** Generated markup in the tree can be edited by hand or left stale, and both are
invisible in a diff. [`../ci/check-site-highlighting.sh`](../ci/check-site-highlighting.sh)
regenerates every block from the plain code inside it and fails if the result differs from what is
committed — and it fails on a `<pre>` naming no language, on an unknown language, and on any block
whose tokens do not reassemble into the exact text they came from. That last one is the point: a
reader copies these blocks into a terminal, so the rendered text must be character-identical to what
was written. [`../ci/check-site-highlight-budget.sh`](../ci/check-site-highlight-budget.sh) holds the
second npm tree in the repository to the same rules as the viewer's, for the reason given there.

## Viewing it

Every page carries a strict Content-Security-Policy, the same stance as the viewer. `'self'` does not
work under `file://`, so open it through a server:

```sh
cd site && python -m http.server 8791     # then http://localhost:8791/
```

On `layers.html` the state is in the URL: `?on=viewer_api,bulk_export` shows a surface configuration,
and `#band` or `#cut_root` jumps to an element. With no parameter it is the **default build** — the
artefact a deployment actually gets.

## What the pages claim, and how they are held to it

**The site orders what is in `docs/`; it is not their source.** Every claim links to the document that
decided the thing, and where the two ever disagree the document is the one maintained with the
software. That is also the known weakness of putting examples on a page: the code in
`integrate.html` is a copy, and nothing in CI compares it to the documents it came from. Whoever
changes an example in `docs/operations/` should grep this directory for it.

**The highlighter does not fix that, and it should not be read as having fixed it.** It guarantees
that the markup around an example is what the mapping produces and that the text inside it survived
the round trip — not that the example still matches the document it was copied from. The gate that
would close this is a different one: pulling the snippets out of `docs/operations/` at build time
instead of copying them. The tool is placed so that this stays possible, and it is not built.

The rules from [`../docs/README.md`](../docs/README.md) apply here too: the pages describe what is
built, and mark separately what is **designed and not built** (MCP, the severe tripwire tiers) and
what is **deferred** (ADR-16, `POST /v1/report`). They carry their own dates, and they change in the
same commit as the statement they present.

**No deployment specifics.** No hostnames, no paths, and not which surface entries *our* instance has
named. The site describes the product, not an installation — the same separation the product
documentation keeps.

### Three rules that carry the diagram

They are here because a change to the drawing that breaks one of them is not a layout change but a
change of statement.

1. **Rings are boundaries with a gate, not quality levels.** Their order is the order in which a
   request crosses them. Outwards it is not the quality that decreases but the number of parties that
   increases.
2. **Crates are not rings.** The reviewed core is a *band* across several rings, because that is its
   property: one shape in every build (ADR-20 property 1). That it crosses the centre, the authz and
   the auth ring and not the outer ones is the reach of the review of 2026-08-21 — geometry as a
   statement, not as decoration.
3. **What crosses no ring is drawn as a cut.** Root on the host and the build pipeline ignore the
   onion. An onion without those cuts would be advertising.

### What the diagram was behind on, and what was done about it

It was drawn against `v0.5.1` and was re-read on 2026-08-24. Two elements were **corrected** then,
because the project had made their old text false:

- `bulk_export`'s cost is one request per path instead of one for all, and no longer "route B cannot
  fetch at all". The clients fall back since ADR-25.
- The CI client names `ciphr-ci` as the thing that masks, rather than a CLI command a runner cannot
  run.

**The surface list is complete again as of that date.** `token_status` and `token_revoke` were added
to the server after `v0.5.1` and are now drawn: two arcs on the surface ring at 80° and 56°, each
with the cost sentence from `crates/ciphr-server/src/surface.rs` and the record that decided it.
Four entries now sit on that ring in one run from 44° to 140°, abutting rather than overlapping, and
`honeypot_alert` stays on the auth ring because that is where it adds code.

The rest of the diagram — rings, cuts, clients, the band — is the `v0.5.1` drawing, re-read on
2026-08-24 and left as it was because it still holds. That is a weaker statement than "verified
against `v0.13.2`" and is meant to be.

## Publishing

**This site went online with the decision to make the repository public**, on 2026-08-24 — not
before it, and not separately from it. The reason was not secrecy: the pages contain nothing `docs/`
does not say, and the threat model explicitly does not rely on obscurity. It is that every claim here
links to `blob/main/…`, and from a private repository each of those links is a 404 for the reader. A
published page whose sources nobody can open is exactly the state in which documentation produces
confident errors.

**That decision was a guard rather than a missing file, and the guard did its job.**
[`../.github/workflows/pages.yml`](../.github/workflows/pages.yml) publishes `site/` on a push that
touches it — and its first job asks the API whether this repository is public and skips the
deployment while the answer is no. `workflow_dispatch` goes through the same guard, so a manual run
cannot get past it either. Two runs fired from pushes on 2026-08-24 while the repository was still
private: both resolved the guard and skipped the deployment. The first run that published was the
manual one after the visibility flipped.

It uses the artefact route rather than a branch source: from a branch, GitHub Pages publishes only
`/` or `/docs`, and `/docs` would send the Markdown documentation through Jekyll. This way `site/` is
served exactly as it is in the tree and `docs/` is untouched. Actions are pinned to a commit hash
rather than a tag, as in `ci.yml` and `release.yml`.

What that day cost, and what it left open:

- **The link** from [`../README.md`](../README.md) and [`../docs/README.md`](../docs/README.md) is
  set. It was deliberately absent while the site was reachable nowhere.
- **The source links resolve.** Every reference points at `blob/main/…`; they resolve in the working
  tree and two were checked against the public repository after publication. Nothing in CI keeps them
  resolving, though, and a rename in `docs/` breaks them silently — that gate does not exist.
- **The version placeholders in `integrate.html` are still placeholders.** Route A names a tag and a
  checksum that do not exist until `ciphr-ci` is released. The page says so on itself; it should carry
  the real numbers as soon as there is a release to take them from.

Two paragraphs that the same decision triggers and that do not belong here, but should be read
together with it: the reproducibility of the builds in
[`../docs/threat-model.md`](../docs/threat-model.md) — it buys something only once a third party can
rebuild an image from source, and the `apt-get install` in the runtime stage of the `Dockerfile` has
to go for that — and the bar for the external review in
[`../docs/security-review.md`](../docs/security-review.md), which rises back to a human reviewer with
a public repository.
