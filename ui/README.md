# ciphr-ui

The read-only viewer: audit trail, secret metadata with a per-value reveal, identities, policies,
health. Its own package and its own container image (ADR-11), talking to the ordinary v1 API from the
browser.

**The documentation for what this is and why it is built this way lives in
[`../docs/ui.md`](../docs/ui.md).** This file is the package-level notes: commands, layout, and the
dependency decisions.

## Commands

```sh
npm ci                 # exact tree from package-lock.json
npm run dev            # http://localhost:4401, /v1 proxied to https://localhost:4400
npm run build          # vue-tsc --noEmit && vite build  →  dist/
npm run typecheck      # just the type check
npm run notices        # third-party attribution  →  THIRD-PARTY-NOTICES.md
```

`npm run notices` collects the license text of every package whose code is in the bundle — the
lockfile's non-dev closure, which is twenty-three packages and not the one `package.json` names,
because `vue` brings the rest with it. The image runs it in its own build and keeps the result at
`/usr/share/doc/ciphr-ui/`; the file is not committed, since it is produced from the lockfile every
time it is needed. A package that ships no license text fails it rather than being attributed from
its `license` field, and `ci/check-npm-licenses.sh` is the separate gate on which licenses may be
here at all.

`npm run dev` serves a page assembled in the browser and therefore **without** the
Content-Security-Policy: Vite's HMR client applies styles at runtime, which `style-src 'self'`
refuses. The policy is defined in `vite.config.ts`, injected into the built document, and sent as a
header by the container — so what needs checking against it is the output of `npm run build`, not the
dev server. CI does exactly that.

The dev proxy verifies the service's certificate, because ADR-8 leaves no room for `--insecure`
anywhere. Point Node at the CA and, if the service is elsewhere, name it:

```sh
NODE_EXTRA_CA_CERTS=/path/to/ca.crt npm run dev
CIPHR_URL=https://ciphr.internal:4400 npm run dev
```

## Layout

```
index.html            the document. No CSP here on purpose: it is injected into the build
public/favicon.svg    served from 'self'; not a data: URI, because img-src allows neither
src/main.ts           mounts the app, and unregisters any stray service worker
src/App.vue           the shell: gate, header, one view at a time via v-if
src/session.ts        the token: sessionStorage, shape check, the only reader of the string
src/api.ts            the v1 calls this viewer makes, all of them reads
src/chain.ts          what a page of audit records can be checked for, and what it cannot
src/router.ts         which view is showing, from the fragment
src/components/       one file per view, plus the sign-in gate
nginx.conf            the container's server block: headers, no proxying, no SPA rewrite
Dockerfile            build with Node, serve with nginx-unprivileged, both pinned by digest
```

## Dependencies, and the ones that are absent

One runtime dependency: `vue`, pinned exactly. `ci/check-ui-budget.sh` enforces that, a ceiling on the
whole tree, that no package runs an install script, and that everything resolves from the public
registry with an integrity hash. Plan section 15 asks for this budget separately from the Rust one,
because frontend dependency sprawl would otherwise quietly undercut the supply-chain discipline the
rest of the repository spends real effort on.

Deliberately not here:

- **No router.** Five flat views need neither nested routes, guards, nor history state; `router.ts` is
  forty lines against the fragment. A secret path is never put in the URL.
- **No state library.** There is no global state to manage, and revealed plaintext must not enter one.
- **No CSS framework and no icon set.** One hand-written stylesheet, light and dark from
  `prefers-color-scheme`, no runtime style injection — `style-src 'self'` refuses inline styles, so
  every conditional appearance is a class.
- **No `@types/node`.** `vite.config.ts` declares the one `process.env` lookup it makes rather than
  pulling in a several-megabyte type package for it.
- **TypeScript 5, not 7.** `vue-tsc` is built on Volar over the TypeScript 5 API surface. Moving a
  security-relevant viewer to the native port on the day it ships is not a trade this package needs to
  make; the pin is a deliberate commit whenever it changes.
