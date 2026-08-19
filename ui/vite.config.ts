import { defineConfig, type Plugin } from "vite";
import vue from "@vitejs/plugin-vue";

/**
 * This file runs in Node, and `CIPHR_URL` below is the only thing it reads from there.
 * Declared rather than pulled in with `@types/node`: a several-megabyte type package for
 * one lookup is not a trade this package's dependency budget should make.
 */
declare const process: { env: Record<string, string | undefined> };

/**
 * The policy, defined once. The container sends the same one as a header (nginx.conf).
 *
 * `frame-ancestors` is deliberately absent here: browsers ignore it in a meta element and
 * log an error about it, and a page that complains about its own policy on every load
 * teaches whoever reads that console to ignore it. Framing is refused by the header and by
 * `X-Frame-Options`.
 */
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

/**
 * Put the policy in the built document, and only there.
 *
 * It belongs in the artifact so that a bundle served by something other than this
 * project's container — `vite preview`, someone's own web server — keeps the policy with
 * it rather than silently losing it.
 *
 * It must **not** sit in `index.html`, because the dev server does not serve the built
 * artifact: it assembles the page in the browser, and Vite's HMR client applies styles by
 * creating elements at runtime, which `style-src 'self'` refuses. With the policy in the
 * source document, development means an unstyled page and a console full of violations —
 * and the fix someone reaches for under that pressure is weakening the policy in
 * production. Injecting at build time keeps it strict where it is actually served, and CI
 * checks the built document for it.
 */
function contentSecurityPolicy(): Plugin {
  return {
    name: "ciphr-csp-meta",
    apply: "build",
    transformIndexHtml() {
      return [
        {
          tag: "meta",
          attrs: { "http-equiv": "Content-Security-Policy", content: CSP },
          injectTo: "head-prepend",
        },
      ];
    },
  };
}

/**
 * Build configuration for the viewer.
 *
 * Three settings are security requirements from plan section 15 rather than taste, and
 * each one exists so the policy above stays satisfiable without an exception:
 *
 * - `assetsInlineLimit: 0` — nothing becomes a `data:` URI. An inlined asset would need
 *   `img-src data:` or `font-src data:`, and every `data:` allowance is a hole someone
 *   later widens.
 * - `modulePreload.polyfill: false` — Vite otherwise injects an inline script into the
 *   HTML, which would need `unsafe-inline` or a hash. Every browser this viewer targets
 *   supports module preloading natively.
 * - `cssCodeSplit: false` — one stylesheet, loaded from `'self'`. Route-level CSS
 *   injection at runtime works by creating `<style>` elements, which `style-src 'self'`
 *   refuses.
 *
 * The dev server proxies `/v1` to the service so that development runs same-origin, the
 * shape the deployment uses (ADR-11). It deliberately does **not** disable certificate
 * verification: ADR-8 says `--insecure` appears in no example, not even for testing, so
 * a developer points `NODE_EXTRA_CA_CERTS` at the deployment's CA instead. See README.
 */
export default defineConfig({
  plugins: [vue(), contentSecurityPolicy()],
  build: {
    target: "es2022",
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    sourcemap: false,
    reportCompressedSize: false,
  },
  server: {
    port: 4401,
    strictPort: true,
    proxy: {
      "/v1": {
        target: process.env.CIPHR_URL ?? "https://localhost:4400",
        changeOrigin: false,
      },
    },
  },
});
