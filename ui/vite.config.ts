import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

/**
 * This file runs in Node, and `CIPHR_URL` below is the only thing it reads from there.
 * Declared rather than pulled in with `@types/node`: a several-megabyte type package for
 * one lookup is not a trade this package's dependency budget should make.
 */
declare const process: { env: Record<string, string | undefined> };

/**
 * Build configuration for the viewer.
 *
 * Three settings are security requirements from plan section 15 rather than taste, and
 * each one is here to keep the strict Content-Security-Policy in `index.html` and
 * `nginx.conf` satisfiable:
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
  plugins: [vue()],
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
