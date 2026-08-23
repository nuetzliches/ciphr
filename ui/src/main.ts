/**
 * Entry point.
 *
 * No service worker is registered, and none should ever be: a cached response to a secret
 * read is a secret without an expiry date (plan section 15).
 *
 * **This file fails closed, and the reason is finding F4 of the 2026-08-21 source review.**
 * The previous version started removing existing registrations and mounted immediately,
 * two independent mistakes. Unregistering is asynchronous, so the app could mount and issue
 * `/v1` requests while a worker was still installed; and unregistering does not take a
 * worker's control of an *already controlled* document away at all — control lasts until
 * every controlled page is closed or reloaded. A worker left by an earlier application on
 * this origin could therefore read bearer tokens and plaintext responses out of a page that
 * had just "cleaned up".
 *
 * So: clean up, wait for it, and mount only if this document is not controlled. If it is,
 * the viewer refuses to start and asks for a reload, which is the point at which the
 * removal takes effect. The strongest form of this property is not code — it is an origin
 * that has never hosted an application that registers a service worker. `docs/ui.md` says
 * so.
 */
import { createApp } from "vue";

import App from "./App.vue";
import "./styles.css";

/**
 * Remove every registration on this origin, and report whether this document is free of
 * one.
 *
 * `controller` is the question that matters. A registration this function removed still
 * controls the page it was found on, and a page that is controlled has its `fetch` calls
 * passed through code this image did not ship.
 *
 * A browser that refuses to answer or to unregister is not a reason to continue: the
 * `controller` check runs either way, and it is the one that decides.
 */
async function isUncontrolled(): Promise<boolean> {
  if (!("serviceWorker" in navigator)) {
    return true;
  }

  try {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map((worker) => worker.unregister()));
  } catch {
    // Nothing to clean up, or the browser refused. Neither changes what is asked below.
  }

  return navigator.serviceWorker.controller === null;
}

/**
 * What a controlled page gets instead of the viewer.
 *
 * Built with DOM calls and existing classes: `script-src 'self'` and `style-src 'self'`
 * refuse an inline script and an inline style, and a blocking CI gate refuses raw markup
 * anywhere in this package. Text nodes throughout, which is what that gate asks for rather
 * than a way around it.
 */
function refuse(): void {
  const app = document.querySelector("#app");
  if (app === null) {
    return;
  }

  const panel = document.createElement("div");
  panel.className = "panel";

  const heading = document.createElement("h1");
  heading.textContent = "This page is controlled by a service worker";

  const refusal = document.createElement("p");
  refusal.className = "error";
  refusal.textContent =
    "The viewer will not start while a service worker can intercept its requests: it " +
    "would see bearer tokens and revealed values. One was found on this origin and has " +
    "been unregistered, and that does not end its control of a page already loaded — " +
    "reload this page to finish it.";

  const note = document.createElement("p");
  note.className = "note";
  note.textContent =
    "If this message comes back after a reload, this origin still hosts something that " +
    "registers a service worker. Serve the viewer from an origin that has never hosted " +
    "one; that is the form of this property no code can provide.";

  panel.append(heading, refusal, note);

  const main = document.createElement("main");
  main.append(panel);

  app.replaceChildren(main);
}

void isUncontrolled().then((uncontrolled) => {
  if (uncontrolled) {
    createApp(App).mount("#app");
    return;
  }
  refuse();
});
