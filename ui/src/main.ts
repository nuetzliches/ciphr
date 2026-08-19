/**
 * Entry point.
 *
 * No service worker is registered, and none should ever be: a cached response to a secret
 * read is a secret without an expiry date (plan section 15). Any existing registration
 * from an earlier deployment of something else on this origin is removed rather than left
 * to serve stale bundles.
 */
import { createApp } from "vue";

import App from "./App.vue";
import "./styles.css";

if ("serviceWorker" in navigator) {
  void navigator.serviceWorker
    .getRegistrations()
    .then((registrations) => Promise.all(registrations.map((worker) => worker.unregister())))
    .catch(() => {
      // Nothing to clean up, or the browser refused. Neither is worth stopping over.
    });
}

createApp(App).mount("#app");
