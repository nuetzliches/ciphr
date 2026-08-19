/**
 * Which view is showing, from the fragment.
 *
 * Forty lines instead of a routing library, for the reason the Rust side hand-writes its
 * hexadecimal encoder: the dependency budget for this package (plan section 15) is spent
 * where it buys something, and five flat views need neither nested routes, nor guards,
 * nor history state.
 *
 * The fragment carries a view name and nothing else. A secret path is *not* put in the
 * URL — plaintext must never reach one (plan section 15), and a URL is the one piece of
 * page state that lands in history, in a shared link, and in a screenshot.
 */
import { ref } from "vue";

export const VIEWS = ["audit", "secrets", "identities", "policies", "health"] as const;

export type View = (typeof VIEWS)[number];

function fromHash(): View {
  const name = window.location.hash.replace(/^#\/?/, "");
  return (VIEWS as readonly string[]).includes(name) ? (name as View) : "audit";
}

export const view = ref<View>(fromHash());

window.addEventListener("hashchange", () => {
  view.value = fromHash();
});

/** Switch views. Written as a fragment so that reload and the back button both work. */
export function go(next: View): void {
  window.location.hash = `#/${next}`;
  // `hashchange` does not fire when the fragment is already what it is being set to.
  view.value = next;
}
