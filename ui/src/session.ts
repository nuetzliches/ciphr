/**
 * The signed-in token, for as long as the tab is open.
 *
 * ADR-12: sign-in is pasting a personal token issued by the CLI for an identity of kind
 * `human`. There is no password, no server-side session, and no cookie — which is what
 * removes the entire CSRF class rather than mitigating it.
 *
 * `sessionStorage`, not `localStorage`: a token that survives closing the tab is a
 * permanent secret on a shared workstation. It is also not held in a module-level
 * variable alone, because a page reload during ordinary use would then look like a
 * session expiry and train people to keep the token somewhere more convenient.
 */
import { computed, ref } from "vue";

const STORAGE_KEY = "ciphr.token";

/** `cph_` + 8 characters of identifier + 43 of secret, as issued by `ciphr token issue`. */
const TOKEN_PATTERN = /^cph_[A-Za-z0-9_-]{8}[A-Za-z0-9_-]{43}$/;

const current = ref<string | null>(readStored());

function readStored(): string | null {
  try {
    const stored = sessionStorage.getItem(STORAGE_KEY);
    return stored !== null && TOKEN_PATTERN.test(stored) ? stored : null;
  } catch {
    // A browser with storage disabled is usable, just not across reloads. Failing to
    // start over it would be worse than the inconvenience.
    return null;
  }
}

/** Whether a token is held. Never exposes the token to a template. */
export const signedIn = computed(() => current.value !== null);

/**
 * The non-secret eight-character identifier of the token, for the header.
 *
 * The same identifier the audit trail records, so a reader can tie what they see in the
 * viewer to the entries their own reads produce.
 */
export const tokenId = computed(() =>
  current.value === null ? null : current.value.slice(4, 12),
);

/** Whether a pasted string is shaped like a token, checked before any request. */
export function looksLikeToken(candidate: string): boolean {
  return TOKEN_PATTERN.test(candidate.trim());
}

/**
 * Hold a token for this tab.
 *
 * Returns false for a string that is not shaped like one: catching a truncated paste
 * here costs nothing, while sending it produces an audit entry for a failed
 * authentication that never had a chance.
 */
export function signIn(candidate: string): boolean {
  const token = candidate.trim();
  if (!TOKEN_PATTERN.test(token)) {
    return false;
  }
  current.value = token;
  try {
    sessionStorage.setItem(STORAGE_KEY, token);
  } catch {
    // Held for this page load only. Still usable.
  }
  return true;
}

/** Forget the token: on sign-out, and on any 401 the API client sees. */
export function signOut(): void {
  current.value = null;
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to remove.
  }
}

/**
 * The `Authorization` header value, or null when signed out.
 *
 * Deliberately the only reader of the token outside this module: a component that could
 * reach the string could also render it.
 */
export function authorization(): string | null {
  return current.value === null ? null : `Bearer ${current.value}`;
}
