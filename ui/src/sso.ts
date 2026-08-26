/**
 * Sign-in through an identity provider (ADR-12's second half, ADR-26's machinery).
 *
 * ADR-12 scheduled this from the beginning — *"token paste in v1, SSO afterwards"* — and
 * said which shape it would take: *"the same OIDC validation as the Actions
 * authentication method — one implementation, two callers"*. That is exactly what this
 * is. Everything that decides whether a token is acceptable is on the server, in
 * `POST /v1/auth/oidc/login`; a human identity is one whose `kind` is `human` in the
 * policy file, and nothing here knows the difference.
 *
 * # Why the ID token arrives in a fragment
 *
 * The obvious flow today is authorization code with PKCE, and it cannot be used here
 * without giving something up. The exchange step is a request to the *provider's* token
 * endpoint, and this page is served under
 * `default-src 'none'; connect-src 'self'` — so a cross-origin `fetch` is a broken page,
 * not a slow one. The three ways out, and what each costs:
 *
 * - **Widen `connect-src` to the provider's origin.** The viewer's policy becomes
 *   deployment-specific and has to be templated at container start, and the strictest
 *   line in it stops being static. It also needs the provider to send CORS headers on its
 *   token endpoint, which several do not.
 * - **Let the server exchange the code.** That puts an outbound HTTP client and public-CA
 *   trust into the process that holds plaintext secrets — the position ADR-17 refused for
 *   the ACME client and ADR-26 refused again for a JWKS fetch.
 * - **Ask for the ID token directly**, which is what this does.
 *
 * So: `response_type=id_token`, and the token comes back in the URL fragment. **What that
 * costs, stated rather than discovered:** the token exists for a moment in
 * `location.hash`, which means it reaches the session-history entry for this page. It is
 * never sent to a server as part of a URL — a fragment is not transmitted — and the
 * fragment is cleared with `history.replaceState` before the exchange request is made, so
 * the window is the length of one function. OAuth 2.1 discourages this response type, and
 * the reason it gives is access-token leakage through exactly that channel; an ID token
 * bound to a `nonce` and spent immediately is the narrow case where the objection is
 * weakest, and it is still an objection.
 *
 * # What the nonce buys, and what it does not
 *
 * The nonce is generated here, sent in the authorization request, and compared against the
 * one in the returned token. It answers *"was this token minted for the request this tab
 * made"*, and only this tab can answer that — which is why the check is here and not on
 * the server. The server is stateless, so an expected nonce passed to it would be one the
 * caller declared, proving nothing.
 *
 * It does **not** stand in for verification. The payload is decoded here without checking
 * the signature, and nothing is trusted on the strength of that: a token that passes the
 * check is then verified by the server, which is the only party holding the provider's
 * keys.
 *
 * # Absent by design
 *
 * The server must keep working with no provider configured, and the viewer must keep
 * working for a deployment that has none (ADR-11 makes the viewer optional; this must not
 * make the provider mandatory). So the configuration below is *the viewer's own*, fetched
 * from its own origin, and its absence is the ordinary case: no file, no button, token
 * paste exactly as before. A viewer route on the service would have been an endpoint that
 * exists for the UI alone, which ADR-11 rules out.
 */
import { ref } from "vue";

/** Where a deployment mounts the provider's details. Same origin, so `connect-src 'self'`. */
const CONFIG_PATH = "/sso.json";

const NONCE_KEY = "ciphr.sso.nonce";
const STATE_KEY = "ciphr.sso.state";

/**
 * What a deployment writes into `/sso.json`.
 *
 * No client secret, and there is nowhere one could go: this is a public client, which is
 * why the nonce rather than a credential is what binds the response to the request.
 */
export interface Provider {
  /** What to call it on the button. */
  name: string;
  /** The provider's authorization endpoint. */
  authorization_endpoint: string;
  /**
   * The client identifier this viewer is registered as.
   *
   * **The service's `[[auth.oidc]] audience` has to be this string**, because a provider
   * sets an ID token's `aud` to the client it issued it for. A mismatch is a `401` that
   * the audit trail explains as `audience-mismatch`.
   */
  client_id: string;
  /** Scopes to ask for. `openid` alone is enough and is the default. */
  scope?: string;
}

/** The configured provider, or null where a deployment mounted no file. */
export const provider = ref<Provider | null>(null);

/** What went wrong, in words for a person. Never carries any part of a token. */
export const complaint = ref<string | null>(null);

/**
 * Read `/sso.json`, if there is one.
 *
 * Every failure is the same answer — no provider — because they are the same situation
 * for the person looking at the page: token paste is available and the button is not. A
 * deployment that meant to configure a provider finds out from the button's absence,
 * which is the one signal that cannot be missed.
 */
export async function load(): Promise<void> {
  try {
    const response = await fetch(CONFIG_PATH, {
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) {
      return;
    }
    const body = (await response.json()) as Partial<Provider>;
    if (
      typeof body.name !== "string" ||
      typeof body.authorization_endpoint !== "string" ||
      typeof body.client_id !== "string"
    ) {
      return;
    }
    provider.value = {
      name: body.name,
      authorization_endpoint: body.authorization_endpoint,
      client_id: body.client_id,
      scope: typeof body.scope === "string" ? body.scope : "openid",
    };
  } catch {
    // No file, not JSON, or a proxy answering for it. All of them mean the same thing.
  }
}

/** Where the provider sends the browser back: this document, with nothing after it. */
function redirectUri(): string {
  return `${window.location.origin}${window.location.pathname}`;
}

/** 32 bytes from the browser's CSPRNG, as unpadded base64url. */
function random(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let text = "";
  for (const byte of bytes) {
    text += String.fromCharCode(byte);
  }
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Leave for the provider.
 *
 * A top-level navigation rather than a form submission: `form-action 'none'` refuses the
 * second, and this page has no reason to submit anything anywhere.
 */
export function begin(): void {
  const configured = provider.value;
  if (configured === null) {
    return;
  }

  const nonce = random();
  const state = random();
  try {
    sessionStorage.setItem(NONCE_KEY, nonce);
    sessionStorage.setItem(STATE_KEY, state);
  } catch {
    // Without somewhere to keep them there is nothing to compare the response against,
    // and a flow that cannot check its own response is worse than no flow.
    complaint.value =
      "This browser is not keeping session storage, so the sign-in response could not be " +
      "checked against the request that asked for it. Paste a token instead.";
    return;
  }

  const url = new URL(configured.authorization_endpoint);
  url.searchParams.set("response_type", "id_token");
  url.searchParams.set("client_id", configured.client_id);
  url.searchParams.set("redirect_uri", redirectUri());
  url.searchParams.set("scope", configured.scope ?? "openid");
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("state", state);

  window.location.assign(url.toString());
}

/** The `nonce` claim of an unverified payload, or null if there is not one. */
function claimedNonce(idToken: string): string | null {
  const parts = idToken.split(".");
  const payload = parts.length === 3 ? parts[1] : undefined;
  if (payload === undefined) {
    return null;
  }
  try {
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    const claims = JSON.parse(new TextDecoder().decode(bytes)) as { nonce?: unknown };
    return typeof claims.nonce === "string" ? claims.nonce : null;
  } catch {
    return null;
  }
}

/** Take the fragment off the address bar, keeping the rest of the URL. */
function clearFragment(): void {
  try {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  } catch {
    // A browser that refuses is a browser where the fragment stays. Nothing else changes.
  }
}

/**
 * Handle a return from the provider, if this page load is one.
 *
 * Returns the ID token to exchange, or null when there is nothing to do — which is every
 * ordinary page load. **The fragment is cleared before this returns**, so the token exists
 * only in the value handed back.
 */
export function idTokenFromFragment(): string | null {
  const fragment = window.location.hash.replace(/^#/, "");
  if (fragment === "" || !fragment.includes("=")) {
    return null;
  }

  const returned = new URLSearchParams(fragment);
  const error = returned.get("error");
  const idToken = returned.get("id_token");
  if (error === null && idToken === null) {
    // An ordinary `#/audit` fragment. Not ours.
    return null;
  }

  const expectedNonce = read(NONCE_KEY);
  const expectedState = read(STATE_KEY);
  forget();
  clearFragment();

  if (error !== null) {
    // The provider's own words, truncated: it is describing a request this page made, and
    // a provider that returns a paragraph should not be able to fill the page with it.
    const description = returned.get("error_description");
    complaint.value = `The provider refused the sign-in: ${(description ?? error).slice(0, 200)}`;
    return null;
  }

  if (idToken === null || expectedState === null || returned.get("state") !== expectedState) {
    complaint.value =
      "That sign-in response does not match the request this tab made, so it was discarded. " +
      "Start again, or paste a token.";
    return null;
  }

  if (expectedNonce === null || claimedNonce(idToken) !== expectedNonce) {
    complaint.value =
      "That sign-in response was issued for a different request, so it was discarded. " +
      "Start again, or paste a token.";
    return null;
  }

  complaint.value = null;
  return idToken;
}

function read(key: string): string | null {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function forget(): void {
  try {
    sessionStorage.removeItem(NONCE_KEY);
    sessionStorage.removeItem(STATE_KEY);
  } catch {
    // Nothing to remove.
  }
}
