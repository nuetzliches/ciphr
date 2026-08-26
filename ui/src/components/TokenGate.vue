<script setup lang="ts">
/**
 * Sign-in: a provider, or a pasted token (ADR-12).
 *
 * **Paste is not the fallback and does not become one.** ADR-12 scheduled SSO from the
 * start, and the same record makes the viewer's optionality real (ADR-11) — so a
 * deployment with no provider has to keep working, and it does: no `/sso.json`, no
 * button, the form below unchanged. The panels are ordered so the provider comes first
 * where there is one, because that is the path that removes a human's long-lived token.
 *
 * The unauthenticated health route is shown here on purpose. It reveals nothing — no
 * counts, no path names, no indication that any secret exists — and it answers the
 * question a person actually has when a sign-in fails: is the service even up, and is it
 * sealed.
 */
import { onMounted, ref } from "vue";

import { ApiError, api, type Health } from "../api";
import { looksLikeToken, signIn } from "../session";
import {
  begin as beginSso,
  complaint as ssoComplaint,
  idTokenFromFragment,
  load as loadSso,
  provider,
} from "../sso";

const pasted = ref("");
const complaint = ref<string | null>(null);
const health = ref<Health | null>(null);
const healthProblem = ref<string | null>(null);
const exchanging = ref(false);

onMounted(async () => {
  // The return leg first, before anything else can be waited on: the fragment is read and
  // cleared synchronously, so the token spends no time in the address bar while a network
  // request is outstanding.
  const idToken = idTokenFromFragment();

  const asked = api.health().then(
    (answer) => {
      health.value = answer;
    },
    (error: unknown) => {
      healthProblem.value =
        error instanceof ApiError ? error.text : "The service could not be reached.";
    },
  );

  // Before the exchange rather than after it, so a refused sign-in leaves a page with the
  // button still on it. The fragment was already cleared above, so this delay costs
  // nothing that was at risk.
  await loadSso();

  if (idToken !== null) {
    exchanging.value = true;
    try {
      const federated = await api.federate(idToken);
      // Straight into the session. The value is not put in a ref, held in a field, or
      // logged: `signIn` is the only thing that keeps a token, and it keeps it where
      // `authorization()` is the only reader.
      signIn(federated.token);
      return;
    } catch (error) {
      ssoComplaint.value =
        error instanceof ApiError && error.status === 404
          ? "This deployment does not accept a provider sign-in. Paste a token instead."
          : "The service did not accept that sign-in. Paste a token, or try again.";
    } finally {
      exchanging.value = false;
    }
  }

  await asked;
});

function submit(): void {
  if (!looksLikeToken(pasted.value)) {
    complaint.value =
      "That is not the shape of a ciphr token: cph_ followed by 8 characters of identifier and 43 of secret. Nothing was sent.";
    return;
  }
  complaint.value = null;
  // Cleared before the token is stored, so the field never holds it while a view renders.
  const token = pasted.value;
  pasted.value = "";
  signIn(token);
}
</script>

<template>
  <div class="gate">
    <h1>ciphr — viewer</h1>
    <p class="lead">
      A read-only view of the audit trail, secret metadata, identities, and policies. Nothing here
      writes: no secret is created or deleted, no policy or identity changed, no token issued or
      revoked. Those stay with the CLI.
    </p>

    <div v-if="provider" class="panel">
      <h2>Sign in with {{ provider.name }}</h2>
      <p class="note">
        The provider vouches for who you are; this deployment decides what that identity may
        read. What comes back is a ciphr token that lives minutes and is gone when the tab
        closes — nothing long-lived is written down anywhere.
      </p>

      <button type="button" class="primary" :disabled="exchanging" @click="beginSso()">
        <template v-if="exchanging">Signing in…</template>
        <template v-else>Continue to {{ provider.name }}</template>
      </button>

      <p v-if="ssoComplaint" class="error">{{ ssoComplaint }}</p>
    </div>

    <div class="panel">
      <h2>Sign in with a token</h2>
      <p class="note">
        A personal token for an identity of kind <code>human</code>, issued with
        <code>ciphr token issue &lt;identity&gt; --ttl 8h</code>. It is kept for this browser tab
        only and is gone when the tab closes.
      </p>

      <form @submit.prevent="submit">
        <label>
          Token
          <input
            v-model="pasted"
            class="wide mono"
            type="password"
            autocomplete="off"
            spellcheck="false"
            placeholder="cph_…"
          />
        </label>
        <button type="submit" class="primary">Sign in</button>
      </form>

      <p v-if="complaint" class="error">{{ complaint }}</p>

      <p class="note">
        What you can see is exactly what your identity's policy allows — the viewer holds no
        privileges of its own, and revealing a value produces an audit entry naming this token.
      </p>
    </div>

    <div class="panel">
      <h2>Service</h2>
      <p v-if="healthProblem" class="error">{{ healthProblem }}</p>
      <table v-else-if="health">
        <tbody>
          <tr>
            <th>Status</th>
            <td>
              <span :class="health.sealed ? 'deny' : 'allow'">
                {{ health.sealed ? "sealed — serving nothing" : health.status }}
              </span>
            </td>
          </tr>
          <tr>
            <th>API</th>
            <td class="mono">{{ health.api_version }}</td>
          </tr>
          <tr>
            <th>Seal</th>
            <td class="mono">{{ health.seal }} / key from {{ health.key_source }}</td>
          </tr>
          <tr>
            <th>Audit devices</th>
            <td>
              <span v-for="device in health.audit_devices" :key="device.name" class="badge">
                {{ device.name }}:
                <span
                  :class="{
                    muted: device.accepting === null,
                    allow: device.accepting === true,
                    deny: device.accepting === false,
                  }"
                >
                  <template v-if="device.accepting === null">nothing written yet</template>
                  <template v-else>{{ device.accepting ? "accepting" : "refusing" }}</template>
                </span>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">Asking…</p>
    </div>
  </div>
</template>
