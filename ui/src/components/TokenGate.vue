<script setup lang="ts">
/**
 * Sign-in: paste a token (ADR-12).
 *
 * The unauthenticated health route is shown here on purpose. It reveals nothing — no
 * counts, no path names, no indication that any secret exists — and it answers the
 * question a person actually has when a paste fails: is the service even up, and is it
 * sealed.
 */
import { onMounted, ref } from "vue";

import { ApiError, api, type Health } from "../api";
import { looksLikeToken, signIn } from "../session";

const pasted = ref("");
const complaint = ref<string | null>(null);
const health = ref<Health | null>(null);
const healthProblem = ref<string | null>(null);

onMounted(async () => {
  try {
    health.value = await api.health();
  } catch (error) {
    healthProblem.value = error instanceof ApiError ? error.text : "The service could not be reached.";
  }
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
