<script setup lang="ts">
/**
 * Who exists and what they hold.
 *
 * Read-only, and not because writing was left for later: identities live in the policy
 * file, which is authoritative (ADR-3). A create form here would need a policy-write API —
 * the most dangerous API this project could have — so the view makes misconfiguration
 * visible without making it creatable.
 */
import { onMounted, ref } from "vue";

import { ApiError, api, type Identity } from "../api";

const identities = ref<Identity[]>([]);
const problem = ref<string | null>(null);

onMounted(async () => {
  try {
    identities.value = (await api.identities()).identities;
  } catch (error) {
    problem.value = error instanceof ApiError ? error.text : "The request failed.";
  }
});
</script>

<template>
  <h1>Identities</h1>
  <p class="lead">
    As loaded from the policy file. That file is the only place identities are defined; nothing in
    this viewer or in the API can add one, and a token can only ever belong to an identity that is
    already there.
  </p>

  <p v-if="problem" class="error">{{ problem }}</p>

  <div v-else class="panel">
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Kind</th>
          <th>Policies</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="identity in identities" :key="identity.name">
          <td class="mono">{{ identity.name }}</td>
          <td>{{ identity.kind }}</td>
          <td class="mono">{{ identity.policies.join(", ") || "—" }}</td>
        </tr>
        <tr v-if="identities.length === 0">
          <td colspan="3" class="muted">No identities.</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
