<script setup lang="ts">
/**
 * The shell: the sign-in gate, or the header plus one view.
 *
 * Views are switched with `v-if` rather than kept alive, so leaving a view destroys its
 * component state. That is what makes "revealed plaintext is removed from component state
 * when leaving the view" (plan section 15) a property of the structure rather than a rule
 * someone has to remember in `SecretsView`.
 */
import { signOut, signedIn, tokenId } from "./session";
import { VIEWS, go, view } from "./router";
import TokenGate from "./components/TokenGate.vue";
import AuditView from "./components/AuditView.vue";
import SecretsView from "./components/SecretsView.vue";
import IdentitiesView from "./components/IdentitiesView.vue";
import PoliciesView from "./components/PoliciesView.vue";
import HealthView from "./components/HealthView.vue";

const titles: Record<string, string> = {
  audit: "Audit",
  secrets: "Secrets",
  identities: "Identities",
  policies: "Policies",
  health: "Health",
};
</script>

<template>
  <TokenGate v-if="!signedIn" />

  <template v-else>
    <header class="top">
      <span class="brand">ciphr<span class="role">viewer</span></span>

      <nav class="tabs">
        <button
          v-for="name in VIEWS"
          :key="name"
          type="button"
          :class="{ on: view === name }"
          @click="go(name)"
        >
          {{ titles[name] }}
        </button>
      </nav>

      <div class="session">
        <span class="mono" title="The non-secret identifier of the token in use">
          token {{ tokenId }}
        </span>
        <button type="button" @click="signOut()">Sign out</button>
      </div>
    </header>

    <main>
      <AuditView v-if="view === 'audit'" />
      <SecretsView v-else-if="view === 'secrets'" />
      <IdentitiesView v-else-if="view === 'identities'" />
      <PoliciesView v-else-if="view === 'policies'" />
      <HealthView v-else-if="view === 'health'" />
    </main>
  </template>
</template>
