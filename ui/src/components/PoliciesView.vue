<script setup lang="ts">
/**
 * The rules, with the number that decides between two of them.
 *
 * Specificity is shown because the semantics are binding and surprising: the most specific
 * matching rule wins **entirely** and inherits nothing from a broader one. A reader working
 * out why an access was refused needs the number the evaluator used, not a re-derivation of
 * it here.
 *
 * An empty capability list is an explicit denial, and it is labelled as such rather than
 * rendered as an empty cell that looks like missing data.
 */
import { onMounted, ref } from "vue";

import { ApiError, api, type Policy } from "../api";

const policies = ref<Policy[]>([]);
const problem = ref<string | null>(null);

onMounted(async () => {
  try {
    policies.value = (await api.policies()).policies;
  } catch (error) {
    problem.value = error instanceof ApiError ? error.text : "The request failed.";
  }
});
</script>

<template>
  <h1>Policies</h1>
  <p class="lead">
    As loaded. Between two rules that match a path, the more specific one — more literal segments —
    decides on its own; capabilities are not inherited from a broader rule. An empty capability list
    is a denial someone wrote deliberately.
  </p>

  <p v-if="problem" class="error">{{ problem }}</p>

  <template v-else>
    <div v-for="policy in policies" :key="policy.name" class="panel">
      <h2 class="mono">{{ policy.name }}</h2>
      <table>
        <thead>
          <tr>
            <th>Pattern</th>
            <th>Capabilities</th>
            <th class="num">Specificity</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(rule, index) in policy.rules" :key="index">
            <td class="mono">{{ rule.path }}</td>
            <td>
              <span v-if="rule.capabilities.length === 0" class="deny">denied explicitly</span>
              <span v-else class="mono">{{ rule.capabilities.join(", ") }}</span>
            </td>
            <td class="num mono">{{ rule.specificity }}</td>
          </tr>
          <tr v-if="policy.rules.length === 0">
            <td colspan="3" class="muted">No rules, so this policy grants nothing.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-if="policies.length === 0" class="panel muted">No policies.</p>
  </template>
</template>
