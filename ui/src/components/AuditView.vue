<script setup lang="ts">
/**
 * The audit browser — the reason this package exists (plan section 15).
 *
 * Filters are sent to the service rather than applied here: the endpoint documents
 * server-side filtering because the alternative is pulling the whole trail to answer a
 * question about part of it.
 *
 * Paging is `after_seq`, which is stable while the trail grows. An offset would shift
 * under the reader every time a record is written, which for this endpoint is constantly.
 */
import { computed, onMounted, ref } from "vue";

import { ApiError, api, narrows, type AuditEntry, type AuditFilters } from "../api";
import { checkLinkage, type Linkage } from "../chain";

const identity = ref("");
const path = ref("");
const decision = ref<"" | "allow" | "deny">("");
const since = ref("");
const limit = ref(100);

const entries = ref<AuditEntry[]>([]);
const linkage = ref<Linkage | null>(null);
const problem = ref<string | null>(null);
const loading = ref(false);
const picked = ref<number | null>(null);

/** The filters as the API takes them, with the local datetime turned into epoch millis. */
function filters(afterSeq?: number): AuditFilters {
  const active: AuditFilters = { limit: limit.value };
  if (afterSeq !== undefined) {
    active.after_seq = afterSeq;
  }
  if (identity.value !== "") {
    active.identity = identity.value;
  }
  if (path.value !== "") {
    active.path = path.value;
  }
  if (decision.value !== "") {
    active.decision = decision.value;
  }
  if (since.value !== "") {
    const millis = Date.parse(since.value);
    if (!Number.isNaN(millis)) {
      active.since = millis;
    }
  }
  return active;
}

async function load(afterSeq?: number): Promise<void> {
  loading.value = true;
  problem.value = null;
  try {
    const active = filters(afterSeq);
    const page = await api.audit(active);
    entries.value = afterSeq === undefined ? page.entries : [...entries.value, ...page.entries];
    linkage.value = checkLinkage(entries.value, narrows(active));
  } catch (error) {
    problem.value = error instanceof ApiError ? error.text : "The request failed.";
  } finally {
    loading.value = false;
  }
}

const newest = computed(() =>
  entries.value.length === 0 ? null : entries.value[entries.value.length - 1]?.seq ?? null,
);

const shownRecord = computed(() =>
  picked.value === null ? null : (entries.value.find((entry) => entry.seq === picked.value) ?? null),
);

/**
 * The entry as stored, formatted for reading.
 *
 * Shown so that a person can see the record the hash covers, rather than a rearranged
 * view of it. `chain.ts` explains why the viewer does not recompute the hash from this.
 */
const shownJson = computed(() =>
  shownRecord.value === null ? "" : JSON.stringify(shownRecord.value.record, null, 2),
);

function principalOf(entry: AuditEntry): string {
  const principal = entry.record.entry.principal;
  if (principal === null || principal === undefined || principal.name === undefined) {
    return "—";
  }
  return principal.kind === undefined || principal.kind === null
    ? principal.name
    : `${principal.name} (${principal.kind})`;
}

function outcomeOf(entry: AuditEntry): string {
  const record = entry.record.entry;
  if (record.results !== null && record.results !== undefined) {
    // A listing authorizes per returned item, so `allowed` there means the operation ran.
    return `${record.results} shown`;
  }
  if (record.allowed) {
    return record.rule?.pattern === undefined ? "allow" : `allow · ${record.rule.pattern}`;
  }
  return record.deny_reason === null || record.deny_reason === undefined
    ? "deny"
    : `deny · ${record.deny_reason}`;
}

onMounted(() => {
  void load();
});
</script>

<template>
  <h1>Audit</h1>
  <p class="lead">
    Every access, in order, as it was recorded. Filters are applied by the service; entries are shown
    oldest first, and <em>Load more</em> continues from the last sequence number rather than an
    offset, so a growing trail does not shift the page under you.
  </p>

  <div class="panel">
    <form class="filters" @submit.prevent="load()">
      <label>
        Identity
        <input v-model="identity" type="text" placeholder="deploy-runner" />
      </label>
      <label>
        Path (exact)
        <input v-model="path" class="wide mono" type="text" placeholder="infra/service-a/DB_PASSWORD" />
      </label>
      <label>
        Decision
        <select v-model="decision">
          <option value="">any</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </label>
      <label>
        Since
        <input v-model="since" type="datetime-local" />
      </label>
      <label>
        Limit
        <input v-model.number="limit" type="number" min="1" max="1000" />
      </label>
      <button type="submit" class="primary" :disabled="loading">
        {{ loading ? "Loading…" : "Apply" }}
      </button>
    </form>
  </div>

  <p v-if="problem" class="error">{{ problem }}</p>

  <div v-if="linkage" class="panel">
    <h2>
      Chain
      <span
        class="badge"
        :class="{
          allow: linkage.status === 'linked',
          deny: linkage.status === 'broken',
          muted: linkage.status === 'not-checked',
        }"
        >{{ linkage.status }}</span
      >
    </h2>
    <p class="note">{{ linkage.summary }}</p>
    <ul v-if="linkage.problems.length > 0">
      <li v-for="(trouble, index) in linkage.problems" :key="index" class="deny mono">
        {{ trouble }}
      </li>
    </ul>
  </div>

  <div class="panel">
    <table>
      <thead>
        <tr>
          <th class="num">Seq</th>
          <th>When</th>
          <th>Identity</th>
          <th>Action</th>
          <th>Path</th>
          <th>Outcome</th>
          <th class="num">HTTP</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="entry in entries"
          :key="entry.seq"
          :class="{ picked: picked === entry.seq }"
          @click="picked = picked === entry.seq ? null : entry.seq"
        >
          <td class="num mono">{{ entry.seq }}</td>
          <td class="mono">{{ entry.record.ts }}</td>
          <td>{{ principalOf(entry) }}</td>
          <td class="mono">{{ entry.record.entry.action }}</td>
          <td class="mono">{{ entry.record.entry.path ?? "—" }}</td>
          <td :class="entry.record.entry.allowed ? 'allow' : 'deny'">{{ outcomeOf(entry) }}</td>
          <td class="num mono">{{ entry.record.entry.request?.http_status ?? "—" }}</td>
        </tr>
        <tr v-if="entries.length === 0 && !loading">
          <td colspan="7" class="muted">No entries match.</td>
        </tr>
      </tbody>
    </table>

    <p v-if="newest !== null" class="note">
      <button type="button" :disabled="loading" @click="load(newest ?? undefined)">Load more</button>
      showing {{ entries.length }} entries, up to sequence {{ newest }}
    </p>
  </div>

  <div v-if="shownRecord" class="panel">
    <h2>Record {{ shownRecord.seq }}, as stored</h2>
    <p class="note">
      hash <code>{{ shownRecord.hash }}</code>
    </p>
    <pre class="mono">{{ shownJson }}</pre>
    <p class="note">
      This is the exact record the hash covers. Recomputing it is
      <code>ciphr audit verify</code>; proving the chain was not rewritten as a whole is
      <code>ciphr audit verify --anchor</code> against a head recorded outside the store.
    </p>
  </div>
</template>
