<script setup lang="ts">
/**
 * The audit browser — the reason this package exists (plan section 15).
 *
 * Filters are sent to the service rather than applied here: the endpoint documents
 * server-side filtering because the alternative is pulling the whole trail to answer a
 * question about part of it.
 *
 * Paging is a sequence number, which is stable while the trail grows. An offset would
 * shift under the reader every time a record is written, which for this endpoint is
 * constantly.
 *
 * **It opens at the end of the trail** (`end=newest`), and that is the whole reason this
 * view is worth opening. A page taken from the oldest end is the first hundred records
 * this store ever wrote; a reader asking what happened today would have to page through
 * everything that ever happened to reach it. Which end a page comes from is the service's
 * to decide, not this view's — `after_seq` only moves forward and nothing tells a client
 * where the head is, so this could not be fixed here.
 *
 * Within a page nothing is reordered: entries are oldest first from either end, because
 * that is what `chain.ts` can check. Reading backwards is `before_seq`, which prepends.
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
/** Whether a page older than the first row shown might exist. See `load`. */
const olderMayExist = ref(false);

/**
 * Which page to ask for.
 *
 * Three requests and not one with two optional numbers: "the end of the trail", "the
 * records before this one" and "the records after this one" are the three things a reader
 * can ask for, and the service refuses a request that names two directions at once.
 */
type Page = { at: "newest" } | { before: number } | { after: number };

/** The filters as the API takes them, with the local datetime turned into epoch millis. */
function filters(page: Page): AuditFilters {
  const active: AuditFilters = { limit: limit.value };
  if ("before" in page) {
    active.before_seq = page.before;
  } else if ("after" in page) {
    active.after_seq = page.after;
  } else {
    active.end = "newest";
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

/**
 * Fetch one page and put it where it belongs.
 *
 * A backward page is prepended and a forward page appended, so what is shown stays one
 * ascending run and `checkLinkage` keeps meaning what it says — it reads the whole table,
 * not the last response.
 *
 * Whether anything older exists is answered by a short page rather than by a sequence
 * number: a trail bounded by `ciphr audit cut` does not begin at 1, so "the first row is
 * sequence 12" says nothing about whether 11 is still there to be read.
 */
async function load(page: Page): Promise<void> {
  loading.value = true;
  problem.value = null;
  try {
    const active = filters(page);
    const fetched = await api.audit(active);
    if ("before" in page) {
      entries.value = [...fetched.entries, ...entries.value];
    } else if ("after" in page) {
      entries.value = [...entries.value, ...fetched.entries];
    } else {
      entries.value = fetched.entries;
    }
    if (!("after" in page)) {
      olderMayExist.value = fetched.entries.length === limit.value;
    }
    linkage.value = checkLinkage(entries.value, narrows(active));
  } catch (error) {
    problem.value = error instanceof ApiError ? error.text : "The request failed.";
  } finally {
    loading.value = false;
  }
}

const oldest = computed(() => entries.value[0]?.seq ?? null);

const newest = computed(() =>
  entries.value.length === 0 ? null : entries.value[entries.value.length - 1]?.seq ?? null,
);

/**
 * The two continuations, from whichever records are shown.
 *
 * They read the ends of the table rather than remembering the last cursor: after a
 * prepend or an append the ends *are* the cursors, and a remembered one would be the
 * second place that has to be right.
 */
function loadOlder(): void {
  if (oldest.value !== null) {
    void load({ before: oldest.value });
  }
}

function loadNewer(): void {
  if (newest.value !== null) {
    void load({ after: newest.value });
  }
}

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

/**
 * The last column: what the action was about.
 *
 * A path for the secret actions, and for the token actions the identity the
 * credential belongs to and its non-secret id. Without this an `issue-token` row
 * says a credential was created and refuses to say for whom — which is the one
 * thing a reader of that row needs.
 */
function aboutOf(entry: AuditEntry): string {
  const record = entry.record.entry;
  if (record.path !== null && record.path !== undefined) {
    return record.path;
  }
  const subject = record.subject;
  if (subject === null || subject === undefined || subject.name === undefined) {
    return "—";
  }
  return subject.token_id === null || subject.token_id === undefined
    ? subject.name
    : `${subject.name} (${subject.token_id})`;
}

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
  void load({ at: "newest" });
});
</script>

<template>
  <h1>Audit</h1>
  <p class="lead">
    Every access, in order, as it was recorded. Filters are applied by the service. This opens at the
    <strong>end</strong> of the trail — the most recent records — and pages in both directions from
    there by sequence number rather than by an offset, so a growing trail does not shift the page
    under you. Within a page entries are oldest first, whichever end it came from, because that is
    the order the chain can be checked in.
  </p>

  <div class="panel">
    <form class="filters" @submit.prevent="load({ at: 'newest' })">
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
    <!-- Above the table, because it loads what goes above the first row. A page arrives
         in chain order and is prepended, so the table stays one run and the linkage
         badge above keeps describing all of it. -->
    <p v-if="oldest !== null" class="note">
      <button type="button" :disabled="loading || !olderMayExist" @click="loadOlder()">
        Load older
      </button>
      <!-- Not "the trail starts here": what a short page shows is that nothing older
           *matches*, and where `ciphr audit cut` bounds the trail those are the same
           answer for a reader of this endpoint. -->
      <span v-if="!olderMayExist" class="muted">nothing older matches</span>
    </p>

    <table>
      <thead>
        <tr>
          <th class="num">Seq</th>
          <th>When</th>
          <th>Identity</th>
          <th>Action</th>
          <!-- Not "Path": for the token actions this column carries the identity a
               credential was issued for and the token's id. -->
          <th>Subject</th>
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
          <td class="mono">{{ aboutOf(entry) }}</td>
          <td :class="entry.record.entry.allowed ? 'allow' : 'deny'">{{ outcomeOf(entry) }}</td>
          <td class="num mono">{{ entry.record.entry.request?.http_status ?? "—" }}</td>
        </tr>
        <tr v-if="entries.length === 0 && !loading">
          <td colspan="7" class="muted">No entries match.</td>
        </tr>
      </tbody>
    </table>

    <p v-if="newest !== null" class="note">
      <!-- Forward from the last row shown. On a view that opens at the end this is
           usually empty and occasionally is not, which is the point: it picks up what
           was written while you were reading. -->
      <button type="button" :disabled="loading" @click="loadNewer()">
        Load newer
      </button>
      showing {{ entries.length }} entries, sequence {{ oldest }} to {{ newest }}
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
