<script setup lang="ts">
/**
 * Secret metadata, and one revealed value at a time.
 *
 * The rules from plan section 15, and where each one lives:
 *
 * - **Reveal is always a single action.** There is one `revealed` ref, so a second reveal
 *   replaces the first. No "show all" exists, and no list renders a value.
 * - **Plaintext leaves component state on leaving the view.** `App.vue` destroys this
 *   component when the tab changes; `onUnmounted` clears the ref for the case where the
 *   component is reused, and picking another path or version clears it too.
 * - **Plaintext never reaches a URL, `localStorage`, or global state.** Nothing here
 *   writes it anywhere; the selected path is component state, not a route parameter.
 *
 * There is deliberately no copy button. The clipboard is a place a value survives the tab,
 * the session, and the person's attention, with no expiry — the same argument that keeps
 * the token out of `localStorage`. Taking a value somewhere is what the CLI is for.
 *
 * A prefix has to be given because `/v1/list/{prefix}` takes one: a prefix is not a path
 * anyone holds a rule about, so there is no "list everything" call to make. The endpoint
 * returns exactly the paths this identity may see, and an empty result is
 * indistinguishable from an empty prefix — which is the intended behaviour, not a gap.
 */
import { onUnmounted, ref } from "vue";

import { ApiError, api, type Classification, type Secret, type VersionSummary } from "../api";

const prefix = ref("");
const paths = ref<string[]>([]);
const listed = ref<string | null>(null);
const listProblem = ref<string | null>(null);
const listing = ref(false);

const chosen = ref<string | null>(null);
const versions = ref<VersionSummary[]>([]);
const rotation = ref<Classification | null>(null);
const versionProblem = ref<string | null>(null);

const revealed = ref<Secret | null>(null);
const revealProblem = ref<string | null>(null);
const revealing = ref(false);

function forget(): void {
  revealed.value = null;
  revealProblem.value = null;
}

onUnmounted(forget);

async function list(): Promise<void> {
  listing.value = true;
  listProblem.value = null;
  forget();
  chosen.value = null;
  versions.value = [];
  rotation.value = null;
  try {
    const result = await api.list(prefix.value.trim().replace(/^\/+|\/+$/g, ""));
    paths.value = result.paths;
    listed.value = result.prefix;
  } catch (error) {
    paths.value = [];
    listed.value = null;
    listProblem.value = error instanceof ApiError ? error.text : "The request failed.";
  } finally {
    listing.value = false;
  }
}

async function choose(path: string): Promise<void> {
  chosen.value = path;
  forget();
  versionProblem.value = null;
  versions.value = [];
  rotation.value = null;
  try {
    const history = await api.versions(path);
    versions.value = history.versions;
    rotation.value = history.rotation;
  } catch (error) {
    versionProblem.value = error instanceof ApiError ? error.text : "The request failed.";
  }
}

async function reveal(version: number): Promise<void> {
  if (chosen.value === null) {
    return;
  }
  revealing.value = true;
  // The previous value goes before the request, not after it: a failure must not leave the
  // last one on screen looking like the answer to what was just asked.
  forget();
  try {
    revealed.value = await api.reveal(chosen.value, version);
  } catch (error) {
    revealProblem.value = error instanceof ApiError ? error.text : "The request failed.";
  } finally {
    revealing.value = false;
  }
}

function when(millis: number): string {
  return new Date(millis).toISOString().replace("T", " ").replace("Z", " UTC");
}
</script>

<template>
  <h1>Secrets</h1>
  <p class="lead">
    Paths, versions, and who wrote them. No value is shown until you ask for one, one at a time — and
    asking produces an audit entry naming your token, exactly as a machine read would.
  </p>

  <div class="panel">
    <form class="filters" @submit.prevent="list()">
      <label>
        Prefix
        <input v-model="prefix" class="wide mono" type="text" placeholder="infra/service-a" />
      </label>
      <button type="submit" class="primary" :disabled="listing">
        {{ listing ? "Listing…" : "List" }}
      </button>
    </form>
    <p class="note">
      A prefix is required: the API lists under a prefix and authorizes every returned path on its
      own, so there is no call that means "everything". You see the paths your policy allows you to
      list, and nothing about the ones it does not.
    </p>
    <p v-if="listProblem" class="error">{{ listProblem }}</p>
  </div>

  <div v-if="listed !== null" class="split">
    <div class="panel">
      <h2>{{ paths.length }} under {{ listed }}</h2>
      <table>
        <tbody>
          <tr
            v-for="path in paths"
            :key="path"
            :class="{ picked: chosen === path }"
            @click="choose(path)"
          >
            <td class="mono">{{ path }}</td>
          </tr>
          <tr v-if="paths.length === 0">
            <td class="muted">Nothing here that you may list.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="chosen" class="panel">
      <h2 class="mono">{{ chosen }}</h2>

      <!--
        Above the versions, not beside them: the class is a property of the secret,
        and it is what a reader needs *before* deciding to write a new version. The
        wording comes from the service so that it cannot drift from what the CLI
        prints at the same moment.
      -->
      <p v-if="rotation" class="rotation">
        <span :class="rotation.needs_care ? 'warn' : 'allow'">{{ rotation.class }}</span>
        <span class="note">{{ rotation.advice }}</span>
      </p>

      <p v-if="versionProblem" class="error">{{ versionProblem }}</p>
      <table v-else>
        <thead>
          <tr>
            <th class="num">Version</th>
            <th>Written</th>
            <th>By</th>
            <th>State</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in versions" :key="entry.version">
            <td class="num mono">{{ entry.version }}</td>
            <td class="mono">{{ when(entry.created_at) }}</td>
            <td>{{ entry.created_by }}</td>
            <td>
              <span v-if="entry.destroyed" class="deny">destroyed</span>
              <span v-else-if="entry.deleted" class="warn">deleted</span>
              <span v-else class="allow">readable</span>
            </td>
            <td>
              <button
                type="button"
                :disabled="entry.destroyed || revealing"
                :title="
                  entry.destroyed
                    ? 'The wrapped key is gone: this version cannot be read by anyone, including from a backup'
                    : 'Read this one value. Produces an audit entry.'
                "
                @click="reveal(entry.version)"
              >
                Reveal
              </button>
            </td>
          </tr>
          <tr v-if="versions.length === 0">
            <td colspan="5" class="muted">No versions.</td>
          </tr>
        </tbody>
      </table>

      <p v-if="revealProblem" class="error">{{ revealProblem }}</p>

      <div v-if="revealed" class="reveal">
        <strong class="warn">Plaintext</strong>
        <span class="muted">
          — {{ revealed.path }} version {{ revealed.version }}, written by
          {{ revealed.created_by }}
        </span>
        <pre>{{ revealed.value }}</pre>
        <p class="note">
          On screen until you hide it or leave this view. It is not copied anywhere, and reloading
          the page will not bring it back — reading it again is another audit entry, which is the
          point.
        </p>
        <button type="button" @click="forget()">Hide</button>
      </div>
    </div>
  </div>
</template>
