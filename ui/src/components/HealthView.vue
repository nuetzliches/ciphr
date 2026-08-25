<script setup lang="ts">
/**
 * Seal state and audit devices.
 *
 * The per-device state is the part worth having on a screen: auditing is fail-closed, so
 * one accepting device is enough for requests to succeed, which makes a second device that
 * refuses every write invisible from the outside. This is where it stops being invisible.
 *
 * `seal` and `key_source` are reported separately because they legitimately differ while a
 * deployment moves the master key from the environment into a file — which is exactly when
 * someone needs to see which one is in effect.
 */
import { computed, onMounted, ref } from "vue";

import { ApiError, api, type Health } from "../api";

const health = ref<Health | null>(null);
const problem = ref<string | null>(null);
const asked = ref<string | null>(null);

async function load(): Promise<void> {
  problem.value = null;
  try {
    health.value = await api.health();
    asked.value = new Date().toISOString().replace("T", " ").replace("Z", " UTC");
  } catch (error) {
    problem.value = error instanceof ApiError ? error.text : "The service could not be reached.";
  }
}

/** What the service says it could not establish. Absent and empty mean the same thing. */
const degradedParts = computed(() => health.value?.degraded ?? []);

/**
 * Sealed is a denial, degraded is a warning, and anything else is fine.
 *
 * The middle case is the one that was missing: before the service could say
 * `degraded`, an unreadable tripwire state was reported as `ok` and rendered green.
 */
const statusClass = computed(() => {
  if (health.value?.sealed) return "deny";
  return degradedParts.value.length ? "warn" : "allow";
});

onMounted(load);
</script>

<template>
  <h1>Health</h1>
  <p class="lead">
    The unauthenticated route, which deliberately reveals nothing else: no counts, no path names, no
    indication that any particular secret exists.
  </p>

  <p v-if="problem" class="error">{{ problem }}</p>

  <div v-if="health" class="panel">
    <table>
      <tbody>
        <tr>
          <th>Status</th>
          <td :class="statusClass">
            {{ health.sealed ? "sealed — no secret can be served" : health.status }}
          </td>
        </tr>
        <!--
          Only where there is something to say. `degraded` means the service is serving
          and could not establish part of what it reports on -- which is neither a denial
          nor a healthy answer, so it is `warn` and it names the part rather than leaving
          a reader to guess which field is missing.
        -->
        <tr v-if="degradedParts.length">
          <th>Could not be established</th>
          <td class="warn mono">{{ degradedParts.join(", ") }}</td>
        </tr>
        <tr>
          <th>API version</th>
          <td class="mono">{{ health.api_version }}</td>
        </tr>
        <tr>
          <th>Seal recorded in the store</th>
          <td class="mono">{{ health.seal }}</td>
        </tr>
        <tr>
          <th>Master key read from</th>
          <td class="mono">{{ health.key_source }}</td>
        </tr>
      </tbody>
    </table>

    <!--
      Only alongside the row it explains. The device table below carries its own
      note; this row had none, and an amber word with no sentence next to it is a
      thing an operator has to guess at -- which is the failure the row exists to
      prevent, moved one step along.
    -->
    <p v-if="degradedParts.length" class="note">
      <strong>Could not be established</strong> names what this process could not read about
      itself. It is still serving, and this is not an outage.
      <code>tripwires</code> means it cannot tell whether bait has been taken — a reason to look,
      not a reason to fail over.
    </p>

    <h2>Audit devices</h2>
    <table>
      <thead>
        <tr>
          <th>Device</th>
          <th>Last record</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="device in health.audit_devices" :key="device.name">
          <td class="mono">{{ device.name }}</td>
          <td
            :class="{
              muted: device.accepting === null,
              allow: device.accepting === true,
              deny: device.accepting === false,
            }"
          >
            <template v-if="device.accepting === null">
              nothing written yet by this process
            </template>
            <template v-else>{{ device.accepting ? "accepted" : "refused" }}</template>
          </td>
        </tr>
      </tbody>
    </table>
    <p class="note">
      A device that refuses is not an outage on its own — one accepting device is enough for a
      request to be served — but it is a copy of the trail that is falling behind, and the reason it
      gave is not on this route because the route is unauthenticated. The service log has it.
      <em>Nothing written yet</em> is a third state and not a healthy one: it means this process has
      recorded nothing since it started, so no device has been asked anything.
    </p>

    <p class="note">
      Asked at {{ asked }}. <button type="button" @click="load()">Ask again</button>
    </p>
  </div>
</template>
