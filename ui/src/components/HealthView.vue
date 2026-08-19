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
import { onMounted, ref } from "vue";

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
          <td :class="health.sealed ? 'deny' : 'allow'">
            {{ health.sealed ? "sealed — no secret can be served" : health.status }}
          </td>
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
