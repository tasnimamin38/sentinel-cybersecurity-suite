import test from "node:test";
import assert from "node:assert/strict";
import { fetchPublicPlanCatalog } from "./plancatalog.js";

const catalogue = { catalog_version: 1, launch_mode: "early_access", plans: [], notice: "Live" };

test("public catalogue fetch requests only the public plans endpoint", async () => {
  const calls = [];
  const signal = new AbortController().signal;
  const result = await fetchPublicPlanCatalog(async (...args) => {
    calls.push(args);
    return { ok: true, json: async () => catalogue };
  }, "/api", signal);
  assert.deepEqual(result, catalogue);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "/api/api/v1/plans");
  assert.equal(calls[0][1].method, "GET");
  assert.deepEqual(calls[0][1].headers, { Accept: "application/json" });
  assert.equal(calls[0][1].signal, signal);
  assert.equal("X-API-Key" in calls[0][1].headers, false);
});

test("non-OK public catalogue responses reject with a safe message", async () => {
  await assert.rejects(
    () => fetchPublicPlanCatalog(async () => ({ ok: false, status: 503 }), "", undefined),
    /Plan details temporarily unavailable/,
  );
});

test("network failures propagate instead of becoming an empty catalogue", async () => {
  const failure = new Error("offline");
  await assert.rejects(
    () => fetchPublicPlanCatalog(async () => { throw failure; }, "", undefined),
    (error) => error === failure,
  );
});
