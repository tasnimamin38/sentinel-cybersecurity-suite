import test from "node:test";
import assert from "node:assert/strict";
import worker from "./worker.js";

const apiOrigin = "https://sentinel-staging-api-q2nk.onrender.com";

test("edge health endpoint returns a no-store health response", async () => {
  const response = await worker.fetch(
    new Request("https://sentinel-api.tasnimamin38.workers.dev/__sentinel/edge-health"),
    { SENTINEL_API_ORIGIN: apiOrigin },
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    status: "ok",
    service: "sentinel-api-edge-proxy",
    upstreamConfigured: true,
  });
});

test("proxies path, query and API credentials to the fixed upstream", async () => {
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (request) => {
    captured = request;
    return new Response('{"ok":true}', {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  try {
    const response = await worker.fetch(
      new Request(
        "https://sentinel-api.tasnimamin38.workers.dev/api/v1/assets?limit=10",
        { headers: { "x-api-key": "test-key", "x-forwarded-host": "spoofed.example" } },
      ),
      { SENTINEL_API_ORIGIN: apiOrigin },
    );

    assert.equal(response.status, 200);
    assert.equal(captured.url, `${apiOrigin}/api/v1/assets?limit=10`);
    assert.equal(captured.headers.get("x-api-key"), "test-key");
    assert.equal(
      captured.headers.get("x-forwarded-host"),
      "sentinel-api.tasnimamin38.workers.dev",
    );
    assert.equal(captured.headers.get("host"), null);
    assert.deepEqual(await response.json(), { ok: true });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("streams POST bodies without changing the API path", async () => {
  const originalFetch = globalThis.fetch;
  let capturedBody;
  let capturedUrl;
  globalThis.fetch = async (request) => {
    capturedUrl = request.url;
    capturedBody = await request.text();
    return new Response("accepted", { status: 202 });
  };

  try {
    const response = await worker.fetch(
      new Request(
        "https://sentinel-api.tasnimamin38.workers.dev/api/v1/assessments",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ target: "example.com" }),
        },
      ),
      { SENTINEL_API_ORIGIN: apiOrigin },
    );
    assert.equal(response.status, 202);
    assert.equal(capturedUrl, `${apiOrigin}/api/v1/assessments`);
    assert.deepEqual(JSON.parse(capturedBody), { target: "example.com" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects an unapproved upstream instead of proxying it", async () => {
  const originalFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return new Response("unexpected");
  };

  try {
    const response = await worker.fetch(
      new Request("https://sentinel-api.tasnimamin38.workers.dev/api/v1/config"),
      { SENTINEL_API_ORIGIN: "https://attacker.example" },
    );
    assert.equal(response.status, 503);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("returns a bounded 502 response when the upstream fetch fails", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("internal networking detail");
  };

  try {
    const response = await worker.fetch(
      new Request("https://sentinel-api.tasnimamin38.workers.dev/healthz"),
      { SENTINEL_API_ORIGIN: apiOrigin },
    );
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), {
      detail: "SENTINEL API upstream is unavailable.",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
