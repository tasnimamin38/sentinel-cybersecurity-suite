import test from "node:test";
import assert from "node:assert/strict";
import worker from "./worker.js";

const TEST_SECRET = "test-only-secret-value-0123456789abcdef";

test("scheduled tick sends an authenticated HTTPS POST to the SENTINEL API", async () => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const calls = [];
  let pending;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response('{"processed":false}', { status: 200 });
  };
  console.error = () => {};

  try {
    await worker.scheduled(
      {},
      {
        SENTINEL_API_URL: "https://sentinel-staging-api.example.onrender.com",
        SENTINEL_WORKER_TICK_SECRET: TEST_SECRET,
      },
      { waitUntil(promise) { pending = promise; } },
    );
    await pending;

    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].url,
      "https://sentinel-staging-api.example.onrender.com/internal/worker/tick",
    );
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers["X-Sentinel-Worker-Secret"], TEST_SECRET);
    assert.equal(calls[0].init.headers["Content-Type"], "application/json");
    assert.equal(calls[0].init.body, "{}");
    assert.equal(calls[0].init.redirect, "error");
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  }
});

test("scheduled tick fails closed when required bindings are missing", async () => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  let fetchCalled = false;
  let logMessage = "";
  globalThis.fetch = async () => {
    fetchCalled = true;
  };
  console.error = (...args) => {
    logMessage = args.join(" ");
  };

  try {
    await worker.scheduled(
      {},
      { SENTINEL_API_URL: "https://api.example.com" },
      { waitUntil() {} },
    );
    assert.equal(fetchCalled, false);
    assert.match(logMessage, /configuration/i);
    assert.doesNotMatch(logMessage, /test-only-secret-value/);
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  }
});

test("scheduled tick rejects non-HTTPS API origins before sending a secret", async () => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  let fetchCalled = false;
  let logMessage = "";
  globalThis.fetch = async () => {
    fetchCalled = true;
  };
  console.error = (...args) => {
    logMessage = args.join(" ");
  };

  try {
    await worker.scheduled(
      {},
      {
        SENTINEL_API_URL: "http://api.example.com",
        SENTINEL_WORKER_TICK_SECRET: TEST_SECRET,
      },
      { waitUntil() {} },
    );
    assert.equal(fetchCalled, false);
    assert.match(logMessage, /HTTPS/i);
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  }
});
