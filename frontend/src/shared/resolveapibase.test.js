import test from "node:test";
import assert from "node:assert/strict";
import { resolveApiBase } from "./resolveapibase.js";

test("preview builds with the proxy flag use the same-origin API route", () => {
  assert.equal(resolveApiBase("https://sentinel-staging-api-q2nk.onrender.com", "true"), "");
});

test("production keeps its configured API origin when proxy mode is disabled", () => {
  assert.equal(resolveApiBase("https://sentinel-staging-api-q2nk.onrender.com/", undefined), "https://sentinel-staging-api-q2nk.onrender.com");
});

test("local development defaults to same-origin when no API origin is configured", () => {
  assert.equal(resolveApiBase(undefined, undefined), "");
});
