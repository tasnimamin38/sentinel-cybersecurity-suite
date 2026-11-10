import test from "node:test";
import assert from "node:assert/strict";
import { resolveRoute } from "./resolveRoute.js";

test("root is the public marketing site", () => assert.equal(resolveRoute("/"), "marketing"));
test("console paths stay inside the authenticated console", () => {
  for (const path of ["/console", "/console/", "/console/assets", "/console/findings"]) {
    assert.equal(resolveRoute(path), "console", path);
  }
});
test("unrelated paths do not fall through to the console", () => {
  for (const path of ["/unknown", "/consolex", "/marketing"]) {
    assert.equal(resolveRoute(path), "not-found", path);
  }
});
