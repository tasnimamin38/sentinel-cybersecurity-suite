import test from "node:test";
import assert from "node:assert/strict";
import { shouldAnimateScene } from "./scenemotion.js";

test("reduced motion disables continuous animation", () => {
  assert.equal(shouldAnimateScene({ reducedMotion: true, documentVisible: true, sceneVisible: true }), false);
});
test("hidden documents disable continuous animation", () => {
  assert.equal(shouldAnimateScene({ reducedMotion: false, documentVisible: false, sceneVisible: true }), false);
});
test("offscreen scenes disable continuous animation", () => {
  assert.equal(shouldAnimateScene({ reducedMotion: false, documentVisible: true, sceneVisible: false }), false);
});
test("visible scenes animate only when motion is allowed", () => {
  assert.equal(shouldAnimateScene({ reducedMotion: false, documentVisible: true, sceneVisible: true }), true);
});
