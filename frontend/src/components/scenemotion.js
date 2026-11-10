export function shouldAnimateScene({ reducedMotion, documentVisible, sceneVisible }) {
  return !reducedMotion && documentVisible && sceneVisible;
}
