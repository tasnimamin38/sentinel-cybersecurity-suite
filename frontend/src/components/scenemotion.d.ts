export interface SceneMotionState {
  reducedMotion: boolean;
  documentVisible: boolean;
  sceneVisible: boolean;
}
export function shouldAnimateScene(state: SceneMotionState): boolean;
