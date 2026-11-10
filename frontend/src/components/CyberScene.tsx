import { useEffect, useRef } from "react";
import * as THREE from "three";
import { RoundedBoxGeometry } from "three/examples/jsm/geometries/RoundedBoxGeometry.js";

type CyberSceneProps = {
  status: string;
  compact?: boolean;
};

function makeShieldGeometry() {
  const shape = new THREE.Shape();
  shape.moveTo(0, 0.78);
  shape.lineTo(0.61, 0.54);
  shape.lineTo(0.56, -0.12);
  shape.quadraticCurveTo(0.42, -0.58, 0, -0.84);
  shape.quadraticCurveTo(-0.42, -0.58, -0.56, -0.12);
  shape.lineTo(-0.61, 0.54);
  shape.closePath();
  return new THREE.ExtrudeGeometry(shape, {
    depth: 0.09,
    bevelEnabled: true,
    bevelSegments: 3,
    steps: 1,
    bevelSize: 0.025,
    bevelThickness: 0.025,
  });
}

function addCircuitTrace(
  parent: THREE.Object3D,
  points: THREE.Vector3[],
  color: number,
  opacity = 0.7,
) {
  const curve = new THREE.CatmullRomCurve3(points);
  const geometry = new THREE.TubeGeometry(curve, 48, 0.012, 5, false);
  const material = new THREE.MeshBasicMaterial({
    color,
    transparent: true,
    opacity,
    blending: THREE.AdditiveBlending,
  });
  const trace = new THREE.Mesh(geometry, material);
  parent.add(trace);
  return trace;
}

export default function CyberScene({ status, compact = false }: CyberSceneProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    const canvas = canvasRef.current;
    if (!host || !canvas) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        canvas,
        alpha: true,
        antialias: true,
        powerPreference: "low-power",
        stencil: false,
        depth: true,
      });
    } catch {
      host.classList.add("webgl-unavailable");
      return;
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 70);
    camera.position.set(3.4, 2.05, 8.7);
    camera.lookAt(0, 0.05, 0);

    renderer.setClearColor(0x030b14, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, compact ? 1.25 : 1.6));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.18;
    renderer.shadowMap.enabled = false;

    const root = new THREE.Group();
    scene.add(root);

    scene.add(new THREE.AmbientLight(0x91d9e5, 1.45));
    const keyLight = new THREE.PointLight(0x57f0df, 46, 18, 1.8);
    keyLight.position.set(-3.6, 3.5, 4.2);
    scene.add(keyLight);
    const rimLight = new THREE.PointLight(0x468cff, 52, 17, 1.7);
    rimLight.position.set(3.8, 1.5, -2.5);
    scene.add(rimLight);
    const baseLight = new THREE.PointLight(0x2ad4d1, 28, 12, 2);
    baseLight.position.set(0, -2.4, 1.5);
    scene.add(baseLight);

    const platform = new THREE.Group();
    platform.position.y = -1.57;
    root.add(platform);

    const plinth = new THREE.Mesh(
      new THREE.CylinderGeometry(2.02, 2.28, 0.18, 96, 1, false),
      new THREE.MeshPhysicalMaterial({
        color: 0x0c2435,
        metalness: 0.82,
        roughness: 0.22,
        clearcoat: 1,
        clearcoatRoughness: 0.12,
      }),
    );
    platform.add(plinth);

    const plinthEdge = new THREE.Mesh(
      new THREE.TorusGeometry(2.16, 0.018, 8, 112),
      new THREE.MeshBasicMaterial({ color: 0x4be9e1, transparent: true, opacity: 0.86 }),
    );
    plinthEdge.rotation.x = Math.PI / 2;
    plinthEdge.position.y = 0.09;
    platform.add(plinthEdge);

    for (const [radius, tube, color, opacity] of [
      [1.72, 0.012, 0x4ce8df, 0.75],
      [1.34, 0.009, 0x4d9cf5, 0.64],
      [2.42, 0.008, 0x3d9bbd, 0.4],
    ] as const) {
      const ring = new THREE.Mesh(
        new THREE.TorusGeometry(radius, tube, 8, 144),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity }),
      );
      ring.rotation.x = Math.PI / 2;
      ring.position.y = 0.11 + radius * 0.002;
      platform.add(ring);
    }

    const core = new THREE.Group();
    core.position.y = 0.12;
    root.add(core);

    const glassMaterial = new THREE.MeshPhysicalMaterial({
      color: 0x123d53,
      metalness: 0.62,
      roughness: 0.14,
      transparent: true,
      opacity: 0.43,
      transmission: 0.22,
      thickness: 0.8,
      ior: 1.35,
      clearcoat: 1,
      clearcoatRoughness: 0.08,
      side: THREE.DoubleSide,
    });
    const housing = new THREE.Mesh(
      new RoundedBoxGeometry(2.5, 2.12, 1.58, 7, 0.12),
      glassMaterial,
    );
    core.add(housing);

    const housingEdges = new THREE.LineSegments(
      new THREE.EdgesGeometry(housing.geometry, 18),
      new THREE.LineBasicMaterial({
        color: 0x70f4e7,
        transparent: true,
        opacity: 0.82,
      }),
    );
    core.add(housingEdges);

    const innerPlate = new THREE.Mesh(
      new RoundedBoxGeometry(2.12, 1.78, 0.12, 5, 0.075),
      new THREE.MeshPhysicalMaterial({
        color: 0x0d2c40,
        metalness: 0.74,
        roughness: 0.24,
        transparent: true,
        opacity: 0.86,
        clearcoat: 1,
      }),
    );
    innerPlate.position.z = 0.67;
    core.add(innerPlate);

    const lock = new THREE.Group();
    lock.position.set(0, -0.17, 0.94);
    core.add(lock);

    const lockBody = new THREE.Mesh(
      new RoundedBoxGeometry(0.94, 0.72, 0.24, 8, 0.12),
      new THREE.MeshPhysicalMaterial({
        color: 0x0d3447,
        metalness: 0.7,
        roughness: 0.16,
        clearcoat: 1,
        emissive: 0x082d3b,
        emissiveIntensity: 0.65,
      }),
    );
    lock.add(lockBody);

    const shackleCurve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-0.3, 0.16, 0.02),
      new THREE.Vector3(-0.3, 0.59, 0.02),
      new THREE.Vector3(-0.21, 0.78, 0.02),
      new THREE.Vector3(0, 0.85, 0.02),
      new THREE.Vector3(0.21, 0.78, 0.02),
      new THREE.Vector3(0.3, 0.59, 0.02),
      new THREE.Vector3(0.3, 0.16, 0.02),
    ]);
    lock.add(
      new THREE.Mesh(
        new THREE.TubeGeometry(shackleCurve, 40, 0.065, 12, false),
        new THREE.MeshStandardMaterial({
          color: 0x91f5f0,
          metalness: 0.84,
          roughness: 0.18,
          emissive: 0x23c9ce,
          emissiveIntensity: 0.75,
        }),
      ),
    );

    const shieldGroup = new THREE.Group();
    shieldGroup.position.set(0, 0.27, 1.13);
    shieldGroup.scale.setScalar(0.74);
    core.add(shieldGroup);
    const shieldGeometry = makeShieldGeometry();
    shieldGeometry.translate(0, 0, -0.045);
    const shield = new THREE.Mesh(
      shieldGeometry,
      new THREE.MeshPhysicalMaterial({
        color: 0x8afaff,
        metalness: 0.22,
        roughness: 0.16,
        transparent: true,
        opacity: 0.88,
        emissive: 0x32dff0,
        emissiveIntensity: 1.35,
        clearcoat: 1,
        side: THREE.DoubleSide,
      }),
    );
    shieldGroup.add(shield);
    shieldGroup.add(
      new THREE.LineSegments(
        new THREE.EdgesGeometry(shieldGeometry, 15),
        new THREE.LineBasicMaterial({
          color: 0xd8ffff,
          transparent: true,
          opacity: 0.95,
        }),
      ),
    );

    const checkCurve = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-0.25, 0.02, 0.12),
      new THREE.Vector3(-0.07, -0.16, 0.12),
      new THREE.Vector3(0.31, 0.24, 0.12),
    ]);
    shieldGroup.add(
      new THREE.Mesh(
        new THREE.TubeGeometry(checkCurve, 22, 0.026, 8, false),
        new THREE.MeshBasicMaterial({ color: 0xe0ffff, transparent: true, opacity: 0.9 }),
      ),
    );

    const orbitA = new THREE.Group();
    const orbitB = new THREE.Group();
    const orbitC = new THREE.Group();
    root.add(orbitA, orbitB, orbitC);

    const makeOrbit = (parent: THREE.Group, radius: number, color: number, opacity: number, tube: number) => {
      const geometry = new THREE.TorusGeometry(radius, tube, 6, 160);
      const material = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity,
        blending: THREE.AdditiveBlending,
      });
      parent.add(new THREE.Mesh(geometry, material));
    };
    makeOrbit(orbitA, 2.42, 0x54e8df, 0.58, 0.012);
    makeOrbit(orbitB, 2.82, 0x4d9ff7, 0.46, 0.009);
    makeOrbit(orbitC, 1.92, 0x8cf5ed, 0.37, 0.007);
    orbitA.rotation.set(1.14, 0.25, -0.22);
    orbitB.rotation.set(0.58, 1.18, 0.42);
    orbitC.rotation.set(1.72, -0.64, 0.2);

    const nodeGeometry = new THREE.SphereGeometry(0.075, 16, 16);
    const nodeMaterials = [
      new THREE.MeshBasicMaterial({ color: 0x91fff0 }),
      new THREE.MeshBasicMaterial({ color: 0x73baff }),
      new THREE.MeshBasicMaterial({ color: 0x52e9d9 }),
    ];
    const orbitNodes: THREE.Mesh[] = [];
    [
      [2.42, 0, 0],
      [2.82, 1, 0],
      [1.92, 2, 0],
    ].forEach(([radius, orbitIndex]) => {
      const node = new THREE.Mesh(nodeGeometry, nodeMaterials[orbitIndex]);
      const holder = orbitIndex === 0 ? orbitA : orbitIndex === 1 ? orbitB : orbitC;
      node.position.set(radius * 0.72, radius * 0.43, radius * 0.43);
      holder.add(node);
      orbitNodes.push(node);
    });

    const traces = new THREE.Group();
    root.add(traces);
    addCircuitTrace(
      traces,
      [
        new THREE.Vector3(-3.5, 0.6, -0.3),
        new THREE.Vector3(-2.7, 0.6, 0.25),
        new THREE.Vector3(-2.4, 1.4, 0.4),
        new THREE.Vector3(-1.55, 1.55, 0.6),
      ],
      0x43d9df,
      0.58,
    );
    addCircuitTrace(
      traces,
      [
        new THREE.Vector3(3.5, -0.2, -0.6),
        new THREE.Vector3(2.75, -0.2, 0.2),
        new THREE.Vector3(2.44, 0.7, 0.32),
        new THREE.Vector3(1.72, 0.86, 0.55),
      ],
      0x4b9ff5,
      0.62,
    );

    const particleCount = compact ? 170 : 340;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let index = 0; index < particleCount; index += 1) {
      const offset = index * 3;
      const seed = index * 12.9898;
      particlePositions[offset] = Math.sin(seed) * 4.5;
      particlePositions[offset + 1] = Math.cos(seed * 0.83) * 2.8;
      particlePositions[offset + 2] = Math.sin(seed * 1.31) * 3.2 - 0.7;
    }
    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute("position", new THREE.BufferAttribute(particlePositions, 3));
    const particles = new THREE.Points(
      particleGeometry,
      new THREE.PointsMaterial({
        color: 0x80e9ec,
        size: 0.022,
        transparent: true,
        opacity: 0.62,
        sizeAttenuation: true,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    );
    root.add(particles);

    const floor = new THREE.GridHelper(22, 44, 0x1c7188, 0x16455c);
    floor.position.y = -1.72;
    const floorMaterial = floor.material as THREE.Material;
    floorMaterial.transparent = true;
    floorMaterial.opacity = 0.25;
    root.add(floor);

    const ambientRing = new THREE.Mesh(
      new THREE.TorusGeometry(3.48, 0.012, 6, 160),
      new THREE.MeshBasicMaterial({ color: 0x2b9cae, transparent: true, opacity: 0.28 }),
    );
    ambientRing.rotation.x = 1.34;
    ambientRing.position.y = -0.15;
    root.add(ambientRing);

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    let elapsed = 0;
    let visible = true;
    let previousTime = 0;

    const resize = () => {
      const width = host.clientWidth;
      const height = host.clientHeight;
      if (!width || !height) return;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, compact ? 1.25 : 1.6));
      renderer.render(scene, camera);
    };

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(host);

    const intersectionObserver = new IntersectionObserver(
      (entries) => {
        visible = entries[0]?.isIntersecting ?? true;
        if (visible && !reducedMotion) previousTime = 0;
      },
      { threshold: 0.02 },
    );
    intersectionObserver.observe(host);

    const onVisibilityChange = () => {
      if (document.visibilityState !== "visible") visible = false;
    };
    document.addEventListener("visibilitychange", onVisibilityChange);

    const animate = (time: number) => {
      frame = window.requestAnimationFrame(animate);
      if (!visible || document.visibilityState !== "visible" || reducedMotion) return;
      const delta = previousTime ? Math.min((time - previousTime) / 1000, 0.05) : 0;
      previousTime = time;
      elapsed += delta;

      core.rotation.y = Math.sin(elapsed * 0.22) * 0.11;
      core.rotation.x = Math.sin(elapsed * 0.19) * 0.055;
      shieldGroup.rotation.y = Math.sin(elapsed * 0.52) * 0.08;
      orbitA.rotation.z += delta * 0.13;
      orbitB.rotation.y += delta * 0.1;
      orbitC.rotation.x -= delta * 0.075;
      particles.rotation.y = elapsed * 0.012;
      particles.rotation.x = Math.sin(elapsed * 0.08) * 0.025;
      keyLight.intensity = 42 + Math.sin(elapsed * 1.4) * 5;
      baseLight.intensity = 24 + Math.sin(elapsed * 1.05) * 4;
      orbitNodes.forEach((node, index) => {
        const pulse = 1 + Math.sin(elapsed * 2.1 + index * 1.8) * 0.2;
        node.scale.setScalar(pulse);
      });
      renderer.render(scene, camera);
    };

    resize();
    if (!reducedMotion) frame = window.requestAnimationFrame(animate);
    else renderer.render(scene, camera);

    return () => {
      window.cancelAnimationFrame(frame);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      document.removeEventListener("visibilitychange", onVisibilityChange);
      scene.traverse((object) => {
        const renderable = object as THREE.Mesh;
        if (renderable.geometry instanceof THREE.BufferGeometry) renderable.geometry.dispose();
        const material = renderable.material;
        if (Array.isArray(material)) material.forEach((item) => item.dispose());
        else if (material instanceof THREE.Material) material.dispose();
      });
      renderer.dispose();
      host.classList.remove("webgl-unavailable");
    };
  }, [compact]);

  return (
    <div className={"three-cyber-scene" + (compact ? " compact" : "")} ref={hostRef}>
      <canvas ref={canvasRef} aria-label="Animated three-dimensional SENTINEL shield and secure hardware core" />
      <div className="scene-vignette" aria-hidden="true" />
      <div className="scene-hud scene-hud-top">
        <span className="scene-pulse" />
        <span>HOLOGRAPHIC SECURITY CORE</span>
      </div>
      <div className="scene-hud scene-hud-bottom">
        <span>SENTINEL / DEFENSIVE CONTROL PLANE</span>
        <b>{status}</b>
      </div>
      <div className="scene-axis scene-axis-left" aria-hidden="true" />
      <div className="scene-axis scene-axis-right" aria-hidden="true" />
    </div>
  );
}
