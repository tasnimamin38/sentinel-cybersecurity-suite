import { lazy, Suspense, useEffect, useState } from "react";
import { ArrowDown, ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react";

const CyberScene = lazy(() => import("../components/cyberscene"));

export default function MarketingHero() {
  const [compact, setCompact] = useState(() =>
    typeof window !== "undefined" && window.matchMedia("(max-width: 760px)").matches,
  );

  useEffect(() => {
    const query = window.matchMedia("(max-width: 760px)");
    const update = (event: MediaQueryListEvent) => setCompact(event.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  return (
    <section className="marketing-hero" id="platform" aria-labelledby="hero-title">
      <div className="hero-grid-glow" aria-hidden="true" />
      <div className="hero-copy">
        <div className="eyebrow"><span className="eyebrow-mark" /> DEFENSIVE SECURITY / BUILT FOR CONTROL</div>
        <h1 id="hero-title">Know your exposure.<br /><span>Control your</span><br /><em>security posture.</em></h1>
        <p className="hero-intro">A focused security operations platform for organizations that need clear ownership, bounded assessment, evidence-led findings and accountable remediation.</p>
        <div className="hero-actions">
          <a className="button-primary" href="/console">Open Security Console <ArrowRight size={17} /></a>
          <a className="button-secondary" href="#capabilities">Explore capabilities <ArrowDown size={16} /></a>
        </div>
        <div className="hero-trust-line"><LockKeyhole size={14} /><span>Authorization first</span><i /> <span>Evidence over noise</span><i /> <span>Defensive by design</span></div>
      </div>
      <div className="hero-visual" aria-label="Decorative three-dimensional SENTINEL security shield">
        <div className="hero-visual-frame">
          <div className="hero-visual-topline"><span><i /> SENTINEL / CONTROL PLANE</span><span>01 — 04</span></div>
          <Suspense fallback={<div className="scene-loading"><ShieldCheck size={76} strokeWidth={1} /><span>Initializing visual core</span></div>}>
            <CyberScene compact={compact} status="AUTHORIZATION · EVIDENCE · REMEDIATION" />
          </Suspense>
          <div className="hero-visual-caption"><span>FIG. 01</span><span>SECURITY POSTURE / SYSTEM OVERVIEW</span></div>
        </div>
        <div className="hero-float-tag hero-float-tag-a"><span className="float-tag-icon"><ShieldCheck size={16} /></span><span><b>Scope aware</b><small>Authorized assets only</small></span></div>
        <div className="hero-float-tag hero-float-tag-b"><span className="float-tag-dot" /><span><b>Evidence led</b><small>Traceable findings</small></span></div>
      </div>
      <div className="hero-bottom-rule"><span>01 / PLATFORM OVERVIEW</span><span>BUILT FOR RESPONSIBLE SECURITY TEAMS</span><span>SCROLL TO EXPLORE ↓</span></div>
    </section>
  );
}
