import { ArrowRight, CheckCircle2, LockKeyhole, Network, ShieldCheck } from "lucide-react";

const flow = [
  ["01", "Operator", "Defines authorized assets"],
  ["02", "SENTINEL console", "Presents scoped workflows"],
  ["03", "Authenticated API", "Checks identity and permission"],
  ["04", "Scope policy", "Enforces authorization boundaries"],
  ["05", "Bounded evidence", "Collects supported DNS / TLS signals"],
  ["06", "Findings & action", "Prioritizes remediation and audit"],
];

export default function ArchitectureSection() {
  return (
    <section className="architecture-section" id="security">
      <div className="section-shell">
        <div className="section-kicker">TRUST BOUNDARIES <span>04 / ARCHITECTURE</span></div>
        <div className="section-heading-row"><h2>Every check has <span>a boundary.</span></h2><p>A readable view of the product's defensive operating path—from a human-defined scope to recorded evidence and follow-up.</p></div>
        <div className="architecture-panel">
          <div className="architecture-panel-head"><span><Network size={16} /> EVIDENCE FLOW</span><span>ILLUSTRATIVE PRODUCT ARCHITECTURE</span></div>
          <div className="architecture-flow">
            {flow.map(([number, title, text], index) => <div className="architecture-step" key={number}>
              <span className="architecture-step-number">{number}</span>
              <div><b>{title}</b><small>{text}</small></div>
              {index < flow.length - 1 && <ArrowRight className="architecture-arrow" size={16} />}
            </div>)}
          </div>
          <div className="architecture-panel-foot"><LockKeyhole size={15} /><span>Protected operational records remain behind API authentication and authorization checks.</span></div>
        </div>
        <div className="security-principles">
          <article><ShieldCheck size={21} /><h3>Authorization before assessment</h3><p>Assets are expected to be explicitly authorized, scoped and time-bounded.</p></article>
          <article><CheckCircle2 size={21} /><h3>Evidence, not assumptions</h3><p>Findings describe supported observations and explain the product's prioritization.</p></article>
          <article><LockKeyhole size={21} /><h3>Honest assurance language</h3><p>Hash-linked audit records are tamper-evident, not immutable. Control mapping is not certification.</p></article>
        </div>
      </div>
    </section>
  );
}
