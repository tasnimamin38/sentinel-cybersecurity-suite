import { Activity, ArrowUpRight, ClipboardCheck, Cloud, Fingerprint, Globe2, Layers3, ListChecks, ShieldCheck, Workflow } from "lucide-react";

const capabilities = [
  { number: "01", icon: Layers3, title: "Authorized asset governance", text: "Keep an accountable inventory with ownership, environment, criticality, authorization references and expiry." },
  { number: "02", icon: Globe2, title: "Bounded web & DNS posture", text: "Review supported HTTPS, DNS, TLS and security-header signals with validation and bounded request behavior." },
  { number: "03", icon: Cloud, title: "Email-domain signals", text: "Inspect supported MX, SPF, DMARC, CAA, MTA-STS discovery and SMTP TLS reporting posture." },
  { number: "04", icon: Activity, title: "Explainable risk context", text: "Turn supported findings into deterministic prioritization with visible drivers—not a claimed CVSS score." },
  { number: "05", icon: ListChecks, title: "Remediation workflow", text: "Assign an owner, set a due date, record notes and track the state of follow-up work." },
  { number: "06", icon: Fingerprint, title: "Redacted secret review", text: "Review supported secret-pattern matches with redaction; submitted source content is not persisted." },
  { number: "07", icon: ClipboardCheck, title: "Audit evidence & exports", text: "Inspect a hash-linked, tamper-evident audit trail and produce audited CSV exports." },
  { number: "08", icon: Workflow, title: "Defensive API monitoring", text: "Review defensive request/security events and use signed HMAC alert webhooks for integrations." },
];

export function CapabilityStrip() {
  return (
    <div className="capability-strip" aria-label="SENTINEL product capabilities">
      {["AUTHORIZED ASSET GOVERNANCE", "DNS / TLS POSTURE", "EVIDENCE-LED FINDINGS", "ACCOUNTABLE REMEDIATION", "AUDIT EVIDENCE"].map((item, index) =>
        <div className="capability-strip-item" key={item}><span>0{index + 1}</span>{item}</div>
      )}
    </div>
  );
}

export function OperatingModel() {
  const steps = [
    { n: "01", title: "Register the scope", copy: "Record the asset, owner, business context and explicit authorization boundary." },
    { n: "02", title: "Assess within bounds", copy: "Run supported DNS, HTTPS and TLS posture checks against the authorized scope." },
    { n: "03", title: "Prioritize & improve", copy: "Review evidence, understand risk drivers and track remediation with an audit trail." },
  ];
  return (
    <section className="section-shell operating-section" id="how-it-works">
      <div className="section-kicker">A CLEAR OPERATING MODEL <span>02 / PROCESS</span></div>
      <div className="section-heading-row"><h2>Security work, <span>with a defined path.</span></h2><p>Move from authorized scope to useful evidence and accountable follow-through—without turning posture review into offensive testing.</p></div>
      <div className="operating-grid">
        {steps.map((step, index) => <article className="operating-card" key={step.n}>
          <div className="operating-card-top"><span>{step.n}</span><span>{index === 0 ? "DEFINE" : index === 1 ? "ASSESS" : "IMPROVE"}</span></div>
          <div className="operating-connector"><i /><i /><i /></div>
          <h3>{step.title}</h3><p>{step.copy}</p>
        </article>)}
      </div>
    </section>
  );
}

export default function CapabilitySections() {
  return (
    <section className="section-shell capabilities-section" id="capabilities">
      <div className="section-kicker">THE PLATFORM <span>03 / CAPABILITIES</span></div>
      <div className="section-heading-row"><h2>Clarity across the <span>security lifecycle.</span></h2><p>One place to govern authorized assets, understand supported security signals and coordinate the work that follows.</p></div>
      <div className="capability-grid">
        {capabilities.map(({ number, icon: Icon, title, text }) => <article className="capability-card" key={number}>
          <div className="capability-card-top"><span>{number}</span><Icon size={20} strokeWidth={1.65} /></div>
          <h3>{title}</h3><p>{text}</p><span className="capability-card-link">PRODUCT CAPABILITY <ArrowUpRight size={13} /></span>
        </article>)}
      </div>
      <div className="capability-footnote"><ShieldCheck size={17} /><p>Scope is explicit. Checks are bounded. Findings are tied to evidence. SENTINEL does not perform exploitation, brute-force attempts or intrusive penetration testing.</p></div>
    </section>
  );
}
