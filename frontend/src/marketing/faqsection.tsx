const faqs = [
  ["What can SENTINEL assess?", "The current product supports authorized asset governance and bounded DNS, HTTPS, TLS, security-header and supported email-domain posture checks. It is a defensive posture workflow, not an exploitation or brute-force tool."],
  ["Do I need authorization to add an asset?", "Yes. Assets should be added only when you own them or have explicit permission to assess them. Keep the authorization reference and expiry accurate."],
  ["Does the website expose my security data?", "No operational inventory, assessments, findings or audit records are rendered on this public marketing page. Those workflows remain inside the authenticated console."],
  ["How are API credentials handled in the console?", "The current console keeps the entered API key in component memory for the active session. Do not share the key or place it in a URL, analytics event or public page."],
  ["Does secret review store submitted source code?", "The supported secret-review flow is designed to return redacted matches without persisting the submitted source content. Review the product's current API behavior and your organization's policy before submitting sensitive material."],
  ["Is the audit trail immutable or a compliance certification?", "No. The product describes its hash-linked audit chain as tamper-evident, not immutable. Operational control mapping is not a regulatory certification or independent assurance report."],
];

export default function FaqSection() {
  return (
    <section className="section-shell faq-section" id="faq">
      <div className="section-kicker">STRAIGHT ANSWERS <span>05 / FAQ</span></div>
      <div className="faq-layout">
        <div className="faq-intro"><h2>Know what the platform does.<br /><span>And what it doesn't.</span></h2><p>Clear boundaries are part of a trustworthy security product. These answers describe the current shipped product, not future roadmap promises.</p><a href="/console">Explore the console <span>↗</span></a></div>
        <div className="faq-list">{faqs.map(([question, answer]) => <details key={question} className="faq-item"><summary>{question}<span aria-hidden="true">+</span></summary><p>{answer}</p></details>)}</div>
      </div>
    </section>
  );
}
