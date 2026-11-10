import { ArrowUpRight, ShieldCheck } from "lucide-react";

export default function MarketingFooter() {
  return (
    <footer className="marketing-footer">
      <div className="footer-main">
        <a className="marketing-brand footer-brand" href="/"><span className="marketing-brand-mark"><ShieldCheck size={22} /></span><span><b>SENTINEL</b><small>DEFENSIVE SECURITY OPERATIONS</small></span></a>
        <p>Know your exposure. Control your security posture.<br />Defensive security, built around authorization and evidence.</p>
        <a className="footer-console-link" href="/console">Open Security Console <ArrowUpRight size={15} /></a>
      </div>
      <div className="footer-bottom"><span>© {new Date().getFullYear()} SENTINEL</span><span>DEFENSIVE USE ONLY · AUTHORIZATION FIRST</span><a href="https://github.com/tasnimamin38/sentinel-cybersecurity-suite" target="_blank" rel="noreferrer">SOURCE REPOSITORY ↗</a></div>
    </footer>
  );
}
