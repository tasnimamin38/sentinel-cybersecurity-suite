import { useState } from "react";
import { ArrowUpRight, Menu, ShieldCheck, X } from "lucide-react";

const links = [
  ["Platform", "#platform"],
  ["Capabilities", "#capabilities"],
  ["How it works", "#how-it-works"],
  ["Security", "#security"],
  ["Plans", "#plans"],
] as const;

export default function MarketingHeader() {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <header className="marketing-header">
      <a className="marketing-brand" href="/" aria-label="SENTINEL home" onClick={() => setMenuOpen(false)}>
        <span className="marketing-brand-mark"><ShieldCheck size={22} strokeWidth={1.8} /></span>
        <span><b>SENTINEL</b><small>DEFENSIVE SECURITY OPERATIONS</small></span>
      </a>
      <button className="mobile-menu-toggle" type="button" aria-label={menuOpen ? "Close navigation" : "Open navigation"} aria-expanded={menuOpen} aria-controls="marketing-navigation" onClick={() => setMenuOpen(!menuOpen)}>
        {menuOpen ? <X size={21} /> : <Menu size={21} />}
      </button>
      <nav id="marketing-navigation" className={menuOpen ? "marketing-nav is-open" : "marketing-nav"} aria-label="Main navigation">
        {links.map(([label, href]) => <a key={href} href={href} onClick={() => setMenuOpen(false)}>{label}</a>)}
        <a className="header-console-link" href="/console" onClick={() => setMenuOpen(false)}>Open console <ArrowUpRight size={15} /></a>
      </nav>
    </header>
  );
}
