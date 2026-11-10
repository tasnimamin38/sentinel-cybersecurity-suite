import { ArrowRight, ArrowUpRight, ShieldCheck } from "lucide-react";
import MarketingHeader from "./marketingheader";
import MarketingHero from "./marketinghero";
import { CapabilityStrip, OperatingModel } from "./capabilitysections";
import CapabilitySections from "./capabilitysections";
import ArchitectureSection from "./architecturesection";
import PlanSection from "./plansection";
import FaqSection from "./faqsection";
import MarketingFooter from "./marketingfooter";
import "./marketing.css";

export default function MarketingSite() {
  return (
    <div className="marketing-site" id="top">
      <a className="skip-to-content" href="#main-content">Skip to content</a>
      <MarketingHeader />
      <main id="main-content">
        <MarketingHero />
        <CapabilityStrip />
        <OperatingModel />
        <CapabilitySections />
        <ArchitectureSection />
        <FaqSection />
        <PlanSection />
        <section className="closing-cta">
          <div className="closing-cta-orb" aria-hidden="true" />
          <div className="closing-cta-copy"><span><ShieldCheck size={15} /> YOUR SECURITY WORKSPACE</span><h2>Make every security action <em>accountable.</em></h2><p>Bring your authorized scope, assessment evidence and remediation workflow into one focused console.</p></div>
          <a href="/console" className="button-primary">Enter SENTINEL <ArrowRight size={17} /></a>
          <div className="closing-cta-index">S / 07</div>
        </section>
      </main>
      <MarketingFooter />
      <a className="back-to-top" href="#top" onClick={(event) => { event.preventDefault(); window.scrollTo({ top: 0, behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" }); }} aria-label="Back to top"><ArrowUpRight size={18} /></a>
    </div>
  );
}
