import { useEffect, useState } from "react";
import { ArrowUpRight, CheckCircle2, Clock3, LockKeyhole } from "lucide-react";
import { API_BASE } from "../shared/apibase";
import type { PublicPlanCatalog } from "../shared/plantypes";
import { fetchPublicPlanCatalog } from "./plancatalog.js";

export default function PlanSection() {
  const [catalog, setCatalog] = useState<PublicPlanCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    fetchPublicPlanCatalog(fetch, API_BASE, controller.signal)
      .then((payload) => { if (!controller.signal.aborted) setCatalog(payload); })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Plan details temporarily unavailable.");
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, []);

  const defaultPlan = catalog?.plans.find((plan) => plan.code === catalog.default_plan_code);
  const availableFeatures = catalog?.feature_catalog?.filter((feature) =>
    feature.status === "available" && (defaultPlan?.feature_codes?.includes(feature.code) ?? false),
  ) ?? [];

  return (
    <section className="section-shell plans-section" id="plans" aria-labelledby="plans-title">
      <div className="section-kicker">ACCESS & AVAILABILITY <span>06 / PLANS</span></div>
      <div className="plans-heading-row">
        <div><h2 id="plans-title">Start with the <span>real product.</span></h2><p>Plan availability, pricing and checkout status come directly from the current SENTINEL API catalogue.</p></div>
        <div className="catalogue-source"><span className="catalogue-source-dot" /> LIVE PUBLIC CATALOGUE</div>
      </div>
      {loading && <div className="plans-state" role="status"><span className="loader-ring" /> Loading the live plan catalogue…</div>}
      {error && <div className="plans-state plans-state-error" role="alert"><Clock3 size={18} /><span>Plan details temporarily unavailable. The rest of the website remains available.</span></div>}
      {catalog && (
        <>
          <div className="catalogue-status-row"><span>LAUNCH MODE <b>{catalog.launch_mode.replace(/_/g, " ")}</b></span><span>CATALOGUE VERSION <b>v{catalog.catalog_version}</b></span><span>CHECKOUT <b>{catalog.checkout_enabled ? "ENABLED" : "NOT ENABLED"}</b></span></div>
          <div className="plans-grid-public">
            {catalog.plans.map((plan) => {
              const featured = plan.code === catalog.default_plan_code;
              return <article className={featured ? "public-plan-card is-featured" : "public-plan-card"} key={plan.code}>
                <div className="public-plan-top"><span className={plan.status === "active" ? "public-plan-status active" : "public-plan-status preview"}>{plan.status === "active" ? "AVAILABLE" : "PREVIEW"}</span>{featured && <span className="public-plan-default">DEFAULT PLAN</span>}</div>
                <h3>{plan.name}</h3>
                <div className="public-plan-price">{plan.price.display}</div>
                <p className="public-plan-notice">{plan.notice ?? plan.planned_for ?? "Details supplied by the current plan catalogue."}</p>
                <div className="public-plan-divider" />
                <div className="public-plan-checkout">
                  <span><LockKeyhole size={14} /> {plan.checkout_enabled && plan.purchasable ? "Checkout available" : "Checkout not enabled"}</span>
                  <span>{plan.status === "active" ? "Current availability" : "Future preview"}</span>
                </div>
              </article>;
            })}
          </div>
          {availableFeatures.length > 0 && <div className="included-capabilities">
            <div className="included-capabilities-head"><div><span className="eyebrow-mark" /> CURRENTLY SHIPPED</div><p>Capabilities available under the default plan, according to the live catalogue.</p></div>
            <div className="included-capability-grid">{availableFeatures.map((feature) => <div key={feature.code}><CheckCircle2 size={15} /><span><b>{feature.name}</b><small>{feature.description}</small></span></div>)}</div>
          </div>}
          <p className="catalogue-notice">{catalog.notice}</p>
        </>
      )}
      <div className="plans-foot-action"><span>Ready to explore the actual workspace?</span><a href="/console">Open the console <ArrowUpRight size={15} /></a></div>
    </section>
  );
}
