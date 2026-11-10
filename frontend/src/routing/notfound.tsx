import { ArrowLeft, ArrowUpRight, ShieldCheck } from "lucide-react";
import "../marketing/marketing.css";

export default function NotFound() {
  return <main className="not-found-page">
    <a className="marketing-brand" href="/"><span className="marketing-brand-mark"><ShieldCheck size={22} /></span><span><b>SENTINEL</b><small>DEFENSIVE SECURITY OPERATIONS</small></span></a>
    <div className="not-found-content"><span>ERROR / 404</span><h1>This route isn't<br /><em>in the system.</em></h1><p>The page you're looking for doesn't exist or may have moved.</p><div><a href="/"><ArrowLeft size={16} /> Return home</a><a href="/console">Open console <ArrowUpRight size={16} /></a></div></div>
  </main>;
}
