import type { CSSProperties, FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, CheckCircle2, ChevronDown, CircleDot, Clock3,
  Command, Cpu, Fingerprint, Globe2, KeyRound, Layers3, LockKeyhole, Play, Radar,
  RefreshCw, Search, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal,
  TerminalSquare, Wifi, Zap,
} from "lucide-react";

type Finding = { code: string; title: string; severity: string; description: string; recommendation: string; category: string };
type Assessment = { id: string; target: string; status: string; score: number; risk_level: string; findings: Finding[]; evidence: Record<string, unknown>; created_at: string };
type Overview = { assessment_count: number; findings_count: number; high_risk_count: number; authorized_domains: string[] };
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
function severityClass(value: string) { return ["critical", "high", "medium", "low"].includes(value) ? value : "info"; }
function prettyDate(value?: string) { return value ? new Date(value).toLocaleString() : "Not yet assessed"; }

export default function App() {
  const [apiKey, setApiKey] = useState("");
  const [domain, setDomain] = useState("");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selected, setSelected] = useState<Assessment | null>(null);
  const [status, setStatus] = useState<"idle" | "checking" | "ready" | "error">("idle");
  const [message, setMessage] = useState("Connect the API to load your authorized security scope.");
  const [filter, setFilter] = useState("all");

  const latest = assessments[0];
  const visibleFindings = useMemo(() => {
    const rows = selected?.findings ?? latest?.findings ?? [];
    return filter === "all" ? rows : rows.filter((item) => item.severity === filter);
  }, [selected, latest, filter]);

  async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(API_BASE + path, {
      ...init,
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey, ...(init.headers ?? {}) },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail ?? "API request failed.");
    return payload as T;
  }

  async function connect() {
    if (!apiKey.trim()) { setMessage("Enter the API key from your local .env file."); setStatus("error"); return; }
    setStatus("checking");
    try {
      const [config, stats, history] = await Promise.all([
        api<{ authorized_domains: string[] }>("/api/v1/config"),
        api<Overview>("/api/v1/overview"),
        api<Assessment[]>("/api/v1/assessments"),
      ]);
      setOverview({ ...stats, authorized_domains: config.authorized_domains });
      setAssessments(history);
      setSelected(history[0] ?? null);
      setStatus("ready");
      setMessage("Secure API connection established. Only allowlisted domains can be assessed.");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Could not connect to API.");
    }
  }

  async function runAssessment(event: FormEvent) {
    event.preventDefault();
    if (!domain.trim()) return;
    setStatus("checking");
    setMessage("Running safe HTTPS, TLS and DNS posture checksâ€¦");
    try {
      const created = await api<Assessment>("/api/v1/assessments", { method: "POST", body: JSON.stringify({ domain: domain.trim() }) });
      const [stats, history] = await Promise.all([api<Overview>("/api/v1/overview"), api<Assessment[]>("/api/v1/assessments")]);
      setOverview(stats);
      setAssessments(history);
      setSelected(created);
      setMessage("Assessment completed. Findings contain recommendations, not exploit actions.");
      setStatus("ready");
    } catch (error) {
      setStatus("error");
      setMessage(error instanceof Error ? error.message : "Assessment failed.");
    }
  }

  useEffect(() => {
    setMessage("API access is manual by design. Your key remains in memory and is not written to browser storage.");
  }, []);

  const risk = selected?.risk_level ?? latest?.risk_level ?? "informational";
  const score = selected?.score ?? latest?.score ?? 0;

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><ShieldCheck size={22} /></div><div><strong>SENTINEL</strong><span>DEFENSIVE SECURITY</span></div></div>
      <div className="workspace"><span className="workspace-dot" /> LOCAL SECURITY WORKSPACE <ChevronDown size={14} /></div>
      <div className="nav-label">OPERATIONS</div>
      <nav>
        <a className="active"><Radar size={17} /> Overview <span className="nav-count">01</span></a>
        <a><Globe2 size={17} /> Asset inventory</a><a><Shield size={17} /> Posture assessments</a>
        <a><AlertTriangle size={17} /> Findings <span className="nav-count">{overview?.findings_count ?? "â€”"}</span></a>
        <a><Fingerprint size={17} /> Secret hygiene</a><a><Layers3 size={17} /> Dependency health</a>
      </nav>
      <div className="nav-label">GOVERNANCE</div>
      <nav><a><LockKeyhole size={17} /> Authorization scopes</a><a><Activity size={17} /> Audit trail</a><a><SlidersHorizontal size={17} /> Integrations</a></nav>
      <div className="sidebar-bottom">
        <div className="secure-card"><div><LockKeyhole size={15} /> SCOPE ENFORCEMENT</div><p>Assessment requests are restricted to configured DNS allowlists.</p><span><CheckCircle2 size={13} /> ENABLED</span></div>
        <div className="profile"><div className="avatar">SA</div><div><b>Security Analyst</b><span>Local operator</span></div><ChevronDown size={15} /></div>
      </div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb"><span>Workspace</span><b>/</b><strong>Overview</strong></div><div className="top-actions"><div className="system-pill"><span className="pulse" /> API {status === "ready" ? "CONNECTED" : "NOT CONNECTED"}</div><button className="icon-button" aria-label="Notifications"><Bell size={17} /></button><div className="top-avatar">SA</div></div></header>
      <section className="content">
        <div className="page-heading"><div><div className="eyebrow"><span /> SECURITY OPERATIONS CENTER <span className="eyebrow-line" /></div><h1>Security posture <em>overview</em></h1><p>Continuous visibility. Measured exposure. Defensible decisions.</p></div><div className="heading-meta"><span>ENVIRONMENT</span><b><CircleDot size={10} /> DEVELOPMENT</b><span>LAST SYNC Â· {latest ? prettyDate(latest.created_at) : "â€”"}</span></div></div>
        <div className="connection-panel"><div className="connection-icon"><KeyRound size={19} /></div><div className="connection-copy"><b>Connect your SENTINEL API</b><span>API key is held in memory only and never saved to local storage.</span></div><input value={apiKey} onChange={(event) => setApiKey(event.target.value)} type="password" placeholder="SENTINEL_API_KEY" autoComplete="off" /><button onClick={connect} disabled={status === "checking"} className="button-secondary">{status === "checking" ? "Connectingâ€¦" : "Connect API"} <ArrowUpRight size={15} /></button></div>
        <div className={"status-message " + (status === "error" ? "error" : status === "ready" ? "success" : "")}>{status === "error" ? <AlertTriangle size={15} /> : status === "ready" ? <CheckCircle2 size={15} /> : <Activity size={15} />}<span>{message}</span></div>
        <div className="metrics-grid">
          <Metric icon={<Radar size={17} />} label="ASSESSMENTS" value={overview?.assessment_count ?? "â€”"} note="Recorded security reviews" trend="LIVE DATA" />
          <Metric icon={<AlertTriangle size={17} />} label="OPEN FINDINGS" value={overview?.findings_count ?? "â€”"} note="Across completed assessments" trend="ALL SEVERITIES" />
          <Metric icon={<ShieldAlert size={17} />} label="HIGH RISK TARGETS" value={overview?.high_risk_count ?? "â€”"} note="High and critical assessments" trend="PRIORITIZE" />
          <Metric icon={<Globe2 size={17} />} label="AUTHORIZED DOMAINS" value={overview?.authorized_domains.length ?? "â€”"} note="Explicitly allowlisted hosts" trend="SCOPE LOCKED" />
        </div>
        <div className="section-head"><div><div className="eyebrow">ASSESSMENT ENGINE</div><h2>Run a posture assessment</h2></div><div className="safe-mode"><ShieldCheck size={14} /> SAFE MODE ACTIVE</div></div>
        <div className="assessment-grid">
          <form className="scan-card" onSubmit={runAssessment}>
            <div className="card-top"><div className="card-icon"><Globe2 size={18} /></div><span className="micro-tag">AUTHORIZED WEB CHECK</span></div>
            <h3>Domain security review</h3><p>Checks HTTPS response headers, TLS certificate health, DNS MX, SPF and DMARC posture. No exploitation or intrusive probing.</p>
            <label htmlFor="domain">TARGET HOSTNAME</label><div className="domain-input"><span>https://</span><input id="domain" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="app.example.com" /></div>
            <div className="scope-note"><LockKeyhole size={13} /> {overview?.authorized_domains.length ? overview.authorized_domains.join(", ") : "Connect API to load authorized scope"}</div>
            <button className="button-primary" type="submit" disabled={status === "checking" || !apiKey.trim()}><Play size={15} /> {status === "checking" ? "ASSESSMENT RUNNING" : "RUN ASSESSMENT"} <ArrowUpRight size={15} /></button>
            <div className="scan-foot"><span><Clock3 size={13} /> BOUNDED TIMEOUTS</span><span><Wifi size={13} /> HTTPS ONLY</span><span><LockKeyhole size={13} /> NO REDIRECTS</span></div>
          </form>
          <div className="posture-card">
            <div className="card-top"><div className="card-icon"><Cpu size={18} /></div><span className="micro-tag">LATEST ASSESSMENT</span></div>
            <div className="posture-main"><div className={"score-ring " + severityClass(risk)} style={{ "--score": score + "%" } as CSSProperties}><div><strong>{score}</strong><span>/ 100</span></div></div><div className="risk-copy"><span>OVERALL RISK</span><b className={severityClass(risk)}>{risk.toUpperCase()}</b><small>{selected?.target ?? "Awaiting first assessment"}</small></div></div>
            <div className="risk-scale"><span>LOW EXPOSURE</span><span>HIGH EXPOSURE</span></div><div className="risk-line"><i style={{ width: score + "%" }} /></div>
            <div className="posture-foot"><span><Zap size={13} /> Evidence-based score</span><span>{selected ? prettyDate(selected.created_at) : "No data"}</span></div>
          </div>
        </div>
        <div className="section-head findings-head"><div><div className="eyebrow">EVIDENCE & REMEDIATION</div><h2>Security findings</h2></div><div className="filter-wrap"><Search size={15} /><select value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div>
        <div className="findings-card">{(selected?.findings ?? latest?.findings ?? []).length === 0 ? <div className="empty-state"><ShieldCheck size={24} /><b>No findings loaded</b><span>Connect the API and run an authorized assessment to populate evidence.</span></div> : visibleFindings.map((finding) => <div className="finding-row" key={finding.code}><div className={"severity-icon " + severityClass(finding.severity)}><AlertTriangle size={16} /></div><div className="finding-detail"><b>{finding.title}</b><span>{finding.description}</span><small>RECOMMENDATION Â· {finding.recommendation}</small></div><span className={"severity-label " + severityClass(finding.severity)}>{finding.severity}</span></div>)}</div>
        <div className="section-head history-head"><div><div className="eyebrow">TRACEABILITY</div><h2>Assessment history</h2></div><button className="text-button" onClick={connect}><RefreshCw size={14} /> Refresh history</button></div>
        <div className="history-card">{assessments.length === 0 ? <div className="history-empty"><TerminalSquare size={17} /> No recorded assessments. Your history will appear here.</div> : assessments.map((item) => <button className={"history-row " + (selected?.id === item.id ? "selected" : "")} key={item.id} onClick={() => setSelected(item)}><span className="history-target"><Globe2 size={15} /> {item.target}</span><span className={"severity-label " + severityClass(item.risk_level)}>{item.risk_level}</span><span className="history-score">{item.score}/100</span><span className="history-date">{prettyDate(item.created_at)}</span><ArrowUpRight size={14} /></button>)}</div>
        <footer><span><Command size={13} /> SENTINEL <b>0.1.0</b></span><span>DEFENSIVE POSTURE PLATFORM Â· DEVELOPMENT BUILD</span><span><LockKeyhole size={12} /> AUTHORIZATION FIRST</span></footer>
      </section>
    </main>
  </div>;
}

function Metric({ icon, label, value, note, trend }: { icon: ReactNode; label: string; value: string | number; note: string; trend: string }) {
  return <div className="metric-card"><div className="metric-top"><span>{icon}</span><small>{trend}</small></div><label>{label}</label><strong>{value}</strong><p>{note}</p></div>;
}