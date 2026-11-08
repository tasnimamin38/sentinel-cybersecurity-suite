import type { CSSProperties, FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, CalendarClock, CheckCircle2, Download,
  ChevronDown, ChevronRight, CircleDot, ClipboardCheck, Database, Fingerprint,
  Globe2, KeyRound, Layers3, ListChecks, LockKeyhole, Plus, Radar, RefreshCw,
  ScanLine, Search, Server, Settings2, Shield, ShieldAlert, ShieldCheck,
  Workflow, FileSearch,
} from "lucide-react";

type View = "overview" | "assets" | "findings" | "remediations" | "controls" | "audit" | "security" | "secrets" | "credentials";
type Finding = {
  code: string; title: string; severity: string; description: string;
  recommendation: string; category?: string; confidence?: number;
};
type RiskExplanation = {
  model?: string; unique_findings?: number;
  drivers?: { code: string; severity: string; weighted_points: number }[];
};
type Assessment = {
  id: string; asset_id?: string | null; target: string; status: string;
  score: number; risk_level: string; findings: Finding[];
  evidence: { risk_explanation?: RiskExplanation; [key: string]: unknown };
  created_at: string;
};
type Overview = {
  assessment_count: number; findings_count: number; high_risk_count: number;
  authorized_domains: string[]; asset_count: number; active_asset_count: number;
  open_remediation_count: number;
};
type Asset = {
  id: string; hostname: string; name: string; owner: string; environment: string;
  criticality: number; authorization_expires_at: string;
  authorization_reference: string; status: string; tags: string[];
  created_at: string; updated_at: string;
};
type Remediation = {
  id: string; assessment_id: string; asset_id?: string | null; finding_code: string;
  title: string; severity: string; assignee: string; status: string;
  due_at?: string | null; notes: string; created_at: string; updated_at: string;
};
type AuditEvent = {
  id: string; sequence_no?: number | null; event_type: string; subject: string; result: string; details: string;
  previous_hash?: string | null; event_hash?: string | null; created_at: string;
};
type Control = {
  id: string; family: string; title: string; description: string;
  mapped_findings: string[]; matched_findings: string[];
  operational: string; status: string;
};
type SecurityEventDetails = {
  rule_id?: string; severity?: string; source_ip?: string; path?: string; method?: string;
  user_agent?: string; request_id?: string; observed_at?: string;
  failure_count?: number; window_seconds?: number;
};
type SecurityEvent = {
  id: string; event_type: string; severity: string; source_ip: string;
  details: SecurityEventDetails; sequence_no?: number | null;
  event_hash?: string | null; created_at: string;
};
type AuditIntegrity = {
  integrity_valid: boolean; verification_status: string; total_events: number; sealed_events: number;
  legacy_unsealed_events: number; verified_until?: string | null;
  errors: string[]; assurance_note: string;
};
type SecretScan = {
  findings: Finding[]; finding_count: number; input_bytes: number;
  source_persisted: boolean; redaction_policy: string;
};
type ApiIdentity = { credential_id: string; role: string; credential_source: string; permissions: string[] };
type ApiCredential = {
  id: string; label: string; role: string; key_prefix: string; expires_at?: string | null;
  revoked_at?: string | null; created_by: string; created_at: string; last_used_at?: string | null;
};
type CreatedCredential = { credential: ApiCredential; secret: string };
type PublicPlan = {
  code: string;
  name: string;
  status: "active" | "preview";
  price: { amount_cents: number | null; currency: string; interval: string; display: string };
  default_for_new_workspaces?: boolean;
  purchasable: boolean;
  checkout_enabled: boolean;
  feature_codes?: string[];
  limits?: Record<string, unknown>;
  limits_enforced?: boolean;
  limit_enforcement_status?: string;
  capacity_preview?: Record<string, number> | null;
  planned_for?: string;
  notice?: string;
};
type PublicPlanCatalog = {
  catalog_version: number;
  launch_mode: string;
  default_plan_code: string;
  billing_enabled: boolean;
  checkout_enabled: boolean;
  usage_limits_enforced: boolean;
  workspace_type: "personal" | "company" | null;
  plans: PublicPlan[];
  notice: string;
};

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");
const viewLabels: Record<View, string> = {
  overview: "Command center", assets: "Asset inventory", findings: "Security findings",
  remediations: "Remediation queue", controls: "Control coverage",
  audit: "Audit integrity", security: "Threat monitor", secrets: "Secret hygiene", credentials: "API access control",
};
const navGroups = [
  { label: "OPERATIONS", items: [
    { id: "overview" as View, label: "Command center", icon: Radar },
    { id: "assets" as View, label: "Asset inventory", icon: Server },
    { id: "findings" as View, label: "Findings", icon: ShieldAlert },
    { id: "security" as View, label: "Threat monitor", icon: Radar },
    { id: "remediations" as View, label: "Remediation", icon: ListChecks },
    { id: "secrets" as View, label: "Secret hygiene", icon: Fingerprint },
  ]},
  { label: "GOVERNANCE", items: [
    { id: "controls" as View, label: "Control coverage", icon: Layers3 },
    { id: "audit" as View, label: "Audit integrity", icon: ClipboardCheck },
  ]},
  { label: "ADMINISTRATION", items: [
    { id: "credentials" as View, label: "API access control", icon: KeyRound },
  ]},
];
const viewPermissions: Record<View, string> = {
  overview: "dashboard.read", assets: "asset.read", findings: "assessment.read",
  remediations: "remediation.read", controls: "controls.read", audit: "audit.read", security: "audit.read",
  secrets: "secrets.scan", credentials: "credential.manage",
};

function localDateTimeAfterDays(days: number) {
  const date = new Date(Date.now() + days * 86_400_000);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
}
function dateLabel(value?: string | null) {
  if (!value) return "Not scheduled";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
function dateTimeLabel(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}
function severityClass(value: string) {
  const current = (value || "").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(current) ? current : "info";
}
function shortHash(value?: string | null) {
  return value ? value.slice(0, 14) + "…" : "Not sealed";
}
function isAuthorizationExpired(value: string) {
  return new Date(value).getTime() <= Date.now();
}

export default function App() {
  const [planCatalog, setPlanCatalog] = useState<PublicPlanCatalog | null>(null);
  const [plansLoading, setPlansLoading] = useState(true);
  const [plansError, setPlansError] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [identity, setIdentity] = useState<ApiIdentity | null>(null);
  const [credentials, setCredentials] = useState<ApiCredential[]>([]);
  const [createdCredential, setCreatedCredential] = useState<CreatedCredential | null>(null);
  const [credentialDraft, setCredentialDraft] = useState({ label: "Service integration", role: "analyst", expires_at: localDateTimeAfterDays(90) });
  const [toast, setToast] = useState("Connect the API to load live security telemetry.");
  const [toastKind, setToastKind] = useState<"info" | "success" | "error">("info");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [auditIntegrity, setAuditIntegrity] = useState<AuditIntegrity | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [showAssetForm, setShowAssetForm] = useState(false);
  const [assessmentTarget, setAssessmentTarget] = useState("");
  const [secretText, setSecretText] = useState("");
  const [secretResult, setSecretResult] = useState<SecretScan | null>(null);
  const [assetDraft, setAssetDraft] = useState({
    hostname: "", name: "", owner: "", environment: "production",
    criticality: "1.0", authorization_expires_at: localDateTimeAfterDays(90),
    authorization_reference: "", tags: "internet-facing",
  });

  useEffect(() => {
    const controller = new AbortController();
    fetch(API_BASE + "/api/v1/plans", { signal: controller.signal, headers: { Accept: "application/json" } })
      .then(async (response) => {
        if (!response.ok) throw new Error("Plan catalogue is temporarily unavailable.");
        return response.json() as Promise<PublicPlanCatalog>;
      })
      .then((catalog) => {
        if (!controller.signal.aborted) setPlanCatalog(catalog);
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setPlansError(error instanceof Error ? error.message : "Could not load the plan catalogue.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setPlansLoading(false);
      });
    return () => controller.abort();
  }, []);

  async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("X-API-Key", apiKey);
    if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(API_BASE + path, { ...init, headers });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail ?? "Request failed (" + response.status + ").");
    return payload as T;
  }

  function notify(message: string, kind: "info" | "success" | "error" = "info") {
    setToast(message);
    setToastKind(kind);
  }

  async function loadCredentials() {
    setCredentials(await api<ApiCredential[]>("/api/v1/credentials"));
  }

  async function refreshData(identityOverride?: ApiIdentity) {
    const principal = identityOverride ?? identity;
    if (!principal) throw new Error("API identity was not loaded.");
    const results = await Promise.all([
      api<Overview>("/api/v1/overview"),
      api<Asset[]>("/api/v1/assets"),
      api<Assessment[]>("/api/v1/assessments?limit=100"),
      api<Remediation[]>("/api/v1/remediations"),
      api<{ controls: Control[] }>("/api/v1/controls"),
    ]);
    setOverview(results[0]); setAssets(results[1]); setAssessments(results[2]);
    setRemediations(results[3]); setControls(results[4].controls);
    if (principal.role === "admin" || principal.permissions.includes("audit.read")) {
      const [events, integrity, security] = await Promise.all([
        api<AuditEvent[]>("/api/v1/audit?limit=100"),
        api<AuditIntegrity>("/api/v1/audit/integrity"),
        api<SecurityEvent[]>("/api/v1/security/events?limit=100"),
      ]);
      setAuditEvents(events); setAuditIntegrity(integrity); setSecurityEvents(security);
    } else { setAuditEvents([]); setAuditIntegrity(null); setSecurityEvents([]); }
    if (principal.role === "admin" || principal.permissions.includes("credential.manage")) await loadCredentials();
  }

  async function downloadExport(dataset: string) {
    await runAction(async () => {
      const response = await fetch(API_BASE + "/api/v1/exports/" + dataset + ".csv", {
        headers: { "X-API-Key": apiKey },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail ?? "Export failed (" + response.status + ").");
      }
      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = "sentinel-" + dataset + ".csv";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(objectUrl);
      notify(dataset.toUpperCase() + " export generated and recorded in the audit journal.", "success");
    });
  }

  async function connect() {
    if (apiKey.trim().length < 32) {
      notify("Enter a valid SENTINEL API key (minimum 32 characters).", "error");
      return;
    }
    setBusy(true);
    try {
      const principal = await api<ApiIdentity>("/api/v1/me");
      setIdentity(principal);
      await refreshData(principal);
      setConnected(true);
      setView("overview");
      notify("Authenticated as " + principal.role.replace("_", " ") + ". Role-authorized live data loaded.", "success");
    } catch (error) {
      setConnected(false);
      notify(error instanceof Error ? error.message : "Could not connect to the API.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function runAction(action: () => Promise<void>) {
    setBusy(true);
    try { await action(); }
    catch (error) { notify(error instanceof Error ? error.message : "The operation failed.", "error"); }
    finally { setBusy(false); }
  }

  async function registerAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await runAction(async () => {
      await api<Asset>("/api/v1/assets", {
        method: "POST",
        body: JSON.stringify({
          ...assetDraft,
          criticality: Number(assetDraft.criticality),
          authorization_expires_at: new Date(assetDraft.authorization_expires_at).toISOString(),
          tags: assetDraft.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        }),
      });
      await refreshData();
      setShowAssetForm(false);
      setAssetDraft({
        hostname: "", name: "", owner: "", environment: "production",
        criticality: "1.0", authorization_expires_at: localDateTimeAfterDays(90),
        authorization_reference: "", tags: "internet-facing",
      });
      notify("Asset registered. Its authorization expiry is now enforced by the assessment API.", "success");
    });
  }

  async function assessAsset(asset: Asset) {
    await runAction(async () => {
      const result = await api<Assessment>("/api/v1/assets/" + asset.id + "/assessments", { method: "POST" });
      await refreshData();
      setView("findings");
      notify("Assessment finished for " + result.target + ": " + result.risk_level.toUpperCase() + " risk.", "success");
    });
  }

  async function assessDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!assessmentTarget.trim()) return;
    await runAction(async () => {
      const result = await api<Assessment>("/api/v1/assessments", {
        method: "POST", body: JSON.stringify({ domain: assessmentTarget.trim() }),
      });
      await refreshData();
      setAssessmentTarget("");
      setView("findings");
      notify("Assessment finished for " + result.target + ".", "success");
    });
  }

  async function createRemediation(assessmentId: string, findingCode: string) {
    await runAction(async () => {
      await api<Remediation>("/api/v1/remediations", {
        method: "POST", body: JSON.stringify({ assessment_id: assessmentId, finding_code: findingCode }),
      });
      await refreshData();
      setView("remediations");
      notify("Remediation task created from the recorded finding.", "success");
    });
  }

  async function updateRemediation(task: Remediation, nextStatus: string) {
    await runAction(async () => {
      await api<Remediation>("/api/v1/remediations/" + task.id, {
        method: "PATCH", body: JSON.stringify({ status: nextStatus }),
      });
      await refreshData();
      notify("Task " + task.finding_code + " moved to " + nextStatus.replace("_", " ") + ".", "success");
    });
  }

  async function scanSecrets(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!secretText.trim()) return;
    await runAction(async () => {
      const result = await api<SecretScan>("/api/v1/secrets/scan", {
        method: "POST", body: JSON.stringify({ content: secretText }),
      });
      setSecretResult(result); await refreshData();
      notify("Secret hygiene review complete. Submitted source text was not persisted.", "success");
    });
  }

  async function createCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await runAction(async () => {
      const created = await api<CreatedCredential>("/api/v1/credentials", {
        method: "POST", body: JSON.stringify({
          label: credentialDraft.label, role: credentialDraft.role,
          expires_at: new Date(credentialDraft.expires_at).toISOString(),
        }),
      });
      setCreatedCredential(created); setCredentialDraft({ label: "Service integration", role: "analyst", expires_at: localDateTimeAfterDays(90) });
      await loadCredentials();
      notify("API credential created. Copy the secret now; it will not be shown again.", "success");
    });
  }

  async function revokeCredential(credential: ApiCredential) {
    if (!window.confirm("Revoke " + credential.label + "? New requests using this credential will be rejected.")) return;
    await runAction(async () => {
      await api("/api/v1/credentials/" + credential.id + "/revoke", { method: "POST" });
      await loadCredentials(); notify("Credential revoked. Subsequent requests will be denied.", "success");
    });
  }

  async function copyCreatedSecret() {
    if (!createdCredential) return;
    await navigator.clipboard.writeText(createdCredential.secret);
    notify("New API secret copied to clipboard. Store it in your secret manager.", "success");
  }

  const allFindings = useMemo(() => assessments.flatMap((assessment) =>
    (assessment.findings || []).map((finding) => ({
      ...finding,
      assessmentId: assessment.id,
      target: assessment.target,
      createdAt: assessment.created_at,
      assetId: assessment.asset_id,
    })),
  ), [assessments]);

  const visibleFindings = allFindings.filter((finding) =>
    (severityFilter === "all" || finding.severity === severityFilter) &&
    (finding.title + " " + finding.code + " " + finding.target).toLowerCase().includes(search.toLowerCase()),
  );
  const visibleAssets = assets.filter((asset) =>
    (asset.hostname + " " + asset.name + " " + asset.owner + " " + asset.environment)
      .toLowerCase().includes(search.toLowerCase()),
  );
  const resolvedCount = remediations.filter((task) => task.status === "resolved").length;
  const activeCount = assets.filter((asset) => asset.status === "active").length;
  const latest = assessments[0];
  const environmentLabel = assets.some((asset) => asset.environment === "production") ? "PRODUCTION SCOPE" : "LOCAL WORKSPACE";
  const can = (permission: string) => identity?.role === "admin" || Boolean(identity?.permissions.includes(permission));
  const visibleNavGroups = navGroups.map((group) => ({ ...group, items: group.items.filter((item) => can(viewPermissions[item.id])) })).filter((group) => group.items.length > 0);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-emblem"><ShieldCheck size={22} strokeWidth={1.8} /></div>
          <div className="brand-copy"><strong>SENTINEL<span> / </span>0.7.0</strong><small>SECURITY OPERATIONS PLATFORM</small></div>
        </div>
        <div className="workspace-chip"><span className="live-dot" /> PRIVATE SECURITY WORKSPACE <ChevronDown size={13} /></div>
        <div className="sidebar-scroll">
          {visibleNavGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-group-label">{group.label}</div>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <button key={item.id} className={"nav-item " + (view === item.id ? "active" : "")} onClick={() => { setView(item.id); if (item.id === "credentials") runAction(loadCredentials); }}>
                    <Icon size={16} strokeWidth={1.8} /><span>{item.label}</span>
                    {item.id === "remediations" && remediations.some((task) => ["open", "in_progress"].includes(task.status)) && <i className="nav-indicator" />}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="sidebar-bottom">
          <div className="sidebar-security-card">
            <div className="security-card-top"><LockKeyhole size={14} /><span>AUTHORIZATION GATE</span><i /></div>
            <p>Assessments are restricted to explicitly allowlisted hostnames with active asset authorization.</p>
            <div className="security-card-state"><CheckCircle2 size={12} /> ENFORCED BY API</div>
          </div>
          <div className="profile-row"><div className="profile-avatar">{(identity?.role ?? "SA").slice(0, 2).toUpperCase()}</div><div className="profile-copy"><b>{identity ? identity.role.replace("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Security Operator"}</b><span>{identity ? identity.credential_source + " credential · " + identity.credential_id.slice(0, 12) : "API identity not connected"}</span></div><Settings2 size={15} /></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb"><span>Workspace</span><ChevronRight size={13} /><b>{viewLabels[view]}</b></div>
          <div className="topbar-actions">
            <div className={"connection-pill " + (connected ? "online" : "offline")}><span />{connected ? "API CONNECTED" : "API DISCONNECTED"}</div>
            <div className="topbar-divider" />
            <button className="top-icon-button" aria-label="Refresh" onClick={() => connected && runAction(refreshData)} disabled={!connected || busy}><RefreshCw size={15} /></button>
            <button className="top-icon-button" aria-label="Notifications" onClick={() => notify("No notification service is configured in this release.")}><Bell size={15} /></button>
            <div className="top-profile">SA</div>
          </div>
        </header>

        <div className="page-content">
          <section className="page-hero">
            <div className="hero-copy">
              <div className="eyebrow"><span className="eyebrow-square" /> SENTINEL SECURITY OPERATIONS CENTER <span className="eyebrow-rule" /></div>
              <h1>{viewLabels[view]}<em>.</em></h1>
              <p>Authorized visibility. Evidence-driven risk. Accountable remediation.</p>
            </div>
            <div className="hero-right">
              <div className="environment-tag"><CircleDot size={11} /> {environmentLabel}</div>
              <div className="hero-time"><span>LAST DATA REFRESH</span><b>{connected ? "LIVE API SNAPSHOT" : "AWAITING API CONNECTION"}</b></div>
            </div>
          </section>

          <section className="connect-strip">
            <div className="connect-symbol"><KeyRound size={17} /></div>
            <div className="connect-text"><b>{connected ? "SENTINEL API session active" : "Connect the SENTINEL control plane"}</b><span>{connected ? "The API key remains in component memory and is never saved to browser storage." : "Authenticate with your local API key to load live inventory, assessments and governance data."}</span></div>
            <input aria-label="API key" type="password" autoComplete="off" value={apiKey} onChange={(event) => setApiKey(event.target.value)} onKeyDown={(event) => event.key === "Enter" && connect()} placeholder="SENTINEL_API_KEY" />
            <button className="button-connect" onClick={connect} disabled={busy}>{busy ? <RefreshCw className="spin" size={14} /> : <ArrowUpRight size={14} />}{connected ? "RECONNECT" : "CONNECT API"}</button>
          </section>

          {toast && <div className={"toast-line " + toastKind}><span className="toast-icon">{toastKind === "error" ? <AlertTriangle size={14} /> : toastKind === "success" ? <CheckCircle2 size={14} /> : <Activity size={14} />}</span>{toast}<button onClick={() => setToast("")}>×</button></div>}

          {!connected ? (
            <>
              <section className="disconnected-panel">
                <div className="disconnected-visual"><div className="radar-ring r1" /><div className="radar-ring r2" /><div className="radar-ring r3" /><div className="radar-center"><Shield size={36} /></div><div className="radar-sweep" /></div>
                <div><div className="eyebrow">CONTROL PLANE NOT AUTHENTICATED</div><h2>Live telemetry is locked.</h2><p>Connect the API to reveal registered assets, security findings, task status, control coverage and audit-chain integrity. No demo metrics are shown.</p><div className="disconnected-actions"><span><LockKeyhole size={13} /> API KEY REQUIRED</span><span><Database size={13} /> DATABASE-BACKED DATA</span><span><ShieldCheck size={13} /> SCOPE ENFORCED</span></div></div>
              </section>
              <PublicPlans catalog={planCatalog} loading={plansLoading} error={plansError} />
            </>
          ) : (
            <>
              {view === "overview" && (
                <>
                  <section className="metric-grid">
                    <Metric icon={<Server size={17} />} label="REGISTERED ASSETS" value={overview?.asset_count ?? 0} foot={String(activeCount) + " active in inventory"} tone="cyan" />
                    <Metric icon={<Radar size={17} />} label="ASSESSMENTS" value={overview?.assessment_count ?? 0} foot="Recorded posture reviews" tone="blue" />
                    <Metric icon={<ShieldAlert size={17} />} label="HIGH-RISK REVIEWS" value={overview?.high_risk_count ?? 0} foot="High and critical assessment records" tone="amber" />
                    <Metric icon={<ListChecks size={17} />} label="OPEN REMEDIATIONS" value={overview?.open_remediation_count ?? 0} foot={String(resolvedCount) + " tasks resolved"} tone="green" />
                  </section>
                  <section className="overview-grid">
                    <div className="panel scan-panel">
                      <PanelHeading eyebrow="SAFE ASSESSMENT ENGINE" title="Run a domain review" icon={<ScanLine size={15} />} />
                      <p className="panel-intro">For ad-hoc checks, the target must belong to the configured authorized DNS scope. Managed assets should be assessed from the Asset Inventory to apply their authorization expiry and criticality profile.</p>
                      {can("assessment.run") && <form className="quick-scan-form" onSubmit={assessDomain}>
                        <label htmlFor="quick-target">AUTHORIZED HOSTNAME</label>
                        <div className="inline-input"><Globe2 size={15} /><input id="quick-target" value={assessmentTarget} onChange={(event) => setAssessmentTarget(event.target.value)} placeholder="app.example.com" /><button disabled={busy || !assessmentTarget.trim()}><ScanLine size={14} /> ASSESS</button></div>
                      </form>}
                      <div className="scope-list"><LockKeyhole size={13} /><span>CONFIGURED SCOPE</span><b>{overview?.authorized_domains.join(" · ") || "No domains configured"}</b></div>
                      <div className="scan-guards"><span><CheckCircle2 size={12} /> DNS PINNING</span><span><CheckCircle2 size={12} /> TLS VERIFY</span><span><CheckCircle2 size={12} /> NO REDIRECTS</span><span><CheckCircle2 size={12} /> HEADER-ONLY</span></div>
                    </div>
                    <div className="panel exposure-panel">
                      <PanelHeading eyebrow="LATEST RISK SNAPSHOT" title="Exposure posture" icon={<Activity size={15} />} />
                      {latest ? (
                        <>
                          <div className="risk-main"><div className={"risk-gauge " + severityClass(latest.risk_level)} style={{ "--risk": String(latest.score) + "%" } as CSSProperties}><div><b>{latest.score}</b><small>/100</small></div></div><div className="risk-summary"><span>OVERALL ASSESSMENT</span><strong className={severityClass(latest.risk_level)}>{latest.risk_level.toUpperCase()}</strong><b>{latest.target}</b><small>{dateTimeLabel(latest.created_at)}</small></div></div>
                          <div className="risk-explanation"><span>SCORING MODEL</span><b>{latest.evidence?.risk_explanation?.model ?? "Explainable risk v2"}</b><span>UNIQUE FINDINGS</span><b>{latest.evidence?.risk_explanation?.unique_findings ?? latest.findings.length}</b></div>
                        </>
                      ) : <EmptyState icon={<Radar size={23} />} title="No assessment history" text="Register an asset and run its first authorized posture review." />}
                    </div>
                  </section>
                  <section className="panel">
                    <div className="section-title-row"><PanelHeading eyebrow="ASSET GOVERNANCE" title="Recently registered assets" icon={<Server size={15} />} /><button className="link-button" onClick={() => setView("assets")}>VIEW INVENTORY <ArrowUpRight size={13} /></button></div>
                    {assets.length ? <AssetTable rows={assets.slice(0, 5)} onAssess={assessAsset} busy={busy || !can("assessment.run")} /> : <EmptyState icon={<Database size={22} />} title="Your inventory is empty" text="Add an authorized domain with an owner and an expiry-dated authorization record." action={can("asset.write") ? <button className="button-small" onClick={() => { setView("assets"); setShowAssetForm(true); }}><Plus size={13} /> REGISTER FIRST ASSET</button> : undefined} />}
                  </section>
                  <section className="bottom-grid">
                    <div className="panel"><PanelHeading eyebrow="PRIORITY QUEUE" title="Open remediation" icon={<ClipboardCheck size={15} />} />{remediations.filter((task) => ["open", "in_progress"].includes(task.status)).slice(0, 4).map((task) => <RemediationMini key={task.id} task={task} />)}{!remediations.some((task) => ["open", "in_progress"].includes(task.status)) && <EmptyState title="No open tasks" text="Create a task from a security finding to start tracking remediation." />}</div>
                    <div className="panel"><PanelHeading eyebrow="AUDIT ASSURANCE" title="Evidence integrity" icon={<Fingerprint size={15} />} /><div className={"integrity-summary " + (auditIntegrity?.integrity_valid ? "good" : "bad")}><div>{auditIntegrity?.integrity_valid ? <ShieldCheck size={23} /> : <AlertTriangle size={23} />}</div><strong>{auditIntegrity?.verification_status === "verified" ? "CHAIN VERIFIED" : auditIntegrity?.verification_status === "incomplete_legacy" ? "LEGACY EVENTS — INCOMPLETE" : auditIntegrity?.verification_status === "empty" ? "NO AUDIT EVENTS" : "CHAIN NEEDS REVIEW"}</strong><b>{auditIntegrity?.sealed_events ?? 0} sealed events</b></div><p className="integrity-copy">{auditIntegrity?.legacy_unsealed_events ?? 0} legacy events pre-date hash chaining. Hash chaining is tamper-evident, not immutable storage.</p><button className="link-button" onClick={() => setView("audit")}>INSPECT AUDIT <ArrowUpRight size={13} /></button></div>
                  </section>
                </>
              )}

              {view === "assets" && (
                <section className="panel page-panel">
                  <div className="section-title-row"><PanelHeading eyebrow="AUTHORIZED ASSET REGISTER" title="Inventory and authorization" icon={<Server size={15} />} /><div className="header-actions">{can("export.read") && <button className="link-button" onClick={() => downloadExport("assets")} disabled={busy}><Download size={13} /> EXPORT CSV</button>}{can("asset.write") && <button className="button-small" onClick={() => setShowAssetForm(!showAssetForm)}><Plus size={14} /> {showAssetForm ? "CLOSE FORM" : "REGISTER ASSET"}</button>}</div></div>
                  <div className="page-toolbar"><div className="search-box"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search hostname, owner or environment" /></div><span className="data-count">{visibleAssets.length} ASSETS</span></div>
                  {can("asset.write") && showAssetForm && <form className="asset-form" onSubmit={registerAsset}>
                    <div className="form-heading"><div><span>NEW AUTHORIZED ASSET</span><b>Register a managed hostname</b></div><span className="form-secure"><LockKeyhole size={12} /> SCOPE CHECKED</span></div>
                    <div className="form-grid">
                      <Field label="HOSTNAME" value={assetDraft.hostname} onChange={(v) => setAssetDraft({ ...assetDraft, hostname: v })} placeholder="portal.example.com" required />
                      <Field label="ASSET NAME" value={assetDraft.name} onChange={(v) => setAssetDraft({ ...assetDraft, name: v })} placeholder="Customer portal" required />
                      <Field label="RESPONSIBLE OWNER" value={assetDraft.owner} onChange={(v) => setAssetDraft({ ...assetDraft, owner: v })} placeholder="Platform Security" required />
                      <label className="field-label">ENVIRONMENT<select value={assetDraft.environment} onChange={(event) => setAssetDraft({ ...assetDraft, environment: event.target.value })}><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option><option value="lab">Lab</option></select></label>
                      <label className="field-label">ASSET CRITICALITY<select value={assetDraft.criticality} onChange={(event) => setAssetDraft({ ...assetDraft, criticality: event.target.value })}><option value="0.5">0.5 · Low</option><option value="0.8">0.8 · Moderate</option><option value="1.0">1.0 · Standard</option><option value="1.2">1.2 · High</option><option value="1.5">1.5 · Critical</option></select></label>
                      <label className="field-label">AUTHORIZATION EXPIRES<input type="datetime-local" value={assetDraft.authorization_expires_at} onChange={(event) => setAssetDraft({ ...assetDraft, authorization_expires_at: event.target.value })} required /></label>
                      <Field label="APPROVAL / CHANGE REFERENCE" value={assetDraft.authorization_reference} onChange={(v) => setAssetDraft({ ...assetDraft, authorization_reference: v })} placeholder="CHANGE-SEC-2048" required />
                      <Field label="TAGS · COMMA SEPARATED" value={assetDraft.tags} onChange={(v) => setAssetDraft({ ...assetDraft, tags: v })} placeholder="internet-facing, tier-1" />
                    </div>
                    <div className="form-footer"><p>Only domains inside the server-side allowlist can be registered. Expired authorization blocks the asset assessment endpoint.</p><button className="button-connect" disabled={busy}><ShieldCheck size={14} /> SAVE AUTHORIZATION RECORD</button></div>
                  </form>}
                  {visibleAssets.length ? <AssetTable rows={visibleAssets} onAssess={assessAsset} busy={busy || !can("assessment.run")} /> : <EmptyState icon={<Database size={23} />} title="No matching assets" text="Register an authorized hostname to create its ownership and approval record." />}
                </section>
              )}

              {view === "findings" && (
                <section className="panel page-panel">
                  <div className="section-title-row"><PanelHeading eyebrow="EVIDENCE & RISK" title="Findings register" icon={<ShieldAlert size={15} />} /><div className="header-actions">{can("export.read") && <button className="link-button" onClick={() => downloadExport("findings")} disabled={busy}><Download size={13} /> EXPORT CSV</button>}<span className="data-count">{visibleFindings.length} MATCHING FINDINGS</span></div></div>
                  <div className="page-toolbar"><div className="search-box"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search code, target or finding" /></div><select className="toolbar-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Informational</option></select></div>
                  {visibleFindings.length ? <div className="finding-list">{visibleFindings.map((finding, index) => {
                    const exists = remediations.some((task) => task.assessment_id === finding.assessmentId && task.finding_code === finding.code);
                    return <div className="finding-card" key={finding.assessmentId + finding.code + index}><div className={"finding-severity " + severityClass(finding.severity)}><AlertTriangle size={15} /></div><div className="finding-body"><div className="finding-meta"><code>{finding.code}</code><span>{finding.category ?? "security"}</span><span>{dateLabel(finding.createdAt)}</span></div><b>{finding.title}</b><p>{finding.description}</p><div className="finding-remediation"><b>RECOMMENDATION</b><span>{finding.recommendation}</span></div><small>{finding.target} · Confidence {Math.round((finding.confidence ?? 1) * 100)}%</small></div><div className="finding-actions"><span className={"severity-chip " + severityClass(finding.severity)}>{finding.severity}</span><button className="button-small" disabled={!can("remediation.write") || busy || exists} onClick={() => createRemediation(finding.assessmentId, finding.code)}><Plus size={13} /> {exists ? "TASK EXISTS" : "CREATE TASK"}</button></div></div>;
                  })}</div> : <EmptyState icon={<ShieldCheck size={23} />} title="No findings match this view" text="Run an authorized assessment or adjust the search and severity filter." />}
                </section>
              )}

              {view === "remediations" && (
                <section className="panel page-panel">
                  <div className="section-title-row"><PanelHeading eyebrow="REMEDIATION LIFECYCLE" title="Action and ownership queue" icon={<Workflow size={15} />} /><div className="header-actions">{can("export.read") && <button className="link-button" onClick={() => downloadExport("remediations")} disabled={busy}><Download size={13} /> EXPORT CSV</button>}<span className="data-count">{remediations.length} TRACKED TASKS</span></div></div>
                  <div className="remediation-summary"><SummaryTile label="OPEN" value={remediations.filter((task) => task.status === "open").length} /><SummaryTile label="IN PROGRESS" value={remediations.filter((task) => task.status === "in_progress").length} /><SummaryTile label="RESOLVED" value={resolvedCount} /><SummaryTile label="ACCEPTED" value={remediations.filter((task) => task.status === "accepted").length} /></div>
                  {remediations.length ? <div className="task-list">{remediations.map((task) => <div className="task-row" key={task.id}><div className={"task-severity " + severityClass(task.severity)}><ClipboardCheck size={16} /></div><div className="task-main"><div><code>{task.finding_code}</code><span className={"severity-chip " + severityClass(task.severity)}>{task.severity}</span></div><b>{task.title}</b><p>{task.assignee || "Unassigned"} · Due {dateLabel(task.due_at)} · Task {task.id.slice(0, 8)}</p></div><select className="task-status" value={task.status} onChange={(event) => updateRemediation(task, event.target.value)} disabled={!can("remediation.write") || busy}><option value="open">Open</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option><option value="accepted">Accepted</option></select></div>)}</div> : <EmptyState icon={<ListChecks size={23} />} title="The remediation queue is empty" text="Open the Findings view and create tasks from findings you want to assign and track." />}
                </section>
              )}

              {view === "controls" && (
                <section className="panel page-panel">
                  <div className="section-title-row"><PanelHeading eyebrow="OPERATIONAL CONTROL MAP" title="Security control coverage" icon={<Layers3 size={15} />} /><span className="neutral-chip">SENTINEL BASELINE · NOT A CERTIFICATION</span></div>
                  <p className="panel-intro">A framework-neutral operational map links recorded findings to security control themes. “Not observed” means no mapped finding appeared in the retained assessments; it is not proof that a control is effective.</p>
                  <div className="control-grid">{controls.map((control) => <div className="control-card" key={control.id}><div className="control-card-top"><code>{control.id}</code><span className={"control-state " + control.status}>{control.status === "attention" ? "ATTENTION" : "NOT OBSERVED"}</span></div><small>{control.family}</small><b>{control.title}</b><p>{control.description}</p><div className="control-footer"><span>{control.matched_findings.length} mapped findings</span><span>{control.operational}</span></div>{control.matched_findings.length > 0 && <div className="control-matches">{control.matched_findings.map((code) => <code key={code}>{code}</code>)}</div>}</div>)}</div>
                </section>
              )}

              {view === "audit" && (
                <section className="panel page-panel">
                  <div className="section-title-row"><PanelHeading eyebrow="TAMPER-EVIDENT TRACEABILITY" title="Audit chain and event journal" icon={<Fingerprint size={15} />} /><div className="header-actions">{can("export.read") && <button className="link-button" onClick={() => downloadExport("audit")} disabled={busy}><Download size={13} /> EXPORT CSV</button>}<button className="link-button" onClick={() => runAction(refreshData)}><RefreshCw size={13} /> VERIFY AGAIN</button></div></div>
                  <div className="audit-banner">
                    <div className={"audit-seal " + (auditIntegrity?.integrity_valid ? "verified" : "warning")}>{auditIntegrity?.integrity_valid ? <ShieldCheck size={26} /> : <AlertTriangle size={26} />}</div>
                    <div className="audit-banner-copy"><span>CHAIN VERIFICATION RESULT</span><b>{auditIntegrity?.integrity_valid ? "NO HASH-CHAIN MISMATCH DETECTED" : "AUDIT CHAIN REQUIRES REVIEW"}</b><small>{auditIntegrity?.assurance_note}</small></div>
                  </div>
                  <div className="audit-metrics"><SummaryTile label="TOTAL EVENTS" value={auditIntegrity?.total_events ?? 0} /><SummaryTile label="SEALED EVENTS" value={auditIntegrity?.sealed_events ?? 0} /><SummaryTile label="LEGACY UNSEALED" value={auditIntegrity?.legacy_unsealed_events ?? 0} /><SummaryTile label="INTEGRITY ERRORS" value={auditIntegrity?.errors.length ?? 0} /></div>
                  {auditIntegrity?.errors.map((error) => <div className="audit-error" key={error}><AlertTriangle size={13} />{error}</div>)}
                  <div className="audit-event-list">{auditEvents.map((event) => <div className="audit-event" key={event.id}><div className="event-mark"><Activity size={14} /></div><div className="event-body"><b>#{event.sequence_no ?? "LEGACY"} · {event.event_type}</b><span>{event.subject || "System event"} · {event.details}</span><small>{dateTimeLabel(event.created_at)}</small></div><div className="event-hash"><span>{shortHash(event.event_hash)}</span><small>{event.event_hash ? "HASH SEALED" : "LEGACY RECORD"}</small></div></div>)}</div>
                </section>
              )}

              {view === "security" && can("audit.read") && (
                <section className="panel page-panel">
                  <div className="section-title-row">
                    <PanelHeading eyebrow="RUNTIME INTRUSION MONITOR" title="Security event stream" icon={<Radar size={15} />} />
                    <div className="header-actions">
                      <span className="data-count">{securityEvents.length} RECENT SIGNALS</span>
                      <button className="link-button" onClick={() => runAction(refreshData)} disabled={busy}><RefreshCw size={13} /> REFRESH EVENTS</button>
                    </div>
                  </div>
                  <p className="panel-intro">Defensive telemetry from requests reaching this SENTINEL deployment: decoy-path probes, API authentication failures, brute-force thresholds and rate-limit signals. Entries are drawn from the hash-linked audit journal. Source IPs identify network endpoints, not verified people.</p>
                  <div className="audit-metrics">
                    <SummaryTile label="RECENT EVENTS" value={securityEvents.length} />
                    <SummaryTile label="CRITICAL" value={securityEvents.filter((event) => event.severity === "critical").length} />
                    <SummaryTile label="HIGH" value={securityEvents.filter((event) => event.severity === "high").length} />
                    <SummaryTile label="AUTH FAILURES" value={securityEvents.filter((event) => event.event_type === "security.api_auth_failure" || event.event_type === "security.brute_force_detected").length} />
                  </div>
                  {securityEvents.length ? (
                    <div className="audit-event-list">
                      {securityEvents.map((event) => (
                        <div className="audit-event" key={event.id}>
                          <div className={"finding-severity " + severityClass(event.severity)}><ShieldAlert size={15} /></div>
                          <div className="event-body">
                            <b>{(event.details.rule_id ?? event.event_type).replace(/_/g, " ")}</b>
                            <span>{event.details.path ?? "API request"} · {event.details.method ?? "—"} · {event.source_ip}</span>
                            <small>{dateTimeLabel(event.created_at)} · Request {event.details.request_id ?? "—"}</small>
                            {event.details.failure_count !== undefined && <small>{event.details.failure_count} failed authentications in {event.details.window_seconds ?? "configured"} seconds</small>}
                          </div>
                          <div className="event-hash">
                            <span className={"severity-chip " + severityClass(event.severity)}>{event.severity}</span>
                            <small>{event.sequence_no ? "EVENT #" + event.sequence_no : shortHash(event.event_hash)}</small>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : <EmptyState icon={<ShieldCheck size={23} />} title="No intrusion signals recorded" text="SENTINEL will list decoy-path probes, failed API authentication and rate-limit signals here when they occur. An empty list does not prove the deployment has never been probed." />}
                </section>
              )}

              {view === "secrets" && can("secrets.scan") && (
                <section className="panel page-panel">
                  <div className="section-title-row"><PanelHeading eyebrow="CREDENTIAL HYGIENE" title="Redacting secret pattern review" icon={<Fingerprint size={15} />} /><span className="neutral-chip">NO SOURCE RETENTION</span></div>
                  <p className="panel-intro">Paste a bounded text snippet such as a configuration excerpt or code fragment. The API checks a small set of known credential patterns, returns fingerprints only and stores neither the submitted text nor matched values. This is not a complete secret scanner.</p>
                  <form onSubmit={scanSecrets}>
                    <label className="field-label">TEXT TO REVIEW · MAXIMUM 256 KB<textarea className="secret-input" value={secretText} onChange={(event) => setSecretText(event.target.value)} rows={8} maxLength={262144} placeholder={"# Paste a small configuration or code excerpt\nAPI_TOKEN=..."} /></label>
                    <div className="secret-actions"><span>{new TextEncoder().encode(secretText).length.toLocaleString()} bytes · API payload is not retained</span><button className="button-connect" disabled={busy || !secretText.trim()}><FileSearch size={14} /> SCAN AND REDACT</button></div>
                  </form>
                  {secretResult && <div className="secret-results"><div className="secret-result-head"><b>{secretResult.finding_count} potential credential patterns</b><span>{secretResult.input_bytes.toLocaleString()} bytes examined · persisted: {String(secretResult.source_persisted)}</span></div><p>{secretResult.redaction_policy}</p>{secretResult.findings.length ? secretResult.findings.map((finding, index) => <div className="finding-card" key={finding.code + index}><div className={"finding-severity " + severityClass(finding.severity)}><KeyRound size={15} /></div><div className="finding-body"><b>{finding.title}</b><p>{finding.description}</p><div className="finding-remediation"><b>REMEDIATION</b><span>{finding.recommendation}</span></div><small>{String((finding as Finding & { evidence?: string }).evidence ?? "[REDACTED]")}</small></div><span className={"severity-chip " + severityClass(finding.severity)}>{finding.severity}</span></div>) : <EmptyState icon={<ShieldCheck size={22} />} title="No supported patterns detected" text="This result does not prove the source is free of secrets; the pattern catalog is intentionally limited." />}</div>}
                </section>
              )}

              {view === "credentials" && can("credential.manage") && (
                <section className="panel page-panel credential-page">
                  <div className="section-title-row"><PanelHeading eyebrow="SERVICE IDENTITY ADMINISTRATION" title="API access and credential inventory" icon={<KeyRound size={15} />} /><span className="neutral-chip">ADMIN ONLY · HASHES NEVER DISPLAYED</span></div>
                  <p className="panel-intro">Create scoped service credentials for integrations and automation. Each key is shown once, stored as a SHA-256 digest, and checked for expiry or revocation on each API request. Keep the bootstrap admin key in a separate secret manager.</p>
                  {createdCredential && <div className="credential-secret-panel">
                    <div className="credential-secret-title"><ShieldCheck size={17} /><div><b>New credential created</b><span>Copy this secret now. It cannot be retrieved after this panel is cleared.</span></div></div>
                    <div className="credential-secret-value"><code>{createdCredential.secret}</code><button className="button-small" onClick={copyCreatedSecret}><ClipboardCheck size={13} /> COPY SECRET</button></div>
                    <div className="credential-secret-meta">{createdCredential.credential.label} · {createdCredential.credential.role} · Expires {dateTimeLabel(createdCredential.credential.expires_at)}</div>
                    <button className="link-button" onClick={() => setCreatedCredential(null)}>CLEAR ONE-TIME SECRET</button>
                  </div>}
                  <form className="credential-create-form" onSubmit={createCredential}>
                    <div className="form-heading"><div><span>NEW SERVICE CREDENTIAL</span><b>Issue a least-privilege API key</b></div><span className="form-secure"><LockKeyhole size={12} /> HASH-ONLY STORAGE</span></div>
                    <div className="credential-form-grid">
                      <label className="field-label">CREDENTIAL LABEL<input value={credentialDraft.label} onChange={(event) => setCredentialDraft({ ...credentialDraft, label: event.target.value })} required minLength={2} maxLength={80} /></label>
                      <label className="field-label">ROLE<select value={credentialDraft.role} onChange={(event) => setCredentialDraft({ ...credentialDraft, role: event.target.value })}><option value="analyst">Analyst</option><option value="asset_manager">Asset manager</option><option value="auditor">Auditor</option><option value="read_only">Read only</option><option value="admin">Administrator</option></select></label>
                      <label className="field-label">EXPIRES AT<input type="datetime-local" value={credentialDraft.expires_at} onChange={(event) => setCredentialDraft({ ...credentialDraft, expires_at: event.target.value })} required /></label>
                    </div>
                    <div className="form-footer"><p>Maximum lifetime: 365 days. Default: 90 days. Keep one independent admin credential for recovery.</p><button className="button-connect" disabled={busy || credentialDraft.label.trim().length < 2}><Plus size={14} /> CREATE API CREDENTIAL</button></div>
                  </form>
                  <div className="credential-inventory-heading"><div><span>MANAGED CREDENTIALS</span><b>{credentials.length} records</b></div><button className="link-button" onClick={() => runAction(loadCredentials)} disabled={busy}><RefreshCw size={13} /> REFRESH</button></div>
                  {credentials.length ? <div className="table-wrap"><table className="data-table credential-table">
                    <thead><tr><th>LABEL / PREFIX</th><th>ROLE</th><th>CREATED</th><th>LAST USED</th><th>EXPIRES</th><th>STATUS</th><th>ACTION</th></tr></thead>
                    <tbody>{credentials.map((credential) => {
                      const expired = Boolean(credential.expires_at && new Date(credential.expires_at).getTime() <= Date.now());
                      const active = !credential.revoked_at && !expired;
                      return <tr key={credential.id}>
                        <td><b>{credential.label}</b><br /><code>{credential.key_prefix}…</code></td><td><span className="env-chip">{credential.role.replace("_", " ")}</span></td>
                        <td>{dateTimeLabel(credential.created_at)}</td><td>{dateTimeLabel(credential.last_used_at)}</td><td>{dateTimeLabel(credential.expires_at)}</td>
                        <td><span className={"credential-state " + (active ? "active" : "inactive")}>{credential.revoked_at ? "REVOKED" : expired ? "EXPIRED" : "ACTIVE"}</span></td>
                        <td><button className="table-action" disabled={busy || !active || credential.id === identity?.credential_id} onClick={() => revokeCredential(credential)}>REVOKE</button></td>
                      </tr>;
                    })}</tbody>
                  </table></div> : <EmptyState icon={<KeyRound size={22} />} title="No managed credentials" text="Create a scoped service key for an integration, analyst or audit workflow." /> }
                </section>
              )}
            </>
          )}
          <footer className="app-footer"><span><ShieldCheck size={13} /> SENTINEL <b>0.7.0</b></span><span>DEFENSIVE SECURITY OPERATIONS · AUTHORIZATION FIRST</span><span><LockKeyhole size={12} /> SAFE MODE</span></footer>
        </div>
      </main>
    </div>
  );
}

 
function PublicPlans({ catalog, loading, error }: { catalog: PublicPlanCatalog | null; loading: boolean; error: string }) {
  return (
    <section className="plans-section" aria-labelledby="plans-heading">
      <div className="plans-heading">
        <div>
          <div className="eyebrow"><span className="eyebrow-square" /> FREE-FIRST SAAS · EARLY ACCESS</div>
          <h2 id="plans-heading">Security operations for every team.</h2>
          <p>Every currently shipped core security module is included in Free Early Access. Future plans are previews only; billing and checkout are disabled.</p>
        </div>
        <div className="plans-billing-state"><span className="live-dot" /> BILLING DISABLED</div>
      </div>
      {loading && <div className="plans-status">Loading the live plan catalogue…</div>}
      {error && <div className="plans-status plans-error">{error}</div>}
      {catalog && (
        <>
          <div className="plans-grid">
            {catalog.plans.map((plan) => {
              const limits = plan.limits?.by_workspace_type as Record<string, Record<string, number | string>> | undefined;
              const personal = limits?.personal;
              const company = limits?.company;
              return (
                <article className={"plan-card " + (plan.code === catalog.default_plan_code ? "plan-card-featured" : "")} key={plan.code}>
                  <div className="plan-card-top">
                    <span className={"plan-status " + (plan.status === "active" ? "active" : "preview")}>{plan.status === "active" ? "AVAILABLE NOW" : "FUTURE PREVIEW"}</span>
                    {plan.default_for_new_workspaces && <span className="plan-default">DEFAULT</span>}
                  </div>
                  <h3>{plan.name}</h3>
                  <div className="plan-price">{plan.price.display}<small>{plan.price.interval === "month" ? "/ month" : ""}</small></div>
                  <p className="plan-description">{plan.notice ?? plan.planned_for}</p>
                  {plan.code === "free_early_access" && (
                    <div className="plan-limits">
                      <div><b>Personal target</b><span>{personal?.max_assets ?? "—"} assets · {personal?.assessments_per_month ?? "—"} assessments/mo</span></div>
                      <div><b>Company target</b><span>{company?.max_assets ?? "—"} assets · {company?.assessments_per_month ?? "—"} assessments/mo</span></div>
                      <small>Usage ceilings are published targets; enforcement is not enabled yet.</small>
                    </div>
                  )}
                  {plan.capacity_preview && (
                    <div className="plan-limits">
                      <div><b>Planned capacity</b><span>{plan.capacity_preview.max_assets.toLocaleString()} assets · {plan.capacity_preview.assessments_per_month.toLocaleString()} assessments/mo</span></div>
                      <div><b>Workspace</b><span>{plan.capacity_preview.max_members} human seats · {plan.capacity_preview.max_machine_identities} machine identities</span></div>
                    </div>
                  )}
                  <div className="plan-card-footer">
                    <span>{plan.code === "free_early_access" ? (plan.feature_codes?.length ?? 0) + " core modules included" : plan.planned_for}</span>
                    <span className="plan-no-checkout">{plan.purchasable || plan.checkout_enabled ? "PURCHASE AVAILABLE" : "NO CHECKOUT"}</span>
                  </div>
                </article>
              );
            })}
          </div>
          <p className="plans-footnote">{catalog.notice} Plan catalogue v{catalog.catalog_version}. All plan details are supplied by the live SENTINEL API.</p>
        </>
      )}
    </section>
  );
}

function PanelHeading({ eyebrow, title, icon }: { eyebrow: string; title: string; icon: ReactNode }) {
  return <div className="panel-heading"><div className="panel-icon">{icon}</div><div><span>{eyebrow}</span><h2>{title}</h2></div></div>;
}
function Metric({ icon, label, value, foot, tone }: { icon: ReactNode; label: string; value: string | number; foot: string; tone: string }) {
  return <div className={"metric-card " + tone}><div className="metric-card-top"><div>{icon}</div><span>LIVE DATA</span></div><label>{label}</label><strong>{value}</strong><small>{foot}</small><i /></div>;
}
function EmptyState({ icon, title, text, action }: { icon?: ReactNode; title: string; text: string; action?: ReactNode }) {
  return <div className="empty-state">{icon && <div className="empty-icon">{icon}</div>}<b>{title}</b><p>{text}</p>{action}</div>;
}
function AssetTable({ rows, onAssess, busy }: { rows: Asset[]; onAssess: (asset: Asset) => void; busy: boolean }) {
  return <div className="table-wrap"><table className="data-table"><thead><tr><th>ASSET</th><th>ENVIRONMENT</th><th>OWNER</th><th>CRITICALITY</th><th>AUTHORIZATION</th><th>STATUS</th><th /></tr></thead><tbody>{rows.map((asset) => {
    const expired = isAuthorizationExpired(asset.authorization_expires_at);
    const actionable = asset.status === "active" && !expired;
    return <tr key={asset.id}><td><div className="asset-name"><span><Globe2 size={14} /></span><div><b>{asset.name}</b><small>{asset.hostname}</small></div></div></td><td><span className="env-chip">{asset.environment}</span></td><td>{asset.owner}</td><td><span className="criticality-value">{asset.criticality.toFixed(1)}×</span></td><td><div className="auth-date"><CalendarClock size={12} /><span>{dateLabel(asset.authorization_expires_at)}</span></div><small className="auth-ref">{asset.authorization_reference}</small></td><td><span className={"asset-status " + (expired ? "inactive" : asset.status)}><i />{expired ? "expired" : asset.status}</span></td><td><button className="table-action" onClick={() => onAssess(asset)} disabled={busy || !actionable}><ScanLine size={13} /> ASSESS</button></td></tr>;
  })}</tbody></table></div>;
}
function Field({ label, value, onChange, placeholder, required = false }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; required?: boolean }) {
  return <label className="field-label">{label}<input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} required={required} /></label>;
}
function SummaryTile({ label, value }: { label: string; value: number }) {
  return <div className="summary-tile"><span>{label}</span><b>{value}</b></div>;
}
function RemediationMini({ task }: { task: Remediation }) {
  return <div className="mini-task"><div className={"mini-dot " + severityClass(task.severity)} /><div><b>{task.finding_code}</b><span>{task.title}</span></div><small>{task.status.replace("_", " ")}</small></div>;
}
