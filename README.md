<div align="center">
  <img src="docs/assets/sentinel-banner.svg" alt="SENTINEL — Defensive Security Operations" width="100%" />

  <p>
    <a href="https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/ci.yml"><img src="https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" /></a>
    <a href="https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/codeql.yml"><img src="https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-3b8f84.svg" alt="Apache 2.0" /></a>
    <img src="https://img.shields.io/badge/Release-0.3.2-3977a7.svg" alt="Version 0.3.2" />
    <img src="https://img.shields.io/badge/Security-Defensive%20Only-1b806b.svg" alt="Defensive only" />
  </p>

  <h3>Authorized asset governance · Evidence-driven posture · Accountable remediation</h3>
  <p><em>A defensive security operations foundation for teams that need to know what they own, what was observed, what needs attention, and who is responsible.</em></p>
</div>

---

## What SENTINEL is

SENTINEL is an open-source, defensive-security engineering platform for systems that you own or are explicitly authorized to assess. It combines a <strong>FastAPI control API</strong>, a <strong>React security operations console</strong>, SQL persistence, expiry-dated asset authorization, a bounded HTTPS assessment engine, remediation tracking and a tamper-evident audit chain.

The current release is an <strong>engineering baseline</strong>, not a certified enterprise product, compliance platform, WAF, EDR or SIEM. The repository intentionally separates working controls from capabilities that still require infrastructure and independent verification.

<div align="center">

| Capability | Implementation |
|:---|:---:|
| Time-bounded authorized asset inventory | Implemented |
| DNS-pinned HTTPS/TLS and extended email/certificate DNS posture | Implemented |
| HSTS/CSP policy-quality analysis | Implemented |
| Explainable risk scoring and findings | Implemented |
| Remediation ownership and task status | Implemented |
| Framework-neutral control mapping | Implemented |
| Redacting inline secret-pattern review | Implemented |
| Hash-linked audit event verification | Implemented |
| Alembic schema migrations | Implemented |
| Overlapping API-key rotation | Implemented |
| Audited CSV exports with formula-injection defense | Implemented |
| PostgreSQL durable assessment queue, idempotency and cancellation | Implemented in 0.6 branch |
| Separate resource-bounded assessment worker service | Implemented in 0.6 branch |
| OIDC/SSO, MFA, full RBAC and multi-tenant isolation | Roadmap |
| Independent network egress gateway and immutable evidence storage | Roadmap |

</div>

## Operations console

The console uses live API-backed information. Asset, finding, remediation and audit views include export actions; the API records each export in the audit journal. It deliberately shows an unauthenticated state instead of presenting fabricated metrics when the control API is not connected.

| Command center | Asset governance |
|:---:|:---:|
| Live assessments, risk snapshot, asset and remediation summary | Owner, environment, criticality, approval reference and expiry-dated scope |

| Findings and remediation | Assurance and audit |
|:---:|:---:|
| Evidence, remediation recommendation and task tracking | Control mapping, event hashes and chain verification |

## Capability map

### 01 — Asset governance

- Register DNS hostnames only inside the configured server-side allowlist.
- Store an asset name, accountable owner, environment, criticality, tags and approval/change reference.
- Require a future, timezone-aware authorization expiry.
- Block managed-asset assessments when the asset is paused, inactive or its authorization has expired.
- Apply asset criticality to the risk model for registered-asset assessments.

### 02 — Bounded web and DNS posture

- Resolve the complete DNS answer set and reject non-global addresses.
- Connect to a literal, previously validated public IP while preserving the original hostname for TLS SNI, certificate verification and the HTTP <code>Host</code> header.
- Send one bounded HTTPS <code>GET /</code>; do not follow redirects or download the response body.
- Enforce a shared timeout budget, bounded DNS answer count and 64 KiB response-header limit.
- Inspect HTTP security-header policy quality, including HSTS lifetime/subdomain scope, CSP unsafe directives, referrer policy and permissive Permissions Policy.
- Inspect MX, SPF duplication and permissive mechanisms, DMARC policy strength, inherited CAA, MTA-STS discovery and SMTP TLS reporting records. DNS checks are passive and do not modify target records; they share a bounded lookup budget and flag incomplete resolver results rather than treating timeouts as missing records.

### 03 — Explainable risk and remediation

- Normalize findings with stable codes, category, severity, confidence, evidence and recommendation.
- Deduplicate <code>(category, code)</code> findings.
- Apply a bounded asset-criticality multiplier and expose the scoring model, weighted points and top risk drivers.
- Create a remediation task only from a finding that exists in a stored assessment.
- Track owner, due date, notes and task state: <code>open</code>, <code>in_progress</code>, <code>resolved</code> or <code>accepted</code>.

> SENTINEL's risk score is its own deterministic prioritization model. It is not a CVSS score and must not be represented as one.

### 04 — Secret hygiene and audit assurance

- Review a submitted text snippet of up to 256 KiB for selected GitHub, AWS, Slack and private-key patterns.
- Return a redacted marker and a short SHA-256 fingerprint; never echo the matched value.
- Do not persist the submitted source text. The audit event records only input byte count and finding count.
- Hash-link audit events with SHA-256 and verify previous-hash continuity and event contents.
- Export bounded assets, assessments, findings, remediations and audit events to authenticated CSV; every export is recorded in the audit journal.
- Neutralize spreadsheet formula-like values in exported cells.
- Report pre-existing unsealed audit records separately.

> Hash chaining is <strong>tamper-evident, not immutable</strong>. A privileged database operator who can rewrite the entire chain can defeat this control. Export signed checkpoints to independently controlled storage for stronger assurance.

### 05 — Operational control mapping

SENTINEL includes a small framework-neutral control catalog that links observations to asset governance, web security, email-domain protection, TLS lifecycle and credential hygiene themes.

<code>not_observed</code> means no matching finding was present in the retained assessments. It does <strong>not</strong> mean a control passed, was tested completely or satisfies a regulatory requirement. This catalog is not a compliance certification or audit opinion.

---

## System architecture

~~~mermaid
flowchart LR
    OP[Security operator] --> UI[React operations console]
    UI -->|API key in memory| API[FastAPI control API]
    API --> AUTH[API authentication]
    AUTH --> INV[Asset registry and authorization expiry]
    AUTH --> SCOPE[Hostname allowlist and scope policy]
    INV --> SCOPE
    SCOPE --> DNS[DNS answer validation]
    DNS --> PIN[DNS-pinned HTTPS probe]
    PIN --> WEB[Authorized HTTPS asset]
    PIN --> EVIDENCE[Header and TLS evidence]
    DNS --> POSTURE[MX / SPF / DMARC posture]
    EVIDENCE --> FIND[Finding normalization]
    POSTURE --> FIND
    FIND --> RISK[Explainable risk engine]
    RISK --> DB[(PostgreSQL / SQLite)]
    API --> REM[Remediation workflow]
    API --> AUDIT[Hash-linked audit journal]
    API --> SECRET[Redacting secret-pattern scan]
    REM --> DB
    AUDIT --> DB
    SECRET --> DB
~~~

### Trust boundaries

| Boundary | Primary controls |
|:---|:---|
| Browser → API | API-key header, explicit CORS allowlist, key held in component memory |
| API → DNS | Hostname normalization, exact/proper-subdomain scope matching, reject non-global answers |
| API → target | Validated-IP connection, hostname-bound TLS, no redirects, bounded header read |
| API → database | SQLAlchemy parameterization, transaction boundaries, assessment retention cap |
| Audit → operator | Hash-chain verification, explicit legacy-unsealed count, assurance limitation |

<strong>Defence in depth still required:</strong> application-level DNS pinning does not replace a production egress firewall/proxy. Production workers should have network-level destination enforcement.

## API surface

All <code>/api/v1/*</code> routes require <code>X-API-Key</code>.

| Method | Endpoint | Purpose |
|:---:|:---|:---|
| <code>GET</code> | <code>/healthz</code> | Liveness |
| <code>GET</code> | <code>/readyz</code> | Database and migration readiness |
| <code>GET</code> | <code>/api/v1/config</code> | Configured scope and feature policy |
| <code>GET</code> | <code>/api/v1/overview</code> | Operational summary |
| <code>GET</code>, <code>POST</code> | <code>/api/v1/assets</code> | List and register authorized assets |
| <code>PATCH</code> | <code>/api/v1/assets/{asset_id}</code> | Update asset metadata/authorization |
| <code>POST</code> | <code>/api/v1/assets/{asset_id}/assessments</code> | Synchronous compatibility route for a registered, currently authorized asset |
| <code>POST</code> | <code>/api/v1/assessment-jobs</code> | Enqueue an idempotent, optionally scheduled registered-asset assessment (HTTP 202) |
| <code>GET</code> | <code>/api/v1/assessment-jobs</code> | List durable jobs with status filter |
| <code>GET</code> | <code>/api/v1/assessment-jobs/{job_id}</code> | Job status, lease and linked result |
| <code>POST</code> | <code>/api/v1/assessment-jobs/{job_id}/cancel</code> | Cancel or request cooperative cancellation |
| <code>POST</code> | <code>/api/v1/assessment-jobs/{job_id}/retry</code> | Manually retry failed/dead-letter jobs after authorization re-check |
| <code>GET</code>, <code>POST</code> | <code>/api/v1/assessments</code> | List or run an ad-hoc in-scope assessment |
| <code>GET</code> | <code>/api/v1/assessments/{assessment_id}</code> | Assessment detail |
| <code>GET</code>, <code>POST</code> | <code>/api/v1/remediations</code> | List or create remediation tasks |
| <code>PATCH</code> | <code>/api/v1/remediations/{task_id}</code> | Update assignee, status, due date or notes |
| <code>GET</code> | <code>/api/v1/controls</code> | Operational finding-to-control mapping |
| <code>POST</code> | <code>/api/v1/secrets/scan</code> | Bounded, non-persisted text secret-pattern review |
| <code>GET</code> | <code>/api/v1/audit</code> | Recent audit events and hashes |
| <code>GET</code> | <code>/api/v1/audit/integrity</code> | Verify hash-chain continuity |
| <code>GET</code> | <code>/api/v1/exports/{dataset}.csv</code> | Authenticated, bounded and audited CSV export (`assets`, `assessments`, `findings`, `remediations`, `audit`) |

Queued work is processed by the separate PostgreSQL-backed worker service; the API does not execute queued network assessments in the request process. See [assessment job and worker operations](docs/assessment-jobs.md) for lifecycle, retry, lease and scaling details.

Interactive API documentation is enabled only outside production at <code>/docs</code>.

---

## Quick start

### Requirements

- Docker Engine + Docker Compose plugin, or Python 3.12+ and Node.js 22.12+
- npm 11.12.1 for the checked-in frontend lockfile
- An explicit list of domains that you are authorized to assess
- A strong API key and PostgreSQL password

### Docker Compose

1. Clone the repository and create a local environment file:

   ~~~powershell
   Copy-Item .env.example .env
   ~~~

2. Generate separate random hex secrets (hex avoids URL-reserved characters in the Compose database URL):

   ~~~powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ~~~

3. Set <code>POSTGRES_PASSWORD</code>, <code>SENTINEL_API_KEY</code> (or <code>SENTINEL_API_KEYS</code> during rotation), <code>SENTINEL_ALLOWED_DOMAINS</code> and <code>SENTINEL_CORS_ORIGINS</code> in <code>.env</code>. Use only assets covered by your authorization. For zero-downtime key rotation, temporarily set <code>SENTINEL_API_KEYS=old-key,new-key</code> (each key must be at least 32 characters), deploy, move clients to the new key, then remove the old key. Never commit real keys; use a secret manager in production.

4. Start the stack:

   ~~~powershell
   docker compose up --build
   ~~~

5. Open the console at <code>http://localhost:8080</code>. API liveness is <code>http://localhost:8000/healthz</code>; readiness is <code>http://localhost:8000/readyz</code>. Compose also starts one isolated assessment worker after API readiness. Scale the worker independently with <code>docker compose up -d --scale worker=3 worker</code>.

The Compose configuration binds API and console ports to localhost. PostgreSQL is isolated on an internal data network; the API joins a private application network for console proxy traffic and a separate outbound network for authorized DNS/HTTPS checks; the static console joins only the private application and web networks. Browser API requests remain same-origin through the console's Nginx reverse proxy. API and console containers use read-only root filesystems, dropped Linux capabilities, no-new-privileges and non-root identities. PostgreSQL health is checked before API startup; Alembic migrations run before Uvicorn; the console waits for API readiness. The egress network is not a destination-filtering firewall—production requires an independent egress proxy or firewall.

### Local development

<strong>Backend</strong>

~~~powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SENTINEL_ENVIRONMENT = "development"
$env:SENTINEL_API_KEY = "replace-with-a-unique-random-secret-at-least-32-characters"
$env:SENTINEL_ALLOWED_DOMAINS = "example.com"
alembic upgrade head
uvicorn app.main:app --reload
~~~

<strong>Frontend</strong> — in a second terminal:

~~~powershell
cd frontend
npm ci
npm run dev
~~~

Vite proxies `/api/*` to the local backend on port 8000; no API-origin build variable is required.

The API key is entered into the console and held in component memory; it is not written to local storage.

---

## Engineering validation

The current local validation suite covers API authentication and overlapping key rotation, scope authorization, time-bounded asset registration, registered-asset assessment, remediation workflows, risk scoring, DNS-pinned transport, audit hash-chain behavior, redacted secret scanning, spreadsheet-safe CSV exports and legacy-database migration.

| Validation | Current local result |
|:---|:---:|
| Backend test suite | 62 passed |
| Ruff 0.17.4 lint | Passed |
| Ruff format check | Passed |
| Frontend React 19 + TypeScript 7 + Vite 8 production build | Passed |
| <code>npm audit --audit-level=moderate</code> | 0 reported vulnerabilities |

The CI workflow runs Python dependency auditing with pip-audit, npm dependency auditing, backend tests, Ruff checks, frontend production build, Docker Compose interpolation validation, backend/frontend container image builds and CodeQL for Python and JavaScript/TypeScript. Docker CLI was unavailable locally, so container runtime was not exercised. pip-audit and npm audit both completed successfully; this does not replace image-level or runtime security testing. Docker runtime, production egress enforcement, high-concurrency behavior, restore drills and independent penetration testing are not certified by this release.

---

## What is still required before multi-user industrial deployment?

| Capability | Status | Why it matters |
|:---|:---:|:---|
| OIDC/SSO, MFA, RBAC and service identities | Roadmap | Current API key is a single shared operator credential |
| Multi-tenant isolation and row-level policy | Roadmap | Current data model is single-workspace |
| Distributed rate limits and quotas | Roadmap | No cluster-wide abuse control yet |
| Per-job disposable sandboxes and stronger worker isolation | Roadmap | Current worker replicas are resource-bounded containers but share the host kernel |
| Network egress gateway / firewall enforcement | Deployment requirement | App-level IP pinning is not a network boundary |
| External append-only audit export/checkpoints | Roadmap | Database administrators can rewrite the stored chain |
| Secret manager and managed key lifecycle | Roadmap | Rotation overlap is implemented; production secret custody still needs a secret manager |
| Metrics, traces, alerting and SLOs | Roadmap | Operational observability is incomplete |
| Backup/restore and disaster-recovery exercises | Roadmap | No tested RPO/RTO claim |
| Independent penetration test | Not performed | External security assurance is still required |

See [system architecture](docs/blueprint/system-architecture.md), [security algorithms](docs/blueprint/security-algorithms.md), [threat model](docs/blueprint/threat-model.md) and [roadmap](docs/blueprint/roadmap.md) for the target architecture and delivery gates.

## Repository layout

~~~text
backend/
  app/
    routes/           # authenticated assessment-job API
    services/         # scope, DNS, pinned HTTPS, risk, audit, queue and evidence persistence
    worker.py         # separate durable assessment worker entry point
  alembic/            # versioned database migrations
  tests/              # API, queue lifecycle, worker safety, PostgreSQL race and migration tests
frontend/
  src/                # React operations console and SOC design system
docs/
  assets/             # project banner and visual assets
  blueprint/          # architecture, algorithms, threat model and roadmap
.github/
  workflows/          # CI and CodeQL
~~~

## Security and responsible use

SENTINEL is defensive software. Do not add a hostname or assess a system without written authorization. It does not perform exploitation, brute force, credential attacks, stealth operations or arbitrary IP-range discovery.

See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting. Never put real credentials into public issues, test fixtures or screenshots. Secret scanning only covers a limited set of patterns and is not a substitute for dedicated secret-management controls.

## License

SENTINEL is licensed under the <strong>Apache License, Version 2.0</strong>. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party packages retain their respective upstream licenses.

---

<div align="center">
  <sub>SENTINEL · Defensive Security Operations · Authorization First</sub>
</div>
