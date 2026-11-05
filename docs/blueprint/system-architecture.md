# SENTINEL — System Architecture Blueprint

**Current implementation:** 0.3.3 engineering baseline
**Design scope:** Authorized, defensive security posture operations.

This blueprint separates working implementation from target-state architecture. A diagram or roadmap item is not evidence that a capability is implemented, scalable or independently verified.

## 1. Architecture principles

1. Authorization precedes target network I/O.
2. Deny by default when scope, asset authorization or production configuration is missing.
3. Keep assessment traffic bounded: authorized hostnames, validated public DNS answers, explicit timeouts and small response evidence.
4. Preserve provenance: asset owner, authorization reference, findings, scoring model, remediation owner and audit event.
5. Explain every score using stable finding codes, severity, confidence and criticality.
6. Use versioned database migrations; never silently mutate production schema at API startup.
7. Separate control plane, data plane, evidence storage and observability before multi-user scale.
8. Treat operational security assurances as claims that require tests and independent evidence.

## 2. Current 0.3 architecture

~~~mermaid
flowchart TB
  OP[Security operator] --> WEB[React 19 / Vite 8 console]
  WEB -->|X-API-Key, memory only| API[FastAPI 0.3 control API]
  API --> AUTH[API-key authentication]
  AUTH --> INV[Asset registry]
  INV -->|owner, criticality, expiry, approval reference| SCOPE[Hostname allowlist and authorization gate]
  AUTH --> SCOPE
  SCOPE --> DNS[DNS A/AAAA validation]
  DNS --> PIN[Validated-IP HTTPS probe]
  PIN --> TARGET[Authorized HTTPS hostname]
  PIN --> HEAD[HTTP headers and TLS evidence]
  DNS --> EMAIL[MX / SPF / DMARC]
  HEAD --> FIND[Finding normalization]
  EMAIL --> FIND
  FIND --> RISK[Explainable risk v2]
  RISK --> ASSESS[(Assessment history)]
  API --> TASK[Remediation workflow]
  API --> CTRL[Operational control catalog]
  API --> SECRET[Bounded redacting secret scan]
  API --> AUDIT[SHA-256 linked audit events]
  TASK --> DB[(PostgreSQL / SQLite)]
  CTRL --> DB
  SECRET --> DB
  AUDIT --> DB
  ASSESS --> DB
~~~

### Request lifecycle

1. Validate API authentication.
2. Normalize hostname and authorize it against the exact/proper-subdomain allowlist.
3. For managed assets, enforce active status and future, timezone-aware authorization expiry.
4. Resolve DNS and reject invalid or non-global answers.
5. Connect to a literal validated IP; keep canonical hostname for TLS SNI, certificate validation and HTTP Host.
6. Issue one HTTP/1.1 GET, read only the bounded response-header block, do not follow redirects and do not download the response body.
7. Evaluate selected HTTP headers, certificate expiry and MX/SPF/DMARC posture.
8. Normalize findings and calculate deterministic, explainable risk.
9. Persist assessment, create a hash-linked audit event and enforce assessment-history retention.
10. Create remediation tasks only from findings stored in a selected assessment.

## 3. Current service responsibilities

| Service | Responsibility | Current boundary |
|---|---|---|
| React console | Asset, findings, remediation, controls, audit and secret review UI | API-key session is in component memory; no user identity |
| FastAPI | Validation, authorization, orchestration and API response | Single shared API-key model |
| Asset registry | Owner, environment, criticality, tags and approval expiry | Single workspace; not multi-tenant |
| HTTPS probe | DNS-pinned TLS connection and headers-only request | One bounded root-path GET |
| Risk engine | Deduplication, confidence, criticality and drivers | SENTINEL score; not CVSS |
| Remediation | Assignee, due date, notes and status | Manual task workflow; no scheduler/ticket sync |
| Control catalog | Links known findings to operational control themes | Not a certification or assurance opinion |
| Secret scanner | Selected regex patterns and redacted fingerprint | Limited pattern catalog; source not persisted |
| Audit service | SHA-256 hash-linked event sequence | Tamper-evident, not immutable against DB administrator |
| Alembic | Versioned schema upgrade | One baseline migration currently |

## 4. Trust boundaries

| Boundary | Controls |
|---|---|
| Browser → API | API key in header, explicit CORS, no local-storage persistence |
| API → asset scope | IDNA normalization, allowlist boundary matching, expiring authorization |
| API → DNS | Complete answer set inspection, reject private/reserved/non-global IPs |
| API → HTTPS asset | Literal validated IP connection, hostname-bound TLS, no redirects, bounded header read |
| API → database | SQLAlchemy parameterization, transactions, migration-based schema |
| Secret text → API | Payload cap, no source persistence, redacted output |
| Audit → operator | Previous-hash continuity and content digest verification |

## 5. Enterprise target architecture — not implemented

### Control plane
- OIDC/SAML identity federation, MFA and short-lived sessions
- RBAC, tenant administration and service identities
- Authorization registry with owner approval and expiry
- Versioned policy-as-code, policy exceptions and approval workflows
- Asset inventory with business service and ownership relationships

### Data plane
- API gateway, WAF and distributed rate limits
- Durable job queue and assessment orchestrator
- Ephemeral workers with CPU, memory, time and egress budgets
- Network egress proxy/firewall with connection-time destination enforcement
- Retry policy, cancellation, idempotency and dead-letter queue

### Evidence and observability
- Encrypted object storage and evidence lifecycle controls
- Append-only external audit sink and signed checkpoints
- Metrics, traces, structured logs, alert rules and SLO dashboards
- Managed secrets, rotation and workload identity

### Multi-tenant data model target

All tenant-owned rows need tenant ownership enforced in API authorization and at the database boundary. Adding a tenant_id column alone is insufficient. Required tests include cross-tenant read/write denial, migration checks, query-scope tests and privileged-role separation.

## 6. Reliability and operations

- Use Alembic revisions for schema changes.
- Database readiness must match the current Alembic head, not a hard-coded historical revision.
- Long network work must not hold database transactions open.
- Assessment retention is configurable; audit evidence requires a separate retention/export policy.
- Production egress controls must independently enforce destination restrictions.
- Backups require restore drills. A successful backup job alone is not recovery assurance.

## 7. Production gate

Before hosted multi-user or industrial deployment, complete OIDC/SSO, RBAC, tenant isolation, distributed rate limits, durable workers, egress enforcement, external audit checkpoints, managed secrets, monitoring, restore drills, independent penetration testing and an operational incident-response exercise.
