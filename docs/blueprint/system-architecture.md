# SENTINEL — System Architecture

**Current implementation baseline:** 0.14 operator-grade incident response console  
**Hardening track:** 0.15 supply-chain security and release assurance  
**Scope:** Authorized defensive security posture operations.

This document describes the repository state and its verified boundaries. The 0.15 backend image uses the official Python 3.13.18 slim Trixie image; CI exercises Python 3.12 and 3.13. Roadmap diagrams and planned components are not evidence that a control has been deployed.

## 1. Architecture principles

1. Authorization must be resolved before target network I/O.
2. Deny by default when scope, credentials, asset status or authorization expiry is missing.
3. Bound assessment traffic by hostname scope, validated public DNS answers, timeouts, response-header limits and worker resources.
4. Preserve evidence provenance from asset authorization through assessment, finding, remediation, incident and audit.
5. Keep service identity separate from human identity; do not present API keys as SSO or MFA.
6. Keep database schema evolution in Alembic migrations; production startup must not silently create or mutate schema.
7. Separate API control plane, assessment worker, persistence, audit evidence and build/release assurance.
8. Treat every security claim as a testable control with an explicit residual risk.

## 2. Current logical architecture

~~~mermaid
flowchart TB
  OP[Authorized operator] --> UI[React operations console]
  UI -->|X-API-Key in component memory| API[FastAPI control API]
  API --> AUTH[API key authentication]
  AUTH --> RBAC[Route permission map and service roles]
  RBAC --> POLICY[Scope and asset authorization]
  POLICY -->|Synchronous compatibility request| PROBE[Bounded assessment services]
  POLICY -->|Durable job| QUEUE[(PostgreSQL job queue)]
  QUEUE --> WORKER[Separate resource-bounded worker]
  WORKER --> PROBE
  PROBE --> DNS[DNS answer validation]
  DNS --> PIN[Validated-IP HTTPS and TLS probe]
  PIN --> TARGET[Authorized hostname]
  PROBE --> POSTURE[HTTP and DNS posture checks]
  POSTURE --> FIND[Finding normalization and risk scoring]
  FIND --> DB[(PostgreSQL production / SQLite development)]
  API --> REM[Remediation workflow]
  API --> INC[Finding-linked incident lifecycle]
  API --> AUDIT[Hash-linked audit journal]
  REM --> DB
  INC --> DB
  AUDIT --> DB
  API --> SECRET[Redacting secret-pattern review]
  SECRET --> DB
  CI[GitHub Actions] --> SAST[CodeQL and dependency audits]
  CI --> SUPPLY[Gitleaks, Trivy and dependency review]
  CI --> SBOM[SPDX JSON SBOM artifact]
~~~

## 3. Component responsibilities

| Component | Responsibility | Implemented boundary |
|:---|:---|:---|
| React console | Asset, assessment, findings, remediation, incident, controls and audit views | Live API-backed records; API key held in component memory |
| FastAPI control API | Authentication, authorization, validation and API orchestration | Route-level permission checks; production docs disabled |
| Service identity | Legacy admin and role-scoped static/database-managed credentials | Hash-only managed-key storage, one-time display, expiry, revocation and bounded rotation |
| Quota service | Per-credential request limits | PostgreSQL-backed atomic minute/day accounting |
| Asset authorization | Owner, environment, criticality, approval reference, status and expiry | Server-side allowlist and time-bounded authorization |
| Assessment services | DNS/TLS/HTTPS and email/domain posture evidence | Python 3.13.18 runtime image; CI compatibility matrix Python 3.12/3.13; validated public addresses, pinned connection, bounded GET/header read, no redirects |
| Queue and worker | Durable assessment job execution | PostgreSQL claims/leases, retry/dead-letter lifecycle and resource-limited worker container |
| Risk/remediation | Stable finding codes, deterministic scoring and task ownership | Score is SENTINEL-specific, not CVSS |
| Incident response | Finding-linked triage, constrained status transitions, operator/deadline/notes | API-enforced permissions and metadata-only audit details |
| Audit | Hash-linked records and integrity verification | Tamper-evident, not immutable against privileged DB operators |
| Secret review | Selected secret-pattern detection | Bounded input; redacted output; no submitted source persistence |
| GitHub Actions | Test, lint, dependency, static analysis, image and supply-chain checks | Full-SHA action references in 0.15 branch; CI status determined per commit |
| SBOM pipeline | Inventory software packages | SPDX JSON repository SBOM artifact with 14-day retention; no automatic release publishing |

## 4. Request and assessment flow

1. API authentication resolves a service principal and role.
2. Route-level RBAC checks the required permission; unknown routes fail closed.
3. The API normalizes a submitted hostname and checks the server-side authorized domain list.
4. Managed assets must be active and have a future, timezone-aware authorization expiry.
5. DNS resolution inspects the complete answer set and rejects private, reserved or otherwise non-global addresses.
6. HTTPS connections use a validated literal IP while preserving the original hostname for SNI, certificate validation and the HTTP Host header.
7. The probe performs one bounded HTTPS GET, does not follow redirects and does not download an unbounded response body.
8. HTTP-header, TLS and DNS email-posture evidence is normalized into stable findings.
9. Risk scoring records the model, weights and top drivers; persisted findings may create remediation tasks or security incidents.
10. Writes commit with audit metadata; audit details do not copy free-form incident notes.

Queued work is processed by a separate worker service. The API does not execute queued network assessment work in the request process.

## 5. Identity and authorization model

Current principals are service credentials, not human users:
- Roles: admin, analyst, asset_manager, auditor and read_only.
- Route permissions are explicitly mapped and fail closed when an API route is not in the map.
- Managed credential secrets are displayed once and stored as SHA-256 digests.
- Managed credentials support expiry, revocation and bounded rotation grace periods.
- Per-credential quotas use PostgreSQL-backed atomic accounting across API replicas.

Not implemented: OIDC/SAML, MFA, short-lived human sessions, just-in-time access, multi-tenant row isolation or per-human assignee identity. Adding a tenant_id field alone would not be sufficient; API authorization and database-level isolation tests are required.

## 6. Deployment and network boundaries

Production Compose separates PostgreSQL data, console web and API/worker egress networks. API and console containers use read-only root filesystems, dropped capabilities, non-root users and no-new-privileges. Workers have explicit CPU, memory and PID limits.

**Important:** the Compose egress network is not a destination-filtering firewall. Application DNS pinning does not replace a production egress proxy/firewall that enforces destination policy at connection time. Per-job disposable VM/sandbox isolation is not implemented.

## 7. Build and supply-chain assurance

The 0.15 branch adds:
- A multi-stage backend image: Python 3.13.18 builder, minimal Debian Trixie runtime, and no pip/setuptools/wheel/ensurepip in the final stage.
- Full commit-SHA references for GitHub Actions used by CI and CodeQL.
- Pull request dependency review for newly introduced high/critical runtime and development vulnerabilities; the action is currently blocked because repository Dependency Graph is disabled and requires an owner setting change.
- Gitleaks repository-history scanning; PR comments are disabled.
- Trivy filesystem scans for vulnerabilities, misconfiguration, secrets and licenses.
- Trivy scans of built backend and frontend images for high/critical OS/library vulnerabilities.
- SPDX JSON SBOM generation as a 14-day workflow artifact.
- Weekly Dependabot updates for Python, npm and GitHub Actions.

Fork-originated pull requests still run scanners; SARIF upload is skipped when GitHub restricts write permissions. No release assets are automatically published by the SBOM workflow.

## 8. Production readiness gaps

Before a hosted multi-user or industrial deployment:
- Implement human identity federation, MFA and session lifecycle controls.
- Design and independently verify tenant isolation across API queries and database boundaries.
- Add destination-enforcing egress controls and per-job disposable worker isolation.
- Export audit checkpoints to independently administered append-only storage.
- Add encrypted evidence storage, retention and managed secret custody.
- Add distributed tracing, metrics, alerting and operational SLOs.
- Automate encrypted off-host backups and recurring restore drills with explicit RPO/RTO.
- Sign release artifacts, publish provenance attestations and perform an independent penetration test.

## 9. Release boundary

A green workflow validates only the checks executed for the exact commit SHA. It does not certify the deployment, prove that the system is free of vulnerabilities or replace independent security review.
