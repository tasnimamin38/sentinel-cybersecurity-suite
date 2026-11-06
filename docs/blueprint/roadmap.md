# SENTINEL Engineering Roadmap

This roadmap is an implementation plan, not a claim that every target feature exists.

## 0.3.0 — Defensive operations foundation (current baseline)

- [x] Time-bounded authorized asset inventory
- [x] Registered-asset assessments with asset criticality context
- [x] DNS-pinned HTTPS, TLS, HTTP-header and DNS email posture checks
- [x] Explainable risk v2 and evidence-linked findings
- [x] Remediation task lifecycle
- [x] Framework-neutral operational control mapping
- [x] Bounded secret-pattern review with redacted output and no source persistence
- [x] SHA-256 hash-linked audit event chain and verifier
- [x] Alembic migration path, including upgrade of legacy schema
- [x] React 19 / Vite 8 / TypeScript 7 operator console
- [x] Apache-2.0 license, source notices, CI and CodeQL workflow

## 0.4 — Identity, authorization and service security

- [x] Overlapping API-key rotation with constant-time comparisons and bounded key configuration
- [x] Audited, formula-safe CSV exports across five operational datasets
- [x] Extended DNS posture: SPF/DMARC policy quality, CAA, MTA-STS discovery and TLS-RPT
- [x] HSTS/CSP policy-quality checks beyond header presence
- [x] Authenticated, audit-logged CSV exports with formula-injection neutralization

- OIDC/SAML federation, MFA, RBAC and short-lived user sessions
- Per-user and per-service credentials, revocation and rotation
- Formal asset authorization approval integration and expiry notifications
- Distributed API rate limiting, quotas and abuse monitoring
- Tenant boundary design and access-control test suite

**Exit gate:** identity threat model, authorization policy review, cross-tenant denial tests and credential lifecycle tests.

## 0.5 — Scalable data plane

- [x] PostgreSQL-backed durable assessment queue, scheduled availability and idempotency
- [x] Authenticated job listing, detail, cancellation and manual retry lifecycle
- [x] Independent resource-bounded worker service; no API-process network assessment for queued jobs
- [x] PostgreSQL `FOR UPDATE SKIP LOCKED` claims, renewable leases and stale-worker recovery
- [x] Authorization re-check before execution and before result persistence
- [x] Bounded automatic retry/backoff and dead-letter workflow
- [x] Worker cancellation polling and atomic assessment/result/audit persistence
- [ ] Per-job disposable sandbox isolation and strict outbound egress gateway/firewall
- [ ] External encrypted evidence storage with retention and access control
- [ ] Sustained load/soak tests and production queue recovery drills

**Exit gate:** PostgreSQL race test, CI backend tests, queue crash-recovery/load tests, independent egress enforcement and stronger per-job isolation.

## 0.6 — Audit and operational assurance

- [x] Operator-controlled offline signed audit checkpoints (0.9 branch)
- [x] Opt-in process-local HTTP counters and duration histograms with bounded Prometheus labels (0.10 branch)
- [ ] Independent append-only audit export with automated signed-checkpoint retention
- [x] Privacy-safe structured JSON request logs correlated with response request IDs (0.11 branch)
- [ ] Distributed metrics and tracing, dashboards and alert rules
- Backup/restore automation, RPO/RTO targets and recovery drills
- Security event integrations and incident-response workflow
- Service-level objectives and dependency supply-chain controls

**Exit gate:** restore proof, alert exercises, audit checkpoint verification and operational readiness review.

## 0.7 — Role-scoped service access control

- [x] Explicit admin, analyst, asset-manager, auditor and read-only roles
- [x] Fail-closed route-to-permission matrix across the API, including queued worker operations
- [x] Backward-compatible legacy admin keys and role-scoped environment credentials
- [x] Database-managed service credentials stored as SHA-256 digests only
- [x] One-time secret display, no-store creation responses and metadata-only listing
- [x] Immediate revocation, expiry enforcement, last-used tracking and self-revocation guard
- [x] Audited credential lifecycle events that never include raw key material or digests
- [ ] Human identity federation, MFA and short-lived user sessions
- [x] Frontend permission-aware administration and operator experience
- [ ] Service ownership, per-credential quotas and rotation notifications

**Exit gate:** CI role-boundary tests, credential hash-only persistence checks, expiry/revocation tests, audit redaction and independent authorization review.

## 0.8 — Service quotas and controlled credential rotation

- [x] Per-service fixed UTC minute and daily quotas for database-managed and environment-managed service identities
- [x] PostgreSQL advisory transaction locking to keep first-use and concurrent counters atomic across API replicas
- [x] HTTP 429 responses with Retry-After semantics
- [x] Database-managed credential quota configuration with bounded values and role-preserving rotation
- [x] Zero-downtime managed-key rotation with a 0–24 hour grace window and automatic old-key rejection
- [x] Audit events for rotation that omit raw secrets and key digests
- [ ] OIDC/SAML federation, MFA and human user sessions
- [ ] Per-tenant quotas, spend budgets and adaptive abuse detection
- [ ] External secret-manager API integration and expiry/rotation notifications

**Exit gate:** minute/day counter boundary tests, PostgreSQL concurrency test, rotation grace/expiry tests, dependency audit, Ruff, frontend build and CodeQL.
## 0.12 — Backup and restore assurance

- [x] Operator-run PostgreSQL custom-format backup from the Compose database service
- [x] Timestamped no-overwrite archive, restrictive backup directory permissions and SHA-256 sidecar
- [x] Disposable PostgreSQL restore verification with networking disabled, resource limits, Alembic revision check and core-table check
- [ ] Automated backup scheduling, encryption/key management and off-site retention
- [ ] Retention policy, RPO/RTO targets and recurring recovery drills

**Exit gate:** encrypted off-host copies, documented retention, successful scheduled restore drills and independently reviewed recovery objectives.

## 0.13 — Security incident triage API

- [x] Create an incident from a finding in a completed stored assessment.
- [x] Enforce uniqueness for an assessment/finding pair and constrained terminal transitions.
- [x] Apply role-scoped read/write permissions and append hash-linked audit events.
- [x] Require timezone-aware response deadlines and bounded notes.
- [ ] Notification delivery, on-call escalation and human assignee directory.
- [ ] SIEM ingestion, alert correlation and automatic incident creation.

**Exit gate:** incident API lifecycle, authorization, migration and audit regression tests pass; notification channels remain unconfigured.

## 0.14 — Operator-grade incident response console

- [x] Live React incident register backed by the authenticated API.
- [x] Status/severity filters, search and response-state summary.
- [x] Accountable operator, timezone-aware response deadline and overdue indicators.
- [x] Per-incident metadata-only audit trace and manual API refresh.
- [x] Frontend regression coverage for the API-backed response workflow.

**Exit gate:** PR #28 and PR #29 remain a stacked dependency chain until individually reviewed and all exact-head CI/CodeQL checks pass.

## 0.15 — Supply-chain security and release assurance

- [x] Pin GitHub Actions dependencies to reviewed full commit SHAs.
- [x] Review pull-request dependency changes for high/critical runtime and development vulnerabilities.
- [x] Scan repository history for exposed secrets with Gitleaks; disable PR comments.
- [x] Scan source, dependencies, secrets, licenses and deployment configuration with Trivy.
- [x] Scan built backend and frontend images for high/critical OS/library vulnerabilities.
- [x] Generate SPDX JSON SBOM and retain it as a short-lived workflow artifact.
- [x] Configure weekly Dependabot updates for Python, npm and GitHub Actions.
- [x] Add regression tests for workflow pinning and security gates.
- [ ] Sign release artifacts and publish provenance attestations for tagged releases.
- [ ] Assign ownership and expiry to SBOM retention and vulnerability exceptions.

**Exit gate:** CI, CodeQL and supply-chain workflows are green on the exact PR head; high/critical findings are triaged; SPDX artifact is present and inspectable.

## 1.0 — Production readiness

- Independent penetration test and remediation of critical/high issues
- Multi-tenant isolation review and external threat-model assessment
- Signed release artifacts, SBOM and provenance
- Privacy/data-retention review and support ownership
- Performance, reliability and recovery objectives validated in deployment

## Explicit non-goals

SENTINEL is not intended to become a stealth tool, exploit launcher, credential attack tool, arbitrary internet scanner or destructive testing framework. Its target-assessment capabilities remain scoped to explicitly authorized defensive work.
