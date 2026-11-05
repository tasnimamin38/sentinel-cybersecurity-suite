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

- Durable queue, scheduler, idempotent jobs and cancellation
- Isolated ephemeral workers and strict execution/resource budgets
- Network egress gateway and connection-time destination enforcement
- Bounded retry policy and dead-letter workflow
- External encrypted evidence storage with retention and access control

**Exit gate:** load tests, queue recovery, worker isolation and egress policy validation.

## 0.6 — Audit and operational assurance

- Independent append-only audit export with signed checkpoints
- Metrics, tracing, structured logs, dashboards and alert rules
- Backup/restore automation, RPO/RTO targets and recovery drills
- Security event integrations and incident-response workflow
- Service-level objectives and dependency supply-chain controls

**Exit gate:** restore proof, alert exercises, audit checkpoint verification and operational readiness review.

## 1.0 — Production readiness

- Independent penetration test and remediation of critical/high issues
- Multi-tenant isolation review and external threat-model assessment
- Signed release artifacts, SBOM and provenance
- Privacy/data-retention review and support ownership
- Performance, reliability and recovery objectives validated in deployment

## Explicit non-goals

SENTINEL is not intended to become a stealth tool, exploit launcher, credential attack tool, arbitrary internet scanner or destructive testing framework. Its target-assessment capabilities remain scoped to explicitly authorized defensive work.
