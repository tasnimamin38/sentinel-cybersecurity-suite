# SENTINEL Engineering Roadmap

This roadmap is a staged implementation plan, not a claim that every listed capability exists today.

## 0.2 — Defensive engine hardening (current branch)

- [x] DNS-pinned HTTPS connection to validated public IPs
- [x] Original hostname retained for TLS SNI and HTTP Host
- [x] Headers-only response handling, no redirects, shared timeout and 64 KiB header cap
- [x] Explainable risk v2 with deduplication, confidence and bounded criticality
- [x] Production configuration guards
- [x] Liveness/readiness endpoints and request correlation ID
- [x] Bounded assessment-history retention
- [x] Threat model, architecture and algorithm blueprints
- [ ] GitHub Actions run and remote CI verification after merge

## 0.3 — Identity, data integrity and operations

- Alembic migrations; remove production dependence on create_all.
- OIDC/SSO, MFA integration, user identity, RBAC and API-key rotation.
- Rate limiting, request quotas and audit event export.
- Append-only external audit storage with integrity checkpoints.
- Structured logs, metrics, traces, alert rules and service-level objectives.
- Database backup/restore automation and tested disaster-recovery runbook.

**Exit gate:** authorization and identity tests, migration upgrade/downgrade tests, audit integrity verification, and a successful restore drill.

## 0.4 — Scalable execution plane

- Durable queue, scheduler and idempotent assessment jobs.
- Ephemeral workers with least privilege and strict resource budgets.
- Network egress gateway with destination IP enforcement and DNS-rebinding controls.
- Per-tenant quotas, job cancellation, bounded retry/backoff and dead-letter handling.
- Evidence object storage with encryption, retention and redaction.

**Exit gate:** load testing, queue recovery tests, isolation tests, egress policy tests and failure-injection exercises.

## 0.5 — Enterprise asset and policy management

- Asset inventory with owners, environments, criticality and authorization expiry.
- Versioned policy-as-code and approver-controlled exceptions.
- Remediation workflow with ticketing integrations and owner assignment.
- Control mapping and executive risk reporting with traceable evidence.
- Multi-tenant security boundaries and tenant-specific encryption keys.

**Exit gate:** cross-tenant access tests, policy approval audit, evidence access tests and external threat-model review.

## 1.0 — Production readiness

- Independent penetration test and remediation of critical/high findings.
- Secure SDLC, signed releases, SBOM and dependency provenance.
- Recovery objectives (RPO/RTO), backup restore proof and incident-response exercises.
- Performance, availability and retention objectives.
- Privacy review and documented data lifecycle.
- Operational runbooks, support ownership and change management.

## Explicit non-goals

SENTINEL will not become a stealth tool, exploit launcher, credential attack platform, unrestricted port scanner or arbitrary network discovery service. Its assessment capabilities remain explicitly authorized and defensive.