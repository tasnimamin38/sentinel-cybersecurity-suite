# SENTINEL Enterprise Delivery Plan

## Current state

SENTINEL 0.3 delivers a single-workspace defensive operations foundation: authorized asset inventory, posture assessments, risk prioritization, remediation tracking, operational control mapping, secret-pattern review and hash-linked audit.

It is not yet a multi-user enterprise service.

## Recent operational increments

- 0.18: authenticated PostgreSQL backup encryption, isolated restore verification and supply-chain gates.
- 0.19: verified encrypted-backup retention with dry-run default, private-directory ownership enforcement, hard-link rejection and timestamp-based ordering.
- 0.20: canonical assessment evidence digests anchored in the hash-linked audit journal, with per-assessment verification and explicit legacy/tamper states.

## Target platform layers

### Identity and governance
- OIDC/SAML SSO, MFA, RBAC and just-in-time privileges
- Tenant-scoped asset ownership and approval registry
- Versioned policies, approvals, exceptions and expiry
- Credential vault and rotation

### Assessment data plane
- API gateway with distributed rate limits
- Durable queue and scheduler
- Isolated, ephemeral workers with no ambient cloud credentials
- Egress gateway with destination allowlist and DNS-pinning enforcement
- Evidence normalizer and deterministic scoring

### Evidence and operations
- Encrypted evidence object storage with lifecycle rules
- External append-only audit export and signed checkpoints
- Metrics, tracing, structured logs, alerting and SLO dashboards
- Backup restore automation, recovery exercises and incident playbooks

## Delivery principles

- Each phase must have acceptance tests.
- Each security claim must have observable evidence.
- Failed or unavailable checks must never be represented as a pass.
- Multi-tenant hosting is blocked until isolation has been independently reviewed.
- Production readiness requires external security testing and recovery proof.
