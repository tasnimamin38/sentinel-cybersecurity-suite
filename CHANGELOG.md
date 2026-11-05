# Changelog

All notable changes to SENTINEL are documented here.

## 0.2.0 — 2026-11-05

### Added
- DNS-pinned HTTPS probe: literal validated IP connection with original hostname SNI and Host header.
- One-request HTTP/1.1 header-only assessment with shared timeout, header-size limit and no redirect/body download.
- Explainable exponential risk model v2 with unique-finding deduplication, confidence weighting, bounded asset criticality and top drivers.
- Production configuration validation for strong API key, authorized scope, non-wildcard CORS and PostgreSQL.
- Database readiness endpoint, request correlation ID and bounded assessment-history retention.
- Risk explanation and top risk drivers in the operator console.
- Advanced system architecture, algorithm, threat-model and implementation roadmap blueprints.
- Additional regression tests for pinned transport, production settings, readiness and risk behavior.

### Validation
- Backend pytest: 35 passed.
- Ruff lint: passed.
- Ruff format check: passed.
- Frontend TypeScript/Vite production build: passed.
- GitHub Actions remote workflow status has not yet been verified for this change.

### Known limitations
- Engineering baseline; not certified or production-ready.
- Single API-key operator authentication; no SSO, RBAC or multi-tenancy.
- Alembic migrations, durable job queue, distributed rate limits and immutable audit export are not implemented.
- Production network egress firewall/proxy enforcement is still required.
- Docker runtime and independent penetration testing are not certified by this change.

## 0.1.0 — 2026-11-05

### Added
- FastAPI service with API-key protected endpoints.
- Explicit domain allowlisting and public-address safety checks.
- HTTPS security-header, TLS certificate and DNS MX/SPF/DMARC posture checks.
- Findings normalization, risk scoring, assessment history and audit events.
- Redacting secret-pattern scanner utility.
- Responsive React/TypeScript operator console.
- PostgreSQL Docker Compose configuration and Nginx security headers.
- Pytest regression suite, Ruff checks, GitHub Actions CI, CodeQL workflow and Dependabot.
- Architecture, security model, runbook and contribution guidance.