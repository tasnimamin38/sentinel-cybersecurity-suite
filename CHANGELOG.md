# Changelog

All notable changes to SENTINEL are documented here.

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

### Known limitations
- Development baseline; not certified or production-ready.
- Single API-key operator authentication; no SSO, RBAC or multi-tenancy.
- No distributed job queue, immutable audit sink or enterprise migrations yet.
- Docker runtime validation depends on a Docker installation.