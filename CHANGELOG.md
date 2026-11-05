# Changelog

All notable changes to SENTINEL are documented here.

## 0.3.2 — 2026-11-06

### Added
- Extended passive DNS posture: duplicate/permissive SPF detection, DMARC policy quality, inherited CAA, MTA-STS discovery and SMTP TLS reporting.
- Bound DNS posture to a shared lookup deadline and suppress false missing-record findings when a resolver times out.
- Expanded security-header analysis for HSTS max-age/subdomain scope, CSP unsafe-eval/unsafe-inline/wildcard script sources, weak Referrer Policy and wildcard Permissions Policy.
- Added DNS posture and header-policy regression coverage.
- Added CI validation for Docker Compose interpolation and backend/frontend container image builds.

### Validation
- Backend pytest: 62 passed.
- Ruff lint and format: passed.
- Frontend TypeScript/Vite production build: pending final run.
- npm audit: 0 reported vulnerabilities.



## 0.3.1 — 2026-11-06

### Added
- Overlapping API-key rotation using `SENTINEL_API_KEYS`, preserving the legacy `SENTINEL_API_KEY` setting for migration compatibility.
- Authenticated CSV exports for assets, assessments, findings, remediation tasks and audit events.
- Export events are written to the hash-linked audit journal; exports are bounded and served with no-store headers.
- Spreadsheet formula-injection neutralization for CSV cells.
- Console export actions on inventory, findings, remediation and audit views.

### Validation
- Backend pytest: 56 passed.
- Ruff lint and formatting: passed.
- Frontend production build: pending final run.
- npm and Python dependency audits: run before release.

## 0.3.0 — 2026-11-06

### Added
- Time-bounded asset registry with owner, environment, criticality, tags and approval reference.
- Registered-asset assessment endpoint; expired, paused and inactive assets are denied.
- Asset criticality context applied to explainable risk v2.
- Remediation task lifecycle with assignee, due date, notes and state transitions.
- Framework-neutral operational control catalog linked to retained findings.
- Bounded inline secret-pattern scan; matched values are redacted and submitted source is not persisted.
- SHA-256 audit chain with monotonic sequence numbers, content verification and explicit legacy-unsealed state.
- Alembic revision 0002 for ordered audit sequence values while preserving legacy records.
- Bounded asynchronous A/AAAA DNS resolution with a shared fail-closed deadline.
- Production readiness checks against the current Alembic head.
- React 19, Vite 8, TypeScript 7 and a redesigned multi-view Security Operations Center.
- Apache License 2.0 and NOTICE.
- Hardened Compose topology: internal data network, separate web network, API egress network, read-only API/console filesystems, dropped capabilities and non-root Nginx.
- CI dependency-audit steps and refreshed GitHub Actions/CodeQL workflow versions.

### Validation
- Backend pytest: 49 passed.
- Ruff 0.17.4 lint and format: passed.
- Frontend TypeScript/Vite production build: passed.
- npm audit: 0 reported vulnerabilities.
- Legacy v0.2 database migration preservation test: passed.
- Docker Compose YAML/static configuration: pending final static validation.
- Docker container runtime and Python dependency audit: not independently completed in the local environment.

### Known limitations
- Single shared API key; no SSO, MFA, RBAC or multi-tenant isolation.
- Hash-chain audit is tamper-evident, not immutable against a privileged database administrator.
- Secret scanning is a limited pattern catalogue, not a full secret detection system.
- No durable worker queue, distributed rate limiting, managed secrets, independent external audit sink or egress gateway.
- Docker Engine was unavailable in the local environment; container startup and production network policy have not been runtime-tested.
- No independent penetration test, disaster-recovery drill or industrial production certification is claimed.

## 0.2.0 — 2026-11-05

### Added
- DNS-pinned HTTPS probe: literal validated IP connection with original hostname SNI and Host header.
- One-request HTTP/1.1 header-only assessment with shared timeout, header-size limit and no redirect/body download.
- Explainable exponential risk model v2 with unique-finding deduplication, confidence weighting, bounded asset criticality and top drivers.
- Production configuration validation for strong API key, authorized scope, non-wildcard CORS and PostgreSQL.
- Database readiness endpoint, request correlation ID and bounded assessment-history retention.
- Risk explanation and top risk drivers in the operator console.
- Advanced system architecture, algorithm, threat-model and implementation roadmap blueprints.

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
