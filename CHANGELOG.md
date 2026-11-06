# Changelog

All notable changes to SENTINEL are documented here.

## 0.10.0-pre — 2026-11-06

### Added
- Opt-in process-local Prometheus HTTP request counters and duration histograms.
- Bounded metric dimensions: normalized HTTP method, registered route template and response status; duration histograms omit status to keep cardinality controlled.
- Metrics are disabled by default through `SENTINEL_METRICS_ENABLED=false`; enabling them requires a separate random `SENTINEL_METRICS_TOKEN` of at least 32 characters.
- Metrics intentionally exclude raw URLs, query strings, client IPs, API keys, credential identifiers, hostnames and request/response bodies.
- Operator documentation describes scrape boundaries, process-local reset behavior and multi-replica limitations.

### Security and operational boundaries
- `/metrics` requires the dedicated `X-Metrics-Token` header with constant-time comparison; the metrics token is separate from API credentials. Do not expose it through a public or shared reverse proxy.
- Counters and histograms are in-memory per process and reset on restart; this is not centralized telemetry, durable accounting or a multi-replica SLO system.

### Validation
- GitHub Actions CI run #42146827384 — success: 120 backend tests passed; pip-audit found no known vulnerabilities; Ruff format and lint passed; frontend npm audit and production build passed; Compose validation and backend/frontend image builds passed.
- CodeQL run #42146827178 — success: Python and JavaScript/TypeScript analyses passed.

## 0.9.0-pre — 2026-11-06

### Added
- Historical audit-journal prefix verification through `GET /api/v1/audit/integrity?through_sequence=<n>`, including fail-closed handling of legacy unsealed records.
- A checkpoint anchor containing the verified sequence and event hash, emitted only for a complete, valid journal prefix.
- Offline Ed25519 checkpoint signing and verification utility with encrypted PKCS#8 private keys, restrictive local file permissions where supported, and refuse-to-overwrite file creation.
- Optional verification against the currently served historical journal prefix to detect changed, truncated or rewritten event history.
- Operator documentation for separate private-key custody and independently controlled signed-checkpoint retention.

### Security boundaries
- The private signing key is never uploaded to or stored by the SENTINEL service.
- Signing and external retention are operator-controlled; automated object-storage export, KMS/HSM integration and immutable-storage guarantees are not included.
- This integrity control does not replace independent security review, penetration testing or disaster-recovery validation.

### Validation
- GitHub Actions CI: 114 backend tests passed; pip-audit reported no known vulnerabilities; Ruff format and lint passed; frontend npm audit and production build passed; Docker Compose validation and backend/frontend image builds passed.
- CodeQL: Python and JavaScript/TypeScript analyses passed.

## 0.8.0-pre — 2026-11-06

### Added
- Per-service fixed UTC minute and daily request quotas for database-managed and environment-managed service credentials.
- PostgreSQL advisory transaction locks to serialize first-use and concurrent quota counters across API replicas.
- HTTP 429 responses with a `Retry-After` value representing the longest exhausted quota window.
- Bounded per-credential limits: 1–600 requests/minute and 1–1,000,000 requests/day; role-scoped environment credentials default to 120/minute and 10,000/day.
- Controlled database-managed API credential rotation with a 0–24 hour grace window. Replacement credentials inherit the role, quota limits and original expiry; previous keys are rejected after grace expires.
- Admin console controls for request limits, key rotation, rotation-grace status and revocation.
- Migration 0005 adds quota policy fields, rotation metadata and the per-credential usage counter table.

### Security and compatibility
- Legacy bootstrap admin keys remain backward-compatible with bounded 600/minute and 1,000,000/day limits.
- Environment-managed keys continue to be rotated through deployment configuration; the managed rotation API only applies to database-managed credentials.
- Audit events record rotation identifiers and grace duration, never raw secrets or key digests.
- Quotas are per credential, not per tenant, user or client IP. Clients sharing a key share its quota.

### Validation
- GitHub Actions CI #192: 107 backend tests passed; no known dependency vulnerabilities; Ruff format passed for 52 Python files; Ruff lint passed; frontend dependency audit and production build passed; Compose validation and backend/frontend Docker image builds passed.
- CodeQL #189: Python and JavaScript/TypeScript analyses both passed.
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
