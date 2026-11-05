# SENTINEL Threat Model

**Status:** Engineering threat model for version 0.2.  
**Method:** STRIDE-style review of the current single-operator architecture.

## Assets to protect

- API authentication key and deployment configuration
- Authorized asset scope and proof-of-authorization records
- Assessment history, audit events and collected evidence
- Database credentials and backups
- Build pipeline and release artifacts

## Trust boundaries and principal threats

| Threat | Example | Current mitigation | Residual risk / next control |
|---|---|---|---|
| Spoofing | Unauthorized party submits assessment requests | API-key auth with constant-time comparison; production minimum length | Single shared key; add OIDC, MFA, RBAC and key rotation |
| Tampering | Hostname attempts suffix confusion or URL injection | IDNA normalization, strict DNS label validation, exact/proper-subdomain allowlist | Add signed authorization approvals and policy-versioned scope |
| Tampering | DNS answer changes between validation and connect | Probe connects to literal validated IP; SNI and Host remain hostname-bound | Egress firewall/proxy must independently enforce destination |
| Repudiation | Operator denies running an assessment | Assessment and audit event persistence; request ID | Audit database is mutable by DB owner; add append-only external export and hash checkpoints |
| Information disclosure | Secret scanner leaks matched credential text | Redacted hash fingerprint only | Expand format coverage and add automated rotation workflow |
| Information disclosure | Browser exposes API key | Key held in component memory; no local storage | Replace shared API key with short-lived scoped sessions |
| Denial of service | Slow TLS handshake or oversized response headers | Shared timeout budget, max header size, bounded DNS answer count | Add gateway rate limits, worker quotas and queue back-pressure |
| Elevation of privilege | One user accesses another user's data | Not applicable to current single-operator deployment | Multi-tenant isolation and row-level authorization are mandatory before shared hosting |

## Attack surface inventory

1. Public HTTP API routes (/healthz, /readyz, /api/v1/*)
2. API-key authentication and configuration parsing
3. DNS resolver and outbound HTTPS client
4. PostgreSQL/SQLite persistence and backups
5. Browser console and API-key memory handling
6. GitHub Actions, dependency resolution and release process

## Security controls by layer

- **Input:** Pydantic validation, strict hostname canonicalization, allowlist boundary matching.
- **Network:** Reject non-global DNS answers, connect to validated literal IPs, verify TLS, no redirects, no body download, bounded deadlines.
- **Application:** Constant-time API-key comparison, production configuration validation, explicit CORS, defensive response headers.
- **Data:** SQLAlchemy parameterization, bounded assessment history, redacted evidence.
- **Operations:** Readiness endpoint, request ID, CI tests, CodeQL and Dependabot configuration.

## Known limitations

- Current API-key authentication is single-operator and does not provide user identity or role separation.
- Audit rows are not immutable against a database administrator.
- The current application does not provide multi-tenant isolation, queue workers or distributed rate limiting.
- Docker runtime, production egress segmentation, backup restore and independent penetration testing have not been certified by this code change.
- The platform does not certify compliance with any regulatory framework.

## Release-blocking security requirements for a hosted multi-user service

1. OIDC/SSO, MFA policy, RBAC and short-lived credentials.
2. Tenant isolation tested at API, service and database layers.
3. Alembic migration and downgrade/restore procedures.
4. Network egress proxy/firewall and DNS pinning enforcement.
5. Distributed rate limits, quotas, job isolation and abuse monitoring.
6. Append-only audit export with integrity verification.
7. External security review and tested incident-response procedures.