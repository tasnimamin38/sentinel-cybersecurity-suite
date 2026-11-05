# SENTINEL Threat Model

**Version:** 0.3.4 engineering baseline
**Method:** STRIDE-style review for the current single-workspace architecture.

## Protected assets

- API key and deployment configuration
- Authorization records, allowlist and asset ownership metadata
- Assessment evidence, findings and remediation tasks
- Database credentials, audit history and backups
- Source repository, CI pipeline and release artifacts

## Principal threats and controls

| STRIDE | Example | Implemented mitigation | Residual risk |
|---|---|---|---|
| Spoofing | Unauthorized API caller | API-key authentication and constant-time comparison | Shared key; no user identity, MFA, SSO or RBAC |
| Tampering | Hostname suffix confusion | Canonicalization and proper-subdomain boundary check | Approval is operator-attested, not externally verified |
| Tampering | DNS rebinding | Connect to validated literal IP and preserve hostname TLS identity | Egress firewall/proxy still mandatory |
| Repudiation | Operator disputes a change | Hash-linked audit event and chain verification | Database administrator can rewrite entire stored chain |
| Information disclosure | Secret text appears in result | Redacted match output; source text not persisted | Limited pattern coverage; request transport must be protected |
| Information disclosure | Browser API key leakage | Component-memory key, no local storage | Shared key still lacks per-user scope and revocation |
| Denial of service | Large input, request floods or slow remote endpoint | 512 KiB API body cap including chunked streams; 256 KiB secret-input schema cap; Redis shared sliding-window limits per direct peer IP/API-key/operation; HTTPS deadline; 64 KiB header cap | No tenant quotas, durable queue or worker isolation; Redis is a required runtime dependency in production |
| Elevation of privilege | User accesses another tenant | No multi-tenant service in current release | Must not host multiple untrusted tenants before isolation controls exist |

## Attack surface

1. API key and CORS configuration
2. Asset authorization and hostname normalization
3. DNS resolver and outbound HTTPS sockets
4. API request validation and persistence
5. Text secret-scanning endpoint
6. Audit hash-chain write and verification
7. PostgreSQL, SQLite tests, backup and restore
8. GitHub Actions, package installation and release process
9. Browser console and the API-key entry component

## Security assumptions

- Operators only add assets they own or have explicit authorization to assess.
- The server-side allowlist is configured by a trusted operator.
- TLS verification is enabled and the system clock is reliable.
- Production deployment provides network-level egress enforcement.
- Database and application secrets are injected out of source control.

## Known limitations

- Single shared API key, no user identity or role separation.
- No multi-tenant data isolation.
- No per-tenant usage budgets, durable queue, ephemeral assessment workers or job cancellation; rate limits are shared per IP/API key but not tenant-aware.
- Hash-chain events are stored in the application database; no independent immutable sink.
- Secret scanner covers selected patterns only.
- Control catalog is operational mapping, not a certification.
- No independent penetration test, disaster-recovery exercise or production load certification is claimed.

## Release-blocking requirements for hosted multi-user service

1. OIDC/SSO, MFA, RBAC and short-lived sessions.
2. Tenant isolation with API and database enforcement tests.
3. Per-tenant quotas, distributed usage budgets and centralized abuse monitoring; Redis API/IP/operation rate limiting is implemented.
4. Dedicated egress policy enforcement and isolated workers.
5. Managed secrets and automated rotation.
6. External append-only audit export and signed checkpoints.
7. Metrics, traces, alerting and incident-response playbooks.
8. Backup restore proof and independent security assessment.
