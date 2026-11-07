# SENTINEL Threat Model

**Version:** 0.3 engineering baseline  
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
| Spoofing | Unauthorized API caller | Constant-time API-key authentication, role-scoped service credentials and route-to-permission authorization | No human user identity, MFA, OIDC/SSO or tenant-aware authorization |
| Tampering | Hostname suffix confusion | Canonicalization and proper-subdomain boundary check | Approval is operator-attested, not externally verified |
| Tampering | DNS rebinding | Connect to validated literal IP and preserve hostname TLS identity | Egress firewall/proxy still mandatory |
| Repudiation | Operator disputes a change | Hash-linked audit event and chain verification | Database administrator can rewrite entire stored chain |
| Information disclosure | Secret text appears in result | Redacted match output; source text not persisted | Limited pattern coverage; request transport must be protected |
| Information disclosure | Browser API key leakage | Component-memory key, no local storage, scoped service credentials and revocation | No human sessions or tenant boundaries; browser compromise can expose the active credential |
| Denial of service | Request flood, large input or slow remote endpoint | Bounded request bodies, HTTPS deadline, 64 KiB header cap, shared Redis per-IP/per-credential sliding windows, endpoint limits and capped security-event writes | Per-tenant quotas, WAF/DDoS protection and disposable worker isolation remain deployment requirements |
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
10. Nginx same-origin proxy, trusted client-IP forwarding and honeypot routes
11. Redis rate-limit store and operator-configured alert webhook

## Security assumptions

- Operators only add assets they own or have explicit authorization to assess.
- The server-side allowlist is configured by a trusted operator.
- TLS verification is enabled and the system clock is reliable.
- Production deployment provides network-level egress enforcement.
- Database and application secrets are injected out of source control.

## Known limitations

- Single shared API key, no user identity or role separation.
- No multi-tenant data isolation, human SSO/MFA or per-tenant quotas.
- Shared Redis rate limiting and the durable assessment queue/job cancellation are implemented; disposable assessment-worker sandboxes are not.
- Application-level intrusion signals and signed HTTPS alerts are implemented; this is not a WAF, EDR or SIEM.
- Hash-chain events are stored in the application database; no independent immutable sink.
- Secret scanner covers selected patterns only.
- Control catalog is operational mapping, not a certification.
- No independent penetration test, disaster-recovery exercise or production load certification is claimed.

## Release-blocking requirements for hosted multi-user service

1. OIDC/SSO, MFA, RBAC and short-lived sessions.
2. Tenant isolation with API and database enforcement tests.
3. Tenant-aware quotas and policy-aware abuse limits beyond the shared per-IP/per-credential Redis baseline.
4. Dedicated egress policy enforcement and isolated workers.
5. Managed secrets and automated rotation.
6. External append-only audit export and signed checkpoints.
7. Metrics, traces, alerting and incident-response playbooks.
8. Backup restore proof and independent security assessment.
