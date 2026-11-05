# SENTINEL Validation Matrix — 0.3.2

This matrix records what the current automated checks exercise. A passing test is evidence for the tested behavior only; it is not a certification.

| Area | Automated coverage |
|:---|:---|
| API authentication | Missing/invalid/weak server key, constant-time comparison path and overlapping key acceptance |
| Production configuration | Strong key requirements, placeholder rejection, scope and PostgreSQL requirements, bounded timeouts |
| Asset governance | Allowlist checks, duplicate assets, time-bounded authorization, pause/inactive denial and criticality context |
| Network safety | Public DNS answer validation, private/reserved address rejection and bounded DNS behavior |
| HTTPS transport | Literal-IP connection, hostname SNI/certificate verification, bounded headers and no redirects/body download |
| DNS posture | MX, SPF presence/duplication/permissive mechanisms, DMARC policy quality, inherited CAA, MTA-STS discovery, TLS-RPT, shared deadline and timeout handling |
| HTTP headers | HSTS max-age/subdomain coverage, CSP unsafe directives, frame protection, MIME sniffing, Referrer Policy and Permissions Policy |
| Risk engine | Severity weighting, deduplication, confidence and asset criticality |
| Remediation | Finding-backed task creation, assignment/status updates and audit records |
| Secret hygiene | Pattern detection, redaction, no source persistence and audit metadata |
| CSV exports | Dataset allowlist, authentication, row caps, audit event and formula-injection neutralization |
| Audit journal | Sequence continuity, hash verification, legacy-unsealed state and event tampering detection |
| Database migration | Upgrade path from legacy schema while preserving existing records |

## Local verification record

- Backend pytest: 62 passed.
- Ruff lint: passed.
- Ruff format check: passed.
- Frontend TypeScript/Vite production build: passed.
- pip-audit: no known vulnerabilities found.
- npm audit: 0 reported vulnerabilities.
- Docker Compose YAML parse: passed locally; GitHub CI now validates Compose interpolation and builds both container images.

## Not covered / not certified

- Container image build/startup and live Docker network behavior on this machine.
- External egress firewall enforcement and DNS rebinding resistance at the infrastructure layer.
- Multi-user SSO/MFA/RBAC, multi-tenant isolation or distributed rate limiting.
- Durable worker/queue recovery, load testing and high-concurrency performance.
- Independent penetration test, backup/restore drill, disaster recovery objectives or regulatory certification.
