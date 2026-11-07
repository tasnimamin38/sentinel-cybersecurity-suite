# SENTINEL Architecture

SENTINEL 0.3 is a defensive asset-governance and posture-operations baseline built from FastAPI, React, SQLAlchemy, Alembic and PostgreSQL/SQLite.

## Current execution path

1. Authenticate using the configured API key.
2. Normalize and authorize a DNS hostname.
3. For registered assets, check active status and expiry-dated authorization.
4. Resolve DNS and reject non-global addresses.
5. Connect to a literal validated public IP while keeping hostname-bound TLS SNI and HTTP Host.
6. Read one bounded HTTPS response-header block; do not follow redirects or download the body.
7. Inspect selected headers, TLS certificate lifecycle and DNS MX/SPF/DMARC posture.
8. Normalize findings and apply explainable risk v2.
9. Persist the assessment and audit event.
10. Create remediation tasks from actual stored findings.

## API request resource guard

All `/api/v1/*` request bodies are limited before FastAPI parses JSON. The default cap is 512 KiB and can be changed with `SENTINEL_MAX_REQUEST_BODY_BYTES` from 1 KiB through 10 MiB. The middleware rejects an oversized declared `Content-Length` before reading the body and counts streamed chunks when the length is missing or the request is chunked. Health and readiness endpoints are outside this API body policy.

## 0.3 operational modules

- Asset inventory and authorization expiry
- Web/TLS/DNS posture assessment
- Explainable risk and finding normalization
- Remediation workflow
- Operational control mapping
- Redacting inline secret-pattern scanning
- Hash-linked audit chain and verification
- Versioned database migration
- React security operations console

See the blueprint directory for target architecture, decision algorithms, threat model and roadmap.

## Current boundary

The current release is a single-workspace engineering baseline. It does not include multi-user identity, RBAC, multi-tenant isolation, durable background workers, distributed rate limits, external immutable audit storage, egress gateway, metrics/tracing or independent penetration-testing evidence.
