# Security Model

## Intended use

SENTINEL assesses only assets owned by the operator or covered by written authorization. The configured allowlist is a technical guardrail, not proof of legal authorization.

## Implemented safeguards in 0.2

- IDNA hostname normalization and exact/proper-subdomain allowlist matching.
- Rejects URLs, IP literals and malformed hostnames.
- Resolves DNS and rejects any non-global address in the answer set.
- Connects to a literal validated IP while retaining the canonical hostname for TLS SNI, certificate validation and HTTP Host.
- HTTPS only; TLS certificate validation enabled; no redirects; shared timeout budget; maximum header size; response body not downloaded.
- API-key comparison uses constant-time comparison.
- Production startup rejects weak API keys, missing authorization scope, wildcard CORS and SQLite.
- CORS origins are explicitly configured.
- Security response headers, request correlation ID, liveness and database readiness endpoints.
- Assessment history retention cap.
- Secret scanner returns redacted fingerprints, not raw matched values.

## Known limitations

API-key authentication is still single-operator. Audit events are stored in the application database and are not immutable against a database administrator. Multi-tenant isolation, durable queue workers, distributed rate limiting, managed secrets, Alembic migrations and immutable audit export are not implemented. Production egress firewall/proxy enforcement remains mandatory defence in depth.

SENTINEL is not a WAF, EDR, SIEM, exploit engine or compliance certification. Docker runtime, external penetration testing, production egress controls and backup restore have not been certified by this release.

## Responsible operation

Never assess third-party systems without written authorization. Do not add domains to the allowlist without approval. Review all findings before changing production infrastructure.