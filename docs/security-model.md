# Security Model

## Intended use

SENTINEL is intended for assets owned by the operator or covered by written authorization. The configured domain allowlist is the first control, not a substitute for legal authorization or network segmentation.

## Current safeguards

- Explicit allowlist with exact and proper subdomain matching.
- Rejects URLs, IP literals and malformed hostnames.
- Resolves target hostnames and refuses non-global addresses.
- HTTPS only, default certificate verification, no redirects, short timeout, no proxy environment inheritance.
- API key comparison uses constant-time comparison.
- Protected API routes fail closed if no API key is configured.
- Audit events record assessment success and scope denial.
- Secret scanner returns redacted fingerprints rather than raw matched values.
- CORS origins are explicitly configured.

## Known limitations

This initial release is not a WAF, EDR, SIEM, exploit engine, compliance certification or replacement for an established enterprise scanner. DNS resolution and connection establishment occur in separate operations; a production egress proxy/firewall with DNS pinning is required to address DNS-rebinding races. API-key authentication is single-operator and should be replaced with managed identity, RBAC and secret rotation for multi-user deployments. Audit records are stored in the application database and are not immutable against a database administrator.

## Responsible operation

Never add third-party domains to the allowlist without written authorization. Start with a small test scope. Review findings with an engineer before making production configuration changes.