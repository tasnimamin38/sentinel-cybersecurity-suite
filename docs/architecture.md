# SENTINEL Architecture

SENTINEL 0.2 is a defensive asset-posture platform built from a FastAPI API, React/TypeScript console, SQL persistence and container deployment scaffolding.

## Current request flow

1. Authenticate the operator using the configured API key.
2. Normalize the target hostname and validate it against the explicit allowlist.
3. Resolve DNS and reject the entire answer set if any result is non-public.
4. Connect to a literal IP from the validated DNS answer set. Preserve the hostname for TLS SNI, certificate validation and HTTP Host.
5. Send one bounded HTTPS GET, read headers only, do not follow redirects and do not consume the response body.
6. Evaluate HTTPS headers, TLS certificate expiry and DNS MX/SPF/DMARC posture.
7. Deduplicate and score findings with explainable risk model v2.
8. Store the assessment and audit event; enforce the configured assessment-history cap.

## Runtime boundaries

- No port scanning, exploit checks, brute force, credential validation or arbitrary IP-range discovery.
- No redirects are followed and no response body is downloaded.
- Target must be a DNS hostname in the configured scope.
- Production configuration rejects weak API keys, missing authorized domains, wildcard CORS and SQLite.
- Production network isolation still requires an egress firewall/proxy and network-level destination enforcement.

## Target architecture

The advanced target design separates the control plane (identity, scope, authorization, inventory and versioned policy) from the data plane (API gateway, orchestrator, durable queue, isolated workers and egress gateway). Evidence storage, tenant-scoped relational data, append-only audit export and telemetry become independent services.

See the system architecture, security algorithms, threat model and roadmap in the docs/blueprint directory.

## Current limitations

This release is not a certified enterprise product. It does not yet include OIDC/SSO, RBAC, multi-tenant isolation, Alembic migrations, durable workers/queues, distributed rate limits, immutable audit export, production egress proxy, disaster recovery or independent penetration testing.