# SENTINEL Architecture

## Current delivery

SENTINEL 0.1 is a modular defensive posture platform, not yet a certified enterprise product. It contains a FastAPI service, a React/TypeScript operator console, SQL persistence, and container deployment scaffolding.

## Request flow

1. An operator authenticates with an API key.
2. The API validates the requested DNS hostname against the explicit SENTINEL_ALLOWED_DOMAINS allowlist.
3. DNS resolution is inspected and private, reserved, loopback and link-local destinations are rejected.
4. A single HTTPS GET is made with certificate verification enabled, redirects disabled and a bounded timeout.
5. TLS certificate metadata and DNS mail-authentication posture are inspected.
6. Findings are normalized, risk-scored, stored and written to an audit event.

## Boundaries

- No port scanning, exploit checks, brute force, credential validation or arbitrary IP-range discovery.
- No redirects are followed.
- No remote response body is intentionally consumed.
- Target must be a DNS hostname in the configured scope.
- Public DNS resolution is checked before outbound assessment.
- Production deployments should add egress firewall policy and DNS/IP pinning at the network layer to close DNS-rebinding windows.
- The UI stores API keys only in component memory. It does not persist them in local storage.

## Growth path

Separate service modules are designed for later workers and queues. Before enterprise rollout, add Alembic migrations, tenant-aware RBAC/SSO, managed secrets, rate limiting at the gateway, durable job queue, immutable audit export, metrics/tracing, policy-as-code, disaster recovery, and external penetration testing.