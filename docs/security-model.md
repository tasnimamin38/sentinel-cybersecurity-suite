# Security Model

## Intended use

SENTINEL assesses only systems owned by the operator or explicitly authorized in writing. A configured hostname allowlist is a technical safety guard, not proof of legal authorization.

## Implemented safeguards in 0.3

- Canonical hostname normalization and exact/proper-subdomain scope checks.
- Registered asset owner, environment, criticality, approval reference and expiry.
- Assessment denial for inactive assets or expired authorization.
- DNS answer validation and literal-IP-pinned HTTPS connection.
- Hostname-bound TLS SNI, certificate verification, no redirects and bounded header-only response.
- Confidence-aware and criticality-aware explainable risk scoring.
- Finding-linked remediation tasks.
- Bounded inline secret-pattern scan; source content not persisted; matched values are not returned.
- SHA-256 hash-linked audit events and chain verifier.
- Canonical SHA-256 assessment snapshot digests anchored in each new `assessment.completed` event, with a read-only per-assessment integrity verifier; legacy assessments remain explicitly incomplete until re-assessed.
- Alembic migrations; production startup runs migrations before API server startup.
- Production API docs are disabled and CORS origins are explicitly configured.

## Known limitations

- API-key authentication is a single shared operator credential.
- Audit hash chaining is tamper-evident, not immutable against a privileged database operator.
- Secret pattern coverage is intentionally limited.
- Control mapping is not regulatory certification or audit evidence.
- Multi-tenant isolation, OIDC/SSO, RBAC, distributed rate limits, durable worker queues, external audit checkpoints, managed secrets and observability stack are not implemented.
- Production egress firewall/proxy, restore drills and independent penetration testing are deployment requirements, not certified by local tests.

## Responsible operation

Never add a third-party domain without written authorization. Keep production credentials outside source control. Review findings with the accountable asset owner before changing production configuration.
