# SENTINEL — Advanced System Architecture Blueprint

**Blueprint version:** 0.2  
**Implementation baseline:** SENTINEL API 0.2.0  
**Scope:** Defensive posture assessment of explicitly authorized DNS assets.

This document separates what is implemented today from the target architecture. A design drawing is not evidence that a service has been implemented or independently security-tested.

## 1. Architecture principles

1. **Authorization before network I/O.** Every assessment begins with explicit hostname normalization and allowlist authorization.
2. **Deny by default.** Missing production configuration, malformed targets, mixed public/private DNS answers and unbounded requests fail closed.
3. **Deterministic evidence.** Every finding has a stable code, severity, explanation and remediation recommendation.
4. **Bounded execution.** Small DNS answer sets, short total request deadlines, header-size limits and no response-body download.
5. **Separation of duties.** The control plane defines scope and policy; the data plane performs only approved checks.
6. **Observable and auditable.** Health/readiness, request IDs, stored assessments and audit events provide operational traceability.
7. **No exploit execution.** The product is a defensive posture and exposure-hygiene platform, not an offensive scanner.

## 2. Current container architecture

Operator
  → React operator console
  → FastAPI API and API-key authentication
  → Hostname normalization and allowlist authorization
  → DNS resolution and public-address validation
  → DNS-pinned HTTPS probe (original hostname retained for SNI and Host)
  → HTTP header / TLS evaluator + MX / SPF / DMARC checks
  → Finding normalization
  → Explainable risk v2
  → SQL assessment history and audit events

### Request lifecycle

1. The operator submits a hostname from the console.
2. The API authenticates the operator and normalizes the hostname using IDNA.
3. Scope policy checks exact-domain or proper-subdomain membership. Suffix-confusion hosts are rejected.
4. DNS resolution collects the complete answer set. If any returned address is non-global, the assessment is denied.
5. The HTTPS probe connects to a literal validated IP address. TLS SNI and the HTTP Host header continue to use the canonical hostname.
6. The probe makes one HTTP/1.1 GET, reads only the response header block, does not follow redirects and closes the connection.
7. DNS email posture checks and HTTPS/TLS evidence are normalized into findings.
8. The risk engine deduplicates findings, applies confidence and asset criticality, and returns a deterministic score with top drivers.
9. The result and an audit event are stored. The assessment-history retention cap is enforced.

## 3. Trust boundaries

| Boundary | Data crossing it | Controls |
|---|---|---|
| Browser → API | API key, hostname, response data | CORS allowlist, API-key check, request validation, no browser persistence of API key |
| API → DNS resolver | Canonical hostname | Strict normalization, bounded DNS use, reject any non-global answer |
| API → external asset | One GET request | Literal-IP pinning, original-host SNI/Host, TLS verification, no redirects, bounded headers/deadline |
| API → database | Findings, evidence, audit events | SQLAlchemy parameterization, retention cap, database not exposed by Compose ports |
| CI → repository | Source and dependency metadata | Read-only CI permissions, CodeQL, Dependabot |

## 4. Target enterprise architecture (not yet implemented)

### Control plane — trusted administration
- OIDC / SSO identity provider and MFA policy
- RBAC and tenant policy service
- Asset inventory and authorization registry
- Versioned policy-as-code and exception approvals
- Security administration console

### Data plane — isolated assessment execution
- API gateway, WAF and distributed rate limits
- Assessment orchestrator and durable job queue
- Ephemeral assessment workers with least privilege
- Restricted egress proxy with destination IP enforcement
- Evidence normalizer and risk/control mapper

### Storage and observability plane
- Tenant-scoped relational database
- Encrypted evidence object store
- Append-only audit export and integrity checkpoints
- Metrics, traces, structured logs and security events

### Target service responsibilities

- **Identity:** OIDC/SAML federation, MFA enforcement, short-lived sessions and service identities.
- **Authorization registry:** asset owner, proof-of-control reference, allowed hostnames, expiry and approver.
- **Policy service:** versioned assessment policies, control applicability, risk appetite and exception expiry.
- **Orchestrator:** idempotent job creation, state transitions, queue delivery and cancellation.
- **Ephemeral workers:** isolated execution with no ambient cloud credentials and no unrestricted filesystem access.
- **Egress gateway:** network-level allowlisting, destination IP pinning, DNS rebinding resistance and per-job egress budgets.
- **Evidence store:** encrypted, retention-controlled evidence with redaction and access logging.
- **Audit export:** append-only external destination with independent retention and integrity verification.
- **Telemetry:** service metrics, traces, structured logs and alert routing.

## 5. Data model evolution

Current tables: assessments, audit_events.

Target entities:
- tenants, users, roles, role_bindings
- assets, asset_authorizations, scope_approvals
- assessment_policies, policy_versions, policy_exceptions
- assessment_jobs, assessment_attempts, assessment_results
- findings, evidence_objects, remediation_tasks
- audit_events, audit_checkpoints, integration_credentials

A future multi-tenant schema must include tenant ownership in every tenant-scoped row and enforce it in the query layer and database. Do not add multi-tenancy by merely adding a tenant_id column without isolation tests.

## 6. Reliability and failure model

- Jobs should be idempotent by tenant, asset, policy version and scheduled time bucket.
- Retries should use bounded exponential backoff with jitter and a maximum attempt count.
- A failed check must be recorded as incomplete or error; it must not be represented as a clean security result.
- Database writes should use explicit transactions. Long network checks should not hold database locks.
- Current 0.2 startup still uses SQLAlchemy create_all to bootstrap tables. This is a known production limitation; Alembic migrations must replace it before production rollout.
- Backups need automated restore tests, not just successful backup jobs.

## 7. Production gate

SENTINEL 0.2.0 is still an engineering baseline. Before a production/enterprise claim, complete the target identity model, tenant isolation, migration system, durable queue, egress gateway, immutable audit export, rate limits, monitoring, restore drills, threat-model review and independent penetration test.