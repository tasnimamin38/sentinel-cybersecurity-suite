# SENTINEL 0.24 — Tenant Isolation and Enterprise Identity Design

**Status:** design baseline for implementation; not an assertion that multi-tenancy is already implemented  
**Parent:** `feat/sentinel-0.23-commit-signing-policy`  
**Date:** 2026-11-07

## 1. Executive decision

SENTINEL currently provides service-to-service API-key authentication, route-level RBAC, credential quotas, managed-key rotation, and per-credential registered-asset scopes. It does **not** yet provide human-user identity, tenant membership, or full tenant isolation.

The next architecture step must add a tenant boundary that is derived from a verified identity/credential and enforced by the data model, every API query, background workers, exports, evidence, and audit records. A request header, URL parameter, frontend selector, or caller-supplied `tenant_id` must never establish authority.

This design deliberately separates three identities:

1. **Human identity:** a user authenticated by an approved OIDC identity provider.
2. **Tenant membership:** the user's role and status inside one tenant.
3. **Service identity:** a managed API credential bound to exactly one tenant and its service role/scope.

A platform operator identity is separate from tenant administrator identity. Tenant administrators must not become platform-wide administrators.

## 2. Confirmed current-state gaps

The following are design gaps in the current 0.23 branch, not claims of a remotely exploitable vulnerability:

- `Asset`, `Assessment`, `AssessmentJob`, `SecurityIncident`, `RemediationTask`, `ApiCredential` and `AuditEvent` do not carry a consistent tenant ownership key.
- A selected-asset credential scope is not equivalent to tenant isolation; an all-assets credential is currently global to the single installation.
- Managed service credentials have roles, expiry, revocation, quota and asset scopes, but no tenant binding.
- There is no OIDC/SAML login, human user, membership, browser session, MFA policy or tenant-scoped actor attribution.
- The audit journal is installation-wide. A future tenant administrator must not be given access to another tenant's audit events or checkpoint metadata.
- Workers process jobs from a shared queue. A job must carry a tenant identity, and the worker must revalidate both tenant ownership and asset authorization immediately before execution and result persistence.
- Shared legacy bootstrap API keys currently have administrator semantics. They must not silently become tenant-wide or platform-wide production access after multi-tenancy is introduced.

## 3. Security invariants (non-negotiable)

1. Every tenant-owned row has one non-null `tenant_id`; ownership is immutable after creation except through a separately authorized, audited migration workflow.
2. Every human membership and managed service credential belongs to exactly one tenant.
3. Tenant context is resolved from the validated session or credential record. Client-provided tenant identifiers are selectors only and must be checked against membership.
4. Every read, write, aggregate, export, evidence lookup, audit lookup, and background-job transition is tenant-scoped server-side.
5. Asset scopes remain a second, narrower authorization layer inside a tenant; `all` means all assets **inside the credential's tenant**, never all tenants.
6. Cross-tenant foreign-key relationships are rejected by database constraints, not only application checks.
7. Missing tenant context, unknown tenant, malformed ownership, or unmapped permission fails closed.
8. Tenant administrators cannot enumerate tenants, read global audit events, rotate platform credentials, or access another tenant's assets.
9. Background workers cannot trust tenant IDs copied into a job payload; they reload the authoritative job and asset rows and compare ownership.
10. Logs, metrics, errors, URLs, cache keys and object-storage keys must not disclose another tenant's identifiers or data.
11. Platform-wide emergency operations require a separate platform role, explicit audit reason, and dedicated credential/session.
12. Existing single-installation data is migrated into one explicit legacy tenant before enforcement; no row is assigned to a tenant based on user-supplied metadata.

## 4. Target data model

Introduce a tenant registry and tenant ownership across the operational data plane.

### Core identity/control-plane tables

- `tenants`: immutable UUID, unique normalized slug, display name, lifecycle status, created/updated timestamps, optional billing/retention policy reference.
- `users`: stable internal UUID, normalized unique issuer+subject identity, email/display metadata from the IdP, status, timestamps. Do not store IdP passwords.
- `tenant_memberships`: tenant_id, user_id, role, status, invited/accepted timestamps, optional membership expiry. Unique (tenant_id, user_id).
- `identity_providers`: tenant_id, issuer, client ID/reference, allowed domains and policy metadata. Client secrets remain in a secret manager, not the database or repository.
- `user_sessions` (or a maintained server-side session store): hashed opaque session token, user_id, tenant_id, created/expiry/revocation timestamps, authentication context and CSRF binding. Never store raw session tokens.

### Tenant-owned operational rows

Add a non-null `tenant_id` to at least:

- assets
- assessments
- assessment_jobs
- remediation_tasks
- security_incidents
- api_credentials
- api_credential_usage
- audit_events and audit checkpoints
- future evidence/artifact metadata

Add indexes beginning with `tenant_id` for common filters and unique constraints that are tenant-local. Use composite foreign keys such as `(tenant_id, asset_id)` to prove that an assessment, job, incident or remediation references an asset from the same tenant. For records that currently allow a null asset reference, define an explicit tenant-owned ad-hoc assessment policy before migration; do not use NULL ownership as a bypass.

The existing global unique asset-hostname rule should be reviewed. The intended multi-tenant rule is normally a tenant-local unique hostname, represented by a composite unique constraint on `(tenant_id, normalized_hostname)`, with a migration path that detects and resolves duplicates before enforcement.

### Audit and evidence

Audit events must carry tenant ownership and actor attribution (`actor_type`, `actor_id`, and optional `credential_id`). Tenant audit verification must be independently scoped. A cross-tenant global checkpoint may exist only in the platform control plane and must not be exposed through tenant APIs.

Assessment evidence digests and their audit anchors must include the tenant ID in the canonical snapshot. Object storage, when introduced, must use tenant-scoped authorization and encryption-key policy; opaque storage prefixes alone are not access control.

## 5. Authentication and authorization

### OIDC human login

Use Authorization Code Flow with PKCE. Validate signature, issuer, audience, expiry, nonce, state, authorized party where applicable, and key rotation. Do not accept unsigned tokens or select an issuer from an untrusted request parameter.

Require TLS and secure cookies. Browser sessions should use opaque, high-entropy, server-revocable tokens with `Secure`, `HttpOnly`, and appropriate `SameSite` settings. Protect state-changing cookie-authenticated requests against CSRF. Rotate session identifiers after login and privilege changes. Enforce short idle and absolute lifetimes, revocation, and reauthentication for sensitive actions.

MFA is enforced through an IdP assurance policy. The platform must verify documented `acr`/`amr` claims (or a provider-specific verified equivalent) for the required assurance level; merely displaying an MFA checkbox or accepting an unverified claim is not MFA enforcement.

### Membership roles

Keep tenant role bindings separate from API service roles. The first release should define explicit tenant roles such as `tenant_owner`, `tenant_admin`, `security_analyst`, `asset_manager`, `auditor`, and `read_only`. Map each operation to a named permission. Never infer permissions from UI navigation or role labels in the browser.

A user with memberships in multiple tenants must select an active tenant, but the server validates that selection against active memberships on every session/context change. A platform operator has a distinct platform role and separate elevation/reauthentication path.

### Service credentials

A managed API credential must contain a required `tenant_id`. Its authority is the intersection of:
- tenant ownership,
- service role permissions,
- per-credential asset scope,
- expiry/revocation/rotation state,
- request quotas.

Creation, rotation and revocation must be restricted to authorized administrators within the same tenant. Credential-list APIs and one-time secret responses are tenant-local. Legacy environment keys are retained only as a controlled migration/bootstrap path; production multi-tenant mode must reject ambiguous global legacy keys after the tenant migration window.

## 6. Enforcement architecture

### Application query layer

Provide one reusable tenant-scoped query/authorization interface. It must require a typed `TenantContext`; do not default to a global tenant when the context is absent. The context should include tenant_id, actor identity, role permissions, credential identity and asset-scope policy.

Direct object reads must use tenant-scoped SQL predicates, e.g. `WHERE tenant_id = :tenant_id AND id = :id`; fetching by primary key first and checking after serialization is prohibited. Apply tenant filters before aggregates, pagination and limits. Avoid post-query Python filtering because it can leak counts, page sizes or timing.

### PostgreSQL Row-Level Security

After explicit query scoping and migration are proven, enable PostgreSQL Row-Level Security on tenant-owned tables as defense in depth. Set the tenant ID with transaction-local configuration inside each request/worker transaction; never use connection-persistent session state with a pooled connection. Use `FORCE ROW LEVEL SECURITY` where the application role is not intended to bypass policies. The migration/backup role is separate from the runtime role.

RLS does not replace explicit application predicates. SQLite tests must exercise application-level tenant filters; PostgreSQL integration tests must additionally prove RLS behavior and connection-pool context reset.

### Worker and queue

Each job stores tenant_id and asset_id. The worker claim query, lease, heartbeat, cancellation, retry, result persistence and audit event are tenant-bound. A worker transaction sets a local tenant context only after loading and validating the job. Before network activity and before commit, it rechecks tenant, asset, authorization expiry, status, scope and worker lease. Tenant data must not be included in another tenant's logs or metrics labels.

### Cache, export and storage

Include tenant_id in all cache keys, idempotency namespaces, report/export identifiers and object-storage authorization decisions. CSV exports must scope the source query before generation. Avoid globally reusable filenames or download tokens. Evidence downloads must reauthorize the tenant and object on every request.

## 7. API contract changes

- Add tenant-aware login, logout, session, membership and active-tenant endpoints.
- Add tenant administration endpoints for a tenant's own users, identity provider settings and service credentials.
- Keep asset, assessment, job, incident, remediation, export and evidence endpoints tenant-context aware.
- Do not accept `tenant_id` in ordinary resource-create payloads. The active server-side context assigns it.
- Platform-only tenant lifecycle APIs live under a separately authorized control-plane surface and are not reachable with tenant-admin credentials.
- Return 404 for out-of-tenant object identifiers to reduce existence disclosure; return 403 for an authenticated operation the principal is allowed to identify but not perform.
- Version API schemas where tenant ownership changes response or request shapes.

## 8. Safe migration and rollout

1. **Inventory:** enumerate every model, query, export, worker operation, audit event, cache key and frontend route that reads or writes tenant-owned data.
2. **Prepare:** add a deterministic legacy tenant record and nullable tenant columns in an additive migration. Do not yet enforce tenant isolation based on partially populated columns.
3. **Backfill:** assign every existing asset and dependent row to the legacy tenant using verified foreign-key relationships. Resolve orphaned/null-asset records with an explicit reviewed rule. Backfill credentials and audit evidence.
4. **Validate:** run reconciliation queries for null tenant IDs, cross-tenant relationships, duplicate tenant-local hostnames, orphan records and audit-chain consistency.
5. **Constrain:** add non-null constraints, tenant-local unique indexes and composite foreign keys. The migration must be tested against a copy of a populated pre-tenant database, not only an empty database.
6. **Dual enforcement:** add explicit tenant predicates in all application paths; add negative cross-tenant tests for every route. Do not infer success from schema columns alone.
7. **RLS:** enable PostgreSQL policies after application predicates and transaction-context reset tests pass.
8. **Identity rollout:** configure OIDC, verify claim validation and MFA assurance, then enable human sessions and membership enforcement.
9. **Credential migration:** create tenant-bound service credentials, rotate clients, then disable legacy global keys in multi-tenant production mode.
10. **Canary:** test two isolated tenants with deliberately overlapping asset names, IDs, jobs, incidents, exports and user memberships. Verify each tenant sees only its own data.
11. **Recovery:** rehearse backup restore and tenant-scoped recovery; verify audit evidence after restore.

No automatic production migration or credential rotation is part of this design PR.

## 9. Required security and QA evidence

A release cannot pass unless tests prove:

- Tenant A cannot read, modify, delete, enumerate, aggregate, export, or infer Tenant B data.
- A Tenant A credential cannot create or rotate a credential for Tenant B.
- A user without active membership cannot select or retain a tenant context.
- A user removed from a tenant loses access on the next request/session refresh.
- A credential revoked, expired, rotated beyond grace or moved to inactive tenant is rejected.
- A job cannot be claimed, cancelled, retried or persisted under a different tenant.
- A foreign-key reference to another tenant's asset fails at the database layer.
- Audit listings, verification, evidence digests and checkpoint metadata remain tenant-isolated.
- Tenant-scoped quotas, cache keys, CSV exports and idempotency keys cannot collide across tenants.
- PostgreSQL RLS denies cross-tenant reads even when an application query accidentally omits its predicate.
- Pooled database connections do not retain a previous request's tenant context.
- OIDC tests reject wrong issuer/audience, expired token, invalid signature, nonce/state mismatch, missing required MFA assurance and replayed state.
- Migration tests preserve legacy installation data, audit integrity and backup restorability.

Required evidence includes backend unit tests, PostgreSQL integration tests, frontend auth/session tests, migration tests against populated fixtures, CodeQL, dependency review, container/config scanning, and a reviewed threat-model update.

## 10. Out of scope for 0.24 design

- No claim of SOC 2, ISO 27001, PCI DSS or other certification.
- No customer-managed encryption keys until a supported key custody and rotation design exists.
- No global platform administrator UI until a separate control-plane threat model exists.
- No production SSO provider is selected by this design; provider selection and production metadata are deployment decisions.
- No automatic tenant provisioning from email domain alone. Domain verification and explicit invitations/approval are required.

## 11. Release gate

The tenant-isolation implementation is not production-ready until all invariants in Sections 3 and 9 are met, the populated-database migration is rehearsed, and an independent reviewer signs off on the cross-tenant negative test matrix. Passing CI on the design document is not evidence that tenant isolation exists.
