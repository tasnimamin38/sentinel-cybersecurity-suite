# SENTINEL 0.24 — Tenant Isolation Implementation Plan

> Parent design: `docs/superpowers/specs/2026-11-07-sentinel-tenant-isolation-design.md`  
> Planning baseline: `feat/sentinel-0.23-commit-signing-policy`  
> This plan is a gated sequence. Do not merge partial tenant isolation as production multi-tenancy.

## Goal

Convert the existing single-installation service-RBAC and asset-scope model into verified tenant ownership across the API, data model, audit/evidence, workers, browser sessions and PostgreSQL. Preserve the existing single-tenant installation through a deterministic legacy-tenant migration.

## Global constraints

- Never trust a tenant identifier supplied in a request body, query parameter, header, URL, cookie or local storage as authorization.
- A missing tenant context fails closed.
- Every tenant-owned resource must be filtered in SQL before pagination, aggregation, serialization or export.
- `all` asset scope means all assets in the credential's own tenant.
- No global tenant-admin bypass; platform operator access is separate.
- Keep old credentials and data usable only through an explicit, time-bounded migration path.
- No production data migration, key rotation, SSO cutover or merge is part of feature implementation PRs.
- Each implementation task must add negative cross-tenant tests before production code is considered complete.
- PostgreSQL integration tests are mandatory for composite foreign keys and RLS; SQLite-only success is insufficient.
- Do not claim tenant isolation until the complete matrix in the parent design passes.

## Work sequence

### Task 1 — Inventory and tenant context contract

- [ ] Enumerate every SQL query and ORM lookup in API routes, services, reports, exports, background workers and scripts.
- [ ] Enumerate every tenant-owned model and every foreign-key relationship.
- [ ] Define typed immutable `TenantContext` and its trusted construction points.
- [ ] Identify ad-hoc assessment rows and orphanable asset references; document their ownership policy.
- [ ] Add a route inventory test that fails when a protected route has no explicit authorization/tenant policy.
- [ ] Review the inventory against the parent design before schema changes.

**Acceptance:** inventory includes each API route, model, worker operation, audit event, export and storage/cache key.

### Task 2 — Tenant registry and additive schema migration

- [ ] Add `Tenant`, `User`, `TenantMembership`, `IdentityProvider` models as appropriate to the chosen rollout slice.
- [ ] Add nullable `tenant_id` columns to assets, assessments, jobs, remediations, incidents, credentials, quota usage, audit events and evidence metadata.
- [ ] Add a deterministic legacy tenant row using a fixed migration-owned ID.
- [ ] Backfill asset ownership first, then dependent rows through verified foreign keys; do not infer ownership from display names or free-text audit fields.
- [ ] Define an explicit rule for assessments without an asset and incidents/remediations/jobs with orphaned asset references.
- [ ] Add tenant-first indexes and tenant-local hostname uniqueness.
- [ ] Add composite foreign keys from dependent rows to `(tenant_id, asset_id)`.
- [ ] Add downgrade guards that refuse destructive data loss where necessary.
- [ ] Build a populated pre-tenant database fixture and test upgrade/downgrade behavior.

**Acceptance:** no null tenant ownership for tenant-owned rows; no cross-tenant foreign-key relationship; existing legacy rows and audit integrity remain accounted for.

### Task 3 — Principal and service credential binding

- [ ] Add required `tenant_id` to managed API credentials and principal context.
- [ ] Bind legacy environment credentials to the single legacy tenant only.
- [ ] Ensure `SENTINEL_API_CREDENTIALS_JSON` cannot assign a tenant through untrusted deployment values without an operator-controlled provisioning path.
- [ ] Restrict credential creation, rotation and revocation to the caller's tenant.
- [ ] Validate selected asset IDs against the caller's tenant as well as their existence.
- [ ] Preserve tenant binding and original expiry across credential rotation.
- [ ] Make credential ID, role, quota and scope audit metadata tenant-local.
- [ ] Add tests for same key/ID isolation, wrong-tenant asset scope, revocation and rotation.

**Acceptance:** a tenant administrator cannot create, enumerate, rotate or revoke another tenant's credential.

### Task 4 — Central SQL tenant enforcement

- [ ] Replace asset-only filtering with a reusable tenant-scoped repository/query layer.
- [ ] Require tenant context for all tenant-owned list, detail, create, update and delete paths.
- [ ] Apply filters before count, grouping, pagination and limit operations.
- [ ] Enforce tenant ownership for overview/dashboard aggregates and configuration-domain disclosure.
- [ ] Enforce tenant ownership for assets, assessments, evidence-integrity reads, jobs, incidents, remediations, controls and exports.
- [ ] Ensure cross-tenant object lookups return 404 without serializing partial records.
- [ ] Add endpoint-by-endpoint negative tests for read, write, update and enumeration.

**Acceptance:** every route in the route inventory has a passing two-tenant isolation test.

### Task 5 — Tenant-scoped audit, evidence and exports

- [ ] Add tenant and actor attribution to audit events.
- [ ] Scope audit list, integrity verification, checkpoints and export operations.
- [ ] Preserve per-tenant hash-chain continuity or define a formally reviewed checkpoint migration.
- [ ] Include tenant ownership in canonical assessment evidence snapshots and attestations.
- [ ] Scope CSV/report generation in SQL before constructing the output.
- [ ] Add tenant IDs to idempotency namespaces and any cache/report keys.
- [ ] Prove that tenant A cannot infer tenant B event counts, sequence positions, evidence IDs or download tokens.

**Acceptance:** tenant evidence verifies independently and global audit metadata is unavailable to tenant administrators.

### Task 6 — Worker isolation and queue ownership

- [ ] Persist tenant_id on every job and derive it from the authoritative asset at enqueue time.
- [ ] Use tenant-aware job claim and lease operations.
- [ ] Establish transaction-local tenant context only after loading the authoritative job.
- [ ] Revalidate tenant, asset, authorization, lease and cancellation immediately before network activity and persistence.
- [ ] Propagate tenant-safe actor/credential metadata to audit events without logging secrets.
- [ ] Add multi-worker tests proving a worker cannot claim or persist another tenant's job through a manipulated payload.
- [ ] Add stale lease, retry, cancellation and tenant-deactivation tests.

**Acceptance:** no worker transition or assessment result can cross tenant ownership.

### Task 7 — PostgreSQL Row-Level Security

- [ ] Add RLS policies to each tenant-owned table.
- [ ] Set tenant context using transaction-local database configuration, not pooled connection-persistent state.
- [ ] Use a restricted application DB role that cannot bypass RLS.
- [ ] Separate migration/backup privileges from runtime API/worker roles.
- [ ] Enable `FORCE ROW LEVEL SECURITY` where supported by the role design.
- [ ] Add integration tests that intentionally omit an application tenant predicate and prove RLS still denies cross-tenant access.
- [ ] Test pooled-connection reuse and rollback behavior to ensure context is cleared.

**Acceptance:** application predicates and database RLS both deny cross-tenant access under PostgreSQL.

### Task 8 — OIDC, human sessions and MFA assurance

- [ ] Select a supported OIDC provider profile and document issuer/client configuration.
- [ ] Implement Authorization Code + PKCE, state and nonce validation, issuer/audience/signature/expiry validation and JWKS refresh/rotation.
- [ ] Store internal user identity by issuer+subject; do not rely on mutable email as the identity key.
- [ ] Implement tenant memberships, invitations, deactivation and role updates.
- [ ] Implement secure, revocable server-side sessions and CSRF protection.
- [ ] Enforce provider-backed MFA assurance using verified `acr`/`amr` semantics.
- [ ] Require reauthentication/step-up for tenant administration, credential issuance and sensitive exports.
- [ ] Add login replay, claim tampering, membership removal and session revocation tests.

**Acceptance:** no tenant session can be created without a verified identity and active membership; required MFA assurance is cryptographically/provider verified.

### Task 9 — Frontend, operational controls and documentation

- [ ] Add sign-in/sign-out and active-tenant selection using server-validated membership.
- [ ] Remove any frontend-only assumptions about authorization; handle 401/403/404 safely.
- [ ] Avoid placing bearer/session secrets in local storage, query strings or logs.
- [ ] Add tenant-safe activity indicators and role-aware UI without treating UI gating as security.
- [ ] Update runbooks, recovery, backup/restore, incident response and security model.
- [ ] Add alerting for cross-tenant authorization denials and tenant-context failures without high-cardinality sensitive labels.
- [ ] Document support/admin break-glass procedures and audit them.

**Acceptance:** frontend session lifecycle and backend policy are consistent; operational runbooks describe tenant-specific recovery and incident handling.

### Task 10 — Release verification

- [ ] Run full Python tests, lint and type checks.
- [ ] Run frontend typecheck/build and auth/session tests.
- [ ] Run migration tests against populated legacy fixtures.
- [ ] Run PostgreSQL multi-tenant integration, RLS and pooled-connection tests.
- [ ] Run worker concurrency/recovery tests across two tenants.
- [ ] Run CodeQL, dependency review, secret-history scanning, SBOM, Trivy source/dependency/config/container scans.
- [ ] Review the cross-tenant negative test matrix manually.
- [ ] Obtain independent security review before changing PR from draft or enabling production tenant mode.
- [ ] Rehearse backup, restore and rollback on an isolated environment.

**Release gate:** all tasks are complete, all security and migration evidence is inspectable, and independent review is recorded. A green CI result on a partial branch does not satisfy this gate.

## Suggested PR decomposition

1. **0.24a — Tenant registry and migration foundation** (schema, legacy tenant backfill, fixture tests).
2. **0.24b — Tenant-bound service identities** (credential binding and provisioning).
3. **0.24c — Tenant-aware API authorization** (all routes, aggregates, reports and exports).
4. **0.24d — Audit/evidence/worker tenant binding** (queue and evidence invariants).
5. **0.25 — OIDC, memberships, browser sessions and MFA assurance**.
6. **0.26 — PostgreSQL RLS and production tenant operations**.

Do not combine all stages into one large PR. Each stage must remain independently reviewable and must not claim a completed security boundary before all dependent stages are present.
