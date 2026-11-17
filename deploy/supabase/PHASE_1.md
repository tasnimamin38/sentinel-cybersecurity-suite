# SENTINEL — Phase 1: Supabase database and tenant security

Last verified: 2026-11-18 (Asia/Dhaka)

## Existing hosted project

- Project: `sentinel-cybersecurity-suite`
- Project ref: `xyzxswnofcychlkgrdsn`
- Region: `ap-south-1`
- PostgreSQL: 17
- URL: `https://xyzxswnofcychlkgrdsn.supabase.co`
- Dashboard: https://supabase.com/dashboard/project/xyzxswnofcychlkgrdsn

This project was already provisioned and healthy. Phase 1 did not create another project.

## Architecture boundary

SENTINEL's operational API and worker continue using the dedicated FastAPI/PostgreSQL runtime login `sentinel_app`. Do not replace that connection with a browser key or a Supabase `service_role` key.

The `sentinel` schema remains a private application schema and must not be added wholesale to Supabase Data API exposed schemas. The browser uses Supabase Auth for identity. The application API remains responsible for privileged onboarding, membership administration, domain verification, and operational actions.

The only browser-safe Supabase variables are:

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`

A publishable key is designed to be public. Never put a `service_role` key, Postgres password, pooler URL, Vault secret, or worker secret in a `NEXT_PUBLIC_*` variable or browser bundle.

## Database changes applied to the hosted project

Supabase migration history includes these Phase 1 migrations:

1. `20261117200510_tenant_registry_auth_rls`
2. `20261117200612_tenant_scoped_fk_indexes`
3. `20261117200857_tenant_identity_auth_foreign_keys`
4. `20261117202023_tenant_identity_fk_indexes`

These migrations are stored in this repository under `deploy/supabase/migrations/`.

### RLS and grants

RLS is enabled on all 12 tables in the `sentinel` schema. The five tenant-registry tables now have policies for the trusted `sentinel_app` runtime role and limited authenticated-user access.

| Table | Browser role access after RLS |
|---|---|
| `sentinel.tenants` | Active member SELECT; owner/admin UPDATE |
| `sentinel.human_profiles` | Self SELECT/INSERT/UPDATE only |
| `sentinel.tenant_memberships` | Self SELECT; active owner/admin may read roster |
| `sentinel.company_profiles` | Active member SELECT; owner/admin INSERT/UPDATE |
| `sentinel.company_domain_challenges` | No anon/authenticated table grant; server-only |

Tenant creation, membership creation/deletion, membership role changes, and company-domain verification are server-side operations. A user cannot make themselves an owner by editing user metadata or inserting their own membership row.

The six operational application tables retain their existing `sentinel_app`-only policies. RLS is not a replacement for the FastAPI authorization layer; both remain required.

### Auth identity constraints

These columns use PostgreSQL UUID and reference `auth.users(id)`:

- `sentinel.human_profiles.user_id`
- `sentinel.tenant_memberships.user_id`
- `sentinel.tenant_memberships.invited_by_user_id`
- `sentinel.company_domain_challenges.created_by_user_id`

Deletion behavior is explicit: human profile CASCADE, membership owner RESTRICT, invitation attribution SET NULL, domain challenge creator RESTRICT.

The backend SQLAlchemy model types and Alembic revision `0006_auth_identity_uuids` match the hosted types. The hosted `sentinel.alembic_version` is stamped at `0006_auth_identity_uuids` after the database migration was verified.

### Verification results

- Supabase security advisor: zero security lints after Phase 1.
- Supabase performance advisor: the five operational tenant-composite foreign keys and two Auth identity foreign keys were indexed; no unindexed-foreign-key warning remains.
- Remaining unused-index notices are informational on a low-traffic staging project; do not delete indexes until real query workload is measured.
- Live table inspection: all 12 `sentinel` tables report RLS enabled.
- Grants: `anon` cannot use the `sentinel` schema; the authenticated role has only explicit table grants; the domain-challenge table is not granted to `authenticated`.
- All four Supabase Auth foreign key constraints are present.

## Local source workflow (Windows PowerShell)

Clone the repository and switch to the Phase 1 branch:

```powershell
git clone https://github.com/tasnimamin38/sentinel-cybersecurity-suite.git
Set-Location sentinel-cybersecurity-suite
git fetch origin
git switch phase-1-supabase-tenant-rls
```

The hosted migrations have already been applied through the connected Supabase project. Do not reapply `bootstrap.sql` or `001_sentinel_schema.sql` to this existing project; they are fresh-install bootstrap artifacts that predate the tenant registry.

Review/apply the tracked SQL migration files only against a disposable staging database, in timestamp order. Do not replay them against the already-migrated hosted database.

## Environment configuration

The repository's `.env.example` includes the two browser-safe Auth values for the planned Next.js client:

```dotenv
NEXT_PUBLIC_SUPABASE_URL=https://xyzxswnofcychlkgrdsn.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_uAHOjyAO5Hy4ISF9VlVT6w_-RTaEdld
```

The public values may be placed in Vercel project environment variables. Keep these only in server-side secret storage (Render environment, Supabase Vault, or an approved secret manager): `SENTINEL_DATABASE_URL`, `SENTINEL_DB_APP_PASSWORD`, `SENTINEL_API_KEY`, `REDIS_PASSWORD`, `SENTINEL_WORKER_TICK_SECRET`, and future OAuth client secrets. Actual secrets are not committed to Git.

## Phase boundary

Phase 1 provides the database foundation, Auth identity linkage, RLS policies, indexes, migration history, and live verification. It does not claim that the Next.js frontend, Supabase Auth signup/login UX, tenant-selection/session propagation, agent tool-calling API, Cloudflare worker, or Render background processing have been implemented.

The current repository frontend is still Vite/React and the current FastAPI API still authenticates operational API keys. These must be coordinated in Phase 2 before enabling customer signup or exposing tenant data through the browser.
