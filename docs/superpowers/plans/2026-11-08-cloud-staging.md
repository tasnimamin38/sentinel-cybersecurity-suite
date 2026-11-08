# Cloud-Only Staging Implementation Plan

> **For agentic workers:** Execute this plan in the isolated branch `feat/cloud-scheduled-assessment-worker`. Use TDD for behavior changes. All execution and verification must occur in GitHub Actions or cloud services; never use the owner's laptop.

**Goal:** Deploy a low-volume cloud staging version of SENTINEL using Supabase Postgres/Vault/Cron and Render Free API, Redis-compatible Key Value, and static console.

**Architecture:** The frontend is a Render static site with a build-time API base URL. The FastAPI backend is a Render Free Docker web service. Its persistent data is in the dedicated Supabase Postgres private schema `sentinel`; the API uses a restricted database role via the Supabase IPv4 session pooler. Supabase Cron calls a secret-protected internal API tick once each minute; a tick processes at most one existing authorized assessment job.

**Tech Stack:** FastAPI, SQLAlchemy, Alembic, PostgreSQL 17, Supabase Vault, Cloudflare Workers Cron Trigger, Render Docker web service, Render static site, Render Key Value, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-08-sentinel-cloud-staging.md`

## Global Constraints
- Never create or commit a `.env` file or any plaintext secret to Git.
- Do not access the user's local computer or run local commands/builds.
- Only use the newly-created Supabase project `xyzxswnofcychlkgrdsn` and Render workspace `tea-d9tlmim5djic73a5ftr0`.
- Keep all cloud resources on $0 plans; stop if any nonzero quote appears.
- Do not use the existing `universal-agent-fabric` or other unrelated project.
- Do not configure a real scan target without owner authorization.
- The deployment is staging-only and is not represented as production-grade for thousands of users.
- Never expose Supabase service-role keys or database passwords in the browser bundle or public API.

## Review Focus
- Worker tick secret missing, wrong, replayed or rate-limiter unavailable must fail closed.
- Retry and cancellation semantics must remain unchanged when a job is processed by a one-shot tick.
- Supabase pooler hostname/username/schema search_path and TLS must be verified before starting the API.
- Render cold start and free instance sleep must not cause duplicate job execution; leases and idempotency must remain authoritative.
- Frontend API base URL and exact HTTPS CORS origin must match the hosted API and static-site origins.

---

### Task 1: Bounded internal worker tick

**Files:**
- Modify: `backend/app/config.py`
- Modify: `backend/app/worker.py`
- Modify: `backend/app/main.py`
- Test: `backend/tests/test_config.py`
- Test: `backend/tests/test_worker.py`
- Test: `backend/tests/test_api_smoke.py`

**Interfaces:**
- Add `worker_tick_enabled: bool = False`, `worker_tick_secret: str = ""`, and `worker_tick_rate_limit_per_minute: int = 1` to `Settings`.
- Add `async def process_one_job() -> str | None` to `app.worker`; it claims and processes at most one job, returning its job ID when one is claimed.
- Add hidden `POST /internal/worker/tick` route. It requires `X-Sentinel-Worker-Secret`, a configured secret of at least 32 random characters, and the shared Redis limiter when `environment == production`. Unauthorized, disabled, or unprotected requests fail closed. Return only `processed` and an optional opaque job ID.

- [ ] Write a config test proving production rejects enabled tick without a strong secret.
- [ ] Write a worker test proving a tick claims/processes at most one job and an empty queue performs no assessment.
- [ ] Write route tests proving disabled/wrong secret is rejected, correct secret is accepted, and the production path fails closed if shared rate limiting is missing.
- [ ] Run focused tests and record their expected RED output before implementation.
- [ ] Implement the minimal settings, one-job helper and hidden route.
- [ ] Run focused tests, then the complete backend suite.

### Task 2: Cloud frontend/API boundary

**Files:**
- Modify: `frontend/src/app.tsx`
- Modify: `frontend/vite-env.d.ts`
- Modify: `backend/app/config.py` only if proxy behavior requires a narrowly scoped setting.
- Test: `frontend/package.json` or an added frontend test file only if a test framework already exists.

**Interfaces:**
- Define API base URL from `import.meta.env.VITE_API_BASE_URL`, defaulting to empty string for same-origin local/Compose use.
- Normalize the value to avoid accidental double slashes and do not allow credentials in URL.
- Keep the browser bundle free of database credentials and privileged Supabase keys.

- [ ] Inspect current API URL use and verify Vite type definitions.
- [ ] Add a behavior test if the current frontend test runner supports it; otherwise verify with `npm run build` and a compiled bundle check.
- [ ] Build frontend with empty and hosted API base URL values.

### Task 3: Supabase schema and least-privilege data plane

**Files:**
- Create: `docs/cloud-deployment.md`
- Create: `deploy/supabase/README.md`
- Modify: `docs/architecture.md` and `docs/runbook.md`

**Interfaces:**
- The cloud project ID is `xyzxswnofcychlkgrdsn`.
- The private application schema is `sentinel`; the runtime login is `sentinel_app`.
- No table is exposed to `anon` or `authenticated` through the Data API.
- The existing four Alembic revisions remain authoritative and are applied to `sentinel`; runtime search_path is `sentinel,public`.
- Store generated DB password and worker tick secret in Vault. Never print either secret into the execution transcript.

- [ ] Review the model and Alembic schema contract.
- [ ] Create the private schema, owner, restricted runtime login, grants and default privileges.
- [ ] Apply the existing schema to the private schema with Alembic revision head `0004_api_credentials` recorded.
- [ ] Verify every table/index/foreign key against the existing models and migration history.
- [ ] Run Supabase security/performance advisors and verify public schema has no SENTINEL tables or public grants.
- [ ] Verify the runtime role cannot create tables or assume owner privileges, but can read/write application rows.

### Task 4: Cloud infrastructure as code

**Files:**
- Create: `render.yaml` (only if Render Blueprint planning validates the full free-only plan); otherwise use direct Render resources and document them.
- Modify: `README.md` with staging URLs only after successful deployment.

**Interfaces:**
- Render workspace ID: `tea-d9tlmim5djic73a5ftr0`.
- API: free Docker web service from `backend/Dockerfile`, Singapore region.
- Redis-compatible rate limiter: free Key Value, Singapore region, volatile/no-persistence policy explicitly documented.
- Console: free static site from `frontend/Dockerfile` is not used; build `cd frontend && npm ci && npm run build`, publish `frontend/dist`.
- All Render env vars are encrypted/sensitive wherever the provider permits.
- Exact backend URL is supplied to the frontend build env and exact frontend URL is supplied to backend CORS.

- [ ] Create the free Key Value and inspect its private connection URL without printing credentials.
- [ ] Create the API service with runtime DB URL, Redis URL, API bootstrap credential, worker tick secret, reserved `sentinel.invalid` scope, and exact HTTPS CORS origin.
- [ ] Create the static console and set `VITE_API_BASE_URL` to the hosted API origin.
- [ ] After API readiness, set Vercel Production `VITE_API_BASE_URL` to the verified API origin and redeploy `sentinel.toolixaai.com`; include the exact custom-domain origin in API CORS. Keep the Render static site as a separate staging smoke-test surface.
- [ ] Verify Render reports healthy deployments, but do not claim uptime guarantees.

### Task 5: External scheduled tick and end-to-end staging validation

**Files:**
- Create: deploy/cloudflare/worker-tick/worker.js
- Create: deploy/cloudflare/worker-tick/worker.test.mjs
- Create: deploy/cloudflare/worker-tick/wrangler.toml
- Create: deploy/supabase/migrations/20261108205814_remove_unused_pg_net_extension.sql

**Interfaces:**
- Cloudflare Worker Cron Trigger runs once per minute with scheduled().
- The Worker reads SENTINEL_API_URL as a non-secret HTTPS origin and SENTINEL_WORKER_TICK_SECRET as a secret binding.
- It POSTs an empty JSON object to /internal/worker/tick; redirects are rejected and only status/error names (never secrets or bodies) may be logged.
- The API's SENTINEL_WORKER_TICK_ENABLED remains false until API readiness, secret equality and scheduler deployment are verified.
- The Supabase project no longer installs pg_net; external scheduling avoids database-originated HTTP and its managed ACL grant path.

- [x] Verify the dedicated Supabase staging project had no pending pg_net requests/responses, no cron jobs, no webhooks, no pg_net-dependent triggers and no application routines referencing net.http_*.
- [x] Remove unused pg_net in recorded migration 20261108205814_remove_unused_pg_net_extension; verify net objects disappear while sentinel remains intact.
- [x] Add a Cloudflare Worker with HTTPS-only destination, fail-closed secret configuration, redirect rejection, bounded request timeout and sanitized logs.
- [x] Add Node built-in tests for authenticated request shape and missing-binding/HTTPS failure behavior.
- [ ] Run Cloudflare Worker tests in GitHub Actions on this PR head.
- [ ] Provision the Render API and static console from main, verify /healthz and /readyz, and confirm $0 plans.
- [ ] Set the same worker secret in Render and Cloudflare through encrypted secret bindings; never print or commit it.
- [ ] Only after API health and secret parity are confirmed, configure the one-minute Cloudflare Cron Trigger and enable the API tick.
- [ ] Verify scheduler HTTP status and one-job-per-tick behavior without real scan targets. Keep sentinel.invalid reserved.

### Task 6: Final review and release gate

- [ ] Re-run complete backend tests, frontend production build, Ruff, dependency audits, CodeQL, Supply Chain and Trivy/Compose CI.
- [ ] Perform a separate whole-branch review.
- [ ] Open PR to main; do not merge or enable automatic production deployment without review.
- [ ] Report exact cloud resource names, URLs, $0 plan evidence, remaining free-tier limits, and any incomplete steps.
