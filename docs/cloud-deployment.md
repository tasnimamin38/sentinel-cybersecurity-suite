# SENTINEL cloud staging deployment

## Status

This document describes the cloud-only staging configuration. It is not a production launch checklist. At the time of writing, Supabase has been provisioned and the Render Blueprint plan is ready for owner review, but the API and console are not deployed. Keep PR #63 in Draft. Do not approve the Render sync until the pg_net ACL issue is resolved and the existing Redis internal-auth change is verified.

- GitHub branch: `feat/cloud-scheduled-assessment-worker`
- Supabase project: `sentinel-cybersecurity-suite` (`xyzxswnofcychlkgrdsn`)
- Render Key Value: `sentinel-cybersecurity-suite-redis` (`red-dbo9k7jm8hqs73fui9r0`)
- Render workspace: `tea-d9tlmim5djic73a5ftr0`
- Vercel project was linked separately but is not part of the selected staging path.

## Planned topology

```text
Browser
  |
  v
Render Static Site: sentinel-staging-console-mpir
  |
  | HTTPS + user-supplied SENTINEL_API_KEY
  v
Render Free Web Service: sentinel-staging-api-mpir
  |                 |
  |                 +--> Render Key Value (private URL, internal auth)
  |
  +--> Supabase IPv4 Session Pooler
          |
          +--> private schema: sentinel
          +--> restricted role: sentinel_app
          +--> Vault secrets
          +--> pg_cron + pg_net (DISABLED pending ACL resolution)
```

Expected default service origins after a successful Render sync:

- Console: `https://sentinel-staging-console-mpir.onrender.com`
- API: `https://sentinel-staging-api-mpir.onrender.com`

The Blueprint planning response reserved these service names and origins; they are not proof of live deployments. The plan has not yet been approved, so no API or console service exists from this plan.

## Resource and cost boundaries

The selected Render API service and static site use the Free plan. The pre-created Key Value remains Free (25 MB, 50 connections, no persistence). Supabase remains on the Free/Nano project. The Blueprint references the existing Key Value service rather than creating a second one.

No paid background worker, Render Postgres, persistent disk, or autoscaling service is included. The scheduled worker is intentionally disabled in the initial staging configuration; do not treat the one-job-per-minute Supabase Cron trigger as available until its security gate is cleared.

## Supabase Data API exposure

The app uses direct PostgreSQL connections and does not require Supabase REST/PostgREST. The current Data API settings expose only `public` and `extensions`; neither `sentinel` nor `net` is exposed. The dashboard showed `0 of 7 tables` and no exposed functions. The `Automatically expose new tables` setting was switched off and saved, so future tables are not granted to Data API roles automatically.

The managed `pg_net` ACL warning remains: direct ACL inspection still shows `anon`, `authenticated`, and `sentinel_app` have privileges because the extension grants are owned by `supabase_admin` and could not be revoked by the connected `postgres` role. Since `net` is not Data API-exposed, public REST clients cannot query those objects through PostgREST. This does not solve direct database-role access. Keep both the internal worker tick and cron job disabled until Supabase Support resolves or the owner explicitly accepts the residual risk after review. The Blueprint sets `SENTINEL_WORKER_TICK_ENABLED=false` as a fail-safe default.

## Required API environment

Render Blueprint values:

| Variable | Source / value |
|---|---|
| `SENTINEL_ENVIRONMENT` | `production` (strict configuration and fail-closed rate limiting) |
| `SENTINEL_PROCESS_ROLE` | `api` |
| `SENTINEL_ALLOWED_DOMAINS` | `sentinel.invalid` until an owner-authorized domain is supplied |
| `SENTINEL_CORS_ORIGINS` | Exact static-site HTTPS origin |
| `SENTINEL_TRUST_CLOUDFLARE_IP_HEADER` | `true` for the managed edge's client-IP header |
| `SENTINEL_REDIS_URL` | Render Key Value `connectionString` service reference |
| `SENTINEL_DATABASE_URL` | Vault secret `sentinel_database_url` |
| `SENTINEL_API_KEY` | Vault secret `sentinel_bootstrap_admin_key`; used by the console operator |
| `SENTINEL_WORKER_TICK_ENABLED` | `false` (mandatory until the pg_net ACL gate is cleared) |
| `SENTINEL_WORKER_TICK_SECRET` | Vault secret `sentinel_worker_tick_secret`; never expose it to the static site |

Do not place these secret values in Git, logs, screenshots, or the browser bundle. The static site must never receive the database URL, Redis URL, worker secret, or service-role API key.

## Deploy order

1. Wait for all PR #63 checks to pass on its exact current head.
2. The dedicated Supabase project is already provisioned. Do not rerun `bootstrap.sql`; verify the current schema/role/revision using `deploy/supabase/README.md`.
3. Confirm `sentinel_database_url`, `sentinel_bootstrap_admin_key`, and `sentinel_worker_tick_secret` exist in Vault. Their decrypted values must not be shown in logs or chat.
4. Review `pg_net` privileges using the ACL queries in `deploy/supabase/README.md`. The revocation migration is recorded but did not change the grantor-owned ACLs; `anon`, `authenticated`, and `sentinel_app` still show access. Do not enable the worker tick or cron until Supabase Support resolves this managed ACL limitation or an owner explicitly records acceptance of the residual risk after review.
5. Verify internal authentication on the existing Render Key Value. Do not deploy the API with an unauthenticated Redis URL.
6. Review the Render Blueprint plan. It should create only one free API web service and one free static site; it must reuse the existing Key Value.
7. Apply the reviewed Blueprint with the required Vault secrets set on the API service. Keep `SENTINEL_WORKER_TICK_ENABLED=false`. If any nonzero cost appears, stop.
8. Verify the API `/healthz` and `/readyz` endpoints and the static console.
9. Do not apply `deploy/supabase/worker-tick.sql` in the current state. Only after the pg_net ACL issue is resolved (or the residual risk is explicitly accepted by the owner), repeat the database ACL checks, review the API tick endpoint configuration, then separately approve enabling `SENTINEL_WORKER_TICK_ENABLED` and applying the cron SQL. Verify cron run status and HTTP result without exposing the request header.
10. Leave the allowed target list at `sentinel.invalid`; do not create a real assessment job without an explicitly authorized domain.

## Staging limitations

- Render Free services can sleep and have finite monthly runtime quotas.
- The Free Key Value has no persistence; Redis counters can reset.
- The Supabase Free project can pause after inactivity and has no production-grade HA/backup guarantee.
- When later enabled, Cron processes at most one queued job per minute; long-running jobs can overlap scheduler invocations, so the database single-flight lock is mandatory.
- This architecture is not sized or validated for thousands of concurrent users.
- No independent penetration test, incident response retainer, or security certification is claimed.
