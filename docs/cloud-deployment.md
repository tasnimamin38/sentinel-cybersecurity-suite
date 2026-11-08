# SENTINEL cloud staging deployment

## Status

This document describes the cloud-only staging configuration. It is not a production launch checklist. At the time of writing, the staging API and console have not been deployed. Keep PR #63 in Draft until the database bootstrap, Render plan, and end-to-end verification are complete.

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
Render Static Site: sentinel-staging-console
  |
  | HTTPS + user-supplied SENTINEL_API_KEY
  v
Render Free Web Service: sentinel-staging-api
  |                 |
  |                 +--> Render Key Value (private URL, internal auth)
  |
  +--> Supabase IPv4 Session Pooler
          |
          +--> private schema: sentinel
          +--> restricted role: sentinel_app
          +--> Vault secrets
          +--> pg_cron + pg_net (one tick/minute)
```

Expected default service origins after a successful Render sync:

- Console: `https://sentinel-staging-console-mpir.onrender.com`
- API: `https://sentinel-staging-api-mpir.onrender.com`

These origins are reserved in the Blueprint configuration; they are not proof of live deployments.

## Resource and cost boundaries

The selected Render API service and static site use the Free plan. The pre-created Key Value remains Free (25 MB, 50 connections, no persistence). Supabase remains on the Free/Nano project. The Blueprint references the existing Key Value service rather than creating a second one.

No paid background worker, Render Postgres, persistent disk, or autoscaling service is included. The one-job-per-minute Supabase Cron trigger is a staging workaround, not a scalable job-processing system.

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
| `SENTINEL_WORKER_TICK_ENABLED` | `true` |
| `SENTINEL_WORKER_TICK_SECRET` | Vault secret `sentinel_worker_tick_secret` |

Do not place these secret values in Git, logs, screenshots, or the browser bundle. The static site must never receive the database URL, Redis URL, worker secret, or service-role API key.

## Deploy order

1. Wait for all PR #63 checks to pass on its exact current head.
2. The dedicated Supabase project is already provisioned. Do not rerun `bootstrap.sql`; verify the current schema/role/revision using `deploy/supabase/README.md`.
3. Confirm `sentinel_database_url`, `sentinel_bootstrap_admin_key`, and `sentinel_worker_tick_secret` exist in Vault. Their decrypted values must not be shown in logs or chat.
4. Restrict `pg_net` HTTP functions to database-admin/scheduler roles with `deploy/supabase/restrict-pg-net-access.sql`. The live project has applied this hardening; the extension itself remains in `public` because it is not relocatable.
5. Enable internal authentication on the existing Render Key Value. Do not deploy the API with an unauthenticated Redis URL.
6. Review the Render Blueprint plan. It should create only one free API web service and one free static site; it must reuse the existing Key Value.
7. Apply the reviewed Blueprint with the required Vault secrets set on the API service. If any nonzero cost appears, stop.
8. Verify the API `/healthz` and `/readyz` endpoints and the static console.
9. Apply `deploy/supabase/worker-tick.sql` only after the API is healthy. Check cron run status and HTTP result without exposing the request header.
10. Leave the allowed target list at `sentinel.invalid`; do not create a real assessment job without an explicitly authorized domain.

## Staging limitations

- Render Free services can sleep and have finite monthly runtime quotas.
- The Free Key Value has no persistence; Redis counters can reset.
- The Supabase Free project can pause after inactivity and has no production-grade HA/backup guarantee.
- Cron processes at most one queued job per minute; long-running jobs can overlap scheduler invocations, so the database single-flight lock is mandatory.
- This architecture is not sized or validated for thousands of concurrent users.
- No independent penetration test, incident response retainer, or security certification is claimed.
