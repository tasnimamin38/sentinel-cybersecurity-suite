# SENTINEL Cloud-Only Staging Design

## Intent
Deploy the existing SENTINEL console and API to hosted infrastructure without using the owner's laptop, local filesystem, or local containers. Use the dedicated Supabase project `sentinel-cybersecurity-suite` and Render workspace `My Workspace` only; do not modify any pre-existing cloud projects.

## Goals
- Host the static React console and FastAPI API in cloud services.
- Store persistent application data in the dedicated Supabase Postgres database under a private, non-Data-API schema.
- Keep the API database login separate from the schema owner and grant only required DML.
- Provide a bounded, authenticated cloud worker trigger invoked by an external Cloudflare Worker Cron Trigger for low-volume staging.
- Store database and worker secrets in Supabase Vault and Render encrypted environment variables, never in Git.
- Keep all service plans at $0 and stop if a provider quotes any charge.

## Non-goals / Anti-goals
- This free-tier deployment is not production-grade, not guaranteed high-availability, and not sized for thousands of concurrent users.
- Do not create a continuous worker on a Render Free web service; Render Free does not offer free background workers.
- Do not put a raw `.env`, database URL, API secret, or service-role key in the public or private Git repository.
- Do not use the owner's laptop or browser for file creation, local builds, Docker, or hosting.
- Do not reuse or mutate the existing `universal-agent-fabric`, `imageforge-ai`, or other unrelated cloud projects.

## Approaches
1. Render free API + static site, Supabase Postgres, and a Supabase Cron-triggered one-job tick. Lowest-cost staging option; limited to one hosted API instance, idle spin-down, transient Redis and one job per tick.
2. Vercel frontend plus Render API. It adds a provider boundary and Vercel Hobby is not a suitable assumption for commercial use; not selected.
3. Fully provisioned Render API + dedicated background worker + persistent Redis/Postgres. Operationally closer to production but not free; excluded until a paid budget is explicitly approved.

## Selected design
Cloud-only staging design. Supabase is the persistent data plane. Application tables live in a private `sentinel` schema, not exposed through the Supabase Data API. A restricted `sentinel_app` PostgreSQL login gets USAGE plus table/sequence DML only and no superuser, role creation, schema creation, or RLS bypass. FastAPI uses Supabase's IPv4 Shared Pooler session endpoint with TLS. Render Free hosts the API and static console; Render Free Key Value is a temporary Redis-compatible rate-limit store only. The shared worker tick secret is kept in Supabase Vault as an operator-controlled source copy and set separately as encrypted secrets in Render and Cloudflare. A Cloudflare Worker Cron Trigger sends one authenticated HTTPS request per minute to the API; each accepted tick processes at most one queued job. The managed pg_net extension was removed from the dedicated Supabase staging project because SENTINEL has no database-originated HTTP dependency.

## Safety / operational constraints
- The worker route is disabled by default and requires a 256-bit random shared secret using constant-time comparison. The external Worker rejects non-HTTPS API origins and redirects, keeps the secret out of logs, and has no public fetch endpoint.
- Worker ticks must be rate-limited through the shared Redis limiter and fail closed when it is unavailable in production.
- The worker must reuse the existing asset authorization, expiry, DNS pinning and HTTPS probe checks; no new target-discovery capability is added.
- Do not set real authorized target domains without an explicit owner-provided domain. Staging starts with a reserved `.invalid` scope and therefore cannot assess a real target.
- A one-minute tick means at most one job processed per accepted API tick; it is deliberately a low-volume staging proof, not a scale solution. Cloudflare Cron Trigger and Workers Free plan limits must be rechecked before rollout.
- Supabase Free project inactivity pause, Render Free cold starts/750-hour limit, no persistent free Redis, and one-instance limits are accepted only for staging. Monitor quotas and avoid storing sensitive production data.
- Any paid upgrade or nonzero service quotation requires separate explicit approval.
