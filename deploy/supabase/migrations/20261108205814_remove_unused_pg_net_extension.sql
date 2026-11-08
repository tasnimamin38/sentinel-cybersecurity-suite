-- SENTINEL staging migration applied on 2026-11-08.
-- Before applying, operators verified that the dedicated staging project had:
--   * no pending pg_net requests or stored HTTP responses;
--   * no Cron jobs or database functions invoking net.http_*;
--   * no Supabase Database Webhooks or pg_net-dependent triggers.
-- Supabase-managed pg_net grants are owned by supabase_admin and cannot be
-- revoked by the ordinary postgres role. SENTINEL no longer needs pg_net:
-- scheduling is handled by an external Cloudflare Worker Cron Trigger.
DROP EXTENSION IF EXISTS pg_net;
