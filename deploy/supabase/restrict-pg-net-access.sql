-- Best-effort pg_net permission restriction. Verify ACLs after applying.
-- Supabase Cron runs jobs as their owner (postgres); the SENTINEL scheduler
-- only needs postgres and Supabase's internal administration roles.
--
-- pg_net is installed in public by the managed Supabase extension and is
-- not relocatable. The net schema is not exposed to the Data API. These
-- the connected database role may not be able to revoke grants owned by
-- supabase_admin. Do not assume this script worked without ACL verification.
-- If has_schema_privilege/has_table_privilege still return true for app roles,
-- contact Supabase Support; the extension's managed ACL owner must revoke them.

REVOKE USAGE ON SCHEMA net FROM PUBLIC, anon, authenticated, service_role, sentinel_app;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA net
    FROM PUBLIC, anon, authenticated, service_role, sentinel_app;
REVOKE ALL ON ALL TABLES IN SCHEMA net
    FROM PUBLIC, anon, authenticated, service_role, sentinel_app;

GRANT USAGE ON SCHEMA net
    TO postgres, supabase_admin, supabase_functions_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA net
    TO postgres, supabase_admin, supabase_functions_admin;

-- Verify after applying:
-- SELECT has_schema_privilege('anon', 'net', 'USAGE') AS anon_net_usage,
--        has_schema_privilege('authenticated', 'net', 'USAGE') AS auth_net_usage,
--        has_schema_privilege('postgres', 'net', 'USAGE') AS postgres_net_usage;
-- SELECT has_function_privilege('anon', 'net.http_post(text,jsonb,jsonb,jsonb,integer)', 'EXECUTE') AS anon_http_post,
--        has_function_privilege('authenticated', 'net.http_post(text,jsonb,jsonb,jsonb,integer)', 'EXECUTE') AS auth_http_post,
--        has_function_privilege('postgres', 'net.http_post(text,jsonb,jsonb,jsonb,integer)', 'EXECUTE') AS postgres_http_post;
