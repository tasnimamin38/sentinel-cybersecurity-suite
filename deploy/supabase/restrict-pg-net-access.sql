-- Keep the pg_net HTTP client private to database administrators.
-- Supabase Cron runs jobs as their owner (postgres); the SENTINEL scheduler
-- only needs postgres and Supabase's internal administration roles.
--
-- pg_net is installed in public by the managed Supabase extension and is
-- not relocatable. The net schema is not exposed to the Data API. These
-- grants add a second line of defense by denying application roles from
-- issuing arbitrary outbound database HTTP requests.

REVOKE USAGE ON SCHEMA net FROM PUBLIC, anon, authenticated, service_role;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA net
    FROM PUBLIC, anon, authenticated, service_role;

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
