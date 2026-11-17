-- SENTINEL tenant registry: authenticated-user RLS.
-- Keep the sentinel schema private from the Supabase Data API.
-- The trusted FastAPI runtime continues to use the separate sentinel_app role.

begin;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create or replace function private.has_active_tenant_membership(p_tenant_id text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select exists (
    select 1
    from sentinel.tenant_memberships as tm
    where tm.tenant_id = p_tenant_id
      and tm.user_id = (select auth.uid())::text
      and tm.status = 'active'
  );
$function$;

create or replace function private.has_tenant_role(
  p_tenant_id text,
  p_allowed_roles text[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select exists (
    select 1
    from sentinel.tenant_memberships as tm
    where tm.tenant_id = p_tenant_id
      and tm.user_id = (select auth.uid())::text
      and tm.status = 'active'
      and tm.role = any(p_allowed_roles)
  );
$function$;

revoke all on function private.has_active_tenant_membership(text) from public;
revoke all on function private.has_tenant_role(text, text[]) from public;
grant execute on function private.has_active_tenant_membership(text) to authenticated;
grant execute on function private.has_tenant_role(text, text[]) to authenticated;

create index if not exists ix_tenant_memberships_rls_lookup
  on sentinel.tenant_memberships (tenant_id, user_id, status, role);

revoke all on schema sentinel from public, anon, authenticated;
grant usage on schema sentinel to authenticated, service_role, sentinel_app;

alter table sentinel.tenants enable row level security;
drop policy if exists sentinel_app_tenant_registry_access on sentinel.tenants;
create policy sentinel_app_tenant_registry_access
  on sentinel.tenants for all to sentinel_app
  using (true) with check (true);
drop policy if exists tenant_members_can_read on sentinel.tenants;
create policy tenant_members_can_read
  on sentinel.tenants for select to authenticated
  using ((select private.has_active_tenant_membership(id)));
drop policy if exists tenant_admins_can_update on sentinel.tenants;
create policy tenant_admins_can_update
  on sentinel.tenants for update to authenticated
  using ((select private.has_tenant_role(id, array['owner', 'admin']::text[])))
  with check ((select private.has_tenant_role(id, array['owner', 'admin']::text[])));

alter table sentinel.human_profiles enable row level security;
drop policy if exists sentinel_app_tenant_registry_access on sentinel.human_profiles;
create policy sentinel_app_tenant_registry_access
  on sentinel.human_profiles for all to sentinel_app
  using (true) with check (true);
drop policy if exists users_can_read_own_human_profile on sentinel.human_profiles;
create policy users_can_read_own_human_profile
  on sentinel.human_profiles for select to authenticated
  using (user_id = (select auth.uid())::text);
drop policy if exists users_can_create_own_human_profile on sentinel.human_profiles;
create policy users_can_create_own_human_profile
  on sentinel.human_profiles for insert to authenticated
  with check (user_id = (select auth.uid())::text);
drop policy if exists users_can_update_own_human_profile on sentinel.human_profiles;
create policy users_can_update_own_human_profile
  on sentinel.human_profiles for update to authenticated
  using (user_id = (select auth.uid())::text)
  with check (user_id = (select auth.uid())::text);

alter table sentinel.tenant_memberships enable row level security;
drop policy if exists sentinel_app_tenant_registry_access on sentinel.tenant_memberships;
create policy sentinel_app_tenant_registry_access
  on sentinel.tenant_memberships for all to sentinel_app
  using (true) with check (true);
drop policy if exists users_can_read_tenant_memberships on sentinel.tenant_memberships;
create policy users_can_read_tenant_memberships
  on sentinel.tenant_memberships for select to authenticated
  using (
    user_id = (select auth.uid())::text
    or (select private.has_tenant_role(tenant_id, array['owner', 'admin']::text[]))
  );

alter table sentinel.company_profiles enable row level security;
drop policy if exists sentinel_app_tenant_registry_access on sentinel.company_profiles;
create policy sentinel_app_tenant_registry_access
  on sentinel.company_profiles for all to sentinel_app
  using (true) with check (true);
drop policy if exists tenant_members_can_read_company_profile on sentinel.company_profiles;
create policy tenant_members_can_read_company_profile
  on sentinel.company_profiles for select to authenticated
  using ((select private.has_active_tenant_membership(tenant_id)));
drop policy if exists tenant_admins_can_insert_company_profile on sentinel.company_profiles;
create policy tenant_admins_can_insert_company_profile
  on sentinel.company_profiles for insert to authenticated
  with check ((select private.has_tenant_role(tenant_id, array['owner', 'admin']::text[])));
drop policy if exists tenant_admins_can_update_company_profile on sentinel.company_profiles;
create policy tenant_admins_can_update_company_profile
  on sentinel.company_profiles for update to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner', 'admin']::text[])))
  with check ((select private.has_tenant_role(tenant_id, array['owner', 'admin']::text[])));

alter table sentinel.company_domain_challenges enable row level security;
drop policy if exists sentinel_app_tenant_registry_access on sentinel.company_domain_challenges;
create policy sentinel_app_tenant_registry_access
  on sentinel.company_domain_challenges for all to sentinel_app
  using (true) with check (true);

revoke all on table
  sentinel.tenants,
  sentinel.human_profiles,
  sentinel.tenant_memberships,
  sentinel.company_profiles,
  sentinel.company_domain_challenges
from public, anon, authenticated;

grant select, update on table sentinel.tenants to authenticated;
grant select, insert, update on table sentinel.human_profiles to authenticated;
grant select on table sentinel.tenant_memberships to authenticated;
grant select, insert, update on table sentinel.company_profiles to authenticated;

grant select, insert, update, delete on table
  sentinel.tenants,
  sentinel.human_profiles,
  sentinel.tenant_memberships,
  sentinel.company_profiles,
  sentinel.company_domain_challenges
to service_role;

commit;
