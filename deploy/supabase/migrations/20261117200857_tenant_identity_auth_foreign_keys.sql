-- Convert identity columns to Supabase Auth UUIDs and enforce referential integrity.
-- Drop policies before altering columns because PostgreSQL tracks policy dependencies.

begin;

drop policy if exists users_can_read_own_human_profile on sentinel.human_profiles;
drop policy if exists users_can_create_own_human_profile on sentinel.human_profiles;
drop policy if exists users_can_update_own_human_profile on sentinel.human_profiles;
drop policy if exists users_can_read_tenant_memberships on sentinel.tenant_memberships;

alter table sentinel.human_profiles
  alter column user_id type uuid using user_id::uuid;

alter table sentinel.tenant_memberships
  alter column user_id type uuid using user_id::uuid,
  alter column invited_by_user_id type uuid using invited_by_user_id::uuid;

alter table sentinel.company_domain_challenges
  alter column created_by_user_id type uuid using created_by_user_id::uuid;

do $constraints$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'fk_human_profiles_auth_user'
      and conrelid = 'sentinel.human_profiles'::regclass
  ) then
    alter table sentinel.human_profiles
      add constraint fk_human_profiles_auth_user
      foreign key (user_id) references auth.users(id) on delete cascade;
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'fk_tenant_memberships_auth_user'
      and conrelid = 'sentinel.tenant_memberships'::regclass
  ) then
    alter table sentinel.tenant_memberships
      add constraint fk_tenant_memberships_auth_user
      foreign key (user_id) references auth.users(id) on delete restrict;
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'fk_tenant_memberships_invited_by_auth_user'
      and conrelid = 'sentinel.tenant_memberships'::regclass
  ) then
    alter table sentinel.tenant_memberships
      add constraint fk_tenant_memberships_invited_by_auth_user
      foreign key (invited_by_user_id) references auth.users(id) on delete set null;
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'fk_company_domain_challenges_created_by_auth_user'
      and conrelid = 'sentinel.company_domain_challenges'::regclass
  ) then
    alter table sentinel.company_domain_challenges
      add constraint fk_company_domain_challenges_created_by_auth_user
      foreign key (created_by_user_id) references auth.users(id) on delete restrict;
  end if;
end
$constraints$;

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
      and tm.user_id = (select auth.uid())
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
      and tm.user_id = (select auth.uid())
      and tm.status = 'active'
      and tm.role = any(p_allowed_roles)
  );
$function$;

create policy users_can_read_own_human_profile
  on sentinel.human_profiles for select to authenticated
  using (user_id = (select auth.uid()));
create policy users_can_create_own_human_profile
  on sentinel.human_profiles for insert to authenticated
  with check (user_id = (select auth.uid()));
create policy users_can_update_own_human_profile
  on sentinel.human_profiles for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy users_can_read_tenant_memberships
  on sentinel.tenant_memberships for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select private.has_tenant_role(tenant_id, array['owner', 'admin']::text[]))
  );

commit;
