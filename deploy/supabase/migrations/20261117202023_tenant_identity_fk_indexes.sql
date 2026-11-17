-- Cover foreign keys that reference a Supabase Auth user as inviter/creator.
begin;
create index if not exists ix_tenant_memberships_invited_by_user_id
  on sentinel.tenant_memberships (invited_by_user_id);
create index if not exists ix_company_domain_challenges_created_by_user_id
  on sentinel.company_domain_challenges (created_by_user_id);
commit;
