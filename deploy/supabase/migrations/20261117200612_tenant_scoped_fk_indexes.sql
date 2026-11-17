-- Cover tenant-scoped composite foreign keys used by operational records.
begin;
create index if not exists ix_assessment_jobs_tenant_assessment
  on sentinel.assessment_jobs (tenant_id, assessment_id);
create index if not exists ix_assessment_jobs_tenant_asset
  on sentinel.assessment_jobs (tenant_id, asset_id);
create index if not exists ix_assessments_tenant_asset
  on sentinel.assessments (tenant_id, asset_id);
create index if not exists ix_remediation_tasks_tenant_assessment
  on sentinel.remediation_tasks (tenant_id, assessment_id);
create index if not exists ix_remediation_tasks_tenant_asset
  on sentinel.remediation_tasks (tenant_id, asset_id);
commit;
