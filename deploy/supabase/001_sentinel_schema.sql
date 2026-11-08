-- SENTINEL managed Supabase staging schema bootstrap.
-- Run only against the dedicated, empty SENTINEL project.
-- Runtime role and encrypted credentials are provisioned separately with Supabase Vault.
-- Alembic's current revision is stamped after creating the schema represented by 0004_api_credentials.

create schema if not exists sentinel authorization postgres;
revoke all on schema sentinel from public;
grant usage on schema sentinel to sentinel_app;

create table if not exists sentinel.assets (
  id varchar(36) primary key,
  hostname varchar(253) not null,
  name varchar(140) not null,
  owner varchar(120) not null,
  environment varchar(24) not null,
  criticality double precision not null,
  authorization_expires_at timestamptz not null,
  authorization_reference varchar(120) not null,
  status varchar(24) not null,
  tags json not null,
  created_at timestamptz not null,
  updated_at timestamptz not null
);
create unique index if not exists ix_assets_hostname on sentinel.assets(hostname);
create index if not exists ix_assets_status on sentinel.assets(status);

create table if not exists sentinel.assessments (
  id varchar(36) primary key,
  asset_id varchar(36) references sentinel.assets(id) on delete set null,
  target varchar(253) not null,
  status varchar(24) not null,
  score integer not null,
  risk_level varchar(24) not null,
  findings json not null,
  evidence json not null,
  created_at timestamptz not null
);
create index if not exists ix_assessments_asset_id on sentinel.assessments(asset_id);
create index if not exists ix_assessments_target on sentinel.assessments(target);

create table if not exists sentinel.remediation_tasks (
  id varchar(36) primary key,
  assessment_id varchar(36) not null references sentinel.assessments(id) on delete cascade,
  asset_id varchar(36) references sentinel.assets(id) on delete set null,
  finding_code varchar(100) not null,
  title varchar(200) not null,
  severity varchar(20) not null,
  assignee varchar(120) not null,
  status varchar(24) not null,
  due_at timestamptz,
  notes text not null,
  created_at timestamptz not null,
  updated_at timestamptz not null
);
create index if not exists ix_remediation_tasks_assessment_id on sentinel.remediation_tasks(assessment_id);
create index if not exists ix_remediation_tasks_asset_id on sentinel.remediation_tasks(asset_id);
create index if not exists ix_remediation_tasks_finding_code on sentinel.remediation_tasks(finding_code);
create index if not exists ix_remediation_tasks_status on sentinel.remediation_tasks(status);

create table if not exists sentinel.audit_events (
  id varchar(36) primary key,
  event_type varchar(80) not null,
  subject varchar(253) not null,
  result varchar(24) not null,
  details text not null,
  sequence_no integer,
  previous_hash varchar(64),
  event_hash varchar(64),
  created_at timestamptz not null
);
create index if not exists ix_audit_events_event_type on sentinel.audit_events(event_type);
create unique index if not exists ix_audit_events_sequence_no on sentinel.audit_events(sequence_no);
create index if not exists ix_audit_events_event_hash on sentinel.audit_events(event_hash);

create table if not exists sentinel.assessment_jobs (
  id varchar(36) primary key,
  asset_id varchar(36) references sentinel.assets(id) on delete set null,
  target varchar(253) not null,
  status varchar(24) not null,
  available_at timestamptz not null,
  attempts integer not null,
  max_attempts integer not null,
  manual_retries integer not null,
  worker_id varchar(64),
  lease_expires_at timestamptz,
  heartbeat_at timestamptz,
  cancel_requested_at timestamptz,
  started_at timestamptz,
  completed_at timestamptz,
  assessment_id varchar(36) references sentinel.assessments(id) on delete set null,
  idempotency_key_hash varchar(64),
  last_error text,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  constraint uq_assessment_jobs_idempotency_key_hash unique(idempotency_key_hash)
);
create index if not exists ix_assessment_jobs_asset_id on sentinel.assessment_jobs(asset_id);
create index if not exists ix_assessment_jobs_status on sentinel.assessment_jobs(status);
create index if not exists ix_assessment_jobs_status_available on sentinel.assessment_jobs(status, available_at);
create index if not exists ix_assessment_jobs_available_at on sentinel.assessment_jobs(available_at);
create index if not exists ix_assessment_jobs_worker_id on sentinel.assessment_jobs(worker_id);
create index if not exists ix_assessment_jobs_assessment_id on sentinel.assessment_jobs(assessment_id);
create index if not exists ix_assessment_jobs_lease_expires_at on sentinel.assessment_jobs(lease_expires_at);

create table if not exists sentinel.api_credentials (
  id varchar(36) primary key,
  label varchar(80) not null,
  role varchar(24) not null,
  key_hash varchar(64) not null,
  key_prefix varchar(16) not null,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_by varchar(64) not null,
  created_at timestamptz not null,
  last_used_at timestamptz,
  constraint uq_api_credentials_key_hash unique(key_hash)
);
create index if not exists ix_api_credentials_role on sentinel.api_credentials(role);

create table if not exists sentinel.alembic_version (
  version_num varchar(32) primary key
);
delete from sentinel.alembic_version;
insert into sentinel.alembic_version(version_num) values ('0004_api_credentials');

grant select, insert, update, delete on all tables in schema sentinel to sentinel_app;
grant usage, select, update on all sequences in schema sentinel to sentinel_app;
