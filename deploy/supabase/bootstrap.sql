-- SENTINEL cloud staging bootstrap.
-- This SQL is applied once to the dedicated Supabase project.
-- Secrets are generated server-side and stored only in Supabase Vault.
-- Never SELECT vault.decrypted_secrets into a shared log or commit plaintext values.
-- Scheduled worker authentication is shared with the external Cloudflare Cron Trigger.

CREATE SCHEMA IF NOT EXISTS sentinel AUTHORIZATION postgres;
REVOKE ALL ON SCHEMA sentinel FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

DO $bootstrap$
DECLARE
    app_password text;
    database_url text;
    worker_secret text;
    admin_api_key text;
    granted_role name;
    app_table name;
BEGIN
    SELECT decrypted_secret
      INTO app_password
      FROM vault.decrypted_secrets
     WHERE name = 'sentinel_db_app_password';

    IF app_password IS NULL THEN
        app_password := encode(extensions.gen_random_bytes(32), 'hex');
        PERFORM vault.create_secret(
            app_password,
            'sentinel_db_app_password',
            'SENTINEL restricted PostgreSQL runtime login password'
        );
    END IF;

    SELECT decrypted_secret
      INTO worker_secret
      FROM vault.decrypted_secrets
     WHERE name = 'sentinel_worker_tick_secret';

    IF worker_secret IS NULL THEN
        worker_secret := encode(extensions.gen_random_bytes(32), 'hex');
        PERFORM vault.create_secret(
            worker_secret,
            'sentinel_worker_tick_secret',
            'SENTINEL external worker scheduler shared secret'
        );
    END IF;

    SELECT decrypted_secret
      INTO admin_api_key
      FROM vault.decrypted_secrets
     WHERE name = 'sentinel_bootstrap_admin_key';

    IF admin_api_key IS NULL THEN
        admin_api_key := encode(extensions.gen_random_bytes(32), 'hex');
        PERFORM vault.create_secret(
            admin_api_key,
            'sentinel_bootstrap_admin_key',
            'SENTINEL bootstrap administrator API key'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
        EXECUTE format(
            'CREATE ROLE sentinel_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT 40',
            app_password
        );
    ELSE
        EXECUTE format(
            'ALTER ROLE sentinel_app WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT 40',
            app_password
        );
    END IF;

    -- A NOINHERIT role can still explicitly SET ROLE into an inherited parent.
    -- Remove every membership so sentinel_app remains a standalone login.
    FOR granted_role IN
        SELECT parent.rolname
          FROM pg_auth_members membership
          JOIN pg_roles parent ON parent.oid = membership.roleid
         WHERE membership.member = 'sentinel_app'::regrole
    LOOP
        EXECUTE format('REVOKE %I FROM sentinel_app', granted_role);
    END LOOP;

    database_url :=
        'postgresql+psycopg://sentinel_app.xyzxswnofcychlkgrdsn:' ||
        app_password ||
        '@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require';

    IF NOT EXISTS (
        SELECT 1
          FROM vault.decrypted_secrets
         WHERE name = 'sentinel_database_url'
    ) THEN
        PERFORM vault.create_secret(
            database_url,
            'sentinel_database_url',
            'SENTINEL SQLAlchemy PostgreSQL session-pooler URL'
        );
    ELSE
        PERFORM vault.update_secret(
            (SELECT id FROM vault.decrypted_secrets WHERE name = 'sentinel_database_url'),
            database_url,
            'sentinel_database_url',
            'SENTINEL SQLAlchemy PostgreSQL session-pooler URL'
        );
    END IF;
END
$bootstrap$;

ALTER ROLE sentinel_app SET search_path = sentinel, public;

CREATE TABLE IF NOT EXISTS sentinel.assets (
    id varchar(36) NOT NULL,
    hostname varchar(253) NOT NULL,
    name varchar(140) NOT NULL,
    owner varchar(120) NOT NULL,
    environment varchar(24) NOT NULL,
    criticality double precision NOT NULL,
    authorization_expires_at timestamptz NOT NULL,
    authorization_reference varchar(120) NOT NULL,
    status varchar(24) NOT NULL,
    tags json NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_assets PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_assets_hostname
    ON sentinel.assets (hostname);
CREATE INDEX IF NOT EXISTS ix_assets_status
    ON sentinel.assets (status);

CREATE TABLE IF NOT EXISTS sentinel.assessments (
    id varchar(36) NOT NULL,
    asset_id varchar(36),
    target varchar(253) NOT NULL,
    status varchar(24) NOT NULL,
    score integer NOT NULL,
    risk_level varchar(24) NOT NULL,
    findings json NOT NULL,
    evidence json NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_assessments PRIMARY KEY (id),
    CONSTRAINT fk_assessments_asset_id_assets
        FOREIGN KEY (asset_id) REFERENCES sentinel.assets (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_assessments_asset_id
    ON sentinel.assessments (asset_id);
CREATE INDEX IF NOT EXISTS ix_assessments_target
    ON sentinel.assessments (target);

CREATE TABLE IF NOT EXISTS sentinel.remediation_tasks (
    id varchar(36) NOT NULL,
    assessment_id varchar(36) NOT NULL,
    asset_id varchar(36),
    finding_code varchar(100) NOT NULL,
    title varchar(200) NOT NULL,
    severity varchar(20) NOT NULL,
    assignee varchar(120) NOT NULL,
    status varchar(24) NOT NULL,
    due_at timestamptz,
    notes text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_remediation_tasks PRIMARY KEY (id),
    CONSTRAINT fk_remediation_tasks_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES sentinel.assessments (id) ON DELETE CASCADE,
    CONSTRAINT fk_remediation_tasks_asset_id_assets
        FOREIGN KEY (asset_id) REFERENCES sentinel.assets (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_remediation_tasks_assessment_id
    ON sentinel.remediation_tasks (assessment_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_asset_id
    ON sentinel.remediation_tasks (asset_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_finding_code
    ON sentinel.remediation_tasks (finding_code);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_status
    ON sentinel.remediation_tasks (status);

CREATE TABLE IF NOT EXISTS sentinel.audit_events (
    id varchar(36) NOT NULL,
    event_type varchar(80) NOT NULL,
    subject varchar(253) NOT NULL,
    result varchar(24) NOT NULL,
    details text NOT NULL,
    sequence_no integer,
    previous_hash varchar(64),
    event_hash varchar(64),
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_audit_events PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS ix_audit_events_event_type
    ON sentinel.audit_events (event_type);
CREATE INDEX IF NOT EXISTS ix_audit_events_event_hash
    ON sentinel.audit_events (event_hash);
CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_events_sequence_no
    ON sentinel.audit_events (sequence_no);

CREATE TABLE IF NOT EXISTS sentinel.assessment_jobs (
    id varchar(36) NOT NULL,
    asset_id varchar(36),
    target varchar(253) NOT NULL,
    status varchar(24) NOT NULL,
    available_at timestamptz NOT NULL,
    attempts integer NOT NULL,
    max_attempts integer NOT NULL,
    manual_retries integer NOT NULL,
    worker_id varchar(64),
    lease_expires_at timestamptz,
    heartbeat_at timestamptz,
    cancel_requested_at timestamptz,
    started_at timestamptz,
    completed_at timestamptz,
    assessment_id varchar(36),
    idempotency_key_hash varchar(64),
    last_error text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT pk_assessment_jobs PRIMARY KEY (id),
    CONSTRAINT uq_assessment_jobs_idempotency_key_hash UNIQUE (idempotency_key_hash),
    CONSTRAINT fk_assessment_jobs_asset_id_assets
        FOREIGN KEY (asset_id) REFERENCES sentinel.assets (id) ON DELETE SET NULL,
    CONSTRAINT fk_assessment_jobs_assessment_id_assessments
        FOREIGN KEY (assessment_id) REFERENCES sentinel.assessments (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_assessment_jobs_asset_id
    ON sentinel.assessment_jobs (asset_id);
CREATE INDEX IF NOT EXISTS ix_assessment_jobs_status
    ON sentinel.assessment_jobs (status);
CREATE INDEX IF NOT EXISTS ix_assessment_jobs_status_available
    ON sentinel.assessment_jobs (status, available_at);
CREATE INDEX IF NOT EXISTS ix_assessment_jobs_available_at
    ON sentinel.assessment_jobs (available_at);
CREATE INDEX IF NOT EXISTS ix_assessment_jobs_worker_id
    ON sentinel.assessment_jobs (worker_id);
CREATE INDEX IF NOT EXISTS ix_assessment_jobs_assessment_id
    ON sentinel.assessment_jobs (assessment_id);
CREATE INDEX IF NOT EXISTS ix_assessment_jobs_lease_expires_at
    ON sentinel.assessment_jobs (lease_expires_at);

CREATE TABLE IF NOT EXISTS sentinel.api_credentials (
    id varchar(36) NOT NULL,
    label varchar(80) NOT NULL,
    role varchar(24) NOT NULL,
    key_hash varchar(64) NOT NULL,
    key_prefix varchar(16) NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_by varchar(64) NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    CONSTRAINT pk_api_credentials PRIMARY KEY (id),
    CONSTRAINT uq_api_credentials_key_hash UNIQUE (key_hash)
);

CREATE INDEX IF NOT EXISTS ix_api_credentials_role
    ON sentinel.api_credentials (role);

CREATE TABLE IF NOT EXISTS sentinel.alembic_version (
    version_num varchar(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

DO $revision$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sentinel.alembic_version
         WHERE version_num <> '0004_api_credentials'
    ) THEN
        RAISE EXCEPTION 'SENTINEL schema has an unexpected Alembic revision';
    END IF;

    INSERT INTO sentinel.alembic_version (version_num)
    VALUES ('0004_api_credentials')
    ON CONFLICT (version_num) DO NOTHING;
END
$revision$;

REVOKE ALL ON ALL TABLES IN SCHEMA sentinel FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA sentinel TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sentinel TO sentinel_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA sentinel TO sentinel_app;
REVOKE CREATE ON SCHEMA sentinel FROM sentinel_app;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA sentinel
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA sentinel
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA sentinel
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO sentinel_app;

GRANT CONNECT ON DATABASE postgres TO sentinel_app;

-- RLS stays enabled on the private tables. Only the isolated runtime login
-- receives an application policy; anon/authenticated receive none.
DO $rls$
DECLARE
    app_table text;
    app_tables text[] := ARRAY[
        'assets',
        'assessments',
        'remediation_tasks',
        'audit_events',
        'assessment_jobs',
        'api_credentials'
    ];
BEGIN
    FOREACH app_table IN ARRAY app_tables LOOP
        EXECUTE format('ALTER TABLE sentinel.%I ENABLE ROW LEVEL SECURITY', app_table);
        IF NOT EXISTS (
            SELECT 1
              FROM pg_policies
             WHERE schemaname = 'sentinel'
               AND tablename = app_table
               AND policyname = 'sentinel_app_access'
        ) THEN
            EXECUTE format(
                'CREATE POLICY sentinel_app_access ON sentinel.%I TO sentinel_app USING (true) WITH CHECK (true)',
                app_table
            );
        END IF;
    END LOOP;

    ALTER TABLE sentinel.alembic_version ENABLE ROW LEVEL SECURITY;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_policies
         WHERE schemaname = 'sentinel'
           AND tablename = 'alembic_version'
           AND policyname = 'sentinel_app_read_revision'
    ) THEN
        CREATE POLICY sentinel_app_read_revision
            ON sentinel.alembic_version
            FOR SELECT TO sentinel_app USING (true);
    END IF;
END
$rls$;

REVOKE ALL ON SCHEMA sentinel FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA sentinel FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA sentinel TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sentinel TO sentinel_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA sentinel TO sentinel_app;
REVOKE CREATE ON SCHEMA sentinel FROM sentinel_app;

DO $assertions$
DECLARE
    role_state record;
BEGIN
    SELECT rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolbypassrls
      INTO role_state
      FROM pg_roles
     WHERE rolname = 'sentinel_app';

    IF role_state.rolsuper
       OR role_state.rolcreatedb
       OR role_state.rolcreaterole
       OR role_state.rolinherit
       OR role_state.rolbypassrls THEN
        RAISE EXCEPTION 'sentinel_app does not satisfy the least-privilege role policy';
    END IF;

    IF has_schema_privilege('sentinel_app', 'sentinel', 'CREATE')
       OR has_schema_privilege('sentinel_app', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'sentinel_app unexpectedly has schema CREATE privileges';
    END IF;
END
$assertions$;
