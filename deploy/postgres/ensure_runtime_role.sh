#!/bin/sh
set -eu

: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${SENTINEL_DB_APP_PASSWORD:?SENTINEL_DB_APP_PASSWORD is required}"

if [ "${#SENTINEL_DB_APP_PASSWORD}" -ne 64 ]; then
    echo "SENTINEL_DB_APP_PASSWORD must be exactly 64 hexadecimal characters." >&2
    exit 1
fi

case "$SENTINEL_DB_APP_PASSWORD" in
    *[!0123456789abcdefABCDEF]*)
        echo "SENTINEL_DB_APP_PASSWORD must be exactly 64 hexadecimal characters." >&2
        exit 1
        ;;
esac

# The bootstrap login is confined to this one-shot service. Runtime containers
# receive only the restricted sentinel_app credential.
export PGPASSWORD="$POSTGRES_PASSWORD"

psql --no-psqlrc --set ON_ERROR_STOP=1 --host db --username sentinel --dbname sentinel <<'SQL'
\getenv app_password SENTINEL_DB_APP_PASSWORD

SELECT format(
    'CREATE ROLE sentinel_app WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 40',
    :'app_password'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app'
)
\gexec

ALTER ROLE sentinel_app
    WITH LOGIN PASSWORD :'app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 40;

-- Remove any pre-existing role memberships too; NOINHERIT alone does not prevent SET ROLE.
SELECT format('REVOKE %I FROM sentinel_app', parent.rolname)
FROM pg_auth_members AS membership
JOIN pg_roles AS parent ON parent.oid = membership.roleid
JOIN pg_roles AS member ON member.oid = membership.member
WHERE member.rolname = 'sentinel_app'
\gexec

GRANT CONNECT ON DATABASE sentinel TO sentinel_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;

-- Migrations continue to run as the schema owner "sentinel". Ensure every
-- future public-schema table/sequence automatically receives runtime DML rights.
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO sentinel_app;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'sentinel_app'
          AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'sentinel_app has an unsafe role attribute';
    END IF;
END
$$;
SQL

unset PGPASSWORD
echo "Restricted SENTINEL database runtime role is ready."
