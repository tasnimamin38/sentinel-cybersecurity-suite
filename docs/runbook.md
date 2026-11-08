# Operator Runbook

## Local development

1. Copy .env.example to .env.
2. Set POSTGRES_PASSWORD, REDIS_PASSWORD and SENTINEL_API_KEY to unique random values.
3. Set SENTINEL_DB_APP_PASSWORD to a separate 64-character hexadecimal secret. Generate it with `python -c "import secrets; print(secrets.token_hex(32))"`.
4. Set SENTINEL_ALLOWED_DOMAINS to one or more domains you are authorized to assess.
5. Run `docker compose up --build`.
6. Compose starts PostgreSQL, runs the one-shot `db-init` role bootstrap, applies Alembic migrations using the database owner account, and only then starts the API and worker with the restricted `sentinel_app` login.
7. Open the console at http://localhost:8080 and API health at http://localhost:8000/healthz.
8. Enter the API key into the console. It remains only in page memory.

The `sentinel` PostgreSQL account is reserved for database initialization and schema migrations. Do not put its password in the API or worker configuration. The `db-init` step is intentionally repeatable and also updates the runtime login on an existing named volume; do not delete the database volume to apply this role change.

## Database backup

Use your organization's standard encrypted PostgreSQL backup process. Verify restore procedures before production use.

## Incident handling

If a credential is exposed, revoke it first, rotate dependent credentials, review audit events, preserve logs, and investigate access. Do not paste live secrets into tickets or chat.

## Production checklist

- TLS termination and trusted reverse proxy configured.
- No public exposure of database port.
- Egress network policy restricts the API to approved destinations.
- DNS rebinding protection enabled outside the app.
- API key replaced with managed identity and rotation.
- Database backups encrypted and restore-tested.
- Monitoring, alerting and incident ownership assigned.
- Migrations, retention and audit immutability policy implemented.
- API and worker use the restricted `sentinel_app` database role; only the one-shot bootstrap/migration services receive the database-owner credential.
- Assessment queue admission is bounded by the per-credential rate limit and global pending-job capacity.
