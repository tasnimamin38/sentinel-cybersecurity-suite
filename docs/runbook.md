# Operator Runbook

## Local development

1. Copy env.example to .env.
2. Set POSTGRES_PASSWORD and SENTINEL_API_KEY to unique random values.
3. Set SENTINEL_ALLOWED_DOMAINS to one or more domains you are authorized to assess.
4. Run docker compose up --build.
5. Open the console at http://localhost:8080 and API health at http://localhost:8000/healthz.
6. Enter the API key into the console. It remains only in page memory.

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
