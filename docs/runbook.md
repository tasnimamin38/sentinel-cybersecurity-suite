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

## Audit checkpoint verification

See [Offline signed audit checkpoints](audit-checkpoints.md) for the operator workflow. Keep the Ed25519 private key outside the SENTINEL host and store signed checkpoint artifacts in an independently controlled retention destination. The application does not store the signing key or automatically upload checkpoint files.

## Optional Prometheus metrics

SENTINEL exposes a small process-local Prometheus exposition endpoint at `/metrics` only when `SENTINEL_METRICS_ENABLED=true`. It is disabled by default. In the supplied Compose topology, the API host port is bound to `127.0.0.1`; keep it loopback-bound and do not publish this endpoint through a public reverse proxy or untrusted/shared network.

The endpoint exports request totals by normalized HTTP method, FastAPI route template and status code, plus duration histograms by method and route template. It does not export request URLs, query strings, client IPs, API keys, credential IDs, hostnames or request/response bodies. Labels are bounded to known methods and registered route templates; unmatched routes are grouped as `unmatched`.

Metrics are in-memory and process-local. They reset on restart and are not aggregated across replicas. This first operational slice is suitable for basic scraping and local diagnostics, not durable billing, multi-replica SLOs or a replacement for centralized telemetry. Keep the endpoint disabled unless a trusted scraper needs it.
