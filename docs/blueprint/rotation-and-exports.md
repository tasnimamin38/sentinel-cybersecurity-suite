# SENTINEL 0.3.1 Operations Guide

## API key rotation

SENTINEL supports a controlled overlap window through `SENTINEL_API_KEYS`.

1. Generate a new random key with at least 32 characters.
2. Store the old and new values in the deployment secret manager.
3. Configure `SENTINEL_API_KEYS=old-key,new-key`. Do not add spaces around the comma-delimited values.
4. Deploy the API. Both keys are accepted during the transition; each configured key must pass production strength checks.
5. Update operator clients to use the new key and verify successful authenticated requests.
6. Remove the old key from `SENTINEL_API_KEYS` and redeploy. The old key is now revoked.
7. Record the change reference in your change-management system.

The legacy `SENTINEL_API_KEY` setting remains supported when `SENTINEL_API_KEYS` is unset. If both are configured, `SENTINEL_API_KEYS` takes precedence. Never place keys in source control, screenshots, tickets or shell history. Use a secret manager and a controlled deployment pipeline for production.

This implementation supports overlapping shared operator credentials. It is not per-user identity, RBAC, tenant isolation or a complete credential-management service.

## CSV exports

Authenticated routes:

- `GET /api/v1/exports/assets.csv`
- `GET /api/v1/exports/assessments.csv`
- `GET /api/v1/exports/findings.csv`
- `GET /api/v1/exports/remediations.csv`
- `GET /api/v1/exports/audit.csv`

Exports are bounded to a maximum of 5,000 source records (findings are capped at 10,000 rows), use no-store response headers, and create a `data.exported` audit event. Spreadsheet formula-like text cells are prefixed to prevent common CSV formula injection. Numeric values remain numeric.

Exports can contain internal asset names, owners, authorization references, remediation notes and audit details. Restrict API-key access, store exported files in approved encrypted locations, apply retention policy, and do not upload them to public issue trackers.

## Verification

- Use the local pytest suite and CI workflow before release.
- Verify the audit chain after exporting audit data; the exported file represents the audit records read before the export event itself is appended.
- Treat the audit chain as tamper-evident, not immutable. Independently controlled append-only storage and signed checkpoints remain future controls.
