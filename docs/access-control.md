# API Access Control and Service Credentials

All `/api/v1/*` operations require `X-API-Key`. Authentication identifies a service credential; route-level authorization then checks its role and the exact HTTP method and FastAPI route template. Any protected route missing from the permission map is administrator-only.

## Roles

| Role | Intended use | Capabilities |
|---|---|---|
| `admin` | Platform bootstrap and administration | All API operations, including credential lifecycle |
| `analyst` | Security analysis | Read inventory/evidence, run assessments, enqueue jobs, create/update incident triage records, scan submitted text and read audit |
| `asset_manager` | Authorized inventory operations | Analyst operations plus asset registration/update, remediation updates, incident triage updates, job cancellation and retry |
| `auditor` | Independent review | Read dashboard, assets, assessments, incidents, jobs, remediation, controls, audit and bounded exports |
| `read_only` | Monitoring integrations | Read dashboard, assets, incidents, assessments, jobs, remediation and controls |

Permissions are enforced in the shared API-key dependency, so the same policy covers the main API and assessment-job router. The frontend is not a security boundary; server-side authorization remains authoritative.

## Bootstrap and environment credentials

Legacy `SENTINEL_API_KEY` and comma-separated `SENTINEL_API_KEYS` remain backward compatible and are treated as administrator credentials. During zero-downtime rotation, configure both keys, move clients, then remove the previous key and restart the service.

Optional role-scoped static service credentials are configured with `SENTINEL_API_CREDENTIALS_JSON`:

```json
[
  {
    "id": "nightly-analyst",
    "key": "<at-least-32-random-characters>",
    "role": "analyst"
  },
  {
    "id": "audit-export",
    "key": "<a-different-at-least-32-character-secret>",
    "role": "auditor"
  }
]
```

IDs must be unique, role names must be supported, keys must be at least 32 characters and no key may be reused. In production, a strong bootstrap administrator credential is required. Never commit real keys to the repository; supply them through an external secret manager or protected deployment environment.

## Database-managed credentials

Only an administrator can list, create or revoke managed credentials.

### Create

```http
POST /api/v1/credentials
X-API-Key: <admin-service-key>
Content-Type: application/json

{
  "label": "Nightly posture analyst",
  "role": "analyst",
  "expires_at": "2027-06-01T00:00:00Z"
}
```

`expires_at` is optional. When omitted, the API sets a 90-day expiry. When present, it must include a timezone, be in the future and be no more than 365 days ahead. Active managed credentials are capped at 250.

The creation response includes the raw secret exactly once and sends `Cache-Control: no-store` and `Pragma: no-cache`. Copy it into the intended secret manager immediately. The database stores only its SHA-256 digest and a short display prefix. The digest and raw secret are never included in API list responses or credential audit details.

### List

```http
GET /api/v1/credentials
X-API-Key: <admin-service-key>
```

The list contains IDs, labels, roles, key prefixes, expiry/revocation state and created/last-used timestamps. It never returns the secret or digest.

### Revoke

```http
POST /api/v1/credentials/<credential-id>/revoke
X-API-Key: <different-admin-service-key>
```

Revocation is immediate for subsequent API calls. A database-managed credential cannot revoke itself; use a separate administrator credential to avoid locking out the only active administrator.

Every authenticated use checks the managed credential's revocation and expiry state. Last-used timestamps are persisted. Creation and revocation append hash-linked audit events that record identifiers and role metadata only.

## Identity endpoint

```http
GET /api/v1/me
X-API-Key: <service-key>
```

Returns credential ID, role, credential source and granted permission names. It never reveals the raw key or digest.

## Limitations and production requirements

This release provides service-to-service RBAC, not human identity. It does not provide OIDC/SAML federation, MFA, browser login sessions, per-user audit attribution, tenant isolation, per-credential quotas or external key custody. Environment credentials remain plaintext in deployment configuration and need secret-manager protection. Database-managed credential hashes are SHA-256 digests of high-entropy random secrets; the system does not claim password-style slow hashing is necessary for these random API tokens.

Keep a separately controlled bootstrap admin key available for managed-key recovery. Review route-to-permission mappings whenever a protected endpoint is added. Unknown routes intentionally fail closed to administrator access.

## Request quotas

Every authenticated and role-authorized service credential uses fixed UTC quota windows. The default is 120 requests per minute and 10,000 requests per day. Managed credentials can set `rate_limit_per_minute` from 1–600 and `daily_request_limit` from 1–1,000,000 when created. Environment-managed entries in `SENTINEL_API_CREDENTIALS_JSON` can set the same optional fields. Legacy bootstrap admin keys have bounded defaults of 600 requests per minute and 1,000,000 per day.

When either quota is exhausted, the API returns HTTP `429 Too Many Requests` with `Retry-After` in seconds. Usage records store only per-credential UTC window counters; request paths, query strings, bodies and source payloads are not retained by the quota subsystem. PostgreSQL advisory transaction locks serialize updates across API replicas, including the first request for a credential. A credential's quota is shared by every client using that key.

## Controlled managed-key rotation

Only an administrator can rotate database-managed credentials:

```http
POST /api/v1/credentials/<credential-id>/rotate
X-API-Key: <admin-service-key>
Content-Type: application/json

{
  "grace_period_seconds": 3600
}
```

The grace period is a whole number from 0 to 86,400 seconds (default 3,600). The response includes a new high-entropy secret exactly once. The previous key remains accepted only until the grace deadline; it is then rejected on the next request. The replacement inherits the old credential's role, quotas and original expiry, so rotation does not silently extend its lifetime. A rotated credential cannot be rotated again; rotate its replacement. A grace period of zero performs an immediate cutover.

Rotation is audited with old/new credential IDs and the grace duration; neither raw secret nor digest is written to the audit event. Environment-managed and legacy keys must be rotated through deployment secret configuration, not this endpoint.
