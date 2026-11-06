# Security incident response and triage — operator console and API

## Purpose and scope

SENTINEL 0.14 adds a live, role-aware React incident register on top of the 0.13 triage API. It is a bounded operator workflow, not a SIEM, EDR, notification service or 24/7 incident-response operation.

An incident cannot be created by submitting an arbitrary hostname or URL. The caller must reference an existing completed assessment and one of its finding codes. SENTINEL copies the finding title and normalized severity into the incident record.

## Create an incident from a finding

All routes require `X-API-Key` and role authorization.

```http
POST /api/v1/incidents
X-API-Key: <analyst-or-admin-service-key>
Content-Type: application/json

{
  "assessment_id": "<completed-assessment-id>",
  "finding_code": "TLS_CERT_EXPIRY_WINDOW",
  "assignee": "Platform Security",
  "due_at": "2026-11-09T12:00:00Z",
  "notes": "Coordinate renewal with the service owner."
}
```

Only `assessment_id`, `finding_code`, `assignee`, `due_at` and bounded `notes` are accepted. The title, asset link and severity are taken from the stored finding. A database uniqueness constraint permits one incident for each `(assessment_id, finding_code)` pair; a duplicate returns HTTP 409. The same finding may be triaged again when it appears in a later assessment.

## Review the incident register

```http
GET /api/v1/incidents?status=open&severity=high&limit=50
X-API-Key: <reviewer-service-key>
```

Supported status filters are `open`, `acknowledged`, `investigating`, `contained`, `resolved` and `accepted`. Severity filters are `critical`, `high`, `medium`, `low` and `informational`. The list limit is 1–200.

## Triage and close

```http
PATCH /api/v1/incidents/<incident-id>
X-API-Key: <analyst-or-admin-service-key>
Content-Type: application/json

{
  "status": "acknowledged",
  "assignee": "On-call Security",
  "notes": "Owner notified; renewal work started."
}
```

Allowed transitions are deliberately constrained:

- `open` → `acknowledged`, `investigating` or `accepted`
- `acknowledged` → `investigating`, `contained`, `resolved` or `accepted`
- `investigating` → `contained`, `resolved` or `accepted`
- `contained` → `investigating`, `resolved` or `accepted`
- `resolved` and `accepted` are terminal states.

The first transition beyond `open` sets `acknowledged_at`; moving to `resolved` or `accepted` sets `closed_at`. Invalid transitions return HTTP 409. Create a new incident from a later assessment instead of reopening a terminal record.

## Operator console

After authenticating with an API key that has `incident.read`, operators can review the live incident register, search by finding/title/owner, filter by status and severity, and inspect response-state counts. Principals with `incident.write` can change status using the same server-enforced transition rules as the API.

The response editor writes an accountable operator, a timezone-aware deadline and bounded operator notes through `PATCH /api/v1/incidents/{incident_id}`. The browser converts a local date-time input to an ISO-8601 timestamp with an explicit UTC offset before submission. An incident is flagged overdue when its deadline has passed and it is not resolved or accepted.

Principals with `audit.read` also see the latest available incident-specific audit events. The UI displays event type, changed field names and timestamp; it does not put free-form notes into the audit trace. The register is refreshed from the API and does not populate synthetic incident records.

## Roles and audit

| Role | Incident access |
|---|---|
| `admin` | Full access |
| `analyst` | List, create and update |
| `asset_manager` | List, create and update |
| `auditor` | Read-only list |
| `read_only` | Read-only list |

Creation and updates append hash-linked audit events. Audit details include incident, assessment, asset and finding identifiers, severity, status and changed field names. Free-form notes are not copied into the audit event.

## Current limitations

The console does not deliver email/chat notifications or on-call pages, ingest SIEM events, correlate alerts automatically, provision human assignees or provide a service-level response guarantee. Teams must monitor the live register and follow their own response procedures.
