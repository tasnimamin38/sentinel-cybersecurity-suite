# Assessment Job Queue and Worker Operations

SENTINEL's queued assessment API is for registered assets covered by current authorization. It is not an arbitrary URL scanner. The existing synchronous assessment routes remain available for compatibility; new long-running work should use the job API.

## Submit a job

All routes require `X-API-Key`.

```http
POST /api/v1/assessment-jobs
X-API-Key: <service-key>
Idempotency-Key: portal-check-2026-11-06-0001
Content-Type: application/json

{
  "asset_id": "00000000-0000-0000-0000-000000000000",
  "scheduled_for": "2026-11-07T12:00:00Z"
}
```

- `asset_id` must belong to an existing asset record.
- The asset must be active, have unexpired authorization, and remain inside `SENTINEL_ALLOWED_DOMAINS`.
- The API snapshots the registered hostname. Clients cannot submit a target hostname or URL.
- `scheduled_for` is optional, must contain a timezone, and may be at most 30 days in the future. Omit it to enqueue immediately.
- `Idempotency-Key` is optional and accepts 8–128 visible ASCII characters. SENTINEL stores only its SHA-256 digest. Repeating the same key for the same asset returns the original job with HTTP 200; a new job returns HTTP 202. Reusing the same key for a different asset returns HTTP 409.

A job response never includes the idempotency digest or API key. Its public fields include the job ID, asset ID, hostname snapshot, status, attempts, schedule, lease/heartbeat timestamps, result assessment ID and a bounded error summary.

## Read, cancel and retry

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/assessment-jobs?status=queued&limit=50` | List recent jobs; optional status filter and bounded limit |
| `GET` | `/api/v1/assessment-jobs/{job_id}` | Read one job |
| `POST` | `/api/v1/assessment-jobs/{job_id}/cancel` | Cancel queued work immediately or request cooperative cancellation of a running job |
| `POST` | `/api/v1/assessment-jobs/{job_id}/retry` | Manually retry a failed/dead-letter job after rechecking asset authorization |

A terminal `succeeded`, `failed` or `dead_letter` job cannot be cancelled. A cancelled job cannot be retried. Manual retries are capped at three per job. Authorization must be active and in scope again at retry time.

## Job lifecycle

| State | Meaning |
|---|---|
| `queued` | Waiting for its scheduled time or retry backoff |
| `running` | Owned by one worker with a renewable database lease |
| `cancel_requested` | API requested cancellation; worker stops the assessment coroutine cooperatively |
| `succeeded` | Assessment evidence, audit event and job result committed together |
| `failed` | Permanent preflight/authorization failure; operator may retry after correcting scope |
| `dead_letter` | Three automatic attempts were exhausted; inspect before manual retry |
| `cancelled` | Queued or running work was cancelled without persisting an assessment |

Automatic execution is capped at three attempts. Transient failures are retried after 5 seconds and then 30 seconds; the third failed attempt becomes `dead_letter`. A worker crash or lost process leaves a lease that becomes reclaimable after 60 seconds. PostgreSQL coordinates claim ownership with `SELECT ... FOR UPDATE SKIP LOCKED`; no in-memory queue is authoritative.

The worker renews leases every 10 seconds and checks cancellation/state at least once per second. Assessment network calls retain the existing `SENTINEL_REQUEST_TIMEOUT_SECONDS` bound. Before network activity and again before result persistence, the worker reloads and revalidates the asset. If authorization expires, the asset is paused, the hostname snapshot changes, the domain is out of scope, the worker lease is lost or cancellation wins the race, no result is written.

## Run and scale workers

The Compose worker uses the same backend image but runs `python -m app.worker`, not Uvicorn. It has no published port, runs as the non-root image user, has a read-only root filesystem, dropped capabilities, `no-new-privileges`, a 32 MiB `/tmp`, a 1 CPU limit, 512 MiB memory limit and 128 PIDs. It joins the internal database network and the outbound assessment network only after the API has completed database migrations and passed readiness.

Start the normal stack:

```sh
docker compose up -d --build
```

Scale to three worker replicas:

```sh
docker compose up -d --scale worker=3 worker
docker compose ps worker
docker compose logs --tail=100 worker
```

The API and worker share PostgreSQL as the authoritative job store. Do not run a worker against SQLite in production. Production egress still requires an independent network-level firewall/proxy: DNS validation and pinned connections in application code are defence in depth, not a replacement for an egress boundary.

## Audit and limitations

Job queue, claim, retry, cancellation, success, failure and dead-letter transitions append events to the existing hash-linked audit journal. Events contain job/asset identifiers, attempt count and outcome only; they never contain API keys, idempotency values, request headers, raw traces or exception messages.

This release does not provide per-job disposable sandboxes, tenant isolation, OIDC/MFA, independent encrypted evidence storage, an external immutable audit checkpoint, production egress firewall policy or independent penetration-test assurance. The worker service is resource-bounded but shares the container image and host kernel with the rest of the Compose deployment.
