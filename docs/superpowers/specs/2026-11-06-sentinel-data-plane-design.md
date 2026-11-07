# SENTINEL 0.6 Data Plane — Design

**Status:** proposed implementation on `feat/sentinel-0.6-data-plane`  
**Baseline:** GitHub `main` commit `e1f79dd2b40e92e34a8c4ca2a08001dc66295b33`  
**Intent:** move authorized asset assessments out of the API request process into a durable, independently running worker service.

## Why

The current API executes domain assessments synchronously in the request handler. That couples client timeouts to assessment duration, limits horizontal execution, and gives the platform no durable job lifecycle. SENTINEL needs a queue that survives API/worker restarts, permits multiple worker replicas, and preserves the existing authorization boundary.

## Goals

1. Submit an authorized asset assessment and return a durable job identifier without waiting for network assessment.
2. Persist queue state in the existing PostgreSQL database; no new broker or Redis dependency is required.
3. Allow independent worker replicas to claim jobs without processing the same job concurrently.
4. Support optional delayed scheduling, request idempotency, automatic bounded retries, lease recovery, and cancellation.
5. Re-check asset status, expiry and hostname allowlist immediately before network activity.
6. Record job lifecycle transitions in the existing hash-linked audit journal.
7. Run workers as a separate, resource-limited container with no published ports.

## Non-goals

- No arbitrary hostname or URL submission. Jobs must reference a registered asset.
- No OIDC/SSO, MFA, user accounts or tenant isolation in this change.
- No new Redis/Celery/RabbitMQ dependency or external queue service.
- No automatic deployment, destructive testing, exploit execution or unrestricted scanning.
- No browser UI redesign. The existing API key remains the service authentication mechanism.
- No claim of production certification or independent security assurance.

## API contract

All endpoints require the existing `X-API-Key` authentication dependency.

| Method | Endpoint | Behavior |
|---|---|---|
| POST | `/api/v1/assessment-jobs` | Create a job for an active, currently authorized asset; return HTTP 202 |
| GET | `/api/v1/assessment-jobs` | List recent jobs; bounded limit and optional status filter |
| GET | `/api/v1/assessment-jobs/{job_id}` | Read job state, attempts, schedule, timestamps and result assessment ID |
| POST | `/api/v1/assessment-jobs/{job_id}/cancel` | Cancel a queued job immediately or request cooperative cancellation of a running job |
| POST | `/api/v1/assessment-jobs/{job_id}/retry` | Requeue a failed/dead-letter job after revalidating the asset authorization |

Create body: `{ "asset_id": "<registered asset id>", "scheduled_for": "<optional timezone-aware ISO-8601>" }`. Scheduled execution must be no more than 30 days ahead. An optional `Idempotency-Key` header (8–128 visible ASCII characters) is hashed before storage; a repeated key returns the original job and does not enqueue a duplicate.

The server captures the normalized hostname and asset ID at creation time. A worker never accepts a target hostname from a job payload supplied by a client.

## Job model and lifecycle

The `assessment_jobs` table contains: job ID, asset foreign key, normalized target snapshot, status, availability timestamp, attempts, maximum attempts, manual retry count, worker ID, lease expiry, heartbeat time, cancellation request time, start/completion times, linked assessment ID, idempotency-key digest, bounded last-error text, and creation/update timestamps.

Allowed states:

- `queued`: eligible after `available_at`.
- `running`: claimed by one worker and protected by a renewable lease.
- `cancel_requested`: running job has a cancellation request; worker stops its assessment coroutine cooperatively.
- `succeeded`: assessment persisted and linked.
- `failed`: terminal failure that may be manually retried.
- `cancelled`: cancellation completed; no assessment is persisted for that run.
- `dead_letter`: automatic attempt budget exhausted; admin/operator can inspect and manually retry.

Automatic attempts are capped at 3. Transient errors use bounded exponential backoff of 5, 30 and 120 seconds. An expired worker lease returns the job to the queue if attempts remain; otherwise it dead-letters. A running cancellation is checked by the heartbeat loop at least once per second. The assessment HTTP/DNS timeout remains bounded by the existing `SENTINEL_REQUEST_TIMEOUT_SECONDS` setting.

## Worker architecture

- The API creates and reads queue rows only; it does not run queued network work inline.
- Each worker process polls PostgreSQL, claims one available row in a short transaction using `SELECT ... FOR UPDATE SKIP LOCKED`, records its worker ID and lease, then closes the claim transaction before network activity.
- A worker renews its lease and checks cancellation while an assessment is in flight. A worker that loses its lease must not persist a result.
- Before each assessment, the worker reloads the asset, verifies it is active, checks authorization expiry and runs the existing hostname allowlist authorization again.
- Result persistence and job success are committed together with the assessment-completed audit event. Failed attempts store a bounded error summary, not credentials or raw request headers.
- Scale by adding worker replicas. PostgreSQL row locking is the coordination mechanism; no in-memory queue is authoritative.

## Deployment and resource boundaries

The worker reuses the backend image but starts `python -m app.worker`, not Uvicorn. It has no published port, runs non-root, read-only root filesystem, dropped Linux capabilities, no-new-privileges, bounded temporary storage, a 1 CPU / 512 MiB memory limit and a 128-process limit. It joins only the database and outbound assessment networks. The API remains a separate service. Compose can scale the worker service horizontally.

## Audit events

Record `assessment.job.queued`, `assessment.job.claimed`, `assessment.job.retry_scheduled`, `assessment.job.cancel_requested`, `assessment.job.cancelled`, `assessment.job.succeeded`, `assessment.job.failed` and `assessment.job.dead_lettered`. Event details may include job ID, asset ID, attempt number and outcome; never include API keys, idempotency values, request authorization headers or full exception traces.

## Verification and exit criteria

- API tests cover unauthorized/unknown/inactive/expired assets, scheduling validation, idempotency, list/detail, cancel transitions and manual retry.
- Service tests cover claim eligibility, lease expiry, attempt budget, retry backoff, and worker ownership checks.
- Worker tests cover successful persistence, transient failure, dead-letter behavior, pre-flight reauthorization, cancellation and lease loss.
- A PostgreSQL integration test runs two claimers concurrently and proves one job is claimed by at most one worker.
- Alembic migration upgrades the existing 0002 schema without modifying prior migration history.
- GitHub Actions runs the complete backend suite, the PostgreSQL concurrency test, Ruff checks, dependency audit, frontend build/audit and container image/Compose validation.
- No production deployment occurs in this change; merge remains a human decision after CI and review.
