# SENTINEL 0.6 Durable Assessment Jobs Implementation Plan

> **For agentic workers:** Use this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add a PostgreSQL-backed assessment queue and isolated worker service for authorized SENTINEL asset assessments.

**Architecture:** The API persists assessment job requests and exposes a bounded job lifecycle API. Separate worker containers claim jobs with PostgreSQL row locking, revalidate asset authorization, execute the existing async posture assessment, persist results, and update durable job state with leases, retries and cooperative cancellation.

**Tech Stack:** Existing FastAPI, SQLAlchemy, Alembic, PostgreSQL, Pydantic, pytest, Docker Compose and GitHub Actions. No new runtime package or external queue broker.

**Spec:** `docs/superpowers/specs/2026-11-06-sentinel-data-plane-design.md`

## Global Constraints

- Only registered assets with active, unexpired authorization and hostname allowlist approval may enter the assessment worker.
- Production queue coordination uses PostgreSQL transactions and `FOR UPDATE SKIP LOCKED`; no in-memory queue may be authoritative.
- API returns HTTP 202 for successful job creation; all job routes retain `X-API-Key` authentication.
- Optional schedule is timezone-aware and no more than 30 days in the future.
- Idempotency header accepts 8–128 visible ASCII characters; store only SHA-256 digest.
- Automatic attempts are capped at 3 with backoff of 5, 30 and 120 seconds.
- Worker lease is 60 seconds and heartbeat interval is 10 seconds; cancellation is checked at least every second.
- Worker runs `python -m app.worker`, without a web listener, and is limited to 1 CPU, 512 MiB RAM and 128 processes.
- Preserve 0001/0002 migrations; add 0003 as a forward-only schema migration.
- Keep the current synchronous assessment endpoint backward-compatible.
- Never write secrets, API keys, request headers or raw idempotency keys to job records, logs or audit events.
- All code, tests, plans and documentation are committed directly to the isolated GitHub branch; do not create a local working copy or laptop artifacts.

## Review Focus

1. Duplicate submission races where two API requests use the same Idempotency-Key concurrently.
2. Worker crash after external network assessment but before job completion is committed.
3. Cancellation arriving between final result computation and the transaction that persists assessment/job state.
4. Asset authorization expiring or being paused after enqueue but before claim.
5. PostgreSQL lock contention and lease expiry when multiple worker replicas claim the same queue.

---

### Task 1: Durable job schema and queue lifecycle service

**Files:**
- Create: `backend/app/services/jobs.py`
- Create: `backend/alembic/versions/0003_assessment_jobs.py`
- Create: `backend/tests/test_jobs.py`
- Modify: `backend/app/models.py`
- Modify: `backend/app/config.py`

**Interfaces:**
- `enqueue_assessment_job(db, asset, scheduled_for, idempotency_digest) -> AssessmentJob`
- `claim_next_job(db, worker_id, now=None) -> AssessmentJob | None`
- `heartbeat_job(db, job_id, worker_id, now=None) -> bool`
- `request_job_cancel(db, job) -> AssessmentJob`
- `complete_job(db, job_id, worker_id, assessment_id) -> bool`
- `fail_job_attempt(db, job_id, worker_id, error_summary, now=None) -> AssessmentJob`
- `retry_job(db, job) -> AssessmentJob`

- [ ] **Step 1: Write failing queue lifecycle tests.** Test queued creation, delayed availability, digest uniqueness, claim increments attempts and sets lease, worker ownership checks, heartbeat renewal, cancellation state transition, retry backoff and dead-letter after attempt 3.
- [ ] **Step 2: Run RED.** Run `cd backend && pytest tests/test_jobs.py -q`. Expected: failures because AssessmentJob and queue service do not exist.
- [ ] **Step 3: Add AssessmentJob model.** Add fields and indexes listed in the spec; use a unique nullable idempotency digest and foreign keys to assets/assessments.
- [ ] **Step 4: Add migration 0003.** Create the table and indexes with schema inspection guards. Downgrade removes only 0003-owned objects.
- [ ] **Step 5: Implement jobs.py.** Use short transactions and `with_for_update(skip_locked=True)` for claims, bounded leases, worker-ID compare-and-set checks and UTC timestamps. Reclaim expired leases; dead-letter exhausted jobs.
- [ ] **Step 6: Run GREEN and full suite.** Run `cd backend && pytest -q`, then `ruff check app tests alembic` and `ruff format --check app tests alembic`. Expected: all tests and lint/format pass.
- [ ] **Step 7: Commit.** `feat: add durable assessment job queue`.

### Task 2: Authenticated assessment-job API

**Files:**
- Modify: `backend/app/main.py`
- Modify: `backend/app/schemas.py`
- Modify: `backend/tests/test_api_smoke.py`

**Consumes:** Task 1 queue service and AssessmentJob model.  
**Produces:** Authenticated job create/list/detail/cancel/retry endpoints.

- [ ] **Step 1: Write failing API tests.** Cover 202 job creation for a registered authorized asset, rejection of unknown/paused/expired/out-of-scope assets, schedule validation, duplicate Idempotency-Key reuse, list/detail, queued cancellation, running cancellation request, terminal cancellation conflict and manual retry constraints.
- [ ] **Step 2: Run RED.** Run `cd backend && pytest tests/test_api_smoke.py -q -k assessment_job`. Expected: 404 because routes do not yet exist.
- [ ] **Step 3: Add Pydantic schemas.** Add request, response and bounded list-filter schemas; require timezone-aware schedule and 30-day horizon.
- [ ] **Step 4: Add routes.** Add POST/GET/detail/cancel/retry routes. Hash idempotency header before passing to the queue service; return existing job for a matching digest. Write audit events for every accepted lifecycle transition.
- [ ] **Step 5: Run GREEN and full suite.** Run `pytest -q`, Ruff lint and format checks. Expected: all tests pass.
- [ ] **Step 6: Commit.** `feat: expose authenticated assessment job lifecycle API`.

### Task 3: Isolated worker runtime and result handling

**Files:**
- Create: `backend/app/worker.py`
- Create: `backend/app/services/assessment_store.py`
- Create: `backend/tests/test_worker.py`
- Modify: `backend/app/main.py`
- Modify: `backend/app/config.py`

**Consumes:** Task 1 claim/heartbeat/finalization service and Task 2 API schemas.  
**Produces:** Worker entry point `python -m app.worker`; shared assessment persistence helper.

- [ ] **Step 1: Write failing worker tests.** Cover successful assessment persistence, reauthorization immediately before network call, cancellation before start, cooperative cancellation while running, transient error backoff, dead-letter after three failures, lost-lease refusal to persist and redacted error storage.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_worker.py -q`. Expected: module/function missing failures.
- [ ] **Step 3: Extract shared result persistence.** Move assessment/audit/retention persistence to `assessment_store.persist_assessment(db, result, asset, max_records)`; preserve the current synchronous endpoint wrapper for compatibility.
- [ ] **Step 4: Implement worker loop.** Claim one job per process; run the existing `assess_domain` coroutine; use heartbeat polling for lease renewal and cancellation; re-check asset status, expiry and hostname authorization; commit assessment, completion status and audit event atomically.
- [ ] **Step 5: Run GREEN and full suite.** Run complete pytest, Ruff lint and format checks. Expected: all tests pass.
- [ ] **Step 6: Commit.** `feat: add isolated assessment worker runtime`.

### Task 4: Container, PostgreSQL concurrency CI and operator docs

**Files:**
- Modify: `docker-compose.yml`
- Modify: `.github/workflows/ci.yml`
- Create: `backend/tests/test_postgres_job_queue.py`
- Create: `docs/assessment-jobs.md`
- Modify: `README.md`
- Modify: `docs/blueprint/roadmap.md`

**Consumes:** Tasks 1–3.  
**Produces:** independently runnable, resource-bounded worker service and automated PostgreSQL claim-race verification.

- [ ] **Step 1: Write failing PostgreSQL integration test.** With `SENTINEL_TEST_POSTGRES_URL`, create an isolated temporary schema, seed two jobs and run two claimers concurrently. Assert each job is claimed at most once and the claim set has no duplicate IDs. Skip only when the environment variable is absent.
- [ ] **Step 2: Run RED.** Run `pytest tests/test_postgres_job_queue.py -q`. Expected locally without the CI Postgres service: one explicit skip; GitHub Actions must provide the service and run it.
- [ ] **Step 3: Add worker configuration.** Validate poll interval, 60-second lease, 10-second heartbeat, max attempts 3 and bounded worker identity.
- [ ] **Step 4: Add Compose worker.** Reuse backend image, run `python -m app.worker`, no ports, read-only root, tmpfs, dropped capabilities, no-new-privileges, non-root, 1 CPU, 512 MiB and 128 PIDs. Depend on API readiness so migration 0003 has run.
- [ ] **Step 5: Add CI Postgres service.** Set a dedicated test database URL, health-check PostgreSQL, run the full suite including the concurrency test, and retain Ruff/dependency-audit/container checks.
- [ ] **Step 6: Document operations.** Explain enqueue/list/cancel/retry API, worker scaling, lease recovery, queue status meanings, retry limits and authorization re-checks. Update roadmap without claiming SSO/MFA or full production certification.
- [ ] **Step 7: Run final verification.** Run full GitHub Actions CI on the branch; review all job outputs and changed-file diff. Expected: backend, PostgreSQL concurrency, dependency audit, Ruff, frontend build/audit and container checks all pass.
- [ ] **Step 8: Commit.** `feat: deploy scalable isolated assessment workers`.

## Final Review Gate

- Review the full branch diff for security, migration compatibility, API auth coverage, queue race behavior and worker isolation.
- Resolve all important findings with tests.
- Open a draft PR to `main`; do not merge or deploy automatically.
- A human reviews CI and the PR before merge.
