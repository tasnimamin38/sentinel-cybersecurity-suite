# Changelog

All notable changes to SENTINEL are documented here.

## 0.3.4 — 2026-11-06

### Added
- Authenticated Redis 8 shared rate-limit store with an atomic Lua sliding-window log using Redis server time.
- Separate direct-peer IP and API-key fingerprint buckets, with stricter assessment and secret-scan operation buckets.
- Rate-limit response headers and HTTP 429 Retry-After behavior; Redis dependency failure returns HTTP 503 rather than bypassing request protection.
- API startup dependency check and readiness probe for the Redis limiter.
- Pure-ASGI request body guard: 512 KiB default cap, early Content-Length rejection and streamed/chunked frame accounting.
- Configurable bounded request, IP, API-key, assessment and secret-scan policies; authenticated Redis password required in production.
- Compose Redis service isolated on the private data network, password protected, non-persistent, memory-capped and configured with noeviction.
- Rate-limit and body-size regression tests, threat model updates, algorithm and architecture diagrams.

### Validation
- Backend pytest: 78 passed, 1 skipped (the live Redis integration test is enabled in GitHub Actions with a dedicated Redis 8 service).
- Ruff lint and format: passed.
- Frontend TypeScript/Vite production build: passed.
- npm audit: 0 reported vulnerabilities.
- pip-audit: no known vulnerabilities found.
- Docker Compose and GitHub Actions YAML parsing: passed.
- Docker container runtime, production egress enforcement, high-concurrency load, restore drills and independent penetration testing remain outstanding.

## 0.3.3 — 2026-11-06

### Fixed
- Assessment retention no longer deletes historical assessment evidence referenced by remediation tasks.
- Retention still removes eligible unreferenced history beyond the configured cap; linked evidence is retained to preserve remediation traceability.
- Corrected the case-sensitive license/NOTICE link in the repository README.
- Updated validation documentation to reflect the completed 61-test run and successful local Python dependency audit.

### Validation
- Backend pytest: 61 passed.
- Ruff lint and format: passed.
- Frontend TypeScript/Vite production build: passed.
- npm audit: 0 reported vulnerabilities.
- pip-audit: no known vulnerabilities found.
- Docker runtime validation remains outstanding because Docker CLI is unavailable on the linked Windows device.
