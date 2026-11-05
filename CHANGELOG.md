# Changelog

All notable changes to SENTINEL are documented here.

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
