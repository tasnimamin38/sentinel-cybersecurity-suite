# SENTINEL — Defensive Security Operations Platform

[![CI](https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/codeql.yml/badge.svg)](https://github.com/tasnimamin38/sentinel-cybersecurity-suite/actions/workflows/codeql.yml)

SENTINEL is a modular defensive-security foundation for organizations assessing systems they own or are explicitly authorized to test. It combines a FastAPI service, a React/TypeScript operator console, SQL persistence, audit events, and container deployment.

**Current release: 0.2.0 engineering baseline.** This is not a certified enterprise security product or a replacement for a specialist security program.

## Capabilities in this baseline

- Explicit DNS domain allowlist with exact and proper subdomain matching.
- DNS-pinned HTTPS probe: connects to a literal validated public IP while retaining hostname-bound TLS SNI and HTTP Host.
- Bounded behavior: one HTTP/1.1 GET, headers-only parsing, no redirect following, no response-body download, shared timeout and 64 KiB header cap.
- Explainable risk v2: severity weights, confidence, bounded asset criticality, duplicate suppression and top risk drivers.
- Production configuration guard: rejects weak API keys, missing authorized scope, wildcard CORS and SQLite in production.
- Liveness/readiness endpoints, request correlation IDs and assessment-history retention cap.
- TLS certificate metadata and expiry check.
- DNS MX, SPF and DMARC posture checks.
- Normalized findings and a transparent severity-based risk score.
- SQL-backed assessment history and audit events.
- API-key-protected routes that fail closed when no key is configured.
- Responsive console, Docker Compose, CI, CodeQL workflow and Dependabot configuration.
- Secret-pattern scanning library that returns redacted evidence only.

## Safety model

The assessment API rejects unlisted domains, URL paths and IP literals. It rejects any non-public DNS answer, then connects to a literal validated IP while retaining the hostname for TLS SNI, certificate validation and the HTTP Host header. It performs one bounded HTTPS GET, reads response headers only, does not follow redirects, does not download response bodies and does not execute exploit payloads.

Only assess assets covered by your own authorization. The domain allowlist is an application guardrail, not legal authorization. Do not add a domain until you have written permission.

## Quick start — Docker

1. Copy `.env.example` to `.env`.
2. Replace both passwords/keys with unique, long random values.
3. Set `SENTINEL_ALLOWED_DOMAINS` to the exact domain(s) you are authorized to assess.
4. Run `docker compose up --build`.
5. Open the console at http://localhost:8080. API liveness is at http://localhost:8000/healthz and database readiness is at http://localhost:8000/readyz.
6. Enter the API key in the console. It remains in page memory and is not persisted in browser storage.

The database is not exposed to the host network. API and console ports bind to localhost by default.

## Backend development

From `backend`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SENTINEL_API_KEY = "use-a-long-local-development-secret-at-least-32-chars"
$env:SENTINEL_ALLOWED_DOMAINS = "example.com"
uvicorn app.main:app --reload
```

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Configure `VITE_API_BASE_URL=http://localhost:8000` when required. API docs are available at `/docs` in development.

## Repository layout

- `backend/app` — API, data models, authorization and security services.
- `backend/tests` — regression tests for core safety and scoring behavior.
- `frontend` — responsive security operations console.
- `docs` — architecture, threat model, algorithms, roadmap and operator runbook.
- `.github/workflows` — CI and CodeQL automation.

## Architecture and blueprints

- System architecture: docs/blueprint/system-architecture.md
- Security algorithms and risk model: docs/blueprint/security-algorithms.md
- Threat model: docs/blueprint/threat-model.md
- Engineering roadmap: docs/blueprint/roadmap.md

The target enterprise design separates control plane, data plane, evidence storage and observability. The target is not fully implemented in 0.2.0.

## Contributing

Bug reports, focused improvements, tests and documentation are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Please do not report exploitable vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

This repository is public for transparency and collaboration, but **no open-source license has been applied yet**. Until a license is added, do not assume that public visibility grants permission to redistribute or reuse the code.