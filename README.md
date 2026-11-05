# SENTINEL — Defensive Security Operations Platform

SENTINEL is a modular defensive-security foundation for organizations assessing systems they own or are explicitly authorized to test. It combines a FastAPI service, a React/TypeScript operator console, SQL persistence, audit events, and container deployment.

**Current release: 0.1.0 development baseline.** This is a working starting platform, not a certified enterprise security product or a replacement for a specialist security program.

## Capabilities in this baseline

- Explicit DNS domain allowlist with exact and proper subdomain matching.
- HTTPS security-header posture review.
- TLS certificate metadata and expiry check.
- DNS MX, SPF and DMARC posture checks.
- Normalized findings and a transparent severity-based risk score.
- SQL-backed assessment history and audit events.
- API-key-protected routes that fail closed when no key is configured.
- Responsive console, Docker Compose, CI, CodeQL workflow and Dependabot configuration.
- Secret-pattern scanning library that returns redacted evidence only.

## Safety model

The assessment API rejects unlisted domains, URL paths and IP literals. It resolves target hostnames and refuses private, loopback, link-local, reserved and otherwise non-global addresses. It performs one bounded HTTPS GET, does not follow redirects, does not intentionally consume response bodies and does not execute exploit payloads.

Only assess assets covered by your own authorization. The domain allowlist is an application guardrail, not legal authorization. Do not add a domain until you have written permission.

## Quick start — Docker

1. Copy env.example to .env.
2. Replace both passwords/keys with unique, long random values.
3. Set SENTINEL_ALLOWED_DOMAINS to the exact domain(s) you are authorized to assess.
4. Run docker compose up --build.
5. Open the console at http://localhost:8080. API health is at http://localhost:8000/healthz.
6. Enter the API key in the console. It remains in page memory and is not persisted in browser storage.

The database is not exposed to the host network. API and console ports bind to localhost by default.

## Backend development

From backend:

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    set SENTINEL_API_KEY=use-a-long-local-development-secret
    set SENTINEL_ALLOWED_DOMAINS=example.com
    uvicorn app.main:app --reload

In a second terminal:

    cd frontend
    npm install
    npm run dev

Configure VITE_API_BASE_URL=http://localhost:8000 when required. API docs are available at /docs in development.

## Repository layout

- backend/app — API, data models, authorization and security services.
- backend/tests — regression tests for core safety and scoring behavior.
- frontend — responsive security operations console.
- docs — architecture, security model and operator runbook.
- .github/workflows — CI and CodeQL automation.

## Enterprise evolution roadmap

Before a production or industrial deployment: add Alembic migrations, multi-tenant RBAC and SSO, managed secret storage and rotation, durable task queues, distributed workers, egress firewall/DNS pinning, immutable audit exports, structured metrics/traces, retention controls, disaster-recovery drills and independent security testing.

## License

No open-source license is granted at this stage. Repository visibility and licensing are separate; keep the repository private unless you intentionally decide to publish it.