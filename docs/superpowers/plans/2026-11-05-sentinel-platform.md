# SENTINEL Platform Implementation Plan

## Scope

Create a modular defensive-security MVP with API, console, storage, security controls, documentation and CI.

## Tasks

1. Add tests for allowlist normalization, security-header checks, risk scoring and secret redaction.
2. Implement backend services for authorization, network safety, HTTPS/TLS/DNS posture and risk normalization.
3. Add FastAPI endpoints, API-key auth, SQLAlchemy persistence and audit events.
4. Build responsive React operator console with in-memory API-key handling.
5. Add Docker Compose, CI, CodeQL, Dependabot, security documentation and runbook.
6. Run backend tests, lint, frontend production build and container configuration checks.
7. Commit the verified repository baseline only after repository privacy is confirmed.

## Acceptance

- Out-of-scope names, malformed hostnames and IP literals are rejected before network checks.
- Secret scanner never emits matched plaintext.
- No redirects are followed and only HTTPS is attempted.
- Protected routes fail closed without configured API key.
- API and console compile/build, and tests report real results.
- Repository visibility is verified private before source publication.