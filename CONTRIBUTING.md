# Contributing to SENTINEL

Thanks for helping improve SENTINEL. Contributions must keep the project defensive, auditable, authorized and safe by default.

## Before opening an issue

- Search existing issues to avoid duplicates.
- Include the affected component, expected behavior and minimal reproducible steps.
- Never publish live tokens, credentials, customer data or private target information.
- Do not submit third-party target details unless you have written authorization to share them.

## Pull requests

1. Create a focused feature branch from `main`.
2. Explain the problem and the smallest safe fix.
3. Add or update tests for every behavior change.
4. Update API, architecture, threat-model and operator documentation when contracts or safeguards change.
5. Keep dependencies within the documented compatibility ranges and update lockfiles.
6. Confirm no secrets, local databases, build outputs, backups or environment files are included.
7. Describe residual risk and distinguish what is implemented from what remains a roadmap item.

## Commit signing

See [Git Commit Signing and Verification](docs/security/commit-signing.md) for the Windows SSH-signing setup, GitHub key registration, verification steps and safe migration guidance. A Verified badge confirms a validated signature; it is not a substitute for code review, CI or security testing. Never publish a private signing key or rewrite shared history solely to change verification badges.

## Local validation

Backend:

~~~powershell
cd backend
python -m pip install -r requirements.txt pytest ruff==0.17.4
python -m pytest -q
ruff format --check app tests alembic
ruff check app tests alembic
~~~

Frontend:

~~~powershell
cd frontend
npm ci
npm audit --audit-level=moderate
npm run build
~~~

## Security requirements

- New assessment modules must enforce authorization scope before network access.
- Network activity must be bounded, transparent, TLS-verified and non-destructive.
- Never add exploit, credential-attack, stealth or persistence functionality.
- Findings must avoid returning credentials, secrets or sensitive response bodies.
- Secret-scanning code must not persist submitted source or echo matched values.
- Database changes require Alembic migrations and upgrade tests against legacy data.
- Audit events must preserve chain order and never claim legacy-unsealed events are verified.
- Document limitations and residual risks honestly.

## Licensing

By submitting a contribution, you agree that your contribution is submitted under the repository's Apache License, Version 2.0. You must have the right to submit the contribution under those terms.
