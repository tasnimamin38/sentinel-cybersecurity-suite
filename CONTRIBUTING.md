# Contributing to SENTINEL

Thanks for helping improve SENTINEL. Contributions should keep the project defensive, auditable, small and safe by default.

## Before opening an issue

- Search existing issues to avoid duplicates.
- Include the affected component, expected behavior and reproducible steps.
- Never publish live tokens, credentials, customer data or private target information.
- Do not submit third-party targets unless you have authorization to share the test details.

## Pull requests

1. Create a focused branch from `main`.
2. Explain the problem and the smallest safe fix.
3. Add or update tests for behavior changes.
4. Update documentation when configuration, API contracts or safeguards change.
5. Keep dependencies justified and pinned through lockfiles where applicable.
6. Confirm no secrets, local databases, build outputs or environment files are included.

## Local validation

Backend:

```powershell
cd backend
python -m pip install -r requirements.txt pytest ruff
python -m pytest -q
ruff format --check app tests
ruff check app tests
```

Frontend:

```powershell
cd frontend
npm ci
npm run build
npm audit --omit=dev --audit-level=moderate
```

## Security requirements

- New assessment modules must enforce authorization scope before network access.
- Network activity must be bounded, transparent and non-destructive.
- Never add exploit, credential-attack, stealth or persistence functionality.
- Findings must avoid returning credentials, secrets or sensitive response bodies.
- Document limitations and residual risks honestly.

By submitting a contribution, you confirm that you have the right to submit it under the repository's future contribution terms.