# SENTINEL 0.15 Supply-chain Security and Release Assurance Implementation Plan

> For agentic workers: use the host's available task-by-task implementation workflow. Steps use checkbox syntax for tracking.

**Goal:** Add verifiable supply-chain security gates and align architecture, threat model and release documentation with the 0.14 implementation.

**Architecture:** Keep the application runtime unchanged. Extend GitHub Actions with immutable action references, dependency review, secret scanning, Trivy filesystem/image scans and SPDX SBOM generation; use Dependabot for update proposals. Add standard-library policy regression tests so workflow security requirements are themselves tested.

**Tech Stack:** GitHub Actions, Gitleaks v3, Trivy v0.36.0, Anchore Syft SBOM Action v0.24.3, Dependabot, Python/pytest, FastAPI, React, TypeScript and Vite.

## Global Constraints

- SENTINEL remains defensive-only and limited to explicitly authorized assets.
- Do not add exploit, stealth, credential-attack or destructive testing functionality.
- Do not add production credentials, PATs, external secrets or sensitive environment values to source, workflow logs or artifacts.
- Do not increase workflow token permissions unless the specific step requires them.
- Pin external GitHub Actions to a reviewed full 40-character commit SHA.
- Do not suppress a high/critical finding without a narrow, documented, expiring exception.
- Fork-originated pull requests must run scanners without attempting write-token SARIF upload.
- SBOM generation must not publish a release asset or mutate the dependency graph in this phase.
- Do not alter database schemas, production deployment configuration or API behavior.
- Keep PR #29 and its upstream dependency chain unmerged; work remains in a draft PR stacked on the 0.14 branch.

---

## Task 1 — Immutable CI references and container image scans

**Files:** .github/workflows/ci.yml, .github/workflows/codeql.yml, backend/tests/test_supply_chain_policy.py.

**Interfaces:** CI builds sentinel-api:ci and sentinel-console:ci; Trivy consumes each local image after its build. The policy test inspects every workflow file under .github/workflows.

- [x] Add a regression test that rejects workflow action references without a full 40-character SHA.
- [x] Add assertions that backend and frontend image scans occur after their respective builds and gate HIGH/CRITICAL vulnerabilities.
- [x] Pin checkout, setup-python, setup-node and CodeQL action references to reviewed commit SHAs.
- [x] Add Trivy OS/library scans for both built images, with available-fix gating and bounded timeouts.
- [ ] Run from backend/: python -m pytest tests/test_supply_chain_policy.py -q; confirm the regression test passes.
- [ ] Run full backend pytest, Ruff format and Ruff lint; review CI and CodeQL on the exact new PR head.

## Task 2 — Dependency review, secret detection, filesystem scan and SBOM

**Files:** .github/workflows/supply-chain-security.yml, .github/dependabot.yml, backend/tests/test_supply_chain_policy.py.

**Interfaces:** Dependency Review runs only on pull_request; Gitleaks uses the automatically issued GITHUB_TOKEN with comments disabled; Trivy emits SARIF; Syft writes SPDX JSON which is uploaded for 14 days.

- [x] Add policy assertions for Dependency Review, Gitleaks, Trivy scanner classes, severity gates, fork upload condition and SBOM behavior.
- [x] Add Dependabot for pip at /backend, npm at /frontend and github-actions at /.
- [x] Add immutable action references and least-privilege workflow/job permissions.
- [x] Add weekly secret, dependency, filesystem/configuration scans and SPDX JSON generation.
- [ ] Run the focused policy tests and inspect the exact PR's Supply-chain Security workflow.
- [ ] Download and parse the generated SPDX JSON artifact; confirm it has the expected SPDX document structure.

## Task 3 — Version and documentation consistency

**Files:** backend/app/main.py, backend/tests/test_api_smoke.py, frontend/src/app.tsx, frontend/package.json, frontend/package-lock.json, CHANGELOG.md, README.md, SECURITY.md, docs/blueprint/roadmap.md, docs/blueprint/system-architecture.md, docs/blueprint/threat-model.md, docs/blueprint/validation-matrix.md, docs/blueprint/supply-chain-security.md.

- [x] Update backend/frontend release metadata to 0.15.0-pre.
- [x] Consolidate duplicate incident endpoint rows in README and replace historical hard-coded test counts with commit-specific CI evidence guidance.
- [x] Update roadmap milestones for 0.14 incident console and 0.15 supply-chain assurance.
- [x] Refresh architecture and STRIDE threat model to reflect actual service roles, managed credentials, PostgreSQL quotas/queue, incident workflow and network boundaries.
- [x] Document scanner controls, exception process, permissions and fork behavior.
- [ ] Run API smoke tests, workflow policy tests and frontend production build; correct any mismatch before asking for review.

## Task 4 — Exact-head verification and draft PR handoff

- [ ] Run backend pytest, Ruff format/lint, npm ci, npm audit and npm production build.
- [ ] Confirm CI, CodeQL and Supply-chain Security results belong to the latest PR head SHA.
- [ ] Record pass/fail/skipped/permission-restricted checks separately; do not treat scanner failure as a clean scan.
- [ ] Inspect the SPDX artifact and the changed-file diff.
- [ ] Keep PR draft while PR #28/#29 are unmerged; do not merge, tag, publish or deploy.

## Verification and rollback

This phase does not change the database schema or production service runtime. Rollback is a reviewable revert of the 0.15 feature-branch commit; no migration rollback is required. Scanner findings must be triaged before merge. A green workflow on an older SHA is not evidence for a newer head.

The initial exact-head CI observed 130 passing backend tests, but Ruff formatting failed on the new policy test; this patch formats it to Ruff's emitted diff. The initial image scan found CVE-2025-47273 in setuptools 70.3.0; remediation is included and must be revalidated. The Dependency Review action is blocked until the repository Dependency Graph is enabled. Treat the new head's checks as pending until they finish.
