# Supply-chain Security and Release Assurance

## Purpose

This policy protects the path from source change to reviewed release. It adds controls around dependency changes, workflow code, secret exposure, build configuration, container images and software inventory.

## Enforcement

| Control | Trigger | Gate | Evidence |
|:---|:---|:---|:---|
| Full-SHA action pinning | Every workflow change | Regression test rejects non-immutable external action references | Test output on the exact CI SHA |
| Dependency vulnerability audits | Pull requests | Run `pip-audit` against backend requirements and `npm audit --audit-level=high` against the exact frontend lockfile | Exact-head audit job; complete dependency-set checks, not a PR-diff delta or license-policy comparison |
| Gitleaks | Push, pull request and weekly schedule | Secret detections fail the job; PR comments stay disabled | Job summary and optional SARIF artifact |
| Trivy filesystem scan | Push, pull request and weekly schedule | SARIF is uploaded for review; a separate table-output gate fails on HIGH/CRITICAL findings with fixes | GitHub code scanning plus a 14-day raw SARIF workflow artifact |
| Trivy image scan | After each CI image build | Fixable HIGH/CRITICAL OS/library findings fail CI; unfixed findings remain visible | Container build job logs |
| SPDX SBOM | Push, pull request, schedule and manual dispatch | Generation must succeed | SPDX JSON workflow artifact retained for 14 days |
| Dependabot | Weekly | Opens reviewable updates for pip, npm and GitHub Actions; minor/patch updates are grouped | Pull requests |

## Action pinning

Workflow actions must use a full 40-character commit SHA. Keep the upstream release tag in a trailing comment for human review. Update a pin only after checking the upstream release and commit provenance. The pinning regression test prevents accidental reintroduction of mutable tags or branches.

## Permissions and untrusted pull requests

- Set workflow and job permissions explicitly; default to contents: read.
- Gitleaks PR comments are disabled, so the secret scan does not request pull-requests: write.
- Trivy receives security-events: write only in the filesystem scanning job.
- Fork-originated pull requests still run scans, but SARIF upload is skipped where GitHub reduces the token to read-only.
- No workflow should execute untrusted pull-request code with repository secrets.
- The SBOM is stored as a workflow artifact; this workflow does not publish release assets or modify the dependency graph.

## Exceptions

Do not suppress a finding merely to make CI green. An exception must identify the exact package/file/rule, owner, severity, rationale, compensating control, expiry date and tracking issue. Prefer a narrow path/rule allowlist over a broad scanner disable. Re-evaluate exceptions when the dependency, scanner database or deployment changes.

## Operating procedure

1. Review the exact commit SHA and all workflow results.
2. Inspect each high/critical result and determine whether it is reachable and applicable to the built artifact.
3. Upgrade the affected dependency/base image where a compatible fix exists.
4. Add a documented, expiring exception only when a fix is unavailable or an accurately scoped false positive is confirmed.
5. Download and inspect the SPDX SBOM artifact; retain it with release evidence when a release process is introduced.
6. Never describe a scanner as clean when it failed, skipped or could not upload results.

## Current limitations

The backend is built in a multi-stage pipeline: the builder uses the official Python 3.13.18 slim Trixie image, while the final runtime is a clean Debian Trixie stage. pip, setuptools, wheel and ensurepip are removed after dependency installation; CI tests both Python 3.12 and 3.13. The SBOM is not yet signed and the workflow does not generate SLSA provenance or attest container artifacts. A repository SBOM is not a complete bill of materials for a production deployment that adds external services or runtime configuration. Independent review of upstream packages, release signing, protected release environments and long-term evidence retention remain future work.


## Current repository prerequisites and findings

- GitHub's Dependency Graph is enabled. Pull requests now run the native `actions/dependency-review-action`, pinned to a verified full commit SHA. The gate blocks newly introduced HIGH and CRITICAL vulnerabilities. License checks are explicitly disabled until the project adopts and documents an approved/denied license policy.
- The independent `pip-audit` and `npm audit` steps remain in place. They audit the complete checked-in backend and frontend dependency sets, while Dependency Review evaluates dependency changes introduced by a pull request. These checks serve different purposes and neither replaces the other.
- The initial backend image scan detected `setuptools 70.3.0` with `CVE-2025-47273` (HIGH; fixed version `78.1.1`). The 0.15 patch removes the Debian `python3-setuptools` package when present and enforces a patched pip setuptools floor in the backend runtime image. The next exact-head image scan must confirm the finding is gone.
- The filesystem Trivy scan retains SARIF as a 14-day artifact and runs a readable table-output security gate. This preserves the detailed evidence while keeping the severity threshold enforceable.
