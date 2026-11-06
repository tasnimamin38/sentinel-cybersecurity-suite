# Supply-chain Security and Release Assurance

## Purpose

This policy protects the path from source change to reviewed release. It adds controls around dependency changes, workflow code, secret exposure, build configuration, container images and software inventory.

## Enforcement

| Control | Trigger | Gate | Evidence |
|:---|:---|:---|:---|
| Full-SHA action pinning | Every workflow change | Regression test rejects non-immutable external action references | Test output on the exact CI SHA |
| Dependency Review | Pull requests | Fail for newly introduced high/critical runtime or development vulnerabilities; review license metadata | Dependency Review job summary |
| Gitleaks | Push, pull request and weekly schedule | Secret detections fail the job; PR comments stay disabled | Job summary and optional SARIF artifact |
| Trivy filesystem scan | Push, pull request and weekly schedule | HIGH/CRITICAL findings fail; scanners cover vulnerability, misconfiguration, secret and license classes | SARIF in GitHub code scanning when upload permissions are available |
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

The SBOM is not yet signed and the workflow does not generate SLSA provenance or attest container artifacts. A repository SBOM is not a complete bill of materials for a production deployment that adds external services or runtime configuration. Independent review of upstream packages, release signing, protected release environments and long-term evidence retention remain future work.
