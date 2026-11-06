# SENTINEL Threat Model

**Baseline:** SENTINEL 0.14 operator-grade incident workflow  
**Hardening track:** 0.15 supply-chain security and release assurance  
**Method:** STRIDE-style analysis of the implemented single-workspace defensive security platform.

This document distinguishes implemented controls from residual risks and roadmap items. A passing test or CI workflow is evidence for the behavior tested; it is not an independent penetration test.

## System context and protected assets

SENTINEL is a FastAPI control plane, React operations console, SQL persistence layer, PostgreSQL-backed assessment queue, separate worker service and GitHub Actions build pipeline. Its assessment engine is limited to explicitly authorized hostnames configured by the operator.

Protected assets:
- Service API credentials, credential digests, bootstrap configuration and database secrets.
- Authorization records, allowlisted hostnames, owner/change references and expiry dates.
- Assessment evidence, normalized findings, risk scores and remediation records.
- Security incidents, operator notes, due dates and audit history.
- Queue state, worker leases, retry/dead-letter records and backups.
- GitHub repository, workflow permissions, dependency manifests, container images and generated SBOMs.

## Trust boundaries

| Boundary | Data crossing it | Existing controls | Residual risk |
|:---|:---|:---|:---|
| Browser → API | API key, filters and operator edits | Key held in component memory; no local-storage persistence; CORS allowlist; security headers; no-store API responses | A compromised browser or endpoint can expose the active service key |
| API → authorization policy | Hostname, asset ID and authorization reference | Server-side allowlist, normalization, exact/proper-subdomain matching, active-state and expiry checks | Approval reference is operator-attested; no external approval directory |
| API → DNS/HTTPS | Authorized hostname and bounded request | Complete answer validation, reject non-global addresses, connect to validated literal IP, preserve TLS hostname identity, no redirects, bounded headers/timeouts | Network-level egress enforcement remains required |
| API/worker → PostgreSQL | Credentials, assets, findings, jobs and incidents | SQLAlchemy parameterization, transactions, Alembic migrations, readiness gate, role-scoped API permissions | Privileged DB operator can access or alter stored records |
| API → audit journal | Event metadata and changed-field names | Hash-linked sequence, integrity verifier and signed offline checkpoints; free-form incident notes excluded | An administrator able to rewrite the full database chain can defeat an in-database hash chain |
| Build pipeline → dependencies/actions | Package archives, workflow action code and base images | pip/npm audits, CodeQL, immutable full-SHA action references, Dependabot, Gitleaks, Trivy and SBOM generation | A compromised upstream dependency or signed malicious release can still enter through an approved update |
| Worker → authorized target | DNS/TLS evidence requests | Allowlist gate, DNS pinning, bounded requests, separate resource-limited worker container | Compose egress network is not a destination-filtering firewall; no per-job disposable sandbox |

## STRIDE threat register

| Threat | Example attack path | Implemented prevention/detection | Severity before controls | Residual risk and next mitigation |
|:---|:---|:---|:---:|:---|
| Spoofing | Attacker reuses a leaked service key | Constant-time comparison; role-scoped static and managed credentials; hash-only managed-key storage; expiry, revocation, bounded rotation and quotas | High | No human SSO/MFA or short-lived user sessions. Add federation, session controls and workload identity before hosted multi-user use |
| Tampering | Hostname suffix confusion or DNS rebinding changes the assessed destination | Canonical hostname policy, strict allowlist boundary, complete DNS answer validation, validated-IP connection and hostname-bound TLS | High | Deploy an independent egress firewall/proxy that enforces destination policy at connection time |
| Tampering | Unauthorized workflow or dependency change alters a release | Full-SHA GitHub Action pins, dependency review, CodeQL and Trivy gates | High | Add signed build provenance, artifact attestations and protected release environments |
| Repudiation | Operator disputes an incident or credential change | Hash-linked audit events, chain verification, principal metadata and field-name-only incident audit details | Medium | Export signed checkpoints automatically to independently controlled append-only storage |
| Information disclosure | Secret value appears in a scan result, UI or audit event | Bounded secret scan with redaction/fingerprints, no source-text persistence, bounded incident notes, no-store headers and audit metadata excluding free-form notes | High | Pattern coverage is incomplete; add external secret manager, encryption/retention and data-classification review |
| Denial of service | Expensive assessment or request burst exhausts API/worker resources | Per-service quotas with PostgreSQL atomic accounting, bounded network timeouts, request-size caps, queue retry/dead-letter controls and CPU/memory/PID-limited worker container | High | No tenant-fair scheduling or independently enforced egress gateway; add load/soak tests and per-job isolation |
| Elevation of privilege | Read-only or auditor credential performs a write | Fail-closed route-to-permission map, role-specific permission sets and server-side state transitions | High | No per-human identity, JIT privilege or tenant row boundary; independent authorization review required before multi-user hosting |
| Supply-chain compromise | Secret, vulnerable package, malicious workflow action or compromised image enters a release | Gitleaks, dependency review, pip/npm audit, CodeQL, Trivy filesystem/image scans, full-SHA action pins, weekly Dependabot and SPDX artifact | High | Scanning cannot prove a dependency benign; add signed provenance, controlled release attestations and long-term SBOM retention |

## Required detection and response signals

- Authentication failures, quota violations, credential expiry/revocation and rotation events.
- Authorization-denied assessment attempts, expired/paused asset assessments and scope violations.
- Assessment job retry exhaustion, lease expiry, dead-letter growth and worker shutdown.
- Audit-chain verification failures and signed-checkpoint mismatches.
- Gitleaks detections, newly introduced dependency advisories, Trivy high/critical findings and SBOM-generation failures.
- CI or CodeQL failures on the current PR head SHA.

## Release-blocking residual risks

1. No multi-tenant isolation or human SSO/MFA: do not expose this single-workspace service to mutually untrusted customer tenants.
2. No independent egress gateway: application DNS pinning is not a network firewall.
3. No independent immutable audit store: do not claim non-repudiation against database administrators.
4. No per-job disposable sandbox: worker containers share the host kernel.
5. No independent penetration test, production load certification or recovery objective has been completed.

## Explicit non-goals

SENTINEL is not an exploit launcher, credential-attack framework, stealth scanner, destructive testing system or arbitrary internet-wide discovery tool. All assessment work remains limited to explicitly authorized assets.
