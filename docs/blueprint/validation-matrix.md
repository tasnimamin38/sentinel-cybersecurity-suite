# SENTINEL Validation Matrix — 0.15

This matrix links security claims to repeatable checks. A skipped check, unavailable scanner or clean result with incomplete coverage must never be described as a pass.

| Area | Automated evidence | Limits |
|:---|:---|:---|
| Backend runtime compatibility | Full backend suite and static checks across Python 3.12 and 3.13; production Docker image on Python 3.13.18 | Exact-head CI matrix results remain the authoritative evidence |\n| API authentication | Missing/invalid/weak key, constant-time comparison path, static/managed credentials | No human SSO/MFA or session testing |
| Role authorization | Route-to-permission map, allowed and denied role tests | No tenant isolation to verify |
| Credential lifecycle | Hash-only persistence, one-time secret, expiry, revocation, rotation grace | External secret-manager integration is absent |
| Per-credential quota | Minute/day boundaries and PostgreSQL atomic concurrency checks | No tenant-wide fair-share policy |
| Asset scope | Allowlist boundaries, normalization, authorization expiry, paused/inactive denial | Approval remains operator-attested |
| Network safety | Public DNS answer validation and private/reserved address rejection | No independent network egress enforcement |
| HTTPS transport | Validated-IP connection, TLS hostname identity, bounded headers, no redirects/body download | No external egress firewall proof |
| DNS posture | MX, SPF, DMARC, CAA, MTA-STS, TLS-RPT and bounded lookup behavior | Resolver outages can produce incomplete evidence |
| Queue and worker | PostgreSQL job lifecycle, row-locked claims, leases, retry, cancellation and dead-letter | No per-job disposable VM isolation or production soak certification |
| Risk/remediation | Finding normalization, deterministic scoring, task lifecycle | SENTINEL score is not CVSS |
| Incident response | Finding-linked create, uniqueness, server-enforced status changes, timezone-aware deadlines, bounded notes, audit privacy | Notifications, SIEM and on-call paging are not configured |
| Audit assurance | Hash continuity, content verification, signed offline checkpoint tests | Privileged DB administrator can rewrite the stored chain |
| Secret hygiene | Pattern tests, redaction, no source persistence | Limited pattern set; not a secret manager |
| CSV exports | Dataset allowlist, authentication, row caps, audit event and formula-injection neutralization | Exports still require operator data-handling controls |
| GitHub Action integrity | Regression test requires a 40-character commit SHA for each workflow action | SHA pinning does not prove upstream code is benign |
| Dependency changes | pip-audit, npm audit and Dependency Review configuration | Dependency Review is blocked until repository Dependency Graph is enabled; advisory databases and metadata have coverage/freshness limits |
| Secret exposure | Gitleaks scans repository history | False positives require documented, reviewed exceptions |
| Filesystem configuration | Trivy vulnerability/misconfiguration/secret/license SARIF plus readable HIGH/CRITICAL gate | Fork PR SARIF upload is skipped by GitHub permission restrictions; raw SARIF retained 14 days |
| Container images | Trivy scans built backend/frontend images for HIGH/CRITICAL OS/library vulnerabilities | First 0.15 scan found setuptools 70.3.0 (CVE-2025-47273); Dockerfile remediation is pending exact-head rescan |
| Static analysis | CodeQL Python and JavaScript/TypeScript | SAST cannot prove absence of vulnerabilities |
| SBOM | SPDX JSON generated from repository workspace and stored as a 14-day artifact | Not yet signed; artifact is not an immutable long-term evidence store |
| Database migrations | PostgreSQL upgrade → downgrade → re-upgrade in CI | Does not prove production recovery objectives |
| Backup/restore | PostgreSQL backup checksum, corruption rejection and isolated restore verification | Checksum is not encryption; no automated off-site retention/RPO/RTO |

## Authoritative verification

For every change, inspect the latest GitHub Actions and CodeQL runs attached to the exact branch head SHA. Do not reuse a green result from a superseded commit. Record failed, skipped, cancelled and permission-restricted steps separately from passed checks.

## Not certified

The repository does not claim an independent penetration test, multi-tenant isolation, a production egress gateway, immutable external audit storage, per-job disposable VM isolation, regulatory certification, production load certification or a proven disaster-recovery objective.
