# SENTINEL Security Policy

## Supported baseline

Security reports are accepted for the latest code on the main branch and the latest tagged release, if any. Development branches and draft pull requests are not production releases.

## Report a vulnerability privately

Please do not disclose exploitable vulnerabilities in public issues or pull requests.

Use GitHub's **Report a vulnerability** feature on this repository's Security tab when private vulnerability reporting is available. Include:
- A clear impact summary and affected component.
- A minimal reproduction using assets you own or are authorized to test.
- Version, configuration and relevant sanitized logs.
- A suggested mitigation, if known.

Do not include live credentials, personal data or customer information. Do not test against third-party systems without written authorization.

## Current security controls

The current engineering baseline includes:
- API-key authentication with route-level role/permission checks for service principals.
- Database-managed service credentials stored as SHA-256 digests, one-time secret display, expiry, revocation and bounded rotation grace periods.
- Per-service request quotas with PostgreSQL-backed atomic accounting.
- Time-bounded asset authorization, hostname allowlisting, validated-public-IP DNS pinning, hostname-bound TLS and bounded HTTPS requests.
- PostgreSQL-backed assessment jobs and a separate resource-bounded worker container.
- Hash-linked audit events, offline signed checkpoints and audited CSV exports with formula-injection neutralization.
- CI dependency auditing, CodeQL, immutable workflow action references, Gitleaks, Trivy filesystem/container scans and SPDX SBOM generation.

These controls are implementation claims that must be checked against the exact commit's workflow results. They are not an independent security certification.

## Known limitations

- Service credentials are not human identities. OIDC/SAML SSO, MFA, human sessions and just-in-time privilege elevation are not implemented.
- The data model is single-workspace. Do not host mutually untrusted tenants until API and database tenant isolation has been implemented and independently reviewed.
- Application-level DNS pinning is not a substitute for a destination-enforcing network egress firewall or proxy.
- The audit chain is tamper-evident, not immutable against a privileged database operator. External append-only audit storage remains a production requirement.
- Assessment workers are resource-bounded containers but do not yet have per-job disposable VM/sandbox isolation.
- Backup checksums and restore verification do not provide encryption, off-site retention or a proven RPO/RTO.
- Secret detection covers known patterns only and is not a replacement for managed secret storage.
- No independent penetration test, production load certification or regulatory certification is claimed.

## Safe-use scope

SENTINEL is defensive software for DNS hostnames and systems owned by the operator or explicitly covered by written authorization. The project does not support stealth, exploitation, credential attacks, destructive testing or arbitrary internet-wide target discovery.

## Response expectations

This is a community development project without a staffed security response team. A maintainer will review reports as capacity allows. Please allow time for triage and coordinated remediation before public disclosure.
