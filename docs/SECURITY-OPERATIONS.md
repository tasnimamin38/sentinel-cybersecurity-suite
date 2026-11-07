# SENTINEL Repository and Runtime Security Operations

This guide covers GitHub repository hardening and the production controls shipped by SENTINEL. It is an operator checklist, not a claim that repository settings have already been changed.

## 1. Protect the GitHub repository

The repository is currently public. Anyone can read and clone its source. Do not commit secrets, customer data, private certificates, database dumps or production logs. If the source itself is proprietary, change repository visibility to **Private** in GitHub Settings; that visibility change is an owner decision and is not performed by this application.

Apply a branch ruleset to `main` in **Settings → Rules → Rulesets → New branch ruleset**:

1. Target the `main` branch and set the ruleset to Active.
2. Require pull requests before merging. Require at least one approval from a trusted reviewer, dismiss stale approvals after new commits, and require approval of the latest reviewable push.
3. Require conversation resolution and branches to be up to date before merging.
4. Require the current checks: **CI**, **CodeQL**, and **Supply-chain Security**. Confirm the exact check names shown by a fresh PR run before selecting them.
5. Block force pushes and branch deletion. Avoid broad administrator bypasses; keep any emergency bypass limited to a documented maintainer procedure.
6. Do not enable CODEOWNERS approval as a sole-review gate while `.github/CODEOWNERS` only names the repository owner. A PR author cannot approve their own changes; add at least one trusted independent reviewer first.

When available, also enable these features under **Settings → Code security and analysis**:

- Secret scanning and push protection.
- Dependabot alerts and Dependabot security updates.
- Code scanning / CodeQL (the repository already defines a CodeQL workflow).
- Private vulnerability reporting.

Use GitHub 2FA, preferably a passkey or hardware security key. Keep personal access tokens short-lived and least-privileged, revoke unused tokens, and never place a PAT in workflow YAML or a committed file. Keep Actions workflow permissions read-only by default and grant write permissions only to the specific job that needs them. Pin third-party Actions to reviewed full commit SHAs.

**Observed repository settings limitation:** the repository-level rulesets read returned an empty list on the last check. The connected GitHub API integration could not read the legacy branch-protection endpoint, and it does not expose a write operation for branch protection/rulesets. Therefore this guide does not claim that `main` is protected. The owner must apply and verify the ruleset in GitHub Settings.

## 2. Runtime protection in the Compose deployment

The Compose stack adds an authenticated Redis 8 service on the private `sentinel-data` network. The API is the only service that needs Redis for rate limits. Redis is not published to the host or browser network. Production API startup requires an authenticated Redis URL and a trusted proxy CIDR; the API refuses to start if Redis cannot be reached. If Redis becomes unavailable later, API requests fail closed with HTTP 503 rather than silently bypassing rate limits.

Generate separate random 32-byte (64-character hex) values for:

- `POSTGRES_PASSWORD`
- `REDIS_PASSWORD`
- `SENTINEL_API_KEY`

Keep real values in the deployment secret store or an uncommitted `.env` file. Never use the example values. When using a non-default `SENTINEL_WEB_SUBNET`, set `SENTINEL_TRUSTED_PROXY_CIDRS` to the same proxy network. The default Compose pair is `172.30.240.0/24`.

Default shared limits per rolling 60-second window:

| Bucket | Default |
|:---|---:|
| Requests per observed client IP | 300 |
| Requests per API credential fingerprint | 120 |
| Assessment requests | 10 |
| Secret scan requests | 20 |
| Honeypot events per observed IP | 10 |

Tune these limits for expected traffic and capacity. A shared IP may represent multiple legitimate users behind NAT or a corporate proxy.

## 3. Intrusion evidence and honeypot behavior

Nginx forwards the following decoy paths to the API. The application does not serve secrets or repository files at those paths; it records the attempted access and returns the normal not-found response:

- `/.env`, `/.git/*`, `/.aws/*`
- `/wp-admin/*`, `/wp-login.php`, `/phpmyadmin/*`, `/adminer.php`
- `/actuator/env`, `/server-status`, `/.well-known/sentinel-canary`

The monitor also records API authentication failures and rate-limit denials. Repeated failed API authentication from an observed source IP triggers a brute-force signal after the configured threshold (default: five attempts within five minutes). Decoy/honeypot traffic has a separate per-IP event ceiling (default: 10/minute); once exceeded, Nginx-forwarded probes receive HTTP 429 and repeated blocked probes are not appended to the audit journal.

Operators with the `audit.read` permission can query:

```http
GET /api/v1/security/events
X-API-Key: <operator-or-auditor-credential>
```

Optional query parameters: `limit` (1–200) and `severity` (`low`, `medium`, `high`, or `critical`). Security events are also appended to the existing hash-linked audit journal.

Stored evidence is deliberately limited to the rule ID, severity, source IP, URL path without query string, method, printable user-agent label, timestamp and request ID. Request bodies, query values, cookies and API keys are not stored. The IP comes from `X-Real-IP` only when the immediate peer is inside `SENTINEL_TRUSTED_PROXY_CIDRS`; otherwise the socket peer IP is used. `X-Forwarded-For` is not trusted.

An IP address identifies a network endpoint, not necessarily a person. VPNs, proxies, NAT and shared networks can conceal the originating device or individual. Do not attempt to access or retaliate against an external system based on these indicators.

## 4. Signed security webhook

To send high/critical signals to an operator-controlled alert receiver, configure:

- `SENTINEL_SECURITY_ALERT_WEBHOOK_URL`: HTTPS URL only.
- `SENTINEL_SECURITY_ALERT_WEBHOOK_SECRET`: random secret of at least 32 characters.

SENTINEL signs the exact JSON request body using HMAC-SHA256 and sends the value in `X-SENTINEL-Signature` as `sha256=<hex>`. The receiver must compute the HMAC over the raw received body and compare signatures in constant time. The client uses a short timeout and does not follow redirects. Delivery failures are logged without printing the URL, signing secret or event payload.

## 5. Incident response checklist

1. Preserve the alert, request ID, audit event and relevant reverse-proxy/server logs.
2. Check whether the event is a honeypot probe, credential failure, rate-limit response or a confirmed application issue.
3. Revoke an exposed managed API credential using the admin credential console or API. Rotate the bootstrap API key, Redis password and database password if their secrecy may be affected.
4. Review `/api/v1/security/events`, `/api/v1/audit` and audit-chain integrity. Export evidence to storage controlled separately from the application database.
5. Temporarily restrict ingress or disable the affected integration if active compromise is suspected. Do not block shared proxy/NAT ranges without evaluating legitimate users.
6. Patch the root cause, run CI/CodeQL/supply-chain checks, and deploy through a reviewed pull request.
7. Report repository or platform vulnerabilities privately using GitHub's **Report a vulnerability** feature. Do not publish exploit details or personal data in public issues.

## 6. Important boundaries

SENTINEL Shield is an application-level intrusion signal and abuse-control layer. It is not a WAF, endpoint detection and response agent, network firewall, DDoS scrubbing service or a guarantee against compromise. Production still requires TLS termination, host/network firewalling, least-privilege deployment, backups and restore exercises, centralized log retention, alert receiver monitoring, and independent security review. The database-resident audit chain is tamper-evident, not immutable; a database administrator who can rewrite the full chain can defeat it.
