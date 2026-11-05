# SENTINEL 0.3.2 — Passive posture analysis

This increment extends the defensive, read-only posture engine. It does not introduce exploitation, brute force, credential testing or arbitrary network discovery.

## DNS observations

The DNS posture service now records:

- MX presence (informational when absent)
- SPF presence, duplicate SPF policies, and permissive/neutral/softfail terminal mechanisms
- DMARC presence, duplicate records, monitor-only policy and malformed policy tags
- CAA presence, including lookup through parent DNS labels so inherited CAA policy is not incorrectly reported as missing
- MTA-STS TXT discovery record presence
- SMTP TLS-RPT TXT reporting record presence

The engine only performs DNS lookups. It does not change records and does not fetch the MTA-STS HTTPS policy file; a TXT discovery record is not proof that the referenced policy is valid or enforced.

## HTTP response-policy observations

The bounded HTTPS probe continues to connect to a validated literal public IP while retaining hostname-bound TLS verification and SNI. Header analysis now checks:

- HSTS presence, max-age below one year and includeSubDomains coverage
- CSP unsafe-eval, unsafe-inline and wildcard script sources
- Referrer policies with broader URL disclosure
- Wildcard Permissions Policy feature allowlists
- Existing MIME sniffing and frame-protection checks

These are static posture indicators, not browser execution tests. CSP compatibility must be tested against the application's real assets before enforcement. includeSubDomains and HSTS preload should only be enabled after all affected hosts are HTTPS-ready.

## Validation

- 62 backend tests pass locally.
- DNS lookups share a bounded deadline; timeouts are reported as incomplete rather than absent records.
- Ruff lint and format checks pass.
- Frontend TypeScript/Vite production build passes.
- pip-audit reports no known vulnerabilities.
- npm audit reports zero vulnerabilities.
- Docker Compose YAML parses locally; container runtime is not verified in this environment.
