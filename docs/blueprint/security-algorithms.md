# SENTINEL — Security Algorithms and Decision Models

**Algorithm set:** 0.2  
**Primary objective:** Safe, repeatable, explainable defensive assessment inside an explicit authorization boundary.

## 1. Domain authorization

Input is a DNS hostname, not an arbitrary URL.

1. Trim whitespace and a single trailing dot.
2. Reject schemes, paths, fragments, query strings, userinfo and IP literals.
3. Convert Unicode labels to IDNA ASCII and lowercase the result.
4. Validate total hostname length, label length and DNS-label syntax.
5. Normalize each configured allowlist entry using the same function.
6. Authorize only an exact match or a proper subdomain boundary (host equals allowed, or host ends in dot + allowed).

A string suffix match without the dot boundary is forbidden. For example, example.com.attacker.invalid must not match example.com.

## 2. DNS safety and pinned HTTPS transport

The assessment uses this fail-closed algorithm:

1. Canonicalize the submitted hostname and authorize it against the allowlist.
2. Resolve its A and AAAA records.
3. Reject an empty answer set, malformed IP, any non-global address, or more than 16 answers.
4. Start one shared monotonic deadline. The configured timeout is bounded to 0.5–20 seconds.
5. Connect TCP to a literal address from the validated answer set, never by resolving the hostname a second time.
6. Start TLS with the original canonical hostname as server_hostname. Certificate hostname validation and SNI therefore remain hostname-bound.
7. Send exactly one GET / HTTP/1.1 request with Host set to the canonical hostname and Connection: close.
8. Read only up to the response-header terminator, with a 64 KiB cap.
9. Do not follow Location redirects and do not download the response body.
10. Close the connection. If no validated address succeeds before the shared deadline, return an incomplete HTTPS result.

**Why pin the IP?** Resolving a hostname, validating its IP, and then connecting to the hostname again creates a time-of-check/time-of-use window. The 0.2 probe connects to a literal address from the already validated answer set, while preserving the original hostname for TLS SNI, certificate verification and the HTTP Host header.

**Residual boundary:** Application-layer pinning is not a replacement for network egress controls. Production workers still need an outbound firewall/proxy that enforces destination policy at connection time. DNS posture queries (MX/TXT) are separate read-only DNS lookups.

## 3. Explainable risk aggregation — sentinel-exponential-v2

### Inputs

Each normalized finding has a stable code, category, severity and optional confidence (default 1.0). Asset criticality is supplied through assessment context (default multiplier 1.0).

Severity points:

| Severity | Base points |
|---|---:|
| Critical | 100 |
| High | 70 |
| Medium | 35 |
| Low | 10 |
| Informational | 1 |

Confidence is clamped to 0.25–1.0. Asset criticality is clamped to 0.5–1.5. Duplicate category + finding-code pairs count once; the highest weighted instance wins.

### Formula

P = sum(severity_points × confidence × asset_criticality)

RiskScore = round(100 × (1 − exp(−P / 50)))

Any critical finding forces RiskScore = 100 and risk_level = critical.

| Score | Level |
|---:|---|
| 0 | Informational |
| 1–39 | Low |
| 40–69 | Moderate |
| 70–89 | High |
| 90–100 | Critical |

The API stores the model identifier, formula, raw weighted points, criticality multiplier, unique finding count and top five score drivers. This makes a score reviewable rather than a black-box number.

## 4. Finding normalization

A finding should be stable across runs and contain:

- code: immutable machine identifier (for example MISSING_CSP)
- category: web security, transport security, DNS, secrets or dependency posture
- severity: critical / high / medium / low / info
- confidence: numeric confidence where applicable
- description: observed condition, without speculative claims
- evidence: minimum required evidence; redact secrets and tokens
- recommendation: specific safe remediation guidance

A failed or unavailable test is an assessment failure/incomplete state, never an automatic pass.

## 5. Policy evaluation pipeline (target)

Identity → Tenant → Asset authorization → Scope policy → Execution policy → Evidence policy → Risk policy → Exception review → Audit export

The future policy engine should reject expired authorizations, prohibit out-of-scope assets, enforce maximum assessment budgets and require approval for high-impact checks. Policy exceptions must have an owner, reason, approver and expiry date.

## 6. Safety invariants

- No arbitrary IP-range discovery.
- No port scanning, exploitation, brute force, credential validation or stealth.
- No redirect following or response-body execution.
- No secret value in findings, logs or user-visible evidence.
- No production startup with weak API key, missing authorization scope, wildcard CORS or SQLite.
- No clean posture result when required evidence is missing.